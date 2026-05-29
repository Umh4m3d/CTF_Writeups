# Silent Interlock DFIR Challenge Writeup

### Description

Marrowgate WTP experienced an unexplained process upset during a planned maintenance window. Investigate the provided forensic evidence and submit answers through the CTFd questions interface.

This challenge provided an offline DFIR and ICS/OT evidence package for a water treatment plant incident. The goal was to reconstruct the access chain, identify the unauthorized engineering change, and correlate the PLC, historian, HMI, and network evidence.

You can Download the files from here: https://drive.google.com/file/d/1gCOK_xXN3Mc5BUgRFLuE-1OuynlTgSJz/view?usp=sharing

### Initial Triage

I started by extracting the case and listing the evidence groups before trying to answer any question.

The inventory showed that the useful artifacts were split across identity logs, Linux jump-host logs, Windows workstation artifacts, ticket records, SAFEPLC project files, historian data, HMI logs, OPC UA logs, and packet captures.

## Solved Questions

### Q01. Which VPN account had the accepted authentication that later correlates to the OT access chain?

I began with the identity evidence and looked at all VPN authentication events.

```bash
cat "$CASE/identity/vpn_gateway.log"
```

This showed multiple VPN sessions. The interesting one was the later successful login from an unknown Windows device:

```text
2026-04-17T21:06:13Z AUTH_SUCCESS MARROWGATE\mara.ellis 198.51.100.77 172.31.44.23 vpn-20260417-884216 allow mfa_ok GateLinkVPN unknown-windows
2026-04-17T21:06:31Z TUNNEL_UP MARROWGATE\mara.ellis 198.51.100.77 172.31.44.23 vpn-20260417-884216 allow split_tunnel GateLinkVPN unknown-windows
```

To make sure this was not just a normal VPN login, I checked the jump-host logs next.

```bash
cat "$CASE/linux/jump-host/auth.log"
```

The same user and VPN session appeared in the OT access path:

```text
Apr 17 21:08:02 jump-host sshd[14881]: Accepted keyboard-interactive/pam for mara.ellis from 172.31.44.23 port 49822 ssh2 session=vpn-20260417-884216
Apr 17 21:12:20 jump-host rdp-proxy[14903]: new channel user=mara.ellis dst=ENG-WS01:3389 src=172.31.44.23 session=vpn-20260417-884216
```

Answer:

```text
MARROWGATE\mara.ellis
```

### Q02. What was the VPN session ID used for the OT access?

From the same VPN and jump-host correlation, I kept the session ID that followed the OT chain.

```bash
cat "$CASE/identity/radius_auth.jsonl" | jq .
cat "$CASE/identity/mfa_events.jsonl" | jq .
cat "$CASE/linux/jump-host/systemd-journal.jsonl" | jq .
```

The session was consistently tied to the accepted RADIUS event, approved MFA event, and jump-host login.

Answer:

```text
vpn-20260417-884216
```

### Q03. What was the first OT host reached after VPN login?

After identifying the VPN session, I moved to the firewall log and read the traffic in time order.

```bash
column -s, -t "$CASE/network/firewall.csv"
```

The first OT access from the assigned VPN IP was:

```text
2026-04-17T21:08:02Z  172.31.44.23  10.42.5.15  JUMP-01  22  allow  vpn-20260417-884216  vpn_to_jump
```

Answer:

```text
JUMP-01
```

### Q04. Which workstation was used for the unauthorized engineering action?

The jump host showed an RDP channel after SSH login. I then checked the engineering upload log to see where the upload came from.

```bash
cat "$CASE/linux/jump-host/auth.log"
cat "$CASE/scada/engineering/upload_logs/upload_20260417.jsonl" | jq .
```

The RDP channel went to `ENG-WS01`, and the SAFEPLC upload also came from that host:

```text
dst=ENG-WS01:3389
"host": "ENG-WS01"
"action": "upload_begin"
"target": "PLC-CHEM"
```

Answer:

```text
ENG-WS01
```

### Q05. What was the compromised user's SID?

Once the compromised account was known, I inspected the AD security events.

```bash
cat "$CASE/identity/ad_security_events.jsonl" | jq .
```

The logon event for `mara.ellis` included the SID:

```text
"TargetUserName": "mara.ellis"
"TargetUserSid": "S-1-5-21-4107334210-2511681102-3907789116-1127"
```

Answer:

```text
S-1-5-21-4107334210-2511681102-3907789116-1127
```

### Q06. What was the maintenance ticket ID that was backfilled?

Next I looked at the ticket artifacts without assuming which ticket was malicious.

```bash
ls -l "$CASE/tickets"
cat "$CASE/tickets/exported_ticket_report.csv"
cat "$CASE/tickets/ticket_audit.log"
```

The audit log exposed a ticket created with `create_backfill` by the compromised user from `ENG-WS01`.

```text
2026-04-17T21:52:43Z seq=1187 ticket=MW-2026-0417-CHM-1842 action=create_backfill effective=2026-04-17T20:41:02Z writer=mara.ellis host=ENG-WS01 rowid=backfilled
```

Answer:

```text
MW-2026-0417-CHM-1842
```

### Q07. Which audit log source exposes the forged/backfilled maintenance event?

The artifact that exposed the forged event was the ticket audit log itself.

```bash
find "$CASE/tickets" -maxdepth 1 -type f -printf '%P\n'
cat "$CASE/tickets/ticket_audit.log"
```

Answer:

```text
tickets/ticket_audit.log
```

### Q08. What was the exact UTC time the attacker first opened the engineering project?

After identifying `ENG-WS01`, I checked workstation artifacts for project access.

```bash
ls -l "$CASE/windows/ENG-WS01"
cat "$CASE/windows/ENG-WS01/RecentFiles.csv"
cat "$CASE/windows/ENG-WS01/JumpLists.csv"
```

The earliest ChemDose project open by the compromised user was:

```text
2026-04-17T21:18:44Z,MARROWGATE\mara.ellis,D:\Projects\Marrowgate_ChemDose.safeplc,SafeLogicStudio.exe,RecentDocs
```

Answer:

```text
2026-04-17T21:18:44Z
```

### Q09. Which PLC area was modified?

I then moved from workstation evidence to the engineering logs.

```bash
find "$CASE/scada/engineering" -maxdepth 3 -type f | sort
cat "$CASE/scada/engineering/compile_logs/compile_20260417_213218.log"
cat "$CASE/scada/engineering/upload_logs/upload_20260417.jsonl" | jq .
```

The compile and upload logs both pointed to the same area:

```text
target=PLC-CHEM
area=chemical_dosing
```

Answer:

```text
chemical_dosing
```

### Q10. What was the original SAFEPLC project VERSION_HASH for the modified PLC?

The compile log gave the baseline hash. I also checked the PLC before snapshot to confirm it.

```bash
cat "$CASE/scada/engineering/compile_logs/compile_20260417_213218.log"
head -n 12 "$CASE/scada/plc/logic_snapshot_before.safeplc.txt"
```

Relevant values:

```text
baseline_version_hash=be1f6a21af9502446067d957f5dc29455bedaae8cfd1e256dbcf63aec110f807
VERSION_HASH be1f6a21af9502446067d957f5dc29455bedaae8cfd1e256dbcf63aec110f807
```

Answer:

```text
be1f6a21af9502446067d957f5dc29455bedaae8cfd1e256dbcf63aec110f807
```

### Q11. What was the modified SAFEPLC project VERSION_HASH compiled for upload?

In the same compile and upload logs, I observed the target hash for the uploaded version.

```bash
cat "$CASE/scada/engineering/compile_logs/compile_20260417_213218.log"
cat "$CASE/scada/engineering/upload_logs/upload_20260417.jsonl" | jq .
head -n 12 "$CASE/scada/plc/logic_snapshot_after_partial.safeplc.txt"
```

Relevant values:

```text
compiled_version_hash=8751fb65a949ed3421dff2c20f5ce2f9548845d5475414ec7b8ca062e49db205
"to_version": "8751fb65a949ed3421dff2c20f5ce2f9548845d5475414ec7b8ca062e49db205"
VERSION_HASH 8751fb65a949ed3421dff2c20f5ce2f9548845d5475414ec7b8ca062e49db205
```

Answer:

```text
8751fb65a949ed3421dff2c20f5ce2f9548845d5475414ec7b8ca062e49db205
```

### Q12. Which exact SAFEPLC boolean condition was removed from the permissive?

To understand what changed, I compared the before and after PLC logic around the permissive.

```bash
nl -ba "$CASE/scada/plc/logic_snapshot_before.safeplc.txt" | sed -n '21,31p'
nl -ba "$CASE/scada/plc/logic_snapshot_after_partial.safeplc.txt" | sed -n '21,29p'
```

Before:

```text
INTERLOCK CHM_DOSING_PUMP_P201_PERMISSIVE :=
    CHM_ESTOP_OK AND
    CHM_P201_LOCAL_READY AND
    CHM_TANK_LEVEL_OK AND
    NOT CHM_BYPASS_VALVE_OPEN AND
    CHM_FLOWPATH_CONFIRMED;
```

After:

```text
INTERLOCK CHM_DOSING_PUMP_P201_PERMISSIVE :=
    CHM_ESTOP_OK AND
    CHM_P201_LOCAL_READY AND
    CHM_TANK_LEVEL_OK AND
    CHM_FLOWPATH_CONFIRMED;
```

The removed condition was the bypass valve safety check.

Answer:

```text
NOT CHM_BYPASS_VALVE_OPEN
```

### Q13. Which HMI alarm was suppressed?

I checked the HMI artifacts after seeing the bypass alarm logic in the PLC program.

```bash
cat "$CASE/scada/hmi/alarm_journal.csv"
cat "$CASE/scada/hmi/operator_actions.csv"
cat "$CASE/scada/hmi/alarm_acknowledgements.csv"
```

The alarm journal showed the suppression:

```text
2026-04-17T21:36:52Z,ALM-CHM-0427,suppressed,CHM_ALM_BYPASS_AND_RUN,HMI-01,,opc-sess-6ce1a4b9
```

Answer:

```text
ALM-CHM-0427
```

### Q14. Which canonical historian tag shows stale pump run-feedback data during the blind window?

The next question pointed to historian evidence, so I inspected the historian quality file.

```bash
find "$CASE/scada/historian" -maxdepth 2 -type f | sort
cat "$CASE/scada/historian/quality_flags.csv"
```

The blind window was marked with `hold_last_good` quality:

```text
CHM.PMP-201.RUN_FB,2026-04-17T21:37:10Z,2026-04-17T21:48:10Z,hold_last_good,HMI-01,blind_window
```

Answer:

```text
CHM.PMP-201.RUN_FB
```

### Q15 and Q16. What were the start and end times of the historian gap?

The same historian quality interval gave the gap boundaries.

```bash
column -s, -t "$CASE/scada/historian/quality_flags.csv"
cat "$CASE/scada/historian/recovered_segments/recovered_chm_window.csv" | head
cat "$CASE/scada/historian/recovered_segments/recovered_chm_window.csv" | tail
```

Answer:

```text
Start: 2026-04-17T21:37:10Z
End:   2026-04-17T21:48:10Z
```

### Q17. Which exact OPC UA NodeId was written to hide the alarm state?

Since the alarm journal referenced an OPC session, I inspected the OPC UA session log.

```bash
cat "$CASE/network/opcua_sessions.jsonl" | jq .
```

The write that hid the alarm state was:

```text
"event": "Write"
"node_id": "ns=4;s=HMI/Alarms/ALM-CHM-0427/Suppressed"
"value": true
```

Answer:

```text
ns=4;s=HMI/Alarms/ALM-CHM-0427/Suppressed
```

### Q18. What Modbus-style unit/register pair received the unauthorized dosing setpoint write?

I first checked the PLC I/O map to understand how tags map to protocol addresses.

```bash
cat "$CASE/scada/plc/io_map.csv"
```

The setpoint tag was mapped like this:

```text
PLC-CHEM,7,CHM_DOSE_P201_SP,modbus,40127,126,holding_register,0.1,L/min
```

Then I inspected the captures for Modbus writes. At this point I did not know which capture had the write, so I checked all capture filenames and then looked for write function codes.

```bash
ls -lh "$CASE/network/captures"

for pcap in "$CASE"/network/captures/*.pcapng.zst; do
  echo "== $(basename "$pcap") =="
  zstdcat "$pcap" \
  | tshark -r - \
      -Y 'modbus.func_code == 6 || modbus.func_code == 16' \
      -T fields \
      -e frame.time_epoch \
      -e frame.number \
      -e ip.src \
      -e ip.dst \
      -e mbtcp.unit_id \
      -e modbus.func_code \
      -e modbus.reference_num \
      -e modbus.regval_uint16 \
  | head
done
```

After seeing the engineering capture had the relevant write from `ENG-WS01` to `PLC-CHEM`, I reran it with the useful fields.

```bash
zstdcat "$CASE/network/captures/eng-span-001.pcapng.zst" \
| tshark -r - \
    -Y 'modbus.func_code == 6 || modbus.func_code == 16' \
    -T fields \
    -e frame.time_epoch \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e mbtcp.unit_id \
    -e modbus.func_code \
    -e modbus.reference_num \
    -e modbus.regval_uint16
```

The relevant packet was:

```text
1776461824.000000000  214018  10.42.20.31  10.42.100.12  7  6  126  375
```

The unit was `7`, and the I/O map showed offset `126` corresponds to holding register `40127`.

Answer:

```text
7:40127
```

### Q19. What was the unauthorized pump run duration in seconds?

The PLC event log showed the pump run feedback state changes.

```bash
cat "$CASE/scada/plc/plc_event_log.csv"
```

Relevant events:

```text
2026-04-17T21:37:10Z,PLC-CHEM,chemical_dosing,pump_run_feedback,,CHM_DOSE_P201_RUN_FB,1,
2026-04-17T21:48:10Z,PLC-CHEM,chemical_dosing,pump_run_feedback,,CHM_DOSE_P201_RUN_FB,0,
```

I calculated the duration:

```bash
python3 - <<'PY'
from datetime import datetime, timezone

start = datetime.fromisoformat("2026-04-17T21:37:10+00:00")
end = datetime.fromisoformat("2026-04-17T21:48:10+00:00")
print(int((end - start).total_seconds()))
PY
```

Answer:

```text
660
```

### Q20. What was the exact chemical dosing setpoint applied during the event?

The same PLC event log showed the setpoint write. I also checked retentive memory as a second source.

```bash
cat "$CASE/scada/plc/plc_event_log.csv"
strings "$CASE/scada/plc/retentive_memory_dump.bin"
```

Relevant values:

```text
2026-04-17T21:37:04Z,PLC-CHEM,chemical_dosing,setpoint_write,,CHM_DOSE_P201_SP,37.5,L/min
CHM_DOSE_P201_SP=37.5
```

Answer:

```text
37.5
```

### Q21. Which packet capture file contains the unauthorized dosing setpoint Modbus write?

While solving Q18, the write was found in the engineering span capture. I verified it by showing the Modbus write packet from that file.

```bash
zstdcat "$CASE/network/captures/eng-span-001.pcapng.zst" \
| tshark -r - \
    -Y 'modbus.func_code == 6 || modbus.func_code == 16' \
    -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e mbtcp.unit_id \
    -e modbus.reference_num \
    -e modbus.regval_uint16
```

Answer:

```text
eng-span-001.pcapng.zst
```

### Q22. What is the SHA256 of the reconstructed effective SAFEPLC project file?

The uploaded SAFEPLC project was split into fragments. I first listed the fragments and their sequence numbers.

```bash
for f in "$CASE"/scada/engineering/project_fragments/*.part; do
  echo "== $(basename "$f") =="
  head -n 2 "$f"
done
```

The observed order was:

```text
cacheblk_002.safeplc.part  sequence=1/3
cacheblk_003.safeplc.part  sequence=2/3
cacheblk_001.safeplc.part  sequence=3/3
```

I reconstructed the effective project by joining the fragment payloads in that order.

```bash
python3 - <<'PY'
from pathlib import Path

case = Path("/home/ethicalone/challenges/forensics/silent-interlock/case")
frag_dir = case / "scada/engineering/project_fragments"
order = [
    "cacheblk_002.safeplc.part",
    "cacheblk_003.safeplc.part",
    "cacheblk_001.safeplc.part",
]

out = b""
for name in order:
    data = (frag_dir / name).read_bytes()
    payload = data.split(b"---BEGIN---\n", 1)[1].rsplit(b"---END---\n", 1)[0]
    out += payload

Path("/home/ethicalone/challenges/forensics/silent-interlock/reconstructed_effective.safeplc").write_bytes(out)
PY

head -n 35 /home/ethicalone/challenges/forensics/silent-interlock/reconstructed_effective.safeplc
sha256sum /home/ethicalone/challenges/forensics/silent-interlock/reconstructed_effective.safeplc
```

Answer:

```text
7b974d5aebf47ae54d28fc31c7a1da7942f7d096b4a580a051bcd96e40a3aee3
```

### Q23. Final incident fingerprint

At this point all required values had already been recovered. The only special detail was that the removed interlock tag must be used without `NOT`, so I used `CHM_BYPASS_VALVE_OPEN`.

```bash
python3 - <<'PY'
import hashlib

vpn_session_id = "vpn-20260417-884216"
compromised_sid = "S-1-5-21-4107334210-2511681102-3907789116-1127"
plc_area = "chemical_dosing"
removed_interlock_tag = "CHM_BYPASS_VALVE_OPEN"
historian_gap_start = "2026-04-17T21:37:10Z"
historian_gap_end = "2026-04-17T21:48:10Z"
reconstructed_project_sha256 = "7b974d5aebf47ae54d28fc31c7a1da7942f7d096b4a580a051bcd96e40a3aee3"

data = "|".join([
    vpn_session_id,
    compromised_sid,
    plc_area,
    removed_interlock_tag,
    historian_gap_start,
    historian_gap_end,
    reconstructed_project_sha256,
])

print(data)
print(hashlib.sha256(data.encode()).hexdigest())
PY
```

Output:

```text
vpn-20260417-884216|S-1-5-21-4107334210-2511681102-3907789116-1127|chemical_dosing|CHM_BYPASS_VALVE_OPEN|2026-04-17T21:37:10Z|2026-04-17T21:48:10Z|7b974d5aebf47ae54d28fc31c7a1da7942f7d096b4a580a051bcd96e40a3aee3
237eb6bc7e52e7ca5874ca35d68254b018dc84a991e4407d68a5a0bdc78970cc
```

Answer:

```text
237eb6bc7e52e7ca5874ca35d68254b018dc84a991e4407d68a5a0bdc78970cc
```

# Final Answers

```text
Q01: MARROWGATE\mara.ellis
Q02: vpn-20260417-884216
Q03: JUMP-01
Q04: ENG-WS01
Q05: S-1-5-21-4107334210-2511681102-3907789116-1127
Q06: MW-2026-0417-CHM-1842
Q07: tickets/ticket_audit.log
Q08: 2026-04-17T21:18:44Z
Q09: chemical_dosing
Q10: be1f6a21af9502446067d957f5dc29455bedaae8cfd1e256dbcf63aec110f807
Q11: 8751fb65a949ed3421dff2c20f5ce2f9548845d5475414ec7b8ca062e49db205
Q12: NOT CHM_BYPASS_VALVE_OPEN
Q13: ALM-CHM-0427
Q14: CHM.PMP-201.RUN_FB
Q15: 2026-04-17T21:37:10Z
Q16: 2026-04-17T21:48:10Z
Q17: ns=4;s=HMI/Alarms/ALM-CHM-0427/Suppressed
Q18: 7:40127
Q19: 660
Q20: 37.5
Q21: eng-span-001.pcapng.zst
Q22: 7b974d5aebf47ae54d28fc31c7a1da7942f7d096b4a580a051bcd96e40a3aee3
Q23: 237eb6bc7e52e7ca5874ca35d68254b018dc84a991e4407d68a5a0bdc78970cc
```

# Conclusion

The attack path was a VPN login as `MARROWGATE\mara.ellis`, followed by access to `JUMP-01`, RDP into `ENG-WS01`, a SAFEPLC logic modification for `PLC-CHEM`, suppression of the HMI alarm, and a historian blind window while the pump ran with an unauthorized dosing setpoint. The key was to move artifact by artifact and let each finding guide the next search instead of searching directly for final answers.
