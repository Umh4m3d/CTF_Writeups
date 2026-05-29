# Matryoshka DFIR Challenge Writeup

## Description

We were given one file:

```text
matryoshka.pcapng
```

---

## Step 1: Find suspicious DNS traffic

First, we checked the protocols inside the PCAP:

```bash
tshark -r matryoshka.pcapng -q -z io,phs
```

The most interesting traffic was DNS TXT traffic.

We found many DNS requests like this:

```text
_svc00.sync.update-cdn.local
_svc01.sync.update-cdn.local
...
_svc20.sync.update-cdn.local
```

These DNS TXT records were hiding data.

We extracted them with:

```bash
tshark -r matryoshka.pcapng \
  -Y 'dns.flags.response == 1 && dns.txt' \
  -T fields \
  -e dns.qry.name \
  -e dns.txt \
  > dns_responses.txt
```

---

## Step 2: Decode the DNS data

The DNS records were small chunks of one big message.

After joining the chunks and decoding them, we recovered a config file.

The important values were:

```json
{
  "family": "MatryoshkaLoader/2.1",
  "operator": "misha",
  "server_key_password": "r0ut3r-cache-2026",
  "stage_url": "https://10.10.0.80/update/checkin"
}
```

This config helped us recover a TLS private key:

```text
server.key
```

This key was important because it allowed us to decrypt the HTTPS traffic.

---

## Step 3: Decrypt the HTTPS traffic

Using `server.key`, we exported the hidden HTTP files from the PCAP:

```bash
mkdir http_out

tshark -r matryoshka.pcapng \
  -o "uat:ssl_keys:\"10.10.0.80\",\"443\",\"http\",\"$PWD/server.key\",\"\"" \
  --export-objects http,http_out
```

This gave us:

```text
checkin
stage.py
blob
```

We also checked the HTTP requests:

```bash
tshark -r matryoshka.pcapng \
  -o "uat:ssl_keys:\"10.10.0.80\",\"443\",\"http\",\"$PWD/server.key\",\"\"" \
  -Y http \
  -T fields \
  -e frame.number \
  -e http.request.method \
  -e http.request.uri \
  -e http.response.code \
  -e http.content_type
```

We saw:

```text
POST /update/checkin
GET  /update/stage.py
GET  /update/blob
```

---

## Step 4: Read the Python stage

The file `stage.py` gave us two important clues:

```python
STAGE1_PASSWORD = "matryoshka"
MASK_LITERAL = b"layer2-mask"
```

The `blob` file was not ready yet.

It had to be:

1. base64-decoded
2. XOR-decoded using `layer2-mask`

---

## Step 5: Decode the blob into a 7z archive

We decoded the blob with this script:

```bash
python3 - <<'PY'
import base64
import hashlib
from pathlib import Path

masked_b64 = Path("http_out/blob").read_text().strip()
masked = base64.b64decode(masked_b64)

key = hashlib.sha256(b"layer2-mask").digest()
plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(masked))

Path("unmasked_layer_rebuilt.7z").write_bytes(plain)

print("Magic:", plain[:16].hex())
print("Size:", len(plain))
PY
```

Then we checked the file:

```bash
file unmasked_layer_rebuilt.7z
```

Output:

```text
7-zip archive data
```

So we had found the next layer.

The archive password was:

```text
matryoshkaaaa
```

We extracted it with:

```bash
7z x unmasked_layer_rebuilt.7z -pmatryoshkaaaa -ostage1_extract
```

This gave us another PCAP:

```text
stage1.pcapng
```

---

## Step 6: Analyze the second PCAP

The second PCAP contained:

```text
USB keyboard traffic
SMB file transfer
```

The USB keyboard traffic showed what the attacker typed.

From the keyboard data, we recovered this password:

```text
n3st3d_d0ll_h4s_t33th
```

Then we exported the SMB files:

```bash
tshark -r stage1.pcapng \
  --export-objects smb,smb_out
```

This gave us another archive:

```text
ops_backup.7z
```

We extracted it using the password from the USB keystrokes:

```bash
7z x ops_backup.7z \
  -pn3st3d_d0ll_h4s_t33th \
  -ostage2_extract
```

This gave us the final PCAP:

```text
stage2.pcapng
```

---

## Step 7: Analyze the final PCAP

The final PCAP was very small.

It contained an ICMP packet.

The payload started with:

```text
MTRY3
```

This matched the value from `stage.py`:

```python
MAGIC = b"MTRY3"
```

So we knew this was the final encrypted payload.

Using the original `checkin` data, the stage code, and the ICMP payload, we decrypted the final message.

The result was:

```json
{
  "case": "MATRYOSHKA-v3",
  "flag": "NSC{idk_what_to_put_here}",
  "host": "WINBOX"
}
```

---

## Flag

```text
NSC{idk_what_to_put_here}
```
---


## Conclusion

The challenge name was **Matryoshka**, which means a nested doll.

That was the main idea of the challenge: every layer gave us another hidden layer.

```text
PCAP
 ↓
DNS hidden data
 ↓
HTTPS files
 ↓
7z archive
 ↓
second PCAP
 ↓
another 7z archive
 ↓
final PCAP
 ↓
flag
``` 

