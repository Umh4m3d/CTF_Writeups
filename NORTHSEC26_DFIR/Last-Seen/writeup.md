# Last Seen DFIR challenge Writeup

### Description

Badr disappeared after heading to a meeting. Police recovered a copy of the MobileSync/Backup directory from his MacBook. Now your turn to investigate.

Flag format: NSC{sha256(Device|Contact|SSID|CallTime|PostCallSearch)}

The goal was to identify:

- Badr's current iPhone backup
- the coordinator contact
- the meetup Wi-Fi SSID
- the answered cellular call after arrival
- the first Safari search after that call

Then build:

```text
Device|Contact|SSID|CallTime|PostCallSearch
```

and hash it with SHA-256.

---

### Initial Triage

I first checked the archive and extracted it.

```bash
file challenge.zip
7z l challenge.zip
7z x challenge.zip -oextract
```

The archive contained three Apple backup roots under:

```text
Last_Seen_Case/MobileSync/Backup/
```

The case notes also said one backup was an iPad and one was an older phone, so the first task was to identify the current iPhone correctly.

---

### Step 1: Identify Badr's current iPhone backup

I read each backup's `Info.plist` and compared device type and backup date.

```bash
python3 - <<'PY'
from pathlib import Path
import plistlib

base = Path("extract/Last_Seen_Case/MobileSync/Backup")
for d in sorted(p for p in base.iterdir() if p.is_dir()):
    info = plistlib.load((d / "Info.plist").open("rb"))
    print(d.name, info["Device Name"], info["Product Name"], info["Last Backup Date"])
PY
```

That showed:

```text
9f1a5c8f4ed2c7a1cb4a7db6c1c55e139ad8a2b4  badr-iphone      iPhone 14 Pro  2025-01-03 14:16:45
c37a8d9b60f1aa52bd99a466eb0f6b8c274e13f1  badr-ipad-mini   iPad mini      2025-01-03 09:11:08
f24be8d6e733bc91d0d4c92811bfbac97ef0a7d2  badr-old-iphone  iPhone 11      2024-09-18 10:03:21
```

So the correct current device was:

```text
badr-iphone
```

---

### Step 2: Map the useful files from Manifest.db

After choosing the correct backup, I used `Manifest.db` to resolve the original artifact paths.

```bash
sqlite3 -header -column 9f1a5c8f4ed2c7a1cb4a7db6c1c55e139ad8a2b4/Manifest.db \
"select fileID, domain, relativePath
 from Files
 order by domain, relativePath;"
```

The important files were:

```text
Library/AddressBook/AddressBook.sqlitedb
Library/SMS/sms.db
Library/CallHistoryDB/CallHistory.storedata
Library/Safari/History.db
SystemConfiguration/com.apple.wifi.known-networks.plist
```

These were enough to solve the whole timeline.

---

### Step 3: Resolve the coordinator contact

I first mapped contact names to numbers from the address book.

```bash
sqlite3 -header -column 31bb7ba8914766d4ba40d6dfb6113c8b614be442 \
"select p.ROWID, p.First, p.Last, m.label, m.value
 from ABPerson p
 left join ABMultiValue m on p.ROWID=m.record_id
 order by p.ROWID;"
```

The important rows were:

```text
Youssef B.  +212687654321
Omar        +212612345678
Nabil       +212644539290
Samir       +212650008888
```

Then I checked the SMS timeline:

```bash
sqlite3 -header -column 3d0d7e5fb2ce288813306e4d4636395e047a3d28 \
"select h.id as handle, m.is_from_me, datetime(m.date/1000000000 + 978307200,'unixepoch') as utc, m.text
 from message m
 left join handle h on h.ROWID=m.handle_id
 order by m.date;"
```

The messages around the meetup were:

```text
2025-01-01 17:55:12  +212687654321  فين وصلتي؟
2025-01-01 17:59:09  +212687654321  أنا قربت الحافة
2025-01-01 18:03:21  +212687654321  طلع للفوق ما توقفش لتحت
2025-01-01 18:06:02  +212687654321  رد عليا ملي توصل
2025-01-01 18:06:50  badr -> +212687654321  أنا داخل دابا
```

This clearly showed the coordinator was:

```text
Youssef
```

---

### Step 4: Identify the meetup Wi-Fi network

For arrival proof, I checked the saved Wi-Fi records.

```bash
python3 - <<'PY'
import plistlib
from pprint import pprint

p = "c663901a1df544dbbf002c6775da1bc5e271e6ec"
obj = plistlib.load(open(p, "rb"))
pprint(obj["List of known networks"])
PY
```

The most relevant network was:

```text
SSID_STR: CAFE-HAFA-GUEST
LastJoined: 2025-01-01 17:52:41
```

This matched the challenge story about the meetup near Café Hafa, so the correct SSID was:

```text
CAFE-HAFA-GUEST
```

---

### Step 5: Find the answered cellular call after arrival

Next I checked the call history database.

```bash
sqlite3 -header -column 5a4935c78a5255723f707230a451d79c540d2741 \
"select ZADDRESS, datetime(ZDATE + 978307200,'unixepoch') as utc, ZDURATION, ZANSWERED, ZCALLTYPE
 from ZCALLRECORD
 order by ZDATE;"
```

The relevant rows were:

```text
+212687654321  2025-01-01 18:07:34  184  1  1
+212699112233  2025-01-01 18:08:40  611  1  8
+33612345678   2025-01-01 18:12:00  520  0  1
```

The challenge specifically asked for the **answered cellular call tied to the coordinator after arrival**.

That means:

- it must be after the Café Hafa Wi-Fi join
- it must be tied to the coordinator number
- it must be answered
- it must be a normal cellular call

So the correct call time was:

```text
2025-01-01T18:07:34Z
```

---

### Step 6: Find the first Safari search after that call

Finally, I checked Safari history.

```bash
sqlite3 -header -column 1a0e7afc19d307da602ccdcece51af33afe92c53 \
"select hi.title, datetime(hv.visit_time + 978307200,'unixepoch') as utc
 from history_visits hv
 join history_items hi on hi.id=hv.history_item
 order by hv.visit_time;"
```

The important rows were:

```text
2025-01-01 17:18:00  Cafe Hafa
2025-01-01 17:24:00  sunset time tangier
2025-01-01 18:14:10  taxi marshan tangier
```

The first Safari search after the `18:07:34Z` call was:

```text
taxi marshan tangier
```

---

### Step 7: Build the final string and hash it

The final string was:

```text
badr-iphone|Youssef|CAFE-HAFA-GUEST|2025-01-01T18:07:34Z|taxi marshan tangier
```

---

### Flag

hashing the result with SHA-256 gave:

```text
NSC{f0c32a3b758affced247a0525f4dbe89f7c9f3a48bfdf9fbb9eba4553df7e3bb}
```
