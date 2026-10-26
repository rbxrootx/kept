"""Generates test databases for KDBXKit tests. Requires pykeepass (and its pycryptodomex dependency)."""
import os, sys, base64, gzip, hashlib, struct, uuid
from pykeepass import create_database
from Cryptodome.Cipher import AES, Salsa20
from Cryptodome.Util.Padding import pad

out = sys.argv[1]
PASSWORD = "test-password"

# ---- KDBX 4 (Argon2d + AES + ChaCha20 inner stream) via pykeepass ----
kp = create_database(os.path.join(out, "v4.kdbx"), password=PASSWORD)
g = kp.add_group(kp.root_group, "Social")
e = kp.add_entry(g, "Twitter", "alex", "hunter2 ünïcødé", url="https://x.com", notes="line1\nline2", tags=["web", "social"])
e.set_custom_property("Recovery", "abcd-efgh", protect=True)
e.otp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&period=30"
e.save_history()
e.password = "newer-pass"
kp.add_entry(kp.root_group, "Bank", "me@bank", "s3cret!")
for item in [*kp.entries, *kp.groups]: item.uuid = uuid.uuid4()  # avoid uuid1 host identifiers
kp.save()

# ---- KDBX 3.1 (AES-KDF + AES-CBC + Salsa20), hand-built to mirror KeePass 2.x output ----
def b64(b): return base64.b64encode(b).decode()
stream_key = os.urandom(32)
start_bytes, master_seed, transform_seed, iv = os.urandom(32), os.urandom(32), os.urandom(32), os.urandom(16)
rounds = 6000
def field(i, v): return struct.pack("<BH", i, len(v)) + v
header = struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 3)
header += field(2, bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")) + field(3, struct.pack("<I", 1))
header += field(4, master_seed) + field(5, transform_seed) + field(6, struct.pack("<Q", rounds))
header += field(7, iv) + field(8, stream_key) + field(9, start_bytes) + field(10, struct.pack("<I", 2))
header += field(0, b"\r\n\r\n")
salsa = Salsa20.new(key=hashlib.sha256(stream_key).digest(), nonce=bytes.fromhex("E830094B97205D2A"))
def prot(s): return b64(salsa.encrypt(s.encode()))
u = lambda: b64(os.urandom(16))
attachment = b64(gzip.compress(b"hello attachment"))
# Protected values must be encrypted in document order.
xml = f"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><HeaderHash>{b64(hashlib.sha256(header).digest())}</HeaderHash><DatabaseName>Legacy DB</DatabaseName>
<Binaries><Binary ID="0" Compressed="True">{attachment}</Binary></Binaries></Meta>
<Root><Group><UUID>{u()}</UUID><Name>Root</Name><IconID>48</IconID>
<Entry><UUID>{u()}</UUID><IconID>0</IconID><Tags>a;b</Tags>
<Times><CreationTime>2020-01-02T03:04:05Z</CreationTime><Expires>False</Expires><ExpiryTime>2020-01-01T00:00:00Z</ExpiryTime></Times>
<String><Key>Title</Key><Value>Mail</Value></String>
<String><Key>UserName</Key><Value>user@mail</Value></String>
<String><Key>Password</Key><Value Protected="True">{prot("first-secret")}</Value></String>
<Binary><Key>note.txt</Key><Value Ref="0"/></Binary>
<History><Entry><UUID>{u()}</UUID><String><Key>Password</Key><Value Protected="True">{prot("old-secret")}</Value></String></Entry></History>
</Entry>
<Group><UUID>{u()}</UUID><Name>Work</Name><IconID>1</IconID>
<Entry><UUID>{u()}</UUID><String><Key>Title</Key><Value>VPN</Value></String>
<String><Key>Password</Key><Value Protected="True">{prot("second-secret")}</Value></String>
<String><Key>PIN</Key><Value Protected="True">{prot("1234")}</Value></String></Entry>
</Group></Group></Root></KeePassFile>""".encode()

payload = gzip.compress(xml)
blocks = struct.pack("<I", 0) + hashlib.sha256(payload).digest() + struct.pack("<I", len(payload)) + payload
blocks += struct.pack("<I", 1) + b"\0" * 32 + struct.pack("<I", 0)

composite = hashlib.sha256(hashlib.sha256(PASSWORD.encode()).digest()).digest()
ecb = AES.new(transform_seed, AES.MODE_ECB)
k = composite
for _ in range(rounds): k = ecb.encrypt(k)
master = hashlib.sha256(master_seed + hashlib.sha256(k).digest()).digest()
cipher = AES.new(master, AES.MODE_CBC, iv).encrypt(pad(start_bytes + blocks, 16))

open(os.path.join(out, "v3.kdbx"), "wb").write(header + cipher)
print("ok")
