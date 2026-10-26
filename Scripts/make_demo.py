"""Builds Demo/Demo.kdbx — a fictional database for trying Kept and taking screenshots.
Password: demo. Requires pykeepass (pip install pykeepass)."""
import datetime, json, os, sys, uuid
from pykeepass import create_database

path = os.path.join(os.path.dirname(__file__), "..", "Demo", "Demo.kdbx")
if os.path.exists(path): os.remove(path)
kp = create_database(path, password="demo")
kp.database_name = "Personal Vault"
kp.root_group.uuid = uuid.uuid4()

def otp(label, secret):
    return f"otpauth://totp/{label}?secret={secret}&issuer={label}&digits=6&period=30"

groups = {name: kp.add_group(kp.root_group, name, icon=icon)
          for name, icon in [("Personal", "60"), ("Work", "20"), ("Finance", "37"), ("Social", "1"), ("Developer", "30")]}
servers = kp.add_group(groups["Developer"], "Servers", icon="3")
for g in [*groups.values(), servers]: g.uuid = uuid.uuid4()

E = []
def add(group, title, user, pw, url="", notes="", tags=None, otp_secret=None, fields=None, expires=None):
    e = kp.add_entry(group, title, user, pw, url=url, notes=notes, tags=tags, force_creation=True)
    e.uuid = uuid.uuid4()  # pykeepass defaults to uuid1, which embeds a host identifier
    if otp_secret: e.otp = otp(title.replace(" ", ""), otp_secret)
    for k, (v, prot) in (fields or {}).items(): e.set_custom_property(k, v, protect=prot)
    if expires:
        e.expires = True
        e.expiry_time = expires
    E.append(e)
    return e

add(groups["Personal"], "iCloud", "alex.morgan@example.com", "Tr4il-Maple-Lantern!", "https://icloud.com",
    tags=["apple"], otp_secret="JBSWY3DPEHPK3PXP")
add(groups["Personal"], "Home Wi-Fi", "Morgan-5G", "correct horse battery staple",
    notes="Router admin is at 192.168.1.1\nGuest network: Morgan-Guest / welcome-friends", tags=["home"])
add(groups["Personal"], "Netflix", "alex.morgan@example.com", "Popcorn&Sofa#2024", "https://netflix.com", tags=["streaming"])
add(groups["Personal"], "Spotify", "alexm", "vinyl-Records-88", "https://open.spotify.com", tags=["streaming"])
add(groups["Personal"], "Passport", "", "", notes="Number: X1234567\nIssued: 2019-03-14\nExpires: 2029-03-13",
    fields={"Number": ("X1234567", True)}, tags=["documents"])

add(groups["Work"], "Acme SSO", "amorgan@acme.example", "Q3-Roadmap-Rocket!", "https://sso.acme.example",
    tags=["work"], otp_secret="KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
add(groups["Work"], "Slack", "amorgan@acme.example", "s1ack-off-Friday", "https://acme.slack.com", tags=["work"])
add(groups["Work"], "Figma", "amorgan@acme.example", "pixel+Perfect=42", "https://figma.com", tags=["work", "design"])
add(groups["Work"], "Office Door Code", "", "4821", notes="Side entrance after 7pm", expires=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))

add(groups["Finance"], "Northwind Bank", "alexmorgan", "Ledger!Balance-77", "https://northwind-bank.example",
    fields={"Account Number": ("00123456789", True), "Routing Number": ("021000021", False),
            "Security Question": ("First pet: Biscuit", True)}, tags=["bank"], otp_secret="GEZDGNBVGY3TQOJQGEZDGNBVGY")
add(groups["Finance"], "Visa •••• 4242", "Alex Morgan", "", fields={"Card Number": ("4242 4242 4242 4242", True),
    "Expiry": ("08/28", False), "CVV": ("123", True), "PIN": ("9876", True)}, tags=["card"])
add(groups["Finance"], "Brokerage", "alex.morgan", "Bull-Market-Bear-91", "https://invest.example", tags=["bank"])

add(groups["Social"], "Mastodon", "@alex@social.example", "toot-Toot-Train!9", "https://social.example")
add(groups["Social"], "Reddit", "alex_morgan_dev", "upvote*Narwhal*Bacon", "https://reddit.com")
add(groups["Social"], "Discord", "alexm#0001", "voice-Chat-Lounge-5", "https://discord.com", otp_secret="MFRGGZDFMZTWQ2LK")

gh = add(groups["Developer"], "GitHub", "alexmorgan-dev", "Merge-Conflict-Resolved!1", "https://github.com",
    notes="Personal account. Recovery codes attached.", tags=["dev"], otp_secret="NBSWY3DPO5XXE3DE",
    fields={"Personal Access Token": ("ghp_EXAMPLEexampleEXAMPLEexample0000", True)})
att = kp.add_binary(b"a1b2c-3d4e5\nf6g7h-8i9j0\nk1l2m-3n4o5\n")
gh.add_attachment(att, "github-recovery-codes.txt")
add(groups["Developer"], "npm", "alexmorgan", "semver^1.0.0-bump", "https://npmjs.com", tags=["dev"])
add(groups["Developer"], "AWS Console", "alex.morgan", "Cloud-Formation-Stack#3", "https://console.aws.example",
    fields={"Account ID": ("123456789012", False)}, tags=["dev"], otp_secret="ONSWG4TFOQYTEMZU")
add(servers, "web-01 (SSH)", "deploy", "ssh-Key-Passphrase!", "ssh://web-01.example.net", tags=["dev", "ssh"])
add(servers, "Postgres Prod", "app_user", "SELECT*FROM-secrets;", "postgres://db.example.net:5432/app",
    tags=["dev", "database"])
kp.save()

favorites = [str(e.uuid).upper() for e in E if e.title in ("iCloud", "GitHub", "Northwind Bank", "Home Wi-Fi", "Acme SSO")]
selected = next(str(e.uuid).upper() for e in E if e.title == "GitHub")
print(json.dumps({"root": str(kp.root_group.uuid).upper(), "favorites": favorites, "selected": selected,
                  "bank": next(str(e.uuid).upper() for e in E if e.title == "Northwind Bank"),
                  "finance": str(groups["Finance"].uuid).upper()}))
