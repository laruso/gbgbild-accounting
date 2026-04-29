"""
find_accdb_password.py — Find the Access database password.

The LFP Accounting Tool .accdb is password-protected.
The password must be stored somewhere in the LFP tool installation.

Strategy:
1. Search config/registry for stored passwords
2. Search DLL/EXE files for embedded strings
3. Try common Epson default passwords
4. Try to crack the Access database password (Access uses weak encryption)

Run on the Windows machine:
  python find_accdb_password.py > accdb_password_log.txt 2>&1
"""

import os, sys, struct, glob, re

ACCDB_PATH = r"C:\ProgramData\EPSON\LFP Accounting Tool\UserData\AccountingTool.accdb"

# ─── Method 1: Search config files for password strings ───────────────────────
print("=" * 70)
print("Method 1: Search config files for password strings")
print("=" * 70)

config_dirs = [
    r"C:\ProgramData\EPSON\LFP Accounting Tool",
    r"C:\Program Files\EPSON\LFP Accounting Tool",
    r"C:\Program Files (x86)\EPSON\LFP Accounting Tool",
    os.path.expanduser(r"~\AppData\Local\EPSON"),
    os.path.expanduser(r"~\AppData\Roaming\EPSON"),
]

for config_dir in config_dirs:
    if not os.path.exists(config_dir):
        continue
    print(f"\nSearching: {config_dir}")
    for root, dirs, files in os.walk(config_dir):
        for f in files:
            path = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            # Skip binary database files
            if ext in ('.accdb', '.mdb', '.laccdb', '.db'):
                print(f"  [skip db] {path}")
                continue
            # Read text/config files
            if ext in ('.ini', '.cfg', '.config', '.xml', '.json', '.txt', '.properties', '.setting', '.dat'):
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                        content = fh.read()
                    # Search for password-related strings
                    for pattern in ['password', 'passwd', 'pwd', 'pass=', 'dbpwd', 'dbpass', 'jet']:
                        if pattern.lower() in content.lower():
                            lines = [l for l in content.split('\n') if pattern.lower() in l.lower()]
                            for line in lines[:5]:
                                print(f"  FOUND in {path}: {line.strip()[:100]}")
                except:
                    pass

            # Also check small binary files for embedded password strings
            if os.path.getsize(path) < 1_000_000:
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read()
                    # Search for "PWD=" or "Password=" in various encodings
                    for needle in [b'PWD=', b'Password=', b'Pwd=', b'password=',
                                   b'P\x00W\x00D\x00=\x00', b'P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00']:
                        idx = data.find(needle)
                        while idx >= 0:
                            context = data[max(0,idx-20):idx+60]
                            # Try to decode
                            try:
                                txt = context.decode('utf-8', errors='replace')
                            except:
                                txt = context.hex()
                            print(f"  FOUND in {path} at offset {idx}: {txt[:80]!r}")
                            idx = data.find(needle, idx + 1)
                except:
                    pass

# ─── Method 2: Check Windows Registry ────────────────────────────────────────
print("\n" + "=" * 70)
print("Method 2: Check Windows Registry for EPSON LFP entries")
print("=" * 70)

try:
    import winreg
    for hive_name, hive in [("HKLM", winreg.HKEY_LOCAL_MACHINE),
                             ("HKCU", winreg.HKEY_CURRENT_USER)]:
        for subkey in [
            r"SOFTWARE\EPSON\LFP Accounting Tool",
            r"SOFTWARE\Epson\LFP Accounting Tool",
            r"SOFTWARE\WOW6432Node\EPSON\LFP Accounting Tool",
            r"SOFTWARE\WOW6432Node\Epson\LFP Accounting Tool",
        ]:
            try:
                key = winreg.OpenKey(hive, subkey)
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, i)
                        print(f"  {hive_name}\\{subkey}\\{name} = {value!r} (type={vtype})")
                        i += 1
                    except OSError:
                        break
                # Also enumerate subkeys
                i = 0
                while True:
                    try:
                        sk_name = winreg.EnumKey(key, i)
                        print(f"  {hive_name}\\{subkey}\\{sk_name}\\")
                        try:
                            sk = winreg.OpenKey(key, sk_name)
                            j = 0
                            while True:
                                try:
                                    name, value, vtype = winreg.EnumValue(sk, j)
                                    print(f"    {name} = {value!r} (type={vtype})")
                                    j += 1
                                except OSError:
                                    break
                        except:
                            pass
                        i += 1
                    except OSError:
                        break
            except FileNotFoundError:
                pass
            except Exception as e:
                print(f"  Error reading {hive_name}\\{subkey}: {e}")
except ImportError:
    print("  winreg not available (not Windows?)")

# ─── Method 3: Extract Access DB password directly from file header ───────────
print("\n" + "=" * 70)
print("Method 3: Extract password from .accdb file header")
print("=" * 70)

if os.path.exists(ACCDB_PATH):
    with open(ACCDB_PATH, 'rb') as f:
        header = f.read(256)

    # Access 2010+ (.accdb) stores the password XOR'd in the header
    # The password is at offset 0x42, XOR'd with a fixed key
    # For Access 2010 (.accdb), the XOR key depends on the version

    print(f"File: {ACCDB_PATH}")
    print(f"Header bytes 0x00-0x0F: {header[0:16].hex()}")
    print(f"Header bytes 0x10-0x1F: {header[16:32].hex()}")
    print(f"Header bytes 0x40-0x5F: {header[64:96].hex()}")
    print(f"Header bytes 0x60-0x7F: {header[96:128].hex()}")

    # Detect Access version
    # Access 2000: bytes at 0x14 = 0x00
    # Access 2007: bytes at 0x14 = 0x01
    # Access 2010: bytes at 0x14 = 0x02
    # Access 2013: bytes at 0x14 = 0x03
    version_byte = header[0x14] if len(header) > 0x14 else 0
    print(f"Version byte at 0x14: {version_byte:#04x}")

    # Access database password is stored at offset 0x42, encrypted
    # The encryption is a simple XOR with a hardcoded key
    # Key depends on Jet version

    # For Access 2010+ (.accdb), the password bytes at 0x42-0x61 (32 bytes)
    # are XOR'd with this key:
    ACCDB_XOR_KEY = bytes([
        0xa1, 0xec, 0x7a, 0x9c, 0xe1, 0x28, 0x34, 0x8a,
        0x73, 0x7b, 0xd2, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    # Alternative key used by some tools
    ACCDB_XOR_KEY2 = bytes([
        0xbe, 0xec, 0x65, 0x9c, 0xfe, 0x28, 0x2b, 0x8a,
        0x6c, 0x7b, 0xcd, 0x12, 0x00, 0x00, 0x00, 0x00,
    ])

    pwd_bytes = header[0x42:0x62]
    print(f"\nPassword bytes at 0x42-0x61: {pwd_bytes.hex()}")

    # Try XOR decryption with both keys
    for key_name, key in [("key1", ACCDB_XOR_KEY), ("key2", ACCDB_XOR_KEY2)]:
        decrypted = bytes(a ^ b for a, b in zip(pwd_bytes, key))
        # Try as UTF-16LE (common for Access passwords)
        try:
            pwd_utf16 = decrypted.decode('utf-16-le').rstrip('\x00')
            if pwd_utf16 and all(32 <= ord(c) < 127 for c in pwd_utf16):
                print(f"  {key_name} → UTF-16LE password: {pwd_utf16!r}")
            else:
                print(f"  {key_name} → UTF-16LE: {pwd_utf16!r} (may contain non-printable)")
        except:
            print(f"  {key_name} → UTF-16LE decode failed: {decrypted.hex()}")

        # Try as ASCII
        try:
            pwd_ascii = decrypted.decode('ascii', errors='replace').rstrip('\x00')
            if pwd_ascii and pwd_ascii != pwd_utf16:
                print(f"  {key_name} → ASCII: {pwd_ascii!r}")
        except:
            pass

# ─── Method 4: Try common Epson passwords ────────────────────────────────────
print("\n" + "=" * 70)
print("Method 4: Try common Epson default passwords")
print("=" * 70)

try:
    import pyodbc
    common_passwords = [
        "", "epson", "EPSON", "Epson", "admin", "password", "1234",
        "lfp", "LFP", "accounting", "epson2021", "epsonlfp",
        "EpsonLFP", "AccountingTool", "accdb", "database",
    ]

    for pwd in common_passwords:
        try:
            conn_str = (
                r"DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};"
                f"DBQ={ACCDB_PATH};"
                f"PWD={pwd};"
            )
            conn = pyodbc.connect(conn_str)
            tables = [row.table_name for row in conn.cursor().tables(tableType='TABLE')]
            conn.close()
            print(f"  PASSWORD FOUND: {pwd!r}  (tables: {tables[:5]})")
            break
        except pyodbc.Error:
            print(f"  '{pwd}' — failed")
    else:
        print("  None of the common passwords worked")
except ImportError:
    print("  pyodbc not available — can't try passwords")

# ─── Method 5: List all files in the LFP installation ────────────────────────
print("\n" + "=" * 70)
print("Method 5: All files in LFP Accounting Tool installation")
print("=" * 70)
for base in [
    r"C:\ProgramData\EPSON\LFP Accounting Tool",
    r"C:\Program Files\EPSON\LFP Accounting Tool",
    r"C:\Program Files (x86)\EPSON\LFP Accounting Tool",
]:
    if not os.path.exists(base):
        continue
    print(f"\n{base}:")
    for root, dirs, files in os.walk(base):
        level = root.replace(base, '').count(os.sep)
        indent = '  ' * level
        print(f"{indent}{os.path.basename(root)}/")
        for f in files:
            fpath = os.path.join(root, f)
            size = os.path.getsize(fpath)
            print(f"{indent}  {f} ({size:,} bytes)")

print("\nDone.")
