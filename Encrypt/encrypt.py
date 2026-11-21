"""
encrypt.py - double-click to encrypt every file in this folder.

Needs once:  pip install cryptography
Each file  report.pdf  ->  report.pdf.enc   (original is deleted after the
encrypted copy is verified). Skips .py and .enc files.
"""
import getpass, os, sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"MYVAULT1"
SALT_LEN, NONCE_LEN = 16, 12


def derive_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())


def encrypt_blob(data, password):
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce
    return header + AESGCM(derive_key(password, salt)).encrypt(nonce, data, header)


def verify(blob, password, original):
    o = len(MAGIC)
    salt, nonce = blob[o:o + SALT_LEN], blob[o + SALT_LEN:o + SALT_LEN + NONCE_LEN]
    header, ct = blob[:o + SALT_LEN + NONCE_LEN], blob[o + SALT_LEN + NONCE_LEN:]
    return AESGCM(derive_key(password, salt)).decrypt(nonce, ct, header) == original


def main():
    folder = Path(__file__).resolve().parent
    skip = {Path(__file__).resolve(), folder / "decrypt.py"}
    files = sorted(f for f in folder.rglob("*")
                   if f.is_file() and f.resolve() not in skip
                   and f.suffix.lower() not in (".enc", ".tmp"))
    if not files:
        print("Nothing to encrypt here. Put your files next to encrypt.py.")
        return
    print(f"Folder: {folder}\nWill encrypt {len(files)} file(s) (including subfolders):")
    for f in files:
        print("  -", f.relative_to(folder))

    pw = getpass.getpass("\nPassword (12+ chars): ")
    if len(pw) < 12:
        print("Too short. Use at least 12 characters.")
        return
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords don't match.")
        return

    for f in files:
        out = f.with_name(f.name + ".enc")
        if out.exists():
            print(f"SKIP  {f.relative_to(folder)} ({out.name} already exists)")
            continue
        try:
            data = f.read_bytes()
            blob = encrypt_blob(data, pw)
            tmp = out.with_name(out.name + ".tmp")
            tmp.write_bytes(blob)
            if not verify(tmp.read_bytes(), pw, data):
                raise RuntimeError("verification failed")
            os.replace(tmp, out)
            f.unlink()
            print(f"OK    {f.relative_to(folder)} -> {out.name}")
        except Exception as e:
            print(f"FAIL  {f.relative_to(folder)}: {e}")
    print("\nDone. Forgotten password = lost data. There is no recovery.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to close...")
