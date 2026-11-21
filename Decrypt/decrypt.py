"""
decrypt.py - double-click to decrypt every .enc file in this folder.

Needs once:  pip install cryptography
report.pdf.enc  ->  report.pdf   (the .enc is deleted after a successful decrypt)
"""
import getpass, os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"MYVAULT1"
SALT_LEN, NONCE_LEN = 16, 12


def derive_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())


def decrypt_blob(blob, password):
    if not blob.startswith(MAGIC):
        raise ValueError("not an encrypted file")
    o = len(MAGIC)
    salt, nonce = blob[o:o + SALT_LEN], blob[o + SALT_LEN:o + SALT_LEN + NONCE_LEN]
    header, ct = blob[:o + SALT_LEN + NONCE_LEN], blob[o + SALT_LEN + NONCE_LEN:]
    try:
        return AESGCM(derive_key(password, salt)).decrypt(nonce, ct, header)
    except Exception:
        raise ValueError("wrong password or corrupted file")


def main():
    folder = Path(__file__).resolve().parent
    files = sorted(f for f in folder.rglob("*.enc") if f.is_file())
    if not files:
        print("No .enc files here. Put them next to decrypt.py.")
        return
    print(f"Folder: {folder}\nFound {len(files)} encrypted file(s) (including subfolders).")

    pw = getpass.getpass("\nPassword: ")
    failed_pw = 0
    for f in files:
        out = f.with_suffix("")  # strips .enc
        if out.exists():
            print(f"SKIP  {f.name} ({out.name} already exists)")
            continue
        try:
            out.write_bytes(decrypt_blob(f.read_bytes(), pw))
            f.unlink()
            print(f"OK    {f.name} -> {out.name}")
        except ValueError as e:
            failed_pw += 1
            print(f"FAIL  {f.name}: {e}")
            if failed_pw >= 3:
                print("Stopping after 3 failures.")
                break
    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to close...")
