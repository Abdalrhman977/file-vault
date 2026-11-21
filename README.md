# file-vault

Small double-click tool that password-encrypts files on Windows, and decrypts them again.
A learning project to practise using modern crypto correctly in Python.

## How it works

| | |
|---|---|
| Cipher | AES-256-GCM (authenticated: tampering or a wrong password is detected) |
| Key | Derived from your password with scrypt (`n=2^17, r=8, p=1`), new random 16-byte salt per file |
| Nonce | New random 12-byte nonce per file |
| File format | `MYVAULT1` + salt + nonce + ciphertext; the header is authenticated as associated data |
| Safety | The encrypted copy is written to `.tmp`, decrypted again and compared **before** the original is deleted |

## Usage

```powershell
pip install -r requirements.txt
```

1. **Encrypt:** put files next to `Encrypt/encrypt.py` (subfolders are included) and double-click it.
   Enter a password (12+ characters) twice. Each `report.pdf` becomes `report.pdf.enc`.
2. **Decrypt:** put the `.enc` files next to `Decrypt/decrypt.py` and double-click it.
   It stops after 3 failed files (wrong password or corrupted data).

Keep `encrypt.py` and `decrypt.py` in their own folders: each script processes **every file in its own folder**.

## Limits (read before using on real data)

- **Forgotten password = lost data.** There is no recovery.
- **Not secure deletion.** Originals are removed with a normal delete, so recovery tools may still find them on the disk.
- Files are read fully into memory, so it suits documents rather than multi-GB files.
- Not audited. Use it to learn, not to protect anything critical.

## Test

```powershell
python -m unittest discover tests
```

Checks a round trip, a wrong password, a tampered file and the pre-delete verification.
