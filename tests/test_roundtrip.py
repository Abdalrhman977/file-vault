import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enc = load("encrypt", "Encrypt/encrypt.py")
dec = load("decrypt", "Decrypt/decrypt.py")
PW = "correct horse battery"
DATA = b"secret report contents\x00\xff"


class RoundTrip(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(dec.decrypt_blob(enc.encrypt_blob(DATA, PW), PW), DATA)

    def test_wrong_password(self):
        with self.assertRaises(ValueError):
            dec.decrypt_blob(enc.encrypt_blob(DATA, PW), "wrong password!!")

    def test_tampered(self):
        blob = bytearray(enc.encrypt_blob(DATA, PW))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            dec.decrypt_blob(bytes(blob), PW)

    def test_verify_before_delete(self):
        self.assertTrue(enc.verify(enc.encrypt_blob(DATA, PW), PW, DATA))

    def test_not_an_encrypted_file(self):
        with self.assertRaises(ValueError):
            dec.decrypt_blob(b"plain text", PW)


if __name__ == "__main__":
    unittest.main()
