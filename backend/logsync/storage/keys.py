"""Ed25519 signing keys: one for signed tree heads, one for parser packs.

Keys are generated on first use and stored as PEM files under data/keys/.
In production they would live in an HSM; for the prototype they are files.
"""
import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class Signer:
    def __init__(self, key_path: Path):
        key_path = Path(key_path)
        if key_path.exists():
            self._key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key = Ed25519PrivateKey.generate()
            key_path.write_bytes(self._key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            key_path.with_suffix(".pub").write_bytes(self.public_pem())
        self.public_key: Ed25519PublicKey = self._key.public_key()

    def public_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def sign(self, message: bytes) -> str:
        return "ed25519:" + base64.b64encode(self._key.sign(message)).decode()

    def verify(self, message: bytes, signature: str) -> bool:
        return verify_signature(self.public_key, message, signature)


def verify_signature(public_key: Ed25519PublicKey, message: bytes, signature: str) -> bool:
    if not signature.startswith("ed25519:"):
        return False
    try:
        public_key.verify(base64.b64decode(signature[8:]), message)
        return True
    except (InvalidSignature, ValueError):
        return False
