import hashlib
from dataclasses import dataclass
from typing import Optional

import nacl.bindings
import nacl.secret
import nacl.signing
import nacl.utils
import ubjson


@dataclass(frozen=True)
class EncryptedData:
    ciphertext: bytes
    nonce: bytes

    def encode(self):
        return ubjson.dump({"d": self.ciphertext, "n": self.nonce})

    @staticmethod
    def decode(obj: dict):
        return EncryptedData(obj["d"], obj["n"])


class Cryptor:
    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.key: bytes = key

    def crypt(self, data: bytes) -> EncryptedData:
        box = nacl.secret.SecretBox(self.key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ciphertext = box.encrypt(data, nonce)
        return EncryptedData(ciphertext, nonce)

    def decrypt(self, data: EncryptedData) -> bytes:
        box = nacl.secret.SecretBox(self.key)
        return box.decrypt(data.ciphertext, data.nonce)


def sha256(key: bytes):
    return hashlib.sha256(hashlib.sha256(key).digest()).hexdigest()


__all__ = ["Cryptor", "EncryptedData", "sha256"]
