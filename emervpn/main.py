import pyemer
import ubjson

import emervpn.crypto
from emervpn.crypto import sha256


def get_peers(emer: pyemer.Emer, crypt_key: bytes, cryptor: emervpn.crypto.Cryptor):
    peers = []
    for i in range(1, 256):
        name = f"vpn:{sha256(sha256(crypt_key).encode() + str(i).encode())}"
        try:
            value = emer.name_show(name, pyemer.ValueType.base64)
            obj = ubjson.loadb(
                cryptor.decrypt(
                    emervpn.crypto.EncryptedData(
                        value.record.value[48:], value.record.value[:24]
                    )
                )
            )
            obj["i"] = i
            peers.append(obj)
        except pyemer.authproxy.JSONRPCException:
            break
    return peers
