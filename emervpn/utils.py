import ipaddress

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
                        value.record.value[24:], value.record.value[:24]
                    )
                )
            )
            obj["i"] = i
            peers.append(obj)
        except pyemer.authproxy.JSONRPCException:
            break
    return peers


def get_addr_for_i(config, i):
    net: ipaddress.IPv4Network = ipaddress.ip_network(config["subnet"])
    return list(net.hosts())[i]


def get_mask(config: dict):
    return config["subnet"].split("/")[1]
