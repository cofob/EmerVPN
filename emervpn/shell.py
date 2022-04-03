import base64
import binascii
import pprint
import subprocess
from argparse import ArgumentParser

import pyemer
import requests
import ubjson

import emervpn.utils
from emervpn.config import ConfigReader, WGConfigBuilder
from emervpn.crypto import Cryptor, sha256


def reconfigure(emer: pyemer.Emer, config: dict) -> None:
    value = emer.name_show(
        f"vpn:{sha256(config['crypt_key'])}", pyemer.ValueType.base64
    )
    cryptor = Cryptor(config["crypt_key"])
    obj = ubjson.loadb(
        cryptor.decrypt(
            emervpn.crypto.EncryptedData(
                value.record.value[24:], value.record.value[:24]
            )
        )
    )
    if obj["revoked"]:
        print("Network revoked!")
        exit(1)
    config["subnet"] = obj["subnet"]
    config["dns"] = obj["dns"]


def start():
    parser = ArgumentParser(description="EmerVPN shell utility.")
    parser.add_argument("command", type=str, help="command")
    parser.add_argument("option", type=str, nargs="?", help="optional argument")
    parser.add_argument("-u", "--user", type=str, help="rpc user", default="emcrpccoin")
    parser.add_argument("-p", "--password", type=str, help="rpc password")
    parser.add_argument("-H", "--host", type=str, help="rpc host", default="localhost")
    parser.add_argument("-P", "--port", type=int, help="rpc port", default=6662)
    parser.add_argument("-i", "--interface", type=str, help="interface name", default="eth0")
    args = parser.parse_args()

    config_reader = ConfigReader()
    config = config_reader.config

    cryptor = Cryptor(config.get("crypt_key"))
    config["crypt_key"] = cryptor.key

    config["privkey"] = config.get(
        "pubkey", subprocess.check_output("wg genkey".split()).decode().strip()
    )
    p = subprocess.Popen(
        "wg pubkey".split(),
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    config["pubkey"] = config.get(
        "pubkey", p.communicate(input=config["privkey"].encode())[0].decode().strip()
    )

    config["interface"] = config.get(args.interface)

    config_reader.save()

    emer = pyemer.Emer(args.user, args.password, args.host, args.port)

    if args.command == "rotate":
        config["crypt_key"] = None
        config_reader.save()
    elif args.command == "getkey":
        print(binascii.hexlify(config["crypt_key"]).decode())
    elif args.command == "setkey":
        config["crypt_key"] = binascii.unhexlify(args.option)
        config_reader.save()
    elif args.command == "init":
        name = f"vpn:{sha256(config['crypt_key'])}"
        try:
            value = emer.name_show(name, pyemer.ValueType.base64)
            create = False
        except pyemer.authproxy.JSONRPCException:
            create = True
        subnet = input("Subnet (10.7.0.0/24): ")
        if not subnet:
            subnet = "10.7.0.0/24"
        obj = {"subnet": subnet, "revoked": False, "dns": "1.1.1.1"}
        if not create:
            if obj == ubjson.loadb(
                cryptor.decrypt(
                    emervpn.crypto.EncryptedData(
                        value.record.value[24:], value.record.value[:24]
                    )
                )
            ):
                return
        data = cryptor.crypt(ubjson.dumpb(obj))
        if create:
            emer.name_new(name, data.ciphertext, 30, emer.get_account_address())
        else:
            emer.rpc_connection.name_update(
                name,
                base64.b64encode(data.ciphertext).decode(),
                30,
                emer.get_account_address().address,
                "base64",
            )
    elif args.command == "introduce":
        for i in range(1, 256):
            name = (
                f"vpn:{sha256(sha256(config['crypt_key']).encode() + str(i).encode())}"
            )
            create = False
            try:
                value = emer.name_show(name, pyemer.ValueType.base64)
                if i == config.get("i"):
                    print(f"Our i: {i}")
                    create = False
                    break
                print(f"Peer {i} found.")
            except pyemer.authproxy.JSONRPCException:
                print(f"Our i: {i}")
                config["i"] = i
                config_reader.save()
                create = True
                break
        obj = {
            "ip": requests.get("https://eth0.me/").text.strip(),
            "port": 51280,
            "pubkey": config["pubkey"],
        }
        if not create:
            if obj == ubjson.loadb(
                cryptor.decrypt(
                    emervpn.crypto.EncryptedData(
                        value.record.value[24:], value.record.value[:24]
                    )
                )
            ):
                return
        data = cryptor.crypt(ubjson.dumpb(obj))
        if create:
            emer.name_new(name, data.ciphertext, 30, emer.get_account_address())
        else:
            emer.rpc_connection.name_update(
                name,
                base64.b64encode(data.ciphertext).decode(),
                30,
                emer.get_account_address().address,
                "base64",
            )
    elif args.command == "wg":
        reconfigure(emer, config)
        config_reader.save()
        config_builder = WGConfigBuilder(config["privkey"], config["pubkey"], config)
        peers = emervpn.utils.get_peers(emer, config["crypt_key"], cryptor)
        config_builder.add_peers(peers)
        print(config_builder.generate())
    elif args.command == "address":
        print(emer.get_account_address().address)
    elif args.command == "config":
        pprint.pprint(config)
    else:
        print("emervpn: error: command not found. Launch with `--help` or `init`.")
