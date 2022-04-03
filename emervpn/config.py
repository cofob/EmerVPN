import ubjson
from emervpn.utils import get_addr_for_i, get_mask


class WGConfigBuilder:
    def __init__(self, private_key: str, public_key: str, config: dict) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.peers = []
        self.config = config

    def add_peers(self, peers: list) -> None:
        for peer in peers:
            self.peers.append(peer)

    def generate_peer(self, peer) -> str:
        if peer["i"] == self.config["i"]:
            return ""
        return f"""\n[Peer]
PublicKey  = {peer["pubkey"]}
AllowedIPs = {get_addr_for_i(self.config, peer["i"])}/32
Endpoint   = {peer["ip"]}:{peer["port"]}"""

    def generate(self) -> str:
        return f"""[Interface]
Address    = {get_addr_for_i(self.config, self.config["i"])}/{get_mask(self.config)}
DNS        = {self.config["dns"]}
PrivateKey = {self.private_key}
ListenPort = 51820
PostUp     = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {self.config["interface"]} -j MASQUERADE
PostDown   = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {self.config["interface"]} -j MASQUERADE
{''.join([self.generate_peer(peer) for peer in self.peers])}"""


class ConfigReader:
    def __init__(self) -> None:
        try:
            with open("config.bin", "rb") as file:
                self.config: dict = ubjson.load(file)
        except FileNotFoundError:
            self.config = {}

    def save(self) -> None:
        with open("config.bin", "wb") as file:
            ubjson.dump(self.config, file)
