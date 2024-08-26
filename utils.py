from loguru import logger
import ipaddress
from random import shuffle
import sys

logger.remove()
logger.add(
    sys.stdout,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> |  <level>{level: <8}</level> | {message}",
)


def convert_subnet_to_ips(subnet):
    if '.' in subnet:
        if '/' not in subnet:
            return [subnet]
        network = ipaddress.IPv4Network(subnet, strict=False)
        ip_list = list(network.hosts())
        if network.broadcast_address not in ip_list:
            ip_list.append(network.broadcast_address)
        if network.network_address not in ip_list:
            ip_list.append(network.network_address)
        return ip_list
    elif ':' in subnet:
        if '/' not in subnet:
            return [subnet]
        network = ipaddress.IPv6Network(subnet, strict=False)
        ip_list = list(network.hosts())
        if network.broadcast_address not in ip_list:
            ip_list.append(network.broadcast_address)
        if network.network_address not in ip_list:
            ip_list.append(network.network_address)
        return ip_list


def add_padding(frame, length, type=b'\x00') -> bytes:
    if len(frame) > length:
        return frame
    padding = type * (length - len(frame))
    return frame + padding


def wrap_integer(num) -> bytes:
    if not type(num) == int:
        raise TypeError('num must be int')
    if num < 0:
        raise ValueError('num must be positive')
    if num <= 63:
        return num.to_bytes(1, 'big')
    elif num <= 16383:
        return (num + 0x4000).to_bytes(2, 'big')
    elif num <= 1073741823:
        return (num + 0x80000000).to_bytes(4, 'big')
    elif num <= 4611686018427387903:
        return (num + 0xc000000000000000).to_bytes(8, 'big')
    else:
        raise ValueError('num too large')


def wrap_integer_len(num) -> int:
    if not type(num) == int:
        raise TypeError('num must be int')
    if num < 0:
        raise ValueError('num must be positive')
    if num <= 63:
        return 1
    elif num <= 16383:
        return 2
    elif num <= 1073741823:
        return 4
    elif num <= 4611686018427387903:
        return 8
    else:
        raise ValueError('num too large')


def pack_crypto_frame(payload):
    crypto_type = b'\x06'
    offset = b'\x00'
    length = wrap_integer(len(payload))
    return crypto_type + offset + length + payload


def sni_bytes(sni):
    # server name
    sni = sni.encode('utf-8')
    # server name length
    sni_len = len(sni)
    # server name type
    sni = b'\x00' + sni_len.to_bytes(2, 'big') + sni
    # server name list length
    sni_len = len(sni)
    sni = sni_len.to_bytes(2, 'big') + sni
    # extension length
    sni_len = len(sni)
    sni = sni_len.to_bytes(2, 'big') + sni
    # type: server name
    return b'\x00' * 2 + sni


def byte_xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


class progress_manager:
    def __init__(self):
        self.geo = True
        self.geo_count = 0
        self.cur_ip = 0
        self.total_ip = 3702258934

    def init_ip(self, ip_subnets):
        self.geo = False
        self.ip_subnets = ip_subnets
        shuffle(self.ip_subnets)
        self.total_ip = 0
        for line in ip_subnets:
            if '/' in line:
                self.total_ip += 2 ** (32 - int(line.split('/')[1]))
            else:
                self.total_ip += 1
        self.cur_subnet = []

    def has_next(self):
        if not self.geo:
            if len(self.cur_subnet) > 0 or len(self.ip_subnets) > 0:
                return True
            return False
        return self.cur_ip < self.total_ip

    def next(self):
        if not self.geo:
            if len(self.cur_subnet) > 0:
                return str(self.cur_subnet.pop())
            else:
                print('run out of ips. generating new subnet...')
                self.generate_subnet()
                return str(self.cur_subnet.pop())
        else:
            ip = ipaddress.IPv4Address(self.geo_count)
            self.geo_count += 1
            while (not ip.is_global) or ip.is_multicast:
                ip = ipaddress.IPv4Address(self.geo_count)
                self.geo_count += 256
            return str(ip)

    def generate_subnet(self):
        tmp_list = []
        need_shuffle = False
        while len(tmp_list) < 1000000:
            if len(self.ip_subnets) == 0:
                break
            line = self.ip_subnets.pop()
            if '/' in line:
                tmp_list += convert_subnet_to_ips(line)
                need_shuffle = True
            else:
                tmp_list.append(line)
        if need_shuffle:
            shuffle(tmp_list)
        self.cur_subnet += tmp_list

    def new_ip(self):
        self.cur_ip += 1
        if self.cur_ip % 1000 == 0 or self.cur_ip == self.total_ip or self.cur_ip == 1:
            self.print_cur()

    def print_cur(self):
        prior = f"{(self.cur_ip * 100 / self.total_ip):.2f}"
        spacer = ' ' * (10 - len(prior))
        logger.info(f"{prior}{spacer}{self.cur_ip}/{self.total_ip}")

class AmpResult:
    def __init__(self, ip, sni, q_version, padding, af):
        self.ip = ip
        self.sni = sni
        self.q_version = int(q_version)
        match padding:
            case '0':
                self.padding = 0
            case '1':
                self.padding = 1
            case _:
                self.padding = None
        self.af = float(af)

    def __lt__(self, other):
        return self.af < other.af

    def __str__(self) -> str:
        return f'{self.ip} {self.sni} {self.q_version} {self.padding} {self.af}'

    def __repr__(self) -> str:
        return self.__str__()


if __name__ == '__main__':
    subnet = convert_subnet_to_ips('1.1.1.0/24')
    print(len(subnet))
    print(subnet)
    subnet = convert_subnet_to_ips('2001:1210:3400:156::')
    print(len(subnet))
    print(subnet)
