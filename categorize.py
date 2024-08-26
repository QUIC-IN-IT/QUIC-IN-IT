from loguru import logger

from header import Header, extract_from_packet
from tls import TLS
from crypto import aes_gcm_encrypt
from utils import add_padding, pack_crypto_frame, AmpResult

import socket
import datetime
import time
import random
import argparse
import sys
import threading

logger.remove()
logger.add(
    sys.stdout,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> |  <level>{level: <8}</level> | {message}",
)

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=float, default=3)
parser.add_argument('-i', '--input', type=argparse.FileType('r'), default='amp_analy.txt')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), default='cat_result.txt')
parser.add_argument('-f', '--full', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-e', '--error', type=argparse.FileType('w'), default='cat_error.txt')
parser.add_argument('-p', '--port', type=int, default=443)
parser.add_argument('-w', '--workers', type=int, default=128)
args = parser.parse_args()

categorizer_list = []

class PNSize:
    def __init__(self):
        self.pn_count = 0
        self.max_size = 0

    def update(self, pn, new_size):
        if pn == -1 or type(pn) is str:
            self.max_size += new_size
        else:
            self.pn_count += 1
            self.max_size = max(self.max_size, new_size)

def categorizer(func):
    categorizer_list.append(func)
    return func

@categorizer
def ResendCategorizer(pack_map, pack_size):
    for scid, pn_count in pack_map.items():
        for pn, pnsize in pn_count.items():
            if pn != -1 and pnsize.pn_count > 1:
                return True
    return False

@categorizer
def BroadcastCategorizer(pack_map, pack_size):
    scid_size = len(pack_map)
    if 'Exception' in pack_map:
        scid_size -= 1
    if 'short header' in pack_map:
        scid_size -= 1
    if scid_size > 1:
        return True
    return False

@categorizer
def InitialPayloadTooLargeCategorizer(pack_map, pack_size):
    for scid, pn_count in pack_map.items():
        result_size = 0
        for pn, pnsize in pn_count.items():
            if type(pn) is int and pn >= 0:
                result_size += pnsize.max_size
        if result_size > 3600:
            return True
    return False

@categorizer
def HandshakePayloadTooLargeCategorizer(pack_map, pack_size):
    for scid, pn_count in pack_map.items():
        pnsize = pn_count.get('Handshake')
        if pnsize and pnsize.max_size > 3600:
            return True
    return False

def NotAmpCaseCategorizer(pack_map, pack_size):
    total_count = 0
    for scid, pn_count in pack_map.items():
        for pn, pnsize in pn_count.items():
            total_count += pnsize.max_size
    if total_count <= 3600:
        return True
    return False

@categorizer
def PaddingNoCheckCategorizer(pack_map, pack_size):
    if pack_size >= 1200:
        return False
    total_count = 0
    for scid, pn_count in pack_map.items():
        for pn, pnsize in pn_count.items():
            total_count += pnsize.max_size
    if total_count > pack_size * 3:
        return True
    return False

@categorizer
def PrematuredShortPayloadCategorizer(pack_map, pack_size):
    short_header = pack_map.get('short header')
    if not short_header:
        return False
    short_header = short_header.get(-1)
    if not short_header:
        return False
    if short_header.max_size > 1200:
        return True
    return False

print(categorizer_list)

timeout = args.timeout
workers = args.workers

cur_ip = ''
cur_max_af = 0
cur_ar = None

max_list = []

for line in args.input:
    if line.startswith('#') or line == '\n' or line == '\r\n':
        continue
    ret = line.split()
    if len(ret) != 5:
        print(f'Invalid line: {line}', end='')
        continue
    ar = AmpResult(*ret)
    if ar.ip != cur_ip:
        if cur_ar:
            max_list.append(cur_ar)
        cur_ip = ar.ip
        cur_max_af = ar.af
        cur_ar = ar
    if ar.af > cur_max_af:
        cur_max_af = ar.af
        cur_ar = ar

max_list.append(cur_ar)
# print(max_list)

total_count = len(max_list)
cur_count = 0

def my_send(ar: AmpResult):
    ip, sni, q_version, p_type = ar.ip, ar.sni, ar.q_version, ar.padding 
    
    tls = TLS(sni)
    tls = tls.to_bytes()
    tls = pack_crypto_frame(tls)
    
    dcid = int.from_bytes(random.randbytes(8), 'big')
    
    header = Header(dcid, q_version)
    
    match p_type:
        case 0:
            tls = add_padding(tls, 1162, b'\x00')
        case 1:
            tls = add_padding(tls, 1162, b'\x01')
        case None:
            pass

    header.length = len(tls) + header.packet_number_length + 1 + 16
    # print(header.to_bytes_raw().hex())

    payload = aes_gcm_encrypt(header.nonce, tls, header.to_bytes_raw(), header.key)
    # print(payload.hex())
    offset = 3 - header.packet_number_length
    sample = payload[offset:16+offset]
    protected_header = header.to_bytes(sample)

    quic_packet = protected_header + payload
    
    length = len(quic_packet)
    
    sock = None
    if '.' in ip:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setblocking(False)
    total_recv = 0
    sock.sendto(quic_packet, (ip, args.port))
    
    result = []
    
    now = datetime.datetime.now()
    while True:
        if (datetime.datetime.now() - now).total_seconds() >= timeout:
            break
        try:
            ret, addr = sock.recvfrom(8192)
            result.append(ret)
            now = datetime.datetime.now()
        except Exception as e:
            pass
    sock.close()
    return dcid, result, len(quic_packet)

output = args.output
errout = args.error

def output_on_send_finish(ar):
    dcid, result, pack_size = my_send(ar)
    pack_map = {}
    for packet in result:
        scid, pn = None, None
        try:
            scid, pn, msg = extract_from_packet(dcid, packet)
            if pn == -1 or msg:
                errout.write(f'Warning: {ar.ip} {ar.sni} {ar.padding} {msg}\n')
                errout.flush()
        except Exception as e:
            errout.write(f'Exception: {ar.ip} {ar.sni} {ar.padding} {e}\n')
            errout.flush()
        finally:
            if not pn:
                pn = -1
            if not scid:
                scid = 'Exception'
            if scid not in pack_map:
                pack_map[scid] = {}
            if pn not in pack_map[scid]:
                pack_map[scid][pn] = PNSize()
            pack_map[scid][pn].update(pn, len(packet))
    total_af = 0
    for scid, pn_count in pack_map.items():
        for pn, pnsize in pn_count.items():
            total_af += pnsize.max_size
    total_af = total_af / pack_size
    
    output_result = f'{ar.ip} {ar.sni} {ar.padding} {total_af:.2f}\n'
    
    if NotAmpCaseCategorizer(pack_map, pack_size):
        if not args.full:
            errout.write(f'NotAmpCase: {output_result}')
            errout.flush()
        else:
            output.write(f'{output_result}\nNotAmpCase\n\n')
            output.flush()
        return
    
    has_cat = False
    for func in categorizer_list:
        if func(pack_map, pack_size):
            output_result += f'{func.__name__}\n'
            has_cat = True
    if not has_cat:
        output_result += f'TotalPayloadTooLarge\n'
    output_result += '\n'
    output.write(output_result)
    output.flush()

print('inited, starting to send')
time.sleep(1)

for ar in max_list:
    while threading.active_count() > workers:
        time.sleep(0.1)
    t = threading.Thread(target=output_on_send_finish, args=(ar,))
    t.start()
    cur_count += 1
    logger.info(f'{cur_count * 100 / total_count:.2f} {cur_count}/{total_count}')

while threading.active_count() > 1:
    print(threading.active_count())
    time.sleep(1)

output.close()
errout.close()