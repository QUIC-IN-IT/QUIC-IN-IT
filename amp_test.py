from loguru import logger

from header import Header
from tls import TLS
from crypto import aes_gcm_encrypt
from utils import add_padding, pack_crypto_frame

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
parser.add_argument('-i', '--input', type=argparse.FileType('r'), default='quic_result.txt')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), default='amp_result.txt')
parser.add_argument('-H', '--host', type=str, default='www.google.com')
parser.add_argument('-p', '--port', type=int, default=443)
parser.add_argument('-w', '--workers', type=int, default=128)
args = parser.parse_args()

timeout = args.timeout

ips = []

for line in args.input:
    if line.startswith('#'):
        continue
    ips.append(line.split()[0].strip())

count = len(ips)
cur_count = 0

ip_sni_map = {}

def reverse_solve(ip):
    try:
        domain = socket.getnameinfo((ip, 0), 0)[0]
        ip_sni_map[ip] = domain
    except:
        logger.info(f'Failed to reverse-resolve {ip}')
        ip_sni_map[ip] = ip

logger.info('Reverse-resolving IPs...')
for ip in ips:
    while threading.active_count() > args.workers:
        time.sleep(0.1)
    t = threading.Thread(target=reverse_solve, args=(ip,))
    t.start()
    cur_count += 1
    if cur_count % 100 == 0:
        prior = f"{(cur_count * 100 / count):.2f} {cur_count}/{count}"
        logger.info(f"{prior}")

while threading.active_count() > 1:
    print(threading.active_count())
    time.sleep(1)

cur_count = 0

result_f = args.output

def my_send(ip, sni, q_version, p_type):
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
    now = datetime.datetime.now()
    while True:
        if (datetime.datetime.now() - now).total_seconds() >= timeout:
            break
        try:
            ret, addr = sock.recvfrom(8192)
            total_recv += len(ret)
            now = datetime.datetime.now()
        except Exception as e:
            pass
    sock.close()
    trail = f'{ip} {sni} {q_version} {p_type} {total_recv} {total_recv/length:.2f}'
    result_f.write(f'{trail}\n')
    result_f.flush()
    prior = f"{(cur_count * 100 / count):.2f} {cur_count}/{count}"
    spacer = ' ' * max(1, (16 - len(prior)))
    logger.info(f"{prior}{spacer}{trail}")

q_versions = [1, 2]
padding_type = [0, 1, None]
for ip in ips:
    ip_list = []
    ip_list.append(ip)
    ip_list.append(args.host)
    domain = ip_sni_map.get(ip, ip)
    if domain not in ip_list:
            ip_list.append(domain)
    for sni in ip_list:
        for q_version in q_versions:
            for p_type in padding_type:
                while threading.active_count() > args.workers:
                    time.sleep(0.1)
                t = threading.Thread(target=my_send, args=(ip, sni, q_version, p_type))
                t.start()
    cur_count += 1

while threading.active_count() > 1:
    print(threading.active_count())
    time.sleep(1)

result_f.close()
                
