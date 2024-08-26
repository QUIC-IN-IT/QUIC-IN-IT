from header import Header
from tls import TLS
from crypto import aes_gcm_encrypt
from utils import add_padding, pack_crypto_frame, progress_manager
from networking import network_manager
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--timeout', type=float, default=10)
parser.add_argument('-s', '--subnet', type=argparse.FileType('r'), default='run.txt')
parser.add_argument('-H', '--host', type=str, default='www.google.com')
parser.add_argument('-p', '--port', type=int, default=443)
parser.add_argument('-l', '--length', type=int, default=1162)
parser.add_argument('-d', '--dcid', type=str, default='7c5e3d0f64e23321')
parser.add_argument('-r', '--rate', type=int, default=4194304)
parser.add_argument('-g', '--geo', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-w', '--workers', type=int, default=16)
parser.add_argument('-v2', '--v2', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('-c', '--count', action=argparse.BooleanOptionalAction, default=False)
args = parser.parse_args()

dcid = int(args.dcid, 16)

q_version = 1
if args.v2:
    q_version = 2

header = Header(dcid, q_version)
tls = TLS(args.host)
# tls.len = 470
tls = tls.to_bytes()
tls = pack_crypto_frame(tls)
# print(tls.hex())
tls = add_padding(tls, args.length, b'\x00')

header.length = len(tls) + header.packet_number_length + 1 + 16
# print(header.to_bytes_raw().hex())

payload = aes_gcm_encrypt(header.nonce, tls, header.to_bytes_raw(), header.key)
# print(payload.hex())
offset = 3 - header.packet_number_length
sample = payload[offset:16+offset]
protected_header = header.to_bytes(sample)

quic_packet = protected_header + payload

print(len(quic_packet))

pm = progress_manager()

is_ipv6 = False

if not args.geo:
    ip_list = []

    for line in args.subnet:
        if line.strip().startswith('#'):
            continue
        if '/' in line:
            ip_list.append(line.strip())
        else:
            ip_list.append(line.split()[0])
        if ':' in line:
            is_ipv6 = True

    pm.init_ip(ip_list)

    if args.count:
        print(pm.total_ip)
        exit(0)
else:
    print('running globally')

nm = network_manager(args.port, args.rate, args.timeout, args.workers, is_ipv6)
# nm.start()

new_nm_count = 0

print('inited, starting to send')
while pm.has_next():
    new_nm_count += 1
    nm.send(quic_packet, pm.next())
    
    if new_nm_count >= 16777216:
        nm.finish()
        print('terminating previous nm and creating a new one...')
        while nm.running:
            print(nm.running)
            time.sleep(1)
        new_nm_count = 0
        nm = network_manager(args.port, args.rate, args.timeout, args.workers, is_ipv6, True)
    
    pm.new_ip()

nm.finish()

while nm.running:
    print(nm.running)
    time.sleep(1)
