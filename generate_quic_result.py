import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', type=argparse.FileType('r'), default='resp_result.txt')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), default='quic_result.txt')
parser.add_argument('-s', '--size', type=int, default=1200)
parser.add_argument('-f', '--full', action=argparse.BooleanOptionalAction, default=False)
args = parser.parse_args()

ori_size = args.size

filename = args.input
ip_map = {}

resp_count = 0
avg_amp = 0
avg_total = 0

for line in args.input:
    ret = line.split()
    ip = ret[0]
    size = int(ret[1])
    if ip not in ip_map:
        ip_map[ip] = 0
    ip_map[ip] += size
    resp_count += 1

ips = list(ip_map.keys())
ips.sort(key=lambda x: ip_map[x], reverse=True)

f = args.output
amp_count = 0
quic_count = 0

count_3_10 = 0
count_10_50 = 0
count_50_100 = 0
count_100_200 = 0
count_200__ = 0

for ip in ips:
    amp_factor = ip_map[ip] / ori_size
    if amp_factor > 3:
        amp_count += 1
        quic_count += 1
        avg_amp += ip_map[ip] / ori_size
    elif ip_map[ip] >= 1200:
        quic_count += 1
        avg_total += ip_map[ip] / ori_size
    if 3 < amp_factor <= 10:
        count_3_10 += 1
    elif 10 < amp_factor <= 50:
        count_10_50 += 1
    elif 50 < amp_factor <= 100:
        count_50_100 += 1
    elif 100 < amp_factor <= 200:
        count_100_200 += 1
    elif 200 < amp_factor:
        count_200__ += 1

f.write(
    f"# Total: {len(ips)} {resp_count}\n# QUIC: {quic_count}\n# AMP>3: {amp_count}\n")
f.write(
    f"# 3-10: {count_3_10}\n# 10-50: {count_10_50}\n# 50-100: {count_50_100}\n# 100-200: {count_100_200}\n# 200+: {count_200__}\n")
if amp_count > 0:
    f.write(f"# AVG AMP(>3): {(avg_amp / amp_count):.2f}\n")
if quic_count > 0:
    f.write(f"# AVG AMP(QUIC): {((avg_total + avg_amp) / quic_count):.2f}\n")
for ip in ips:
    if ip_map[ip]/ori_size > 3:
        f.write(f"{ip} {ip_map[ip]} {(ip_map[ip]/ori_size):.2f}\n")
    elif ip_map[ip] >= 1200 and args.full:
        f.write(f"{ip} {ip_map[ip]} {(ip_map[ip]/ori_size):.2f}\n")
    else:
        break
