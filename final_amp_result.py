import argparse
from typing import Mapping
from utils import AmpResult

parser = argparse.ArgumentParser()
parser.add_argument('-qi', '--quic_input', type=argparse.FileType('r'), default='quic_result.txt')
parser.add_argument('-ai', '--amp_input', type=argparse.FileType('r'), default='amp_result.txt')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), default='amp_analy.txt')
parser.add_argument('-f', '--full', action=argparse.BooleanOptionalAction, default=False)
args = parser.parse_args()

quic_file = args.quic_input
amp_file = args.amp_input

quic_map = {}
amp_map: Mapping[str, list[AmpResult]] = {}

for line in quic_file:
    if line.startswith('#'):
        continue
    ret = line.split()
    ip = ret[0]
    af = float(ret[2])
    quic_map[ip] = af


for line in amp_file:
    if line.startswith('#'):
        continue
    ret = line.split()
    ip = ret[0]
    sni = ret[1]
    q_version = ret[2]
    padding = ret[3]
    af = ret[5]
    if float(af) == 0:
        continue
    ar = AmpResult(ip, sni, q_version, padding, af)
    if ip not in amp_map:
        amp_map[ip] = []
    amp_map[ip].append(ar)


for ip in amp_map:
    amp_map[ip].sort(reverse=True)

f = args.output
r_count = 0
t_count = 0
f_count = 0
total_count = 0
for ip in amp_map:
    one_shot_af = quic_map[ip]
    max_af = 0
    
    sni_case = False
    padding_case = False
    ping_case = False
    
    for ar in amp_map[ip]:
        if ar.af > 0:
            max_af = max(max_af, ar.af)
        else:
            break
    for ar in amp_map[ip]:
        if ar.af == max_af:
            if ar.padding is None:
                padding_case = True
            if ar.padding == 1:
                ping_case = True
            if ar.sni == ar.ip:
                sni_case = None
            if ar.sni != ar.ip and sni_case is not None:
                sni_case = True

    flag = False
    # if max_af > one_shot_af and max_af > 3:
    if max_af > 3 or one_shot_af > 3:
        flag = True
        total_count += 1
        if max_af > one_shot_af:
            r_count += 1
        elif max_af < one_shot_af:
            f_count += 1
        if max_af - one_shot_af > 1 or one_shot_af <= 3:
            f.write(f'# Note This! {one_shot_af} -> {max_af}\n')
            t_count += 1
    if flag or args.full:
        if not flag:
            f.write(f'# default: {one_shot_af}\n')
        if padding_case:
            f.write('# Potential padding case\n')
        if ping_case:
            f.write('# Potential ping case\n')
        if sni_case:
            f.write('# Potential sni case\n')
        for ar in amp_map[ip]:
            if ar.af > 0:
                f.write(f'{ar}\n')
            else:
                break
        f.write(f'\n')

print(t_count, r_count, f_count)
print(total_count)
