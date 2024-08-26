quic_resp_results = [
    'result1.txt',
    'result2.txt',
]

with open('merged_result.txt', 'w') as outfile:
    for fname in quic_resp_results:
        with open(fname) as infile:
            for line in infile:
                if line.strip():
                    outfile.write(line.strip())
                    outfile.write('\n')