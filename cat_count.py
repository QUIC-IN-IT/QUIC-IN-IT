import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', type=argparse.FileType('r'), default='cat_result.txt')
args = parser.parse_args()

handling = False
results = []
result_count = {}
for line in args.input:
    if not line.strip():
        handling = False
        for result in results:
            if result not in result_count:
                result_count[result] = 0
            result_count[result] += 1
        if len(results) > 1:
            results.sort()
            combine_str = ' '.join(results)
            if combine_str not in result_count:
                result_count[combine_str] = 0
            result_count[combine_str] += 1
        continue
    if not handling:
        handling = True
        ip = line.strip().split()[0]
        results = []
        continue
    results.append(line.strip())

result_names = list(result_count.keys())
result_names.sort(key=lambda x: len(x))
for result in result_names:
    print(result, result_count[result])
