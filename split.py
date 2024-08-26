class Subnet:
    def __init__(self, subnet):
        self.subnet = subnet
        if '/' in subnet:
            self.prefix = subnet.split('/')[0]
            self.prefix_len = int(subnet.split('/')[1])
        else:
            self.prefix = subnet
            self.prefix_len = 0
        self.true_len = 32 - self.prefix_len

    def __str__(self):
        return self.subnet

    def __repr__(self):
        return self.subnet

    def __lt__(self, other):
        return self.prefix_len < other.prefix_len

subnet_file_name = 'allocspace-prefix.txt'
subnet_prefix_name = subnet_file_name.split('.')[0]

with open(subnet_file_name, 'r') as f:
    subnets = f.readlines()
    subnets = [Subnet(x.strip()) for x in subnets]
    subnets = sorted(subnets)
print(subnets[0])
visited = [False] * len(subnets)

total_num = 0
for subnet in subnets:
    total_num += 2 ** subnet.true_len
print('Total number of subnets: ' + str(total_num))


divide_num = input('How many files do you want to divide into? ')
try:
    divide_num = int(divide_num)
except:
    print('Please input a positive integer')
    exit(0)
if divide_num <= 0:
    print('Please input a positive integer')
    exit(0)
if divide_num == 1:
    print('Only one file, no need to split')
    exit(0)

each_size = total_num // int(divide_num)

print('Each file will have about ' + str(each_size) + ' subnets')
    
for result_list_count in range(divide_num):
    result_list = []
    cur_size = 0
    for i in range(len(subnets)):
        if not visited[i]:
            result_list.append(subnets[i])
            visited[i] = True
            cur_size += 2 ** subnets[i].true_len
        if cur_size >= each_size:
            break
    if cur_size == 0:
        print('No more subnets to split')
        break
    print(f'File {result_list_count + 1} has {len(result_list)} subnets; counting {cur_size} ips')
    with open(f'{subnet_prefix_name}-{result_list_count}.txt', 'w') as f:
        for subnet in result_list:
            f.write(str(subnet) + '\n')