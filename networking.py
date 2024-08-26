import socket
import datetime
import time
from decimal import Decimal
import threading


class single_ip_result:
    def __init__(self, ip, ori_size) -> None:
        self.ip = ip
        self.ori_size = ori_size
        self.resp_size = 0
        self.times = 0
        self.last_time = datetime.datetime.now()

    def __str__(self) -> str:
        return f"{self.ip} {self.resp_size} {self.times} {self.resp_size / self.ori_size}"


class network_manager:
    def __init__(self, port, speed, timeout, num, is_ipv6=False, is_append=False) -> None:
        self.port = port
        self.speed = speed
        self.timeout = timeout
        self.num = num
        # self.amp_f = open('amp_result.txt', 'w')
        if is_append:
            self.resp_f = open('resp_result.txt', 'a')
        else:
            self.resp_f = open('resp_result.txt', 'w')
        # self.strange_f = open('strange_result.txt', 'w')
        self.socks = []
        self.sock_queue = []
        self.finished_sending = False
        for i in range(num):
            if not is_ipv6:
                self.socks.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            else:
                self.socks.append(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
            self.socks[i].setblocking(False)
            self.sock_queue.append([])
        self.cur_sock = 0
        self.running = num
        # self.ip_map = [{} for _ in range(num)]

        self.threads = []
        self.started = []

        for i in range(num):
            t1 = threading.Thread(target=self.recv, args=(i,))
            t1.start()
            t2 = threading.Thread(target=self.socket_send_loop, args=(i,))
            t2.start()
            print(i)
            # self.threads.append((t1, t2,))
            # self.started.append(False)

    def start(self, i):
        if self.started[i]:
            return
        print(i)
        t1, t2 = self.threads[i]
        t1.start()
        t2.start()

    def finish(self):
        self.finished_sending = True

    def send(self, quic_packet, ip):
        now = datetime.datetime.now()
        # self.ip_map[self.cur_sock][ip] = single_ip_result(ip, len(quic_packet))
        # self.socks[self.cur_sock].sendto(quic_packet, (ip, 443))
        # self.start(self.cur_sock)
        rate_time = Decimal(len(quic_packet)) / Decimal(self.speed)
        while len(self.sock_queue[self.cur_sock]) > 1000:
            self.cur_sock = (self.cur_sock + 1) % self.num
        self.sock_queue[self.cur_sock].append((ip, quic_packet,))
        self.cur_sock = (self.cur_sock + 1) % self.num
        while (datetime.datetime.now() - now).total_seconds() < rate_time:
            pass
        # print(len(quic_packet) / self.speed)
        # time.sleep(len(quic_packet) / self.speed)
        # gap = (datetime.datetime.now() - now).total_seconds()
        # print(gap)
        # if gap < len(quic_packet) / self.speed:
            # print(1)
            # time.sleep((len(quic_packet) / self.speed) - gap)

    def socket_send_loop(self, i):
        cur_sock: socket.socket = self.socks[i]
        cur_queue = self.sock_queue[i]
        while (not self.finished_sending) or len(cur_queue) != 0:
            if len(cur_queue) == 0:
                continue
            ip, data = cur_queue.pop(0)
            cur_sock.sendto(data, (ip, self.port))

    def print_result(self, i, cur_time, force=False):
        # Create a new list so that del won't break iteration
        ip_list = list(self.ip_map[i].keys())
        for ip in ip_list:
            result: single_ip_result = self.ip_map[i][ip]
            if (cur_time - result.last_time).total_seconds() >= self.timeout or force:
                # This delete is to make sure that the result won't be printed more than once
                del self.ip_map[i][ip]
                if result.resp_size > 3 * result.ori_size:
                    self.amp_f.write(f"{str(result)}\n")
                    '''elif result.resp_size > 0:
                    self.resp_f.write(f"{str(result)}\n")'''
                else:
                    pass
        # self.amp_f.flush()

    def recv(self, i):
        now = datetime.datetime.now()
        have_recv = False
        first_finish = False
        sock = self.socks[i]
        while True:
            if (datetime.datetime.now() - now).total_seconds() >= self.timeout:
                # if (not have_recv) or len(self.ip_map[i]) == 0:
                if not have_recv:
                    if self.finished_sending:
                        if not first_finish:
                            first_finish = True
                            now = datetime.datetime.now()
                            continue
                        # self.print_result(i, now, True)
                        break
                    else:
                        pass
                        # self.print_result(i, now)
                else:
                    have_recv = False
                    now = datetime.datetime.now()
                    # self.print_result(i, now)
            try:
                ret, addr = sock.recvfrom(8192)
                # if addr[0] not in self.ip_map[i]:
                # self.strange_f.write(f"{addr[0]} {len(ret)}\n")
                # continue
                self.resp_f.write(f"{addr[0]} {len(ret)} {i}\n")
                self.resp_f.flush()
                have_recv = True
                '''nxt_result = self.ip_map[i][addr[0]]
                nxt_result.resp_size += len(ret)
                nxt_result.times += 1
                nxt_result.last_time = datetime.datetime.now()
                self.ip_map[i][addr[0]] = nxt_result'''
            except Exception as e:
                pass
        print(f"{i} finished")
        self.running -= 1
