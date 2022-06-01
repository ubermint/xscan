#!/usr/bin/python

import os
import sys
import socket
import ipaddress
import threading
import subprocess
import argparse
import errno
import datetime
import json
import time
from alive_progress import alive_bar


class Client():
    def __init__(self, report):
        self.report = report
    
    def save(self):
        f_name = f"report-{int(time.time())}.json"
        with open(f_name, "w") as outf:
            json.dump(self.report, outf)
        print(f"System: отчёт сохранен как {f_name}")

    def send(self, addr):
        port = 4444
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            data = json.dumps(self.report)
            sock.sendto(data.encode(), (str(addr), port))
            print("System: сервер получил отчёт.")
        except:
            sys.exit("Error! Невозможно отправить отчёт!.")
        finally:
            sock.close()


class Scanner():
    def __init__(self, network):
        self.network = network
        self.delay = 3
        with open("tcp_ports.txt", "r") as f:
            self.ports = list(map(int, f.read().strip().split(",")))
        
    def run(self):
        active = 0
        if self.network.prefixlen < 31:
            num_hosts = self.network.num_addresses - 2
        else:
            self.network.num_addresses
        print(f"Сканирование TCP-портов для {num_hosts} хостов.")

        result = {}
        with alive_bar(num_hosts, enrich_print=False) as bar:
            for addr in self.network.hosts():
                host = Host(str(addr), self.delay)
                latency = host.ICMP_ping()

                if latency:
                    t_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Хост {host.addr} работает. Задержка {latency} мс.")
                    active += 1
                    output = self.scan_ports(host)
                    if output:
                        for port in output:
                            try:
                                name = socket.getservbyport(port)
                            except:
                                name = "unknown"
                            print(f"\tПорт {port}/tcp {name} - открыт.")
                    else:
                        print("\tНе обнаружено открытых портов.")

                    result[str(addr)] = {'time': t_now, 'ports': output}

                bar()

        print(f"\nСканирование завершено! Всего {active} активных хостов.")
        return result

    def scan_ports(self, host):
        threads = []
        output = []

        for port in range(len(self.ports)):
            t = threading.Thread(
                target=host.TCP_connect,
                args=(self.ports[port], output))
            threads.append(t)

        for i in range(len(self.ports)):
            threads[i].start()

        for i in range(len(self.ports)):
            threads[i].join()

        return output


class Host():
    def __init__(self, addr, delay):
        self.addr = addr
        self.delay = delay

    def TCP_connect(self, port, output):
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(self.delay)
        try:
            TCPsock.connect((self.addr, port))
            output.append(port)
        except socket.timeout as err:
            pass
            # unable to distinguish timeout from firewall filtering
        except socket.error as err:
            pass
        finally:
            TCPsock.close()

    def ICMP_ping(self):
        command = ['ping', "-c1", '-W0.5', self.addr]
        proc = subprocess.Popen(command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
        output = str(proc.communicate()[0])
        if proc.returncode == 0:
            return float(output[output.index("time")+5:output.index("ms")])
        return None


if __name__ == "__main__":
    os.system('clear')
    print("xscan v0.5")

    parser = argparse.ArgumentParser()
    parser.add_argument("network", help="адрес и маска сети для сканирования.")
    parser.add_argument("-r", "--report",
        action="store_true", help="формирование отчёта для сервера.")

    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.network, strict=False)
        if not network.is_private:
            sys.exit("Error! Только для приватных сетей.")
    except:
        sys.exit("Error! Некорректно задана сеть.")

    scanner = Scanner(network)

    try:
        result = scanner.run()
    except KeyboardInterrupt:
        sys.exit("\nСканер прерван.")

    if args.report:
        cl = Client(result)
        print("\nДля отправки отчёта введите адрес сервера,"
            "иначе он будет сохранен локально.")
        inp = input()
        try:
            addr = ipaddress.ip_address(inp)
            cl.send(addr)
        except:
            cl.save()
