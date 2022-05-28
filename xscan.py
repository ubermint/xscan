#!/usr/bin/python
import socket
import ipaddress
import sys
import os
import threading
import errno


class Scanner():
    def __init__(self, net):
        self.net = net

    def scan(self):
        print(f"Scanning for {self.net.num_addresses} hosts")
        for addr in self.net.hosts():
            ip = str(addr)
            print("Scan", ip)
            host = Host(ip)
            if host.ICMP_ping():
                print(f"host {ip} is up!")
                output = host.scan_ports()
                if output:
                    for port in output:
                        try:
                            name = socket.getservbyport(port[0])
                        except:
                            name = "unknown"
                        print(f"\tPORT {port[0]}/tcp {name} - {port[1]}")
                else:
                    print("\tHas no open ports!")


class Host():
    def __init__(self, addr):
        self.addr = addr
        self.delay = 5

    def scan_ports(self):
        threads = []
        output = []

        for port in range(200):
            t = threading.Thread(target=self.TCP_connect, args=(port+1, output))
            threads.append(t)

        for i in range(200):
            threads[i].start()

        for i in range(200):
            threads[i].join()

        return output

    def TCP_connect(self, port, output):
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(self.delay)
        try:
            TCPsock.connect((self.addr, port))
            output.append((port, "open"))
        except socket.timeout as err:
            output.append((port, "filtered"))
        except socket.error as err:
            pass

    def ICMP_ping(self):
        ping = os.system(f"ping -c 1 -W 0.5 {self.addr} > /dev/null 2>&1")
        if ping == 0:
            return True
        return False


if __name__ == "__main__":
    if len(sys.argv) == 2:
        net = ipaddress.ip_network(sys.argv[1], strict=False)
        scanner = Scanner(net)
        scanner.scan()
    else:
        print("Usage: xscan [network]/[mask]")