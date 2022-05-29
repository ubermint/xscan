#!/usr/bin/python

import os
import sys
import socket
import ipaddress
import threading
import subprocess
import errno
import time


class Scanner():
    def __init__(self, net, ports):
        self.net = net
        self.ports = ports

        if self.net.prefixlen < 31:
            self.hosts = self.net.num_addresses - 2
        else:
            self.hosts = self.net.num_addresses

    def scan(self):
        active = 0
        print(f"Scanning top{len(self.ports)} TCP ports for {self.hosts} hosts.")
        for addr in self.net.hosts():
            ip = str(addr)
            host = Host(ip)
            if host.ICMP_ping():
                active += 1
                output = host.scan_ports(self.ports)
                if output:
                    for port in output:
                        try:
                            name = socket.getservbyport(port[0])
                        except:
                            name = "unknown"
                        print(f"\tPORT {port[0]}/tcp {name} - {port[1]}")
                else:
                    print("\tNo open ports detected.")

        print(f"Scan complete! Detected {active} active hosts.")

    def report(self):
        pass


class Host():
    def __init__(self, addr, delay=5):
        self.addr = addr
        self.delay = delay

    def scan_ports(self, ports):
        threads = []
        output = []

        for port in range(len(ports)):
            t = threading.Thread(target=self.TCP_connect, args=(ports[port], output))
            threads.append(t)

        for i in range(len(ports)):
            threads[i].start()

        for i in range(len(ports)):
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
            pass
            #output.append((port, "filtered"))  # unable to distinguish timeout from firewall filtering
        except socket.error as err:
            pass

    def ICMP_ping(self):
        "ping -c 1 -W 0.5 ip > /dev/null 2>&1"
        command = ['ping', "-c1", '-W0.5', self.addr]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = str(proc.communicate()[0])
        if proc.returncode == 0:
            latency = float(output[output.index("time")+5:output.index("ms")])
            print(f"Host {self.addr} is up! Latency {latency} ms.")
        return proc.returncode == 0


def main():
    if len(sys.argv) >= 2:
        arg = sys.argv[1]
        if "/" not in arg:
            arg += "/32"
        net = ipaddress.ip_network(arg, strict=False)
        if not net.is_private:
            sys.exit("\nOnly for private subnets!")

        if len(sys.argv) == 3 and (1 <= int(sys.argv[2]) <= 1000):
            n_port = int(sys.argv[2])
        else:
            n_port = 100

        with open("top.txt", "r") as f:
            ports = list(map(int, f.read().strip().split(",")))[:n_port]

        scanner = Scanner(net, ports)
        try:
            scanner.scan()
        except KeyboardInterrupt:
            sys.exit("\nScanner aborted.")

    else:
        print("Usage: xscan [network]{/[mask]} {ports}")

if __name__ == "__main__":
    main()
