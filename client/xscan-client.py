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

from alive_progress import alive_bar  # external library


class Client():
    def __init__(self, report, network):
        self.report = report
        self.network = network
    
    def save(self):
        sub  = f"{int(self.network.network_address)}-{self.network.prefixlen}"
        f_name = f"report-{int(time.time())}-{sub}.json"
        with open(f_name, "w") as outf:
            json.dump(self.report, outf)
        print(f"System: report saved as {f_name}")

    def send(self, addr):
        port = 4444
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            data = json.dumps(self.report)
            sock.sendto(data.encode(), (str(addr), port))
            print("System: report received by server!")
        except:
            sys.exit("Error! Unable to send report.")
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
        num_hosts = self.network.num_addresses - 2 if self.network.prefixlen < 31 else self.network.num_addresses
        print(f"Scanning top{len(self.ports)} TCP ports for {num_hosts} hosts.")

        result = {}
        with alive_bar(num_hosts, enrich_print=False) as bar:
            for addr in self.network.hosts():
                host = Host(str(addr), self.delay)
                latency = host.ICMP_ping()

                if latency:
                    t_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Host {host.addr} is up! Latency {latency} ms.")
                    active += 1
                    output = self.scan_ports(host)
                    if output:
                        for port in output:
                            try:
                                name = socket.getservbyport(port)
                            except:
                                name = "unknown"
                            print(f"\tPORT {port}/tcp {name} - open")
                    else:
                        print("\tNo open ports detected.")

                    result[str(addr)] = {'time': t_now, 'ports': output}

                bar()

        print(f"\nScan completed! Detected {active} active hosts.")
        return result


    def scan_ports(self, host):
        threads = []
        output = []

        for port in range(len(self.ports)):
            t = threading.Thread(target=host.TCP_connect, args=(self.ports[port], output))
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
            #output.append((port, "open"))
        except socket.timeout as err:
            pass
            #output.append((port, "filtered"))  # unable to distinguish timeout from firewall filtering
        except socket.error as err:
            pass
        finally:
            TCPsock.close()

    def ICMP_ping(self):
        "ping -c 1 -W 0.5 ip > /dev/null 2>&1"
        command = ['ping', "-c1", '-W0.5', self.addr]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = str(proc.communicate()[0])
        if proc.returncode == 0:
            return float(output[output.index("time")+5:output.index("ms")])
        return None


def main():
    os.system('clear')
    print("xscan v0.4")

    parser = argparse.ArgumentParser()
    parser.add_argument("network", help="Private subnetwork for scan.")
    #parser.add_argument("-d", "--delay", type=int, help="Delay in seconds. (default: 5s)")
    #parser.add_argument("-t", "--top", type=int, help="Number of most used ports. (default: 100)")
    parser.add_argument("-r", "--report",
        action="store_true", help="Report based on report.json (default: off)")

    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.network, strict=False)
        if not network.is_private:
            sys.exit("Error! Only for private network.")
    except:
        sys.exit("Error! Invalid network.")

    """
    top_n_ports = 100
    if args.top:
        if 1 <= args.top <= 1000:
            top_n_ports = args.top
        else:
            sys.exit("Error! Invalid number of ports.")
    """

    scanner = Scanner(network)

    try:
        result = scanner.run()
    except KeyboardInterrupt:
        sys.exit("\nScanner aborted by interruption.")

    if args.report:
        cl = Client(result, network)
        print("\nTo send report type server address, otherwise it will be saved locally.")
        inp = input()
        try:
            addr = ipaddress.ip_address(inp)
            cl.send(addr)
        except:
            cl.save()

if __name__ == "__main__":
    main()
