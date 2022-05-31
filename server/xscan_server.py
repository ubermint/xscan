#!/usr/bin/python

import os
import sys
import socketserver
import socket
import threading
import ipaddress
import datetime
import json


class Storage():
    def __init__(self):
        pass

    def merge(self, data):
        data = json.loads(data)
        with open("xscan.json") as f:
            try:
                base = json.load(f)
            except:
                base = {}
            for i in data:
                if i in base:
                    dt = datetime.datetime.strptime(data[i]['time'], '%Y-%m-%d %H:%M:%S')
                    bt = datetime.datetime.strptime(base[i]['time'], '%Y-%m-%d %H:%M:%S')
                    if dt > bt: 
                        base[i] = data[i]
                else:
                    base[i] = data[i]

        with open("xscan.json", "w") as f:
            f.write(json.dumps(base))

    def search(self, addr):
        with open("xscan.json") as f:
            base = json.load(f)
            if addr in base:
                return base[addr]
            return None

    def report(self):
        with open("xscan.json") as f:
            base = json.load(f)
        
        with open("allowed.json") as f:
            allowed = json.load(f)

        result = {}
        for i in allowed:
            if i in base:
                inter = set(base[i]['ports']).difference(set(allowed[i]))
                if inter:
                    result[i] = inter

        return result


        


class Server():
    def __init__(self, host, port):
        self.counter = 0
        self.server = socketserver.UDPServer((host, port), UDPHandler)
        
        th = threading.Thread(target=self.server.serve_forever)
        th.daemon = True
        th.start()

        self.run()

    def run(self):
        print("Server: waiting for reports on port 4444.")
        while True:
            try:
                print("1. Search host in storage.\n2. Report for blocked ports.\nCtrl^C - Exit")
                x = input()
                if x == '1':
                    addr = input("IP address: ")
                    res = storage.search(addr)
                    if res and res['ports']:
                        print(f"Last update: {res['time']}")
                        for port in res['ports']:
                            try:
                                name = socket.getservbyport(port)
                            except:
                                name = "unknown"
                            print(f"\tPORT {port}/tcp {name} - open")
                    else:
                        print("No data or no open ports for this host.")
                elif x  == '2':
                    res = storage.report()
                    if res:
                        for i in res:
                            print(f"Host {i}, blocked ports detected: {', '.join(map(str, res[i]))}.")
                        #print("Would you like to receive a report by mail?")
                    else:
                        print("No blocked ports found.")
                else:
                    print("Incorrect input.")

                input("\n+")
                os.system('clear')
            except KeyboardInterrupt:
                sys.exit("\nServer aborted by interruption.")

    def main_report(self, rep):
        pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        
        print(f"Server: received report from {self.client_address[0]}.")
        storage.merge(data.decode())
        socket = self.request[1]
        # socket.sendto(data.upper(), self.client_address)


if __name__ == "__main__":
    os.system('clear')
    print("xscan-server v0.4")

    storage = Storage()
    srv = Server("", 4444)
    
    try:
        srv.run()
    except KeyboardInterrupt:
        sys.exit("\nServer aborted by interruption.")
