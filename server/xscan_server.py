#!/usr/bin/python
import os
import sys
import socketserver
import smtplib, ssl
from email.mime.text import MIMEText
from email.header import Header
import socket
import threading
import ipaddress
import datetime
import json


class Storage():
    def __init__(self):
        self.xscan = "xscan.json"
        self.allowed = "allowed.json"

    def merge(self, data):
        data = json.loads(data)
        with open(self.xscan) as f:
            try:
                base = json.load(f)
            except:
                base = {}
            for i in data:
                if i in base:
                    dt = datetime.datetime.strptime(
                        data[i]['time'], '%Y-%m-%d %H:%M:%S')
                    bt = datetime.datetime.strptime(
                        base[i]['time'], '%Y-%m-%d %H:%M:%S')
                    if dt > bt: 
                        base[i] = data[i]
                else:
                    base[i] = data[i]

        with open(self.xscan, "w") as f:
            f.write(json.dumps(base))

    def search(self, net):
        result = {}
        with open(self.xscan) as f:
            base = json.load(f)
            for i in base:
                ip = ipaddress.ip_address(i)
                if ip in net:
                    result[i] = base[i]
        return result

    def report(self):
        with open(self.xscan) as f:
            base = json.load(f)
        
        with open(self.allowed) as f:
            allowed = json.load(f)

        result = {}
        for i in allowed:
            if i != 'mail' and i in base:
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
        print("Server: ожидается подключение на порту 4444.")
        while True:
            try:
                print("xscan-server v0.5")
                print("1. Показать состояние сети.\n"
                    "2. Проверить разрешенные порты.\nCtrl^C - Выход")
                x = input()
                if x == '1':
                    a = input("Адрес подсети: ")
                    addr = ipaddress.ip_network(a, strict=False)
                    res = storage.search(addr)
                    if res:
                        for i in res:
                            print(f"Хост {i}. ({res[i]['time']})")
                            for port in res[i]['ports']:
                                try:
                                    name = socket.getservbyport(port[i])
                                except:
                                    name = "unknown"
                                print(f"\tPORT {port}/tcp {name} - open")
                    else:
                        print("Нет данных по этой сети.")
                elif x  == '2':
                    res = storage.report()
                    if res:
                        txt  = []
                        for i in res:
                            a = f"Хост {i}, обнаружены запрещённые порты: "
                            b = f"{', '.join(map(str, res[i]))}."
                            s = a+b
                            print(s)
                            txt.append(s+"\n")
                        mail = input("Введите почту"
                            ", на которую можно отправить отчёт: ")
                        mailer = Mail()
                        if '@' in mail:
                            mailer.send(mail,
                                "Отчёт сканирования сети.",
                                "".join(txt).encode('utf-8').strip())
                            print("Отчёт отправлен.")
                    else:
                        print("Не обнаружено запрещённых портов.")
                else:
                    print("Incorrect input.")

                input("\n+")
                os.system('clear')
            except KeyboardInterrupt:
                sys.exit("\nСервер прерван.")


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        print(f"Server: получен отчёт от {self.client_address[0]}.")
        storage.merge(data.decode())


class Mail:
    def __init__(self):
        self.port = 465
        self.smtp_server_domain_name = "smtp.gmail.com"
        with open("allowed.json") as fs:
            sender = json.load(fs)
        self.sender_mail = sender["mail"]["login"]
        self.password = sender["mail"]["password"]

    def send(self, email, subject, content):
        ssl_context = ssl.create_default_context()
        service = smtplib.SMTP_SSL(self.smtp_server_domain_name, self.port, context=ssl_context)
        service.login(self.sender_mail, self.password)

        msg = MIMEText(content, _charset="UTF-8")
        msg['Subject'] = Header(subject, "utf-8")

        result = service.sendmail(self.sender_mail, email, msg.as_string())
        service.quit()


if __name__ == "__main__":
    os.system('clear')

    storage = Storage()
    srv = Server("", 4444)
    
    try:
        srv.run()
    except KeyboardInterrupt:
        sys.exit("\nСервер прерван из-за сбоя.")
