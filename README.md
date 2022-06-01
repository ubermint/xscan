### xscan  -  сканирование локальной сети

### Getting started
Эти  инструкции помогут вам запустить копию проекта
на вашем локальном компьютере для целей разработки и тестирования.

### Installing
Python 3, система с Ubuntu 16.04 или Debian 9.

Установка зависимостей, для работы клиента необходима python-библиотека [alive_progress](https://github.com/rsalmei/alive-progress/blob/main/LICENSE).
```sh
pip install alive_progress
```
Настройка прав доступа.
```sh
chmod 744 ./client/xscan_client.py
chmod 744 ./server/xscan_server.py
```

Также необходимо заполнить конфигурационный файл.
```json
{
  "mail": {
    "login": "server@example.com",
    "password": "yourpassword"
  },
  "192.168.0.1": [21, 22, 80, 443],
  "192.168.0.2": [22, 8080, 4444],
  "192.168.0.8": [22, 80, 5555]
}
```

### Launching server
Сервер сможет принимать отчёты на порту 4444 и сохранять их в базу.
```sh
./server/xscan_server.py
```

### Launching scanner
Требует указать сеть для сканирования. С ключем --report будет сформирован отчёт.
```sh
./server/xscan_client.py [network] {--report}
```

### License
Этот проект находится под лицензией MIT License.
