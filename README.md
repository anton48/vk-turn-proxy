# VK TURN Proxy (server)

Серверная часть для приложения [vk-turn-proxy-ios](https://github.com/anton48/vk-turn-proxy-ios)

## Установка

Скачать бинарный файл под нужную операционную систему и процессорную архитектуру из раздела [Releases](https://github.com/anton48/vk-turn-proxy/releases). Дать права на исполнение. Запускать с ключами:

```shell
./server-linux-amd64 -listen XXX.XXX.XXX.XXX:56000 -connect YYY.YYY.YYY.YYY:51820 -srtp -logfile /var/log/srtp.server.log
```
здесь:

- XXX.XXX.XXX.XXX: IP адрес сервера (в общем случае это его публичный адрес)

- 56000: порт, на котором будет слушать серверное приложение (при наличии firewall, необходимо разрешить доступ к этим IP:port)

- YYY.YYY.YYY.YYY: адрес, на котором должен слушать WireGuard сервер (обычно выбирается локальный 127.0.0.1)
  
- 51820: порт, на котором должен слушать WireGuard сервер

## Собственный turn-relay

Дополнительная необязательная утилита, которая реализует собственный TURN relay и может работать в паре с серверной частью vk-turn-proxy (в том числе на той же машине). Проверка MESSAGE-INTEGRITY отключена, поэтому релей принимает любые credentials, в том числе полученные от VK. 

Скачать бинарный файл под нужную операционную систему и процессорную архитектуру из раздела [Releases](https://github.com/anton48/vk-turn-proxy/releases). Дать права на исполнение. Запускать с ключами:

```
turn-relay -listen XXX.XXX.XXX.XXX:3478 -peer AAA.AAA.AAA.AAA,BBB.BBB.BBB.BBB
```
здесь:

- XXX.XXX.XXX.XXX: IP адрес сервера (в общем случае это его публичный адрес)

- 3478: порт, на котором будет слушать релей (при наличии firewall, необходимо разрешить доступ к этим IP:port)

- AAA.AAA.AAA.AAA,BBB.BBB.BBB.BBB: через запятую перечисляются IP адреса на которые релей может отправлять пакеты (там должны быть адрес или адреса серверов, где запущено серверное приложение vk-turn-proxy). Это единственный обязательный параметр, так как он ограничивает куда можно подключаться и релей не становится открытым из-за отсутствия авторизации по паролям.

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by [cacggghp](https://github.com/cacggghp).
