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

- YYY.YYY.YYY.YYY:51820: адрес и порт, на котором должен слушать WireGuard сервер (IP обычно выбирается локальный 127.0.0.1)

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by [cacggghp](https://github.com/cacggghp).

## License

MIT
