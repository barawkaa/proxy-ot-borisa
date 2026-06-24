# Proxy от Бориса

Текущая версия: v2.0.0

> Текущая версия add-on: **2.0.0**. Архив собран как полный Home Assistant add-on repository: `repository.yaml`, корневой `README.md`, `CHANGELOG.md`, папка `proxy-ot-borisa` и все файлы для установки/публикации.

**Proxy от Бориса** — Home Assistant add-on для Raspberry Pi/Home Assistant, который превращает VPN/VLESS-подписки и отдельные серверы в управляемый proxy gateway.

## Что нового в 2.0.0

- База возвращена к рабочей ветке v1.26.1 по внешнему HTTP/SOCKS/MTProto транспорту.
- Убраны невалидные быстрые патчи v1.26.2/v1.26.3/v1.26.4 из релизной линии: сломанная Python-логика `SOCKS_SNI_ROUTE` не используется.
- `sing-box` больше не берётся из плавающего `latest`: Dockerfile закреплён на `ghcr.io/sagernet/sing-box:v1.12.12`, чтобы не получить внезапное удаление legacy inbound fields в sing-box 1.13+.
- Добавлена нормализация uTLS fingerprints из Hiddify/Clash/Xray-стиля: `helloChrome_120`, `HelloFirefox_Auto` и похожие значения приводятся к совместимым `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `random`, `randomized`.
- Нормализация применяется и при импорте подписок, и перед генерацией runtime-конфига, поэтому уже сохранённые серверы в `/data/servers.json` не должны валить запуск `sing-box`.
- Для IP-first SOCKS5 от роутеров вроде Keenetic включён native sniffing на внутреннем localhost SOCKS inbound sing-box: внешний SOCKS5 gateway остаётся прозрачным, без Python pre-read TLS-потока.
- Smoke-test расширен проверкой Dockerfile pin, версии 2.0.0, uTLS-normalization, отсутствия `SOCKS_SNI_ROUTE`, структуры internal SOCKS sniffing и согласованности публичных файлов.

## Основные функции

- HTTP proxy: порт по умолчанию `2081`.
- SOCKS5 proxy: порт по умолчанию `2080`.
- Telegram MTProto proxy: порт по умолчанию `2083`.
- Trusted IP/CIDR без авторизации.
- Клиенты, соединения, история и трафик.
- Ручные правила маршрутизации, Re:filter rule-set, VPN/DIRECT.
- Диагностика URL, маршрутов, задержек, speed-test и реального клиента.
- Подписки VPN/VLESS, отдельные серверы, авто-выбор сервера.
- Backup/restore/cleanup/audit/maintenance.

## Критичные сценарии проверки после установки

1. Аддон стартует, UI открывается через Ingress.
2. В журнале нет `unknown uTLS fingerprint: helloChrome_120`.
3. В журнале нет ошибки `legacy inbound fields are deprecated ... removed in sing-box 1.13.0`.
4. HTTP 2081 работает через ZeroOmega.
5. SOCKS5 2080 работает через Keenetic.
6. Trusted IP `188.143.204.77` работает без auth, если внесён в trusted.
7. ChatGPT/OpenAI/oaiusercontent через роутер идут через VPN, а не DIRECT.
8. MTProto 2083 работает по secret.
9. Клиенты, соединения, история, диагностика, скорость и задержки отображаются корректно.

## Установка

1. Установить репозиторий Home Assistant add-on.
2. Открыть add-on `Proxy от Бориса`.
3. Проверить конфигурацию портов и паролей.
4. Запустить add-on.
5. Добавить VPN/VLESS подписку или серверы.
6. Проверить вкладку диагностики и журнал запуска.

## Важное по sing-box

Версия 2.0.0 намеренно не использует `ghcr.io/sagernet/sing-box:latest`. В sing-box 1.13+ удалены legacy inbound fields, из-за чего старый runtime-конфиг падал при старте. До полноценной миграции конфигурации на новый формат rule actions используется закреплённый `sing-box:v1.12.12`.

## Важное по SOCKS5/Keenetic

Внешний SOCKS5 gateway не переписывает поток и не читает TLS руками. Для IP-first HTTPS-соединений от роутера используется native sniffing sing-box на внутреннем SOCKS inbound. Это сделано, чтобы не повторять поломку транспорта из экспериментальной v1.26.2.

## Безопасность

- Не открывайте HTTP/SOCKS порты в интернет без авторизации или trusted CIDR.
- Для внешнего доступа используйте отдельных пользователей и сильные пароли.
- Trusted bypass применяйте только к известным IP/CIDR.
- Диагностика и история не должны перехватывать содержимое HTTPS, логины, пароли, cookie или формы.
