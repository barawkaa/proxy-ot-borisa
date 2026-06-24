## 2.0.1

- Исправлена критичная регрессия SOCKS5 через маршрутизатор: gateway relay больше не закрывает весь TCP-туннель из-за idle timeout только в upload-направлении.
- Relay теперь различает короткий socket timeout как служебный wake-up, общий idle timeout всего туннеля и штатный half-close одной стороны соединения.
- Для HTTPS/HTTP2/WebSocket сохранено поведение: если upload временно молчит, но download активен, соединение остаётся живым.
- Добавлены regression-тесты relay: download после простоя upload и download после half-close upload.
- Сохранены исправления 2.0.0: закреплённая версия sing-box, нормализация uTLS fingerprint и отсутствие сломанной Python-логики SOCKS_SNI_ROUTE.

## 2.0.0

- Релизная ветка возвращена к рабочей базе v1.26.1 по внешнему HTTP/SOCKS/MTProto транспорту.
- Исключена сломанная экспериментальная логика `SOCKS_SNI_ROUTE`, которая ломала SOCKS5 через Keenetic.
- Dockerfile больше не использует `ghcr.io/sagernet/sing-box:latest`; sing-box закреплён на `ghcr.io/sagernet/sing-box:v1.12.12`.
- Исправлена причина падения `sing-box` на `unknown uTLS fingerprint: helloChrome_120`: fingerprints из Hiddify/Clash/Xray-стиля нормализуются в совместимые значения sing-box.
- Нормализация применяется перед генерацией runtime `sing-box.json`, поэтому уже сохранённые серверы с `helloChrome_120` не должны ломать запуск.
- Для IP-first SOCKS5 от роутеров добавлен безопасный native sniffing на внутреннем localhost SOCKS inbound sing-box без Python pre-read TLS-потока.
- Расширен smoke-test: Dockerfile pin, версия 2.0.0, uTLS-normalization, internal SOCKS sniffing, отсутствие `SOCKS_SNI_ROUTE`, согласованность README/CHANGELOG/config/backend.
- README обновлён под версию 2.0.0 и фиксирует причину отказа от плавающего `sing-box:latest`.

## 1.26.1

- URL-диагностика показывает этапы TCP / CONNECT / SOCKS5 / TLS / HTTP / чтение / закрытие.
- Исправлена ложная ошибка `SSLError RECORD_LAYER_FAILURE` после HTTP 200 и полученных данных.
- Рабочие HTTP/SOCKS/SNI/Re:filter не должны переписываться.

## 1.26.0

- Релизная стабилизация клиентов, соединений, истории и документации.
- Группировка одинаковых соединений.
- Полировка карточек клиентов.
- Скрытие fallback-дубликатов.
- Smoke-test получил проверку согласованности версий.
