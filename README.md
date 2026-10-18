# Llmmaa — автоматическая сборка Sing-box

GitHub Actions запускает сборку каждые 6 часов и вручную по кнопке **Actions → Build VPN subscription → Run workflow**.

## Источники
Добавляйте по одному URL подписки на строку в [`sources/urls.txt`](sources/urls.txt). Поддерживаются URI `vless://`, `vmess://`, `trojan://` и `ss://`.

## Raw-результаты
После успешного запуска workflow:

- [Sing-box JSON](https://raw.githubusercontent.com/Ttttttttttw7188181/Llmmaa/main/dist/antinet-singbox.json)
- [Список узлов](https://raw.githubusercontent.com/Ttttttttttw7188181/Llmmaa/main/dist/nodes.txt)
- [Статус сборки](https://raw.githubusercontent.com/Ttttttttttw7188181/Llmmaa/main/dist/status.json)

В Antinet проверьте, что импорт поддерживает sing-box JSON-конфигурации. Это не base64-формат обычной подписки.

## Важно о группах
`Авто` — urltest-группа Sing-box. `БС` и `ЧС` пока создаются как выбираемые группы узлов, а не как готовые раздельные маршруты белого/чёрного списков: для настоящего split-routing нужны конкретные списки доменов/IP/CIDR и правила маршрутизации. Страны определяются по названию/флагу в имени узла, а не по геолокации IP; имена без метки страны не попадут в страновые группы.

Проверка доступности сейчас проверяет только TCP-порт. Она не гарантирует успешный VLESS/TLS/Reality handshake. Если все TCP-проверки не проходят, сборка сохраняет распознанные узлы, чтобы не публиковать пустой результат.

Workflow использует только `GITHUB_TOKEN` с `contents: write`; секреты не нужны. Сборка коммитит файлы в `dist/` автоматически.
