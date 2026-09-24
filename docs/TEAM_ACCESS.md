# Доступ команды к Identity Risk Analyzer

## Для участника команды

1. Установите Tailscale и войдите в разрешённый tailnet команды.
2. Откройте https://identity-risk-team.tail54a46d.ts.net/

Это один общий стенд: Dashboard, история scan и SQLite на DigitalOcean одинаковы для всех участников. Python, Node и локальный `.env` не нужны.

## Если что-то не работает

- **Tailscale disconnected:** подключитесь к tailnet и повторите открытие URL.
- **Site unavailable:** проверьте, что устройство `identity-risk-team` онлайн в Tailscale; обратитесь к владельцу стенда.
- **DC unavailable:** сайт может открываться с последним сохранённым scan, но новый анализ AD завершится ошибкой. Дождитесь восстановления связи DigitalOcean → DC через Tailscale.

Приложение доступно только внутри tailnet. Не используйте публичный IP Droplet для доступа к нему.
