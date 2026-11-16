Первый выпуск TG Alerts Manager — пересылка алертов Grafana в темы группы Telegram с панелью управления.

- Установка и обновление одной командой: `bash <(curl -fsSL https://github.com/deluwr/tg-alerts-manager/releases/latest/download/install.sh)`
- Маршруты по label (`alertname`, `service`, `grafana_folder` или свой) с несколькими условиями и приоритетом
- Выход в Telegram через встроенный xray (VLESS), если api.telegram.org недоступен напрямую
- Бэкап конфига в Telegram по расписанию и кнопкой, восстановление из файла в панели или с консоли
- Обновление из панели по кнопке, когда на GitHub выходит новый релиз
- HTTPS: Let's Encrypt для домена с автопродлением, иначе самоподписанный сертификат
