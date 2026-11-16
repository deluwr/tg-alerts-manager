#!/usr/bin/env bash
# Проверка на чистой машине с systemd (CI): установка из собранного архива, вход, маршруты, вебхук,
# бэкап и восстановление, повторный запуск установщика как обновление. Запускать от root.
set -euo pipefail
cd "$(dirname "$0")/.."

PANEL=https://127.0.0.1:1337
HOOK=https://127.0.0.1:6969
JAR=$(mktemp)
fail() { echo "FAIL: $*" >&2; journalctl -u tgam -n 50 --no-pager || true; exit 1; }
api() {  # метод путь [json]
  curl -sk -b "$JAR" -c "$JAR" -X "$1" -H 'X-Requested-With: tgam' -H 'Content-Type: application/json' \
       ${3:+--data "$3"} "$PANEL$2"
}
wait_up() {
  for _ in $(seq 1 40); do curl -skf "$HOOK/health" >/dev/null && return 0; sleep 0.5; done
  fail "сервис не поднялся"
}

echo "== сборка"
bash scripts/build-release.sh

echo "== правила маршрутов"
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location('app', 'app/app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
cfg = {'default_thread': '9', 'routes': [
    {'thread_id': '1', 'general': False, 'conditions': [{'label': 'alertname', 'values': ['a', 'b*']},
                                                        {'label': 'service', 'values': ['api']}]},
    {'thread_id': '', 'general': True, 'conditions': [{'label': 'grafana_folder', 'values': ['F']}]},
    {'label': 'alertname', 'value': 'legacy', 'thread_id': '3'},
]}
assert app.route_threads({'alertname': 'b2', 'service': 'api'}, cfg) == [('1', 'alertname=a | b*; service=api')]
assert app.route_threads({'alertname': 'b2', 'service': 'web'}, cfg)[0][0] == '9', 'И между условиями'
assert app.route_threads({'grafana_folder': 'F'}, cfg)[0][0] == '0', 'General'
assert app.route_threads({'alertname': 'legacy'}, cfg)[0][0] == '3', 'старый формат'
print('ok')
PY

echo "== установка"
out=$(TGAM_ARCHIVE=dist/tg-alerts-manager.tar.gz DOMAIN=127.0.0.1 bash install.sh 2>&1) || { echo "$out"; fail "install.sh"; }
echo "$out" | tail -8
PASS=$(sed -n 's/^Пароль:  \([^ ]*\).*/\1/p' <<<"$out")
[ -n "$PASS" ] || fail "установщик не показал пароль"
systemctl is-active --quiet tgam-xray || fail "tgam-xray не запущен"
wait_up
tgam url | grep -q 1337 || fail "tgam url"

echo "== вход"
[ "$(api POST /api/login '{"user":"admin","password":"wrong"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"])')" = False ] || fail "вход с неверным паролем"
api POST /api/login "{\"user\":\"admin\",\"password\":\"$PASS\"}" | grep -q '"ok": true' || fail "вход"
api GET /api/state | python3 -c '
import json, sys
s = json.load(sys.stdin)
assert s["update"]["version"] == open("VERSION").read().strip(), s["update"]
assert s["cert"]["source"] == "self-signed", s["cert"]
print("state ok", s["update"]["version"])'
curl -sk "$PANEL/" | grep -q 'tg alerts manager' || fail "страница входа"
curl -sk -b "$JAR" "$PANEL/" | grep -q 'data-page="routes"' || fail "панель"

echo "== маршруты и настройки"
api POST /api/routes '{"routes":[{"thread_id":"12, 34","general":true,"conditions":[{"label":"service","values":["api","web"]}]}]}' | grep -q '"ok": true' || fail "сохранение маршрутов"
api POST /api/routes '{"routes":[{"thread_id":"abc","conditions":[]}]}' | grep -q 'числа через запятую' || fail "проверка thread_id"
api POST /api/settings '{"backup_chat_id":"123456","backup_hours":"12","webhook_secret":"s3cret"}' | grep -q '"ok": true' || fail "настройки"
api POST /api/settings '{"backup_chat_id":"@user"}' | grep -q 'числовой id' || fail "проверка получателя бэкапа"

echo "== вебхук"
payload='{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test","service":"api"},"annotations":{"summary":"x"},"startsAt":"2026-01-01T00:00:00Z"}]}'
code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST --data "$payload" "$HOOK/api/v1/alerts/webhook")
[ "$code" = 401 ] || fail "вебхук без секрета: $code"
curl -sk -X POST -H 'Authorization: Bearer s3cret' --data "$payload" "$HOOK/api/v1/alerts/webhook" | grep -q '"alerts": 1' || fail "вебхук"
api GET /api/state | grep -q 'service=api | web (тред 12)' || fail "алерт не ушёл в маршрут"

echo "== бэкап и восстановление"
python3 - <<'PY' > /tmp/tgam-backup.json
import importlib.util, os
os.environ.setdefault('TGAM_DATA', '/var/lib/tg-alerts-manager')
spec = importlib.util.spec_from_file_location('app', '/opt/tg-alerts-manager/app/app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
print(app.backup_content().decode())
PY
grep -q '"backup_chat_id": "123456"' /tmp/tgam-backup.json || fail "в бэкапе нет настроек"
grep -q session_key /tmp/tgam-backup.json && fail "в бэкап попал ключ сессий"
api POST /api/routes '{"routes":[]}' >/dev/null
api POST /api/restore "{\"data\":$(cat /tmp/tgam-backup.json)}" | grep -q '"moved": false' || fail "восстановление"
sleep 3
wait_up
api POST /api/login "{\"user\":\"admin\",\"password\":\"$PASS\"}" | grep -q '"ok": true' || fail "вход после восстановления"
api GET /api/state | python3 -c '
import json, sys
s = json.load(sys.stdin)
assert s["routes"] and s["routes"][0]["thread_id"] == "12, 34", s["routes"]
print("restore ok")'

echo "== повторный запуск (обновление)"
TGAM_ARCHIVE=dist/tg-alerts-manager.tar.gz TGAM_UPDATE=1 bash install.sh >/tmp/tgam-update.log 2>&1 || { cat /tmp/tgam-update.log; fail "обновление"; }
grep -q 'Обновлено до' /tmp/tgam-update.log || fail "обновление: нет итоговой строки"
wait_up
api POST /api/login "{\"user\":\"admin\",\"password\":\"$PASS\"}" | grep -q '"ok": true' || fail "пароль сбросился при обновлении"
api GET /api/state | grep -q '"backup_chat_id": "123456"' || fail "настройки потерялись при обновлении"

echo "ВСЁ ОК"
