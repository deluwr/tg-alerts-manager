#!/usr/bin/env bash
# Проверка на чистой машине с systemd (CI): установка из собранного архива с заданными логином и паролем, вход,
# маршруты, вебхук, настройки сертификата, бэкап и восстановление, повторный запуск как обновление,
# обновление с прошлого релиза 1.0.0 с переносом конфига. Запускать от root.
set -euo pipefail
cd "$(dirname "$0")/.."

PANEL=https://127.0.0.1:1337
HOOK=https://127.0.0.1:6969
JAR=$(mktemp)
ARCHIVE=dist/tg-alerts-manager.tar.gz
fail() { echo "FAIL: $*" >&2; journalctl -u tgam -n 50 --no-pager || true; exit 1; }
api() {  # метод путь [json]
  curl -sk -b "$JAR" -c "$JAR" -X "$1" -H 'X-Requested-With: tgam' -H 'Content-Type: application/json' \
       ${3:+--data "$3"} "$PANEL$2"
}
login() { api POST /api/login "{\"user\":\"$1\",\"password\":\"$2\"}" | grep -q '"ok": true'; }
wait_up() {
  for _ in $(seq 1 40); do curl -skf "$HOOK/health" >/dev/null && return 0; sleep 0.5; done
  fail "сервис не поднялся"
}
state_py() { api GET /api/state | python3 -c "import json,sys; s=json.load(sys.stdin); $1"; }

echo "== сборка"
bash scripts/build-release.sh

echo "== правила маршрутов и перенос конфига 1.0"
python3 - <<'PY'
import importlib.util, json, os, tempfile
os.environ['TGAM_DATA'] = tempfile.mkdtemp()
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
for old, want in (({'domain': '1.2.3.4'}, ('self', '1.2.3.4', '', '1.2.3.4')),
                  ({'domain': 'a.example.com', 'public_ip': '5.6.7.8'}, ('domain', '5.6.7.8', 'a.example.com', 'a.example.com'))):
    json.dump(old, open(app.CONFIG_PATH, 'w'))
    c = app.load_config()
    got = (c['tls_mode'], c['public_ip'], c['domain'], app.public_host(c))
    assert got == want, (old, got)
print('ok')
PY

echo "== установка с логином и паролем"
out=$(TGAM_ARCHIVE=$ARCHIVE PANEL_USER=ops PANEL_PASS=ci-pass-12345 TGAM_TLS=self bash install.sh 2>&1) || { echo "$out"; fail "install.sh"; }
echo "$out" | tail -6
grep -q 'Пароль:  заданный при установке' <<<"$out" || fail "установщик не учёл заданный пароль"
systemctl is-active --quiet tgam-xray || fail "tgam-xray не запущен"
wait_up
tgam url | grep -q 'логин ops' || fail "tgam url"

echo "== вход"
login ops wrong-password && fail "вход с неверным паролем"
login admin ci-pass-12345 && fail "вход со старым логином admin"
login ops ci-pass-12345 || fail "вход"
state_py '
assert s["update"]["version"] == open("VERSION").read().strip(), s["update"]
assert s["cert"]["source"] == "self-signed" and s["tls_mode"] == "self", s["cert"]
print("state ok", s["update"]["version"])'
curl -sk "$PANEL/" | grep -q 'tg alerts manager' || fail "страница входа"
curl -sk -b "$JAR" "$PANEL/" | grep -q 'data-page="routes"' || fail "панель"

echo "== маршруты и настройки"
api POST /api/routes '{"routes":[{"thread_id":"12, 34","general":true,"conditions":[{"label":"service","values":["api","web"]}]}]}' | grep -q '"ok": true' || fail "сохранение маршрутов"
api POST /api/routes '{"routes":[{"thread_id":"abc","conditions":[]}]}' | grep -q 'числа через запятую' || fail "проверка thread_id"
api POST /api/settings '{"backup_chat_id":"123456","backup_hours":"12","webhook_secret":"s3cret"}' | grep -q '"ok": true' || fail "настройки"
api POST /api/settings '{"backup_chat_id":"@user"}' | grep -q 'числовой id' || fail "проверка получателя бэкапа"

echo "== настройки сертификата"
api POST /api/settings '{"tls_mode":"domain","domain":""}' | grep -q 'укажите домен' || fail "домен обязателен в режиме domain"
api POST /api/settings '{"public_ip":"999.1.1.1"}' | grep -q 'IP сервера' || fail "проверка IP"
api POST /api/settings '{"tls_mode":"self","domain":"https://Alerts.Example.com:1337/"}' | grep -q '"ok": true' || fail "сохранение домена"
state_py 'assert s["domain"] == "alerts.example.com", s["domain"]'
api POST /api/cert '{}' | grep -q 'самоподписанный' || fail "выпуск в режиме self должен отказать"
{ tgam cert 2>&1 || true; } | grep -q 'самоподписанный' || fail "tgam cert в режиме self"

echo "== вебхук"
payload='{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"Test","service":"api"},"annotations":{"summary":"x"},"startsAt":"2026-01-01T00:00:00Z"}]}'
code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST --data "$payload" "$HOOK/api/v1/alerts/webhook")
[ "$code" = 401 ] || fail "вебхук без секрета: $code"
curl -sk -X POST -H 'Authorization: Bearer s3cret' --data "$payload" "$HOOK/api/v1/alerts/webhook" | grep -q '"alerts": 1' || fail "вебхук"
api GET /api/state | grep -q 'service=api | web (тред 12)' || fail "алерт не ушёл в маршрут"

echo "== бэкап и восстановление"
python3 - <<'PY' > /tmp/tgam-backup.json
import importlib.util
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
login ops ci-pass-12345 || fail "вход после восстановления"
state_py 'assert s["routes"] and s["routes"][0]["thread_id"] == "12, 34", s["routes"]; print("restore ok")'

echo "== смена логина и пароля"
api POST /api/password '{"user":"bad user","password":"12345678"}' | grep -q 'логин' || fail "проверка логина"
api POST /api/password '{"user":"ops2","password":"new-pass-123"}' | grep -q '"ok": true' || fail "смена логина"
login ops ci-pass-12345 && fail "старый пароль ещё действует"
login ops2 new-pass-123 || fail "вход с новым логином"

echo "== повторный запуск (обновление)"
TGAM_ARCHIVE=$ARCHIVE TGAM_UPDATE=1 bash install.sh >/tmp/tgam-update.log 2>&1 || { cat /tmp/tgam-update.log; fail "обновление"; }
grep -q 'Обновлено до' /tmp/tgam-update.log || fail "обновление: нет итоговой строки"
wait_up
login ops2 new-pass-123 || fail "логин сбросился при обновлении"
api GET /api/state | grep -q '"backup_chat_id": "123456"' || fail "настройки потерялись при обновлении"

echo "== обновление с релиза 1.0.0"
systemctl stop tgam tgam-xray
rm -rf /var/lib/tg-alerts-manager /opt/tg-alerts-manager/app
old=$(TGAM_VERSION=v1.0.0 bash <(curl -fsSL https://github.com/deluwr/tg-alerts-manager/releases/download/v1.0.0/install.sh) 2>&1) \
  || { echo "$old"; fail "установка 1.0.0"; }
OLDPASS=$(sed -n 's/^Пароль:  \([^ ]*\).*/\1/p' <<<"$old")
[ -n "$OLDPASS" ] || fail "1.0.0 не показала пароль"
wait_up
TGAM_ARCHIVE=$ARCHIVE TGAM_UPDATE=1 bash install.sh >/tmp/tgam-update.log 2>&1 || { cat /tmp/tgam-update.log; fail "обновление с 1.0.0"; }
wait_up
login admin "$OLDPASS" || fail "после обновления с 1.0.0 не входит прежний пароль"
state_py '
assert s["tls_mode"] == "self" and s["domain"] == "" and s["public_ip"], (s["tls_mode"], s["domain"], s["public_ip"])
assert s["hook_url"].startswith("https://" + s["public_ip"] + ":"), s["hook_url"]
print("migration ok", s["public_ip"])'

echo "ВСЁ ОК"
