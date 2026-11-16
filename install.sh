#!/usr/bin/env bash
# TG Alerts Manager: вебхук Grafana → темы группы Telegram (через xray/VLESS). Установка и обновление.
#
#   bash <(curl -fsSL https://github.com/deluwr/tg-alerts-manager/releases/latest/download/install.sh)
#
# Повторный запуск обновляет до последнего релиза; конфиг в /var/lib/tg-alerts-manager сохраняется.
# При первой установке спрашивает логин и пароль панели и на что выпускать сертификат (IP / домен / самоподписанный).
# Без вопросов: PANEL_USER, PANEL_PASS, TGAM_TLS=ip|domain|self, DOMAIN, LE_EMAIL. Ещё: BOT_TOKEN, CHAT_ID, VLESS,
#   PANEL_PORT, HOOK_PORT, TGAM_VERSION=v1.1.0 (конкретный релиз), TGAM_RESTORE=/путь/к/бэкапу.json
set -euo pipefail

REPO=${TGAM_REPO:-deluwr/tg-alerts-manager}
APP_DIR=/opt/tg-alerts-manager
DATA_DIR=/var/lib/tg-alerts-manager
UPDATE=${TGAM_UPDATE:-0}
PROXY_PORT=17777

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }
tty_ok() { { : < /dev/tty; } 2>/dev/null; }
# Вопрос в терминал (работает и при bash <(curl …)): ask "вопрос" [по умолчанию]
ask() {
  local a=''
  while read -r -t 0.05 _ < /dev/tty 2>/dev/null; do :; done  # не принимать за ответ то, что набрано заранее
  read -r -p "$1" a < /dev/tty || true
  a=${a//$'\r'/}
  printf '%s' "${a:-${2:-}}"
}

[ "$(id -u)" = 0 ] || die "Запускайте от root"
command -v systemctl >/dev/null || die "Нужен Linux с systemd"

# Скачивание: напрямую, а если GitHub недоступен — через уже работающий xray панели.
fetch() {
  curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1" && return 0
  if ss -ltnH "sport = :$PROXY_PORT" 2>/dev/null | grep -q .; then
    echo "напрямую не вышло, пробую через xray"
    curl -fsSL --retry 3 --connect-timeout 15 -x "http://127.0.0.1:$PROXY_PORT" -o "$2" "$1" && return 0
  fi
  return 1
}

log "Пакеты"
need=()
for b in python3 curl tar unzip openssl ss sha256sum; do command -v "$b" >/dev/null || need+=("$b"); done
python3 -c 'import ensurepip, venv' 2>/dev/null || need+=(python3-venv)
if [ ${#need[@]} -gt 0 ]; then
  echo "доустанавливаю: ${need[*]}"
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv curl tar unzip openssl ca-certificates iproute2 coreutils >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q python3 curl tar unzip openssl ca-certificates iproute coreutils
  elif command -v yum >/dev/null; then
    yum install -y -q python3 curl tar unzip openssl ca-certificates iproute coreutils
  else
    die "Установите вручную: ${need[*]}"
  fi
fi

log "Релиз"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "${TGAM_ARCHIVE:-}" ]; then  # локальный архив — для проверки сборки
  cp "$TGAM_ARCHIVE" "$tmp/tgam.tar.gz"
  ver=local
else
  ver=${TGAM_VERSION:-}
  if [ -z "$ver" ]; then
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json" || die "Не удалось узнать последнюю версию на GitHub"
    ver=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$tmp/latest.json")
  fi
  base="https://github.com/$REPO/releases/download/$ver"
  fetch "$base/tg-alerts-manager.tar.gz" "$tmp/tgam.tar.gz" || die "Не удалось скачать релиз $ver"
  fetch "$base/tg-alerts-manager.tar.gz.sha256" "$tmp/tgam.sha256" || die "Не удалось скачать контрольную сумму релиза $ver"
  [ "$(cut -d' ' -f1 "$tmp/tgam.sha256")" = "$(sha256sum "$tmp/tgam.tar.gz" | cut -d' ' -f1)" ] \
    || die "Контрольная сумма архива $ver не совпала"
fi
mkdir -p "$tmp/x"
tar -xzf "$tmp/tgam.tar.gz" -C "$tmp/x"
[ -f "$tmp/x/app/app.py" ] || die "В архиве нет app/app.py"

mkdir -p "$APP_DIR"/{bin,hooks} "$DATA_DIR"
chmod 700 "$APP_DIR" "$DATA_DIR"
rm -rf "$APP_DIR/app.new"
cp -r "$tmp/x/app" "$APP_DIR/app.new"
rm -rf "$APP_DIR/app"
mv "$APP_DIR/app.new" "$APP_DIR/app"
install -m 644 "$tmp/x/VERSION" "$APP_DIR/VERSION"
install -m 755 "$tmp/x/install.sh" "$APP_DIR/install.sh"
VERSION=$(cat "$APP_DIR/VERSION")
echo "TG Alerts Manager $VERSION ($ver)"

# certbot в собственном venv: не зависит от системных пакетов и не трогает системный certbot
log "certbot"
CERTBOT="$APP_DIR/certbot-venv/bin/certbot"
[ -x "$CERTBOT" ] || python3 -m venv "$APP_DIR/certbot-venv"
# сертификаты на IP требуют certbot ≥ 5.4
if ! "$CERTBOT" --version 2>/dev/null | awk '{split($2, v, "."); exit !(v[1] > 5 || (v[1] == 5 && v[2] >= 4))}'; then
  "$APP_DIR/certbot-venv/bin/pip" install -q --disable-pip-version-check -U 'certbot>=5.4'
fi
"$CERTBOT" --version

log "xray"
if [ ! -x "$APP_DIR/bin/xray" ] || [ "${UPDATE_XRAY:-0}" = 1 ]; then
  case "$(uname -m)" in
    x86_64|amd64) xarch=64 ;;
    aarch64|arm64) xarch=arm64-v8a ;;
    *) die "Неизвестная архитектура $(uname -m)" ;;
  esac
  if fetch "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$xarch.zip" "$tmp/xray.zip"; then
    unzip -o -q "$tmp/xray.zip" xray -d "$tmp"
    install -m 755 "$tmp/xray" "$APP_DIR/bin/xray"
  elif command -v xray >/dev/null; then
    echo "GitHub недоступен, копирую установленный xray"
    install -m 755 "$(command -v xray)" "$APP_DIR/bin/xray"
  else
    die "Не удалось скачать xray"
  fi
fi
"$APP_DIR/bin/xray" version | sed -n 1p  # не head: ранний выход даёт SIGPIPE при pipefail

log "Хуки certbot (освобождение порта 80)"
cat > "$APP_DIR/hooks/pre.sh" <<'EOF'
#!/bin/bash
# Останавливает всё, что слушает :80, и запоминает это для post.sh.
STATE=/run/tgam-port80
touch "$STATE"
for pid in $(ss -ltnpH 'sport = :80' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
  [ -d "/proc/$pid" ] || continue  # воркеры уже завершились вместе с остановленным мастером
  comm=$(cat "/proc/$pid/comm" 2>/dev/null)
  if [ "$comm" = docker-proxy ]; then
    for c in $(docker ps -q --filter publish=80 2>/dev/null); do
      grep -qx "docker $c" "$STATE" || { docker stop "$c" >/dev/null && echo "docker $c" >> "$STATE" && echo "pre-hook: остановлен контейнер $c"; }
    done
    continue
  fi
  unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
  case "$unit" in
    *.service)
      grep -qx "unit $unit" "$STATE" || { systemctl stop "$unit" && echo "unit $unit" >> "$STATE" && echo "pre-hook: остановлен $unit"; } ;;
    *) echo "pre-hook: не знаю, как остановить pid $pid ($comm, ${unit:-без юнита})" >&2 ;;
  esac
done
for _ in $(seq 1 30); do
  ss -ltnH 'sport = :80' | grep -q . || exit 0
  sleep 0.5
done
echo "pre-hook: порт 80 всё ещё занят" >&2
EOF
cat > "$APP_DIR/hooks/post.sh" <<'EOF'
#!/bin/bash
# Запускает обратно то, что остановил pre.sh.
STATE=/run/tgam-port80
[ -f "$STATE" ] || exit 0
while read -r kind name; do
  case "$kind" in
    unit) systemctl start "$name" && echo "post-hook: запущен $name" ;;
    docker) docker start "$name" >/dev/null && echo "post-hook: запущен контейнер $name" ;;
  esac
done < "$STATE"
rm -f "$STATE"
EOF
chmod 700 "$APP_DIR/hooks/"*.sh

FRESH=1
[ -f "$DATA_DIR/config.json" ] && FRESH=0
PUBLIC_HOST=$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)
[ -n "$PUBLIC_HOST" ] || PUBLIC_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -o 'src [0-9.]*' | cut -d' ' -f2 || true)
PANEL_USER=${PANEL_USER:-}
PANEL_PASS=${PANEL_PASS:-}
TGAM_TLS=${TGAM_TLS:-}
DOMAIN=${DOMAIN:-}
LE_EMAIL=${LE_EMAIL:-}

if [ "$FRESH" = 1 ] && tty_ok; then
  if [ -z "$PANEL_PASS" ]; then
    log "Вход в панель"
    PANEL_USER=$(ask "  Логин [${PANEL_USER:-admin}]: " "${PANEL_USER:-admin}")
    while :; do
      p1=''; p2=''
      read -r -s -p "  Пароль (Enter — сгенерировать): " p1 < /dev/tty || true; echo
      [ -z "$p1" ] && break
      if [ ${#p1} -lt 8 ]; then echo "  минимум 8 символов"; continue; fi
      read -r -s -p "  Повторите пароль: " p2 < /dev/tty || true; echo
      if [ "$p1" = "$p2" ]; then PANEL_PASS=$p1; break; fi
      echo "  пароли не совпали"
    done
  fi
  if [ -z "$TGAM_TLS" ]; then
    log "Сертификат HTTPS"
    echo "  1) Let's Encrypt на IP ${PUBLIC_HOST:-сервера} — без домена, на 6 дней, продлевается сам"
    echo "  2) Let's Encrypt на домен — A-запись домена должна указывать на этот сервер (без прокси Cloudflare)"
    echo "  3) Самоподписанный — браузер и Grafana будут предупреждать"
    def=1
    [ -n "$DOMAIN" ] && def=2
    case "$(ask "  Выберите [$def]: " "$def")" in
      2) TGAM_TLS=domain
         DOMAIN=$(ask "  Домен${DOMAIN:+ [$DOMAIN]}: " "$DOMAIN")
         [ -n "$DOMAIN" ] || die "домен не указан" ;;
      3) TGAM_TLS=self ;;
      *) TGAM_TLS=ip ;;
    esac
    if [ "$TGAM_TLS" != self ]; then
      [ -n "$LE_EMAIL" ] || LE_EMAIL=$(ask "  E-mail для уведомлений Let's Encrypt (Enter — без): ")
      echo "  Выпуск сертификата означает согласие с условиями Let's Encrypt: https://letsencrypt.org/repository/"
    fi
  fi
fi

log "Конфиг"
init_out=$(PANEL_USER="$PANEL_USER" PANEL_PASS="$PANEL_PASS" TGAM_TLS="$TGAM_TLS" DOMAIN="$DOMAIN" LE_EMAIL="$LE_EMAIL" \
           PUBLIC_HOST="$PUBLIC_HOST" python3 "$APP_DIR/app/app.py" init)
val() { sed -n "s/^$1=//p" <<<"$init_out"; }
python3 "$APP_DIR/app/app.py" xray-config
cfg_vals() { python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c["panel_port"], c["hook_port"], c.get("tls_mode") or "self")' "$DATA_DIR/config.json"; }
read -r PANEL_PORT HOOK_PORT TLS_MODE < <(cfg_vals)

# порты должны быть свободны или заняты самой панелью
for p in "$PANEL_PORT" "$HOOK_PORT"; do
  holder=$(ss -ltnpH "sport = :$p" 2>/dev/null || true)
  if [ -n "$holder" ] && ! systemctl is-active --quiet tgam; then
    die "Порт $p уже занят: $holder (другой порт: PANEL_PORT=… / HOOK_PORT=…)"
  fi
done

log "systemd"
PY=$(command -v python3)
cat > /etc/systemd/system/tgam-xray.service <<EOF
[Unit]
Description=TG Alerts Manager: xray (выход в Telegram)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$APP_DIR/bin/xray run -c $DATA_DIR/xray.json
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/tgam.service <<EOF
[Unit]
Description=TG Alerts Manager: вебхук Grafana -> Telegram
After=network-online.target tgam-xray.service
Wants=network-online.target tgam-xray.service

[Service]
ExecStart=$PY $APP_DIR/app/app.py serve
Environment=PYTHONUNBUFFERED=1 TGAM_REPO=$REPO
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/tgam-certbot-renew.service <<EOF
[Unit]
Description=TG Alerts Manager: продление сертификата Let's Encrypt

[Service]
Type=oneshot
ExecStart=$CERTBOT renew --config-dir $DATA_DIR/letsencrypt --work-dir $DATA_DIR/letsencrypt/work --logs-dir $DATA_DIR/letsencrypt/logs --no-random-sleep-on-renew
StandardOutput=append:$DATA_DIR/certbot.log
StandardError=append:$DATA_DIR/certbot.log
EOF
cat > /etc/systemd/system/tgam-certbot-renew.timer <<EOF
[Unit]
Description=TG Alerts Manager: проверка продления сертификата

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
cat > /usr/local/bin/tgam <<'EOF'
#!/bin/bash
# TG Alerts Manager: команды на сервере
APP=@APP@
DATA=@DATA@
PY=@PY@
case "${1:-}" in
  ""|url) "$PY" "$APP/app/app.py" url ;;
  update) bash "$APP/install.sh" ;;
  password)
    read -r -p "Логин (Enter — прежний): " u < /dev/tty || true
    read -r -s -p "Новый пароль (Enter — сгенерировать): " p < /dev/tty || true; echo
    if [ -n "$p" ]; then
      PANEL_USER="$u" PANEL_PASS="$p" "$PY" "$APP/app/app.py" init >/dev/null && echo "Логин и пароль изменены"
    else
      PANEL_USER="$u" RESET_PASSWORD=1 "$PY" "$APP/app/app.py" init | sed -n 's/^PANEL_PASSWORD=/Новый пароль: /p'
    fi
    systemctl restart tgam ;;
  cert) "$PY" "$APP/app/app.py" cert-issue "${@:2}" 2>&1 | tee -a "$DATA/certbot.log" ;;
  restore) [ -f "${2:-}" ] || { echo "tgam restore <файл бэкапа.json>"; exit 1; }; "$PY" "$APP/app/app.py" restore "$2" ;;
  logs) journalctl -u tgam -f ;;
  version) "$PY" "$APP/app/app.py" version ;;
  *) echo "tgam [url|update|password|cert [--force]|restore <файл>|logs|version]"; exit 1 ;;
esac
EOF
sed -i "s|@APP@|$APP_DIR|; s|@DATA@|$DATA_DIR|; s|@PY@|$PY|" /usr/local/bin/tgam
chmod 755 /usr/local/bin/tgam

systemctl daemon-reload
systemctl enable -q tgam-xray tgam
systemctl enable -q --now tgam-certbot-renew.timer

if [ -n "${TGAM_RESTORE:-}" ]; then
  log "Восстановление из $TGAM_RESTORE"
  python3 "$APP_DIR/app/app.py" restore "$TGAM_RESTORE"
  read -r PANEL_PORT HOOK_PORT TLS_MODE < <(cfg_vals)
fi
systemctl restart tgam-xray tgam

if command -v ufw >/dev/null && [[ $(ufw status) == *"Status: active"* ]]; then
  log "ufw: открываю $PANEL_PORT, $HOOK_PORT$([ "$TLS_MODE" != self ] && echo ' и 80 (проверка Let'"'"'s Encrypt)')"
  ufw allow "$PANEL_PORT/tcp" >/dev/null
  ufw allow "$HOOK_PORT/tcp" >/dev/null
  [ "$TLS_MODE" = self ] || ufw allow 80/tcp >/dev/null
fi

# сертификат выпускается, только если его нет или он выпущен на другой адрес; обновление его не трогает
if [ "$UPDATE" != 1 ] && [ "$TLS_MODE" != self ]; then
  log "Сертификат Let's Encrypt"
  if python3 "$APP_DIR/app/app.py" cert-issue --if-needed 2>&1 | tee -a "$DATA_DIR/certbot.log"; then
    echo "Сертификат в порядке, панель подхватывает его без перезапуска"
  else
    echo "!! Сертификат не выпущен — пока работает самоподписанный. Повторить: раздел «сертификат» в панели или tgam cert"
  fi
fi

sleep 2
systemctl is-active --quiet tgam || { journalctl -u tgam -n 30 --no-pager; die "Сервис не запустился"; }

echo
if [ "$UPDATE" = 1 ]; then
  log "Обновлено до $VERSION"
  exit 0
fi
log "Готово: TG Alerts Manager $VERSION"
python3 "$APP_DIR/app/app.py" url
if [ -n "${TGAM_RESTORE:-}" ]; then
  echo "Пароль:  прежний, из бэкапа (сменить: tgam password)"
elif [ -n "$(val PANEL_PASSWORD)" ]; then
  echo "Пароль:  $(val PANEL_PASSWORD)   ← сохраните, повторно не показывается (сменить: tgam password)"
elif [ -n "$PANEL_PASS" ]; then
  echo "Пароль:  заданный при установке"
fi
echo "Команды: tgam url | update | password | cert | restore <файл> | logs"
