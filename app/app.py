#!/usr/bin/env python3
"""TG Alerts Manager: вебхук Grafana → темы (треды) группы Telegram через локальный xray (VLESS)."""
import base64
import fnmatch
import hashlib
import hmac
import html
import http.cookies
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_DIR = os.environ.get('TGAM_DIR', '/opt/tg-alerts-manager')
DATA_DIR = os.environ.get('TGAM_DATA', '/var/lib/tg-alerts-manager')
REPO = os.environ.get('TGAM_REPO', 'deluwr/tg-alerts-manager')
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')
XRAY_BIN = os.path.join(APP_DIR, 'bin', 'xray')
XRAY_CONFIG = os.path.join(DATA_DIR, 'xray.json')
CERT_LOG = os.path.join(DATA_DIR, 'certbot.log')
UPDATE_LOG = os.path.join(DATA_DIR, 'update.log')
UPDATE_SCRIPT = os.path.join(DATA_DIR, 'update-install.sh')
SELF_CERT = os.path.join(DATA_DIR, 'certs', 'self.crt')
SELF_KEY = os.path.join(DATA_DIR, 'certs', 'self.key')
LE_DIR = os.path.join(DATA_DIR, 'letsencrypt')
CERTBOT = os.path.join(APP_DIR, 'certbot-venv', 'bin', 'certbot')
PRE_HOOK = os.path.join(APP_DIR, 'hooks', 'pre.sh')
POST_HOOK = os.path.join(APP_DIR, 'hooks', 'post.sh')
HOOK_PATH = '/api/v1/alerts/webhook'
XRAY_UNIT = 'tgam-xray'
RENEW_TIMER = 'tgam-certbot-renew.timer'


def read_version():
    try:
        with open(os.path.join(APP_DIR, 'VERSION'), encoding='utf-8') as f:
            return f.read().strip().lstrip('v') or '0.0.0'
    except OSError:
        return '0.0.0'


VERSION = read_version()

CERT_NAME = 'tgam'  # одна цепочка Let's Encrypt: на IP или на домен, при смене — перевыпуск

DEFAULTS = {
    'tls_mode': 'ip',  # ip | domain | self — на что выпускать сертификат Let's Encrypt (self — самоподписанный)
    'public_ip': '',
    'domain': '',
    'cert_for': '',  # «ip:1.2.3.4» / «domain:x.y» — для чего выпущен текущий сертификат
    'panel_port': 1337,
    'hook_port': 6969,
    'proxy_port': 17777,
    'panel_user': 'admin',
    'panel_pass_hash': '',
    'bot_token': '',
    'chat_id': '',
    'default_thread': '',
    'webhook_secret': '',
    'routes': [],
    'hide_labels': ['alertname', 'grafana_folder', '__*'],
    'tz_offset': 3,
    'fmt_firing': '🔥 Есть активные алерты',
    'fmt_resolved': '✅ Всё решено',
    'label_titles': 'service=Сервис\nendpoint=Endpoint\npath=Endpoint\nmethod=Метод\nerror_code=Код ошибки\n'
                    'code=Код ошибки\nstatus_code=Код ошибки',
    'link_titles': 'logs=Логи\nlogs_url=Логи\nrunbook_url=Runbook',
    'vless': '',
    'le_email': '',
    'backup_chat_id': '',
    'backup_hours': 24,
    'backup_last': 0,
    'known_threads': [],
    'session_key': '',
}

_cfg_lock = threading.RLock()
EVENTS = deque(maxlen=300)
SEND_Q = queue.Queue(maxsize=2000)
CERT_STATE = {'unit': ''}
UPD = {'latest': '', 'notes': '', 'checked': 0, 'error': '', 'unit': ''}
SESSION_COOKIE = 'tgam_s'
SESSION_TTL = 30 * 86400
_FAILS = {}  # ip -> время неудачных входов


# ---------- конфиг ----------

def is_ip(s):
    try:
        ipaddress.ip_address(str(s).strip())
        return True
    except ValueError:
        return False


def load_config():
    with _cfg_lock:
        cfg = json.loads(json.dumps(DEFAULTS))
        try:
            with open(CONFIG_PATH, encoding='utf-8') as f:
                raw = json.load(f)
        except FileNotFoundError:
            return cfg
        cfg.update(raw)
        if 'tls_mode' not in raw:  # конфиг 1.0: в domain лежал либо IP (самоподписанный), либо домен
            d = str(raw.get('domain') or '')
            if not d or is_ip(d):
                cfg.update(tls_mode='self', public_ip=d, domain='')
            else:
                cfg['tls_mode'] = 'domain'
        return cfg


def save_config(cfg):
    with _cfg_lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = CONFIG_PATH + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_PATH)


def update_config(**kw):
    with _cfg_lock:
        cfg = load_config()
        cfg.update(kw)
        save_config(cfg)
        return cfg


def hash_pw(pw):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 200_000).hex()
    return f'pbkdf2${salt}${dk}'


def verify_pw(pw, stored):
    try:
        _, salt, dk = stored.split('$')
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 200_000).hex()
    return hmac.compare_digest(calc, dk)


def log_event(kind, text, ok=True):
    EVENTS.append({'t': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'kind': kind, 'text': text, 'ok': ok})
    print(f'[{kind}] {"OK" if ok else "ERR"} {text}', flush=True)


def run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def public_host(cfg):
    """Адрес для ссылок на панель и вебхук: домен в режиме «домен», иначе IP сервера."""
    if cfg.get('tls_mode') == 'domain' and cfg.get('domain'):
        return cfg['domain']
    return cfg.get('public_ip') or cfg.get('domain') or socket.gethostname()


# ---------- Telegram ----------

def tg_opener():
    proxy = f"http://127.0.0.1:{load_config()['proxy_port']}"
    return urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))


def tg_request(method, data, ctype, timeout):
    cfg = load_config()
    if not cfg['bot_token']:
        raise RuntimeError('не задан токен бота')
    req = urllib.request.Request(f"https://api.telegram.org/bot{cfg['bot_token']}/{method}",
                                 data=data, headers={'Content-Type': ctype})
    try:
        with tg_opener().open(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as ex:
        try:
            return json.load(ex)
        except Exception:
            raise RuntimeError(f'Telegram HTTP {ex.code}')
    except urllib.error.URLError as ex:
        raise RuntimeError(f'нет связи с Telegram через xray: {ex.reason}')


def tg(method, payload=None, timeout=25):
    return tg_request(method, json.dumps(payload or {}).encode(), 'application/json', timeout)


def tg_upload(method, fields, file_field, filename, content, timeout=60):
    """multipart/form-data: поля + один файл (sendDocument)."""
    boundary = secrets.token_hex(16)
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
                 f'Content-Type: application/json\r\n\r\n'.encode() + content + b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    return tg_request(method, b''.join(parts), f'multipart/form-data; boundary={boundary}', timeout)


def strip_tags(text):
    return html.unescape(re.sub(r'<[^>]+>', '', text))


def deliver(thread_id, text, origin):
    cfg = load_config()
    if not cfg['chat_id']:
        log_event('send', f'{origin}: не задан chat_id', False)
        return False, 'не задан chat_id'
    payload = {'chat_id': cfg['chat_id'], 'text': text, 'parse_mode': 'HTML',
               'link_preview_options': {'is_disabled': True}}
    thread_id = str(thread_id).strip()
    if thread_id not in ('', '0'):
        payload['message_thread_id'] = int(thread_id)
    where = thread_label(thread_id)
    err = 'неизвестная ошибка'
    for attempt in range(6):
        try:
            r = tg('sendMessage', payload)
        except Exception as ex:
            err = str(ex)
            time.sleep(min(30, 2 ** attempt))
            continue
        if r.get('ok'):
            log_event('send', f'{origin} → {where}')
            return True, 'отправлено'
        err = r.get('description', 'ошибка')
        params = r.get('parameters') or {}
        low = err.lower()
        if r.get('error_code') == 429:
            time.sleep(int(params.get('retry_after', 5)) + 1)
            continue
        if params.get('migrate_to_chat_id'):
            update_config(chat_id=str(params['migrate_to_chat_id']))
            payload['chat_id'] = str(params['migrate_to_chat_id'])
            continue
        if 'thread not found' in low and 'message_thread_id' in payload:
            payload.pop('message_thread_id')
            payload['text'] = f'⚠️ тред {html.escape(str(thread_id))} не найден, отправлено в General\n\n' + payload['text']
            continue
        if "can't parse entities" in low and payload.get('parse_mode'):
            payload.pop('parse_mode')
            payload['text'] = strip_tags(payload['text'])
            continue
        break
    log_event('send', f'{origin} → {where}: {err}', False)
    return False, err


def sender_loop():
    while True:
        thread_id, text, origin = SEND_Q.get()
        try:
            deliver(thread_id, text, origin)
        except Exception as ex:
            log_event('send', f'{origin}: {ex}', False)


# ---------- алерты ----------

def e(v):
    return html.escape(str(v), quote=True)


def fmt_value(v):
    return f'{v:g}' if isinstance(v, float) else str(v)


def fmt_time(s, off):
    if not s or s.startswith('0001'):
        return ''
    s = re.sub(r'\.(\d{6})\d+', r'.\1', s).replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return s
    return dt.astimezone(timezone(timedelta(hours=off))).strftime('%d.%m.%Y %H:%M:%S')


def thread_label(t):
    return 'General' if str(t).strip() in ('', '0') else f'тред {t}'


def route_values(r):
    """Значения маршрута старого формата (один label + value/values)."""
    vals = r['values'] if 'values' in r else [r.get('value', '')]
    return [str(v).strip() for v in vals if str(v).strip()]


def route_conds(r):
    """Условия маршрута: [(label, [значения])]. Старый формат тоже понимаем."""
    if 'conditions' in r:
        src = [(c.get('label', ''), c.get('values') or []) for c in r['conditions']]
    else:
        src = [(r.get('label', ''), route_values(r))]
    out = []
    for label, vals in src:
        label = str(label).strip()
        vals = [str(v).strip() for v in vals if str(v).strip()]
        if label:
            out.append((label, vals))
    return out


def route_name(r):
    return r.get('name') or '; '.join(f"{label}={' | '.join(vals)}" for label, vals in route_conds(r))


def route_threads(labels, cfg):
    """Первый подходящий маршрут сверху вниз: все его треды, плюс General, если отмечено.
    Подходит, если совпали все условия (И); внутри условия — любое значение (ИЛИ).
    Маршрут без тредов, без General или без условий пропускается; 0 — General."""
    for r in cfg['routes']:
        threads = [t.strip() for t in str(r.get('thread_id', '')).split(',') if t.strip()]
        if r.get('general'):
            threads.append('0')
        conds = route_conds(r)
        if not threads or not conds:
            continue
        if all(labels.get(label) is not None and any(fnmatch.fnmatchcase(str(labels[label]), p) for p in vals)
               for label, vals in conds):
            return [(t, route_name(r)) for t in threads]
    return [(str(cfg.get('default_thread', '')).strip(), 'по умолчанию')]


def parse_pairs(text):
    """«ключ=Заголовок» по строке → упорядоченный dict."""
    out = {}
    for line in str(text or '').splitlines():
        k, sep, v = line.partition('=')
        if sep and k.strip() and v.strip():
            out[k.strip()] = v.strip()
    return out


def bold_keys(text):
    """Экранирует текст аннотации и выделяет короткие «Ключ:» в начале строк (Сервис:, Метод:, Код:)."""
    def line(s):
        m = re.match(r'(\s*)([^\s:][^:]{0,24}):(\s.*|)$', s)
        if m and len(m.group(2).split()) <= 2:
            return f'{e(m.group(1))}<b>{e(m.group(2))}:</b>{e(m.group(3))}'
        return e(s)
    return '\n'.join(line(s) for s in str(text).splitlines())


def current_value(a):
    """Значение из valueString: результат reduce, иначе query, иначе первое из values."""
    found = re.findall(r"var='([^']+)'[^\]]*?type='([^']+)' value=([^\s\]]+)", a.get('valueString') or '')
    for want in ('reduce', 'query', 'math'):
        for _, typ, val in found:
            if typ == want:
                return val
    vals = a.get('values') or {}
    return fmt_value(next(iter(vals.values()))) if vals else ''


def alert_block(a, labels, cfg):
    off = float(cfg.get('tz_offset') or 0)
    rows = [('Начало', fmt_time(a.get('startsAt'), off))]
    if a.get('status') == 'resolved':
        rows.append(('Конец', fmt_time(a.get('endsAt'), off)))
    titles = parse_pairs(cfg.get('label_titles'))
    hide = cfg.get('hide_labels') or []
    rows += [(t, labels.get(k)) for k, t in titles.items()]
    rows += [(k, v) for k, v in labels.items()
             if k not in titles and not any(fnmatch.fnmatchcase(k, p) for p in hide)]
    rows.append(('Текущее значение', current_value(a)))
    return '\n'.join(f'  ▪️ <b>{e(t)}:</b> <code>{e(v)}</code>' for t, v in rows if str(v or '').strip())


def render_message(items, p, cfg):
    """items — [(alert, labels)] одного треда → список сообщений (длинные режутся по алертам)."""
    a0, l0 = items[0]
    name = (p.get('groupLabels') or {}).get('alertname') or l0.get('alertname', 'alert')
    ann = dict(a0.get('annotations') or {})
    ann.update(p.get('commonAnnotations') or {})
    head = [f'<b>{e(name)}</b>']
    texts = [bold_keys(ann[k]) for k in ('summary', 'description') if str(ann.get(k) or '').strip()]
    if texts:
        head += [''] + texts
    firing = [(a, l) for a, l in items if a.get('status') != 'resolved']
    resolved = [(a, l) for a, l in items if a.get('status') == 'resolved']
    state, n = (cfg['fmt_firing'], len(firing)) if firing else (cfg['fmt_resolved'], len(resolved))
    head += ['', '', f'<b>{e(state)} (всего: {n})</b>']

    pieces = ['\n'.join(head)]
    for title, group in (('Активные алерты:', firing), ('Решённые алерты:', resolved)):
        for i, (a, l) in enumerate(group):
            block = alert_block(a, l, cfg)
            pieces.append(f"<b>{title}</b>\n{'—' * 24}\n{block}" if i == 0 else block)

    links1 = [('🔗', 'Grafana Dashboard', a0.get('panelURL') or a0.get('dashboardURL'))]
    link_titles = parse_pairs(cfg.get('link_titles'))
    for k, v in ann.items():
        if str(v).startswith(('http://', 'https://')):
            links1.append(('🔗', link_titles.get(k, k), v))
    links2 = [('🔗', 'Настройки алерта', a0.get('generatorURL')), ('🔕', 'Заглушить (Silence)', a0.get('silenceURL'))]
    groups = ['\n'.join(f'{ic} <a href="{e(u)}">{e(t)}</a>' for ic, t, u in g if u) for g in (links1, links2)]
    footer = '\n\n'.join(g for g in groups if g)
    if footer:
        pieces.append(footer)
    return chunk_blocks(pieces)


def chunk_blocks(blocks, limit=3900):
    chunks, cur = [], ''
    for b in blocks:
        if len(b) > limit:
            b = b[:limit] + '…'
        if cur and len(cur) + 2 + len(b) > limit:
            chunks.append(cur)
            cur = b
        else:
            cur = f'{cur}\n\n{b}' if cur else b
    if cur:
        chunks.append(cur)
    return chunks


def handle_payload(p, origin='alert'):
    cfg = load_config()
    groups = {}
    alerts = p.get('alerts') or []
    for a in alerts:
        labels = dict(p.get('commonLabels') or {})
        labels.update(a.get('labels') or {})
        hits = route_threads(labels, cfg)
        for thread in dict.fromkeys(t for t, _ in hits):  # один тред — одно сообщение, даже если совпало несколько маршрутов
            groups.setdefault(thread, []).append((a, labels))
        dest = ', '.join(f'{name} ({thread_label(t)})' for t, name in hits)
        log_event('alert', f"{a.get('status')} {labels.get('alertname', '?')} → {dest}")
    for thread, items in groups.items():
        for chunk in render_message(items, p, cfg):
            try:
                SEND_Q.put_nowait((thread, chunk, origin))
            except queue.Full:
                log_event('send', 'очередь переполнена, алерт отброшен', False)
    return len(alerts)


# ---------- xray ----------

def parse_outbound(s):
    s = s.strip()
    if s.startswith('{'):
        j = json.loads(s)
        if 'outbounds' in j:
            cands = [o for o in j['outbounds'] if o.get('protocol') not in ('freedom', 'blackhole', 'dns')]
            if not cands:
                raise ValueError('в конфиге нет прокси-outbound')
            ob = dict(cands[0])
        elif 'protocol' in j:
            ob = dict(j)
        else:
            raise ValueError('JSON должен быть outbound или полным конфигом xray')
        ob.pop('tag', None)
        return ob
    if not s.startswith('vless://'):
        raise ValueError('ожидается ссылка vless://… или JSON')
    u = urllib.parse.urlsplit(s)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    if not u.username or not u.hostname:
        raise ValueError('в ссылке нет uuid или адреса')
    user = {'id': urllib.parse.unquote(u.username), 'encryption': q.get('encryption', 'none')}
    if q.get('flow'):
        user['flow'] = q['flow']
    net = q.get('type', 'tcp')
    if net == 'splithttp':
        net = 'xhttp'
    sec = q.get('security', 'none')
    ss = {'network': net, 'security': sec}
    if sec == 'tls':
        tls = {'serverName': q.get('sni') or u.hostname, 'fingerprint': q.get('fp', 'chrome')}
        if q.get('alpn'):
            tls['alpn'] = q['alpn'].split(',')
        if q.get('allowInsecure') in ('1', 'true'):
            tls['allowInsecure'] = True
        ss['tlsSettings'] = tls
    elif sec == 'reality':
        rs = {'serverName': q.get('sni', ''), 'fingerprint': q.get('fp', 'chrome'),
              'publicKey': q.get('pbk', ''), 'shortId': q.get('sid', ''), 'spiderX': q.get('spx', '')}
        if q.get('pqv'):
            rs['mldsa65Verify'] = q['pqv']
        ss['realitySettings'] = rs
    if net == 'ws':
        ss['wsSettings'] = {'path': q.get('path', '/'), 'host': q.get('host', '')}
    elif net == 'grpc':
        ss['grpcSettings'] = {'serviceName': q.get('serviceName', ''), 'multiMode': q.get('mode') == 'multi'}
    elif net == 'httpupgrade':
        ss['httpupgradeSettings'] = {'path': q.get('path', '/'), 'host': q.get('host', '')}
    elif net == 'xhttp':
        xs = {'path': q.get('path', '/'), 'host': q.get('host', ''), 'mode': q.get('mode', 'auto')}
        if q.get('extra'):
            xs['extra'] = json.loads(q['extra'])
        ss['xhttpSettings'] = xs
    elif net == 'tcp' and q.get('headerType') == 'http':
        ss['tcpSettings'] = {'header': {'type': 'http', 'request': {
            'path': [q.get('path', '/')], 'headers': {'Host': [q.get('host', u.hostname)]}}}}
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': u.hostname, 'port': u.port or 443, 'users': [user]}]},
            'streamSettings': ss}


def build_xray(vless, proxy_port):
    outs = []
    if vless.strip():
        ob = parse_outbound(vless)
        ob['tag'] = 'proxy'
        outs.append(ob)
    outs.append({'protocol': 'freedom', 'tag': 'direct'})
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'tag': 'http-in', 'listen': '127.0.0.1', 'port': proxy_port, 'protocol': 'http', 'settings': {}}],
            'outbounds': outs}


def write_xray(vless, restart=True):
    cfg = load_config()
    conf = build_xray(vless, cfg['proxy_port'])
    tmp = os.path.join(DATA_DIR, 'xray.new.json')  # xray определяет формат по расширению
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(conf, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    r = run([XRAY_BIN, 'run', '-test', '-c', tmp])
    if r.returncode != 0:
        os.unlink(tmp)
        raise ValueError('xray отверг конфиг: ' + (r.stdout + r.stderr).strip()[-600:])
    os.replace(tmp, XRAY_CONFIG)
    if restart:
        run(['systemctl', 'restart', XRAY_UNIT])


# ---------- сертификат ----------

def ensure_self_cert(cn):
    if os.path.exists(SELF_CERT) and os.path.exists(SELF_KEY):
        return
    os.makedirs(os.path.dirname(SELF_CERT), exist_ok=True)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650', '-subj', f'/CN={cn or "localhost"}',
         '-keyout', SELF_KEY, '-out', SELF_CERT])
    os.chmod(SELF_KEY, 0o600)


def cert_paths():
    cfg = load_config()
    if cfg['tls_mode'] != 'self':
        for name in (CERT_NAME, cfg['domain']):  # вторая — цепочка 1.0, названная по домену
            if not name:
                continue
            c, k = os.path.join(LE_DIR, 'live', name, 'fullchain.pem'), os.path.join(LE_DIR, 'live', name, 'privkey.pem')
            if os.path.exists(c) and os.path.exists(k):
                return c, k
    return SELF_CERT, SELF_KEY


def cert_target(cfg):
    """(вид, значение) — на что выпускать сертификат в текущем режиме."""
    if cfg['tls_mode'] == 'domain':
        if not cfg.get('domain'):
            raise ValueError('укажите домен')
        if is_ip(cfg['domain']):
            raise ValueError('в поле домена — IP; для IP выберите режим «на IP»')
        return 'domain', cfg['domain']
    if cfg['tls_mode'] == 'ip':
        if not is_ip(cfg.get('public_ip')):
            raise ValueError('укажите IP сервера')
        return 'ip', cfg['public_ip']
    raise ValueError('выбран самоподписанный сертификат — Let\'s Encrypt не нужен')


_DNS = {'at': 0, 'key': None, 'val': None}


def dns_check(cfg):
    """Куда указывает домен: если не на IP сервера — подсказка (чаще всего прокси Cloudflare)."""
    d, ip = cfg.get('domain'), cfg.get('public_ip')
    if cfg['tls_mode'] != 'domain' or not d:
        return None
    if _DNS['key'] == (d, ip) and time.time() - _DNS['at'] < 60:
        return _DNS['val']
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)})
        val = {'domain': d, 'ips': ips, 'ok': not ip or ip in ips}
    except OSError as ex:
        val = {'domain': d, 'ips': [], 'ok': False, 'error': f'домен не находится в DNS: {ex}'}
    _DNS.update(at=time.time(), key=(d, ip), val=val)
    return val


class CertHolder:
    def __init__(self):
        self.lock = threading.Lock()
        self.key = None
        self.ctx = None

    def get(self):
        c, k = cert_paths()
        key = (c, os.path.getmtime(c), os.path.getmtime(k))
        with self.lock:
            if key != self.key:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(c, k)
                self.ctx, self.key = ctx, key
            return self.ctx


CERTS = CertHolder()


def port80_holders():
    out = run(['ss', '-ltnpH', 'sport = :80']).stdout
    items = set()
    for pid in set(re.findall(r'pid=(\d+)', out)):
        try:
            with open(f'/proc/{pid}/comm') as f:
                comm = f.read().strip()
        except OSError:
            comm = '?'
        unit = run(['ps', '-o', 'unit=', '-p', pid]).stdout.strip()
        items.add(f'{comm} ({unit})' if unit else comm)
    return ', '.join(sorted(items)) or 'свободен'


def cert_info():
    cfg = load_config()
    c, _ = cert_paths()
    info = {'source': 'letsencrypt' if c.startswith(LE_DIR) else 'self-signed', 'not_after': '', 'days_left': None,
            'mode': cfg['tls_mode'], 'cert_for': cfg.get('cert_for', ''), 'dns': dns_check(cfg)}
    san = run(['openssl', 'x509', '-noout', '-ext', 'subjectAltName', '-in', c]).stdout
    info['names'] = re.findall(r'(?:DNS|IP Address):([^,\s]+)', san)
    try:
        kind, value = cert_target(cfg)
        info['target'] = f'{kind}:{value}'
    except ValueError:
        info['target'] = ''
    end = run(['openssl', 'x509', '-noout', '-enddate', '-in', c]).stdout.strip().partition('=')[2]
    if end:
        info['not_after'] = end
        try:
            dt = datetime.strptime(end, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            info['days_left'] = (dt - datetime.now(timezone.utc)).days
        except ValueError:
            pass
    unit = CERT_STATE['unit']
    info['running'] = bool(unit) and run(['systemctl', 'is-active', unit]).stdout.strip() in ('active', 'activating')
    info['log'] = tail_file(CERT_LOG, 4000)
    info['port80'] = port80_holders()
    info['timer'] = run(['systemctl', 'is-active', RENEW_TIMER]).stdout.strip()
    return info


def tail_file(path, n):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read()[-n:]
    except FileNotFoundError:
        return ''


LE_ARGS = ['--config-dir', LE_DIR, '--work-dir', os.path.join(LE_DIR, 'work'), '--logs-dir', os.path.join(LE_DIR, 'logs')]


def issue_cert(force=False, if_needed=False):
    """Выпуск Let's Encrypt на IP (профиль shortlived, 6 дней) или на домен. Вывод certbot — в stdout."""
    cfg = load_config()
    if cfg['tls_mode'] == 'self':
        if if_needed:
            return
        raise ValueError('выбран самоподписанный сертификат')
    kind, value = cert_target(cfg)
    target = f'{kind}:{value}'
    lineage = os.path.join(LE_DIR, 'live', CERT_NAME, 'fullchain.pem')
    if if_needed and cfg.get('cert_for') == target and os.path.exists(lineage):
        return
    print(f"=== {datetime.now().isoformat(timespec='seconds')}: Let's Encrypt на {value} ===", flush=True)
    if os.path.exists(os.path.join(LE_DIR, 'renewal', f'{CERT_NAME}.conf')) and cfg.get('cert_for') != target:
        # цепочка выпущена на другой адрес — certbot не меняет его без вопроса, поэтому заново
        subprocess.run([CERTBOT, *LE_ARGS, 'delete', '--cert-name', CERT_NAME, '--non-interactive'])
    args = [CERTBOT, *LE_ARGS, 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--cert-name', CERT_NAME,
            '--key-type', 'ecdsa', '--pre-hook', PRE_HOOK, '--post-hook', POST_HOOK]
    args += ['-m', cfg['le_email']] if cfg.get('le_email') else ['--register-unsafely-without-email']
    args += ['--preferred-profile', 'shortlived', '--ip-address', value] if kind == 'ip' else ['-d', value]
    args += ['--force-renewal'] if force else ['--keep-until-expiring']
    if subprocess.run(args).returncode != 0:
        raise RuntimeError("Let's Encrypt не выдал сертификат. Частая причина — порт 80 закрыт снаружи "
                           '(firewall в панели хостера) или домен указывает не на этот сервер.')
    if kind == 'ip':
        # 6-дневный сертификат: продлевать за 3 дня до конца (таймер проверяет дважды в сутки)
        rc = os.path.join(LE_DIR, 'renewal', f'{CERT_NAME}.conf')
        with open(rc, encoding='utf-8') as f:
            lines = [ln for ln in f.read().splitlines() if not ln.startswith('renew_before_expiry')]
        lines.insert(1, 'renew_before_expiry = 3 days')
        with open(rc, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
    update_config(cert_for=target)
    print(f'Сертификат на {value} выпущен', flush=True)


def unit_active(unit):
    return bool(unit) and run(['systemctl', 'is-active', unit]).stdout.strip() in ('active', 'activating')


def start_cert(force):
    if unit_active(CERT_STATE['unit']):
        raise RuntimeError('certbot уже работает')
    cert_target(load_config())  # ошибку настроек — сразу в панель, а не в журнал certbot
    unit = f'tgam-certbot-{int(time.time())}'
    # отдельный transient-юнит: перезапуск панели не оборвёт certbot между pre- и post-hook
    r = run(['systemd-run', f'--unit={unit}', '--collect',
             '-p', f'StandardOutput=append:{CERT_LOG}', '-p', f'StandardError=append:{CERT_LOG}',
             sys.executable, os.path.abspath(__file__), 'cert-issue', *(['--force'] if force else [])])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'systemd-run failed')
    CERT_STATE['unit'] = unit
    log_event('cert', 'запущен certbot' + (' (принудительно)' if force else ''))


# ---------- бэкап ----------

def backup_content():
    cfg = load_config()
    for k in ('session_key', 'backup_last'):
        cfg.pop(k, None)
    return json.dumps({'app': 'tg-alerts-manager', 'version': VERSION,
                       'created': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'config': cfg},
                      ensure_ascii=False, indent=2).encode()


def send_backup(origin):
    cfg = load_config()
    to = str(cfg.get('backup_chat_id') or '').strip()
    if not to:
        raise RuntimeError('не указан получатель бэкапа')
    host = public_host(cfg)
    name = f"tgam-backup-{re.sub(r'[^A-Za-z0-9.-]', '_', host)}-{datetime.now():%Y%m%d-%H%M}.json"
    r = tg_upload('sendDocument', {'chat_id': to, 'caption': f'Бэкап TG Alerts Manager {VERSION} · {host}'},
                  'document', name, backup_content())
    if not r.get('ok'):
        desc = r.get('description', 'ошибка Telegram')
        if 'chat not found' in desc.lower() or 'blocked' in desc.lower():
            desc += ' — получатель должен сначала написать боту /start'
        raise RuntimeError(desc)
    update_config(backup_last=int(time.time()))
    log_event('backup', f'{origin}: отправлен → {to}')


def backup_loop():
    while True:
        time.sleep(60)
        try:
            cfg = load_config()
            hours = float(cfg.get('backup_hours') or 0)
            if hours <= 0 or not cfg.get('backup_chat_id') or not cfg.get('bot_token'):
                continue
            if time.time() - float(cfg.get('backup_last') or 0) >= hours * 3600:
                send_backup('по расписанию')
        except Exception as ex:
            log_event('backup', f'по расписанию: {ex}', False)
            time.sleep(1800)  # не повторять ошибку каждую минуту


def apply_restore(data):
    """Восстановление из бэкапа (или из голого config.json прежних версий). Сессии и время бэкапа — свои."""
    if isinstance(data, dict) and isinstance(data.get('config'), dict):
        src = data['config']
    elif isinstance(data, dict) and ('routes' in data or 'bot_token' in data):
        src = data
    else:
        raise ValueError('это не бэкап TG Alerts Manager')
    cfg = load_config()
    # IP и сертификат принадлежат этой машине — при переезде на новый сервер они свои
    for k in DEFAULTS:
        if k in src and k not in ('session_key', 'backup_last', 'public_ip', 'cert_for'):
            cfg[k] = src[k]
    if is_ip(cfg.get('domain')):  # бэкап 1.0: в domain лежал IP старого сервера
        cfg['domain'] = ''
    elif cfg.get('domain') and 'tls_mode' not in src:
        cfg['tls_mode'] = 'domain'
    save_config(cfg)
    try:
        write_xray(cfg.get('vless') or '')
    except Exception as ex:
        write_xray('')
        log_event('restore', f'VLESS из бэкапа не применён ({ex}), xray идёт напрямую', False)
    log_event('restore', 'конфиг восстановлен из бэкапа')
    return cfg


# ---------- обновление ----------

def http_get(url, timeout=25):
    """GET напрямую, при ошибке — через локальный xray."""
    req = urllib.request.Request(url, headers={'User-Agent': f'tg-alerts-manager/{VERSION}',
                                               'Accept': 'application/vnd.github+json'})
    errs = []
    for proxy in (None, f"http://127.0.0.1:{load_config()['proxy_port']}"):
        handler = urllib.request.ProxyHandler({'http': proxy, 'https': proxy} if proxy else {})
        try:
            with urllib.request.build_opener(handler).open(req, timeout=timeout) as r:
                return r.read()
        except Exception as ex:
            errs.append(f"{'через xray' if proxy else 'напрямую'}: {ex}")
    raise RuntimeError('; '.join(errs))


def vtuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', str(v))[:3])


def check_update():
    try:
        j = json.loads(http_get(f'https://api.github.com/repos/{REPO}/releases/latest'))
        UPD.update(latest=str(j.get('tag_name', '')).lstrip('v'), notes=str(j.get('body') or '')[:3000], error='')
    except Exception as ex:
        UPD['error'] = str(ex)
    UPD['checked'] = time.time()


def update_loop():
    time.sleep(20)
    while True:
        check_update()
        time.sleep(6 * 3600)


def update_info():
    latest = UPD['latest']
    return {'version': VERSION, 'latest': latest, 'notes': UPD['notes'], 'error': UPD['error'], 'repo': REPO,
            'available': bool(latest) and vtuple(latest) > vtuple(VERSION),
            'running': unit_active(UPD['unit']), 'log': tail_file(UPDATE_LOG, 6000)}


def start_update():
    if unit_active(UPD['unit']):
        raise RuntimeError('обновление уже идёт')
    check_update()
    if UPD['error']:
        raise RuntimeError('GitHub недоступен: ' + UPD['error'])
    if not (UPD['latest'] and vtuple(UPD['latest']) > vtuple(VERSION)):
        raise RuntimeError('установлена последняя версия')
    tag = 'v' + UPD['latest']
    script = http_get(f'https://github.com/{REPO}/releases/download/{tag}/install.sh')
    if not script.startswith(b'#!'):
        raise RuntimeError('в релизе нет install.sh')
    fd = os.open(UPDATE_SCRIPT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, 'wb') as f:
        f.write(script)
    with open(UPDATE_LOG, 'w', encoding='utf-8') as f:
        f.write(f"=== {datetime.now().isoformat(timespec='seconds')}: обновление {VERSION} → {tag} ===\n")
    unit = f'tgam-update-{int(time.time())}'
    # отдельный юнит: установщик перезапускает панель и не должен умереть вместе с ней
    r = run(['systemd-run', f'--unit={unit}', '--collect',
             '-p', f'StandardOutput=append:{UPDATE_LOG}', '-p', f'StandardError=append:{UPDATE_LOG}',
             f'--setenv=TGAM_VERSION={tag}', '--setenv=TGAM_UPDATE=1', f'--setenv=TGAM_REPO={REPO}',
             '/bin/bash', UPDATE_SCRIPT])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or 'systemd-run failed')
    UPD['unit'] = unit
    log_event('update', f'запущено обновление до {tag}')


# ---------- API панели ----------

def mask(tok):
    return f'…{tok[-4:]}' if tok else ''


def state():
    cfg = load_config()
    return {
        'ok': True,
        'domain': cfg['domain'],
        'tls_mode': cfg['tls_mode'],
        'public_ip': cfg['public_ip'],
        'host': public_host(cfg),
        'hook_url': f"https://{public_host(cfg)}:{cfg['hook_port']}{HOOK_PATH}",
        'bot_token': mask(cfg['bot_token']),
        'chat_id': cfg['chat_id'],
        'default_thread': cfg['default_thread'],
        'webhook_secret': cfg['webhook_secret'],
        'routes': cfg['routes'],
        'hide_labels': cfg['hide_labels'],
        'tz_offset': cfg['tz_offset'],
        'fmt_firing': cfg['fmt_firing'],
        'fmt_resolved': cfg['fmt_resolved'],
        'label_titles': cfg['label_titles'],
        'link_titles': cfg['link_titles'],
        'vless': cfg['vless'],
        'le_email': cfg['le_email'],
        'backup_chat_id': cfg['backup_chat_id'],
        'backup_hours': cfg['backup_hours'],
        'backup_last': cfg['backup_last'],
        'panel_user': cfg['panel_user'],
        'xray': run(['systemctl', 'is-active', XRAY_UNIT]).stdout.strip(),
        'cert': cert_info(),
        'queue': SEND_Q.qsize(),
        'events': list(EVENTS)[::-1][:150],
        'threads': find_threads()['rows'],
        'update': update_info(),
    }


def check_telegram():
    me = tg('getMe')
    if not me.get('ok'):
        raise RuntimeError(me.get('description', 'getMe failed'))
    res = {'ok': True, 'bot': '@' + me['result'].get('username', '')}
    cfg = load_config()
    if cfg['chat_id']:
        c = tg('getChat', {'chat_id': cfg['chat_id']})
        if c.get('ok'):
            res['chat'] = c['result'].get('title', '')
            res['forum'] = bool(c['result'].get('is_forum'))
        else:
            res['chat_error'] = c.get('description', '')
    return res


SEEN = {}  # (chat_id, thread_id) -> последнее сообщение боту, для поиска id в панели
TOPICS = {}  # (chat_id, thread_id) -> название темы


def remember(chat, tid, text):
    SEEN[(chat['id'], tid)] = {'chat_id': chat['id'], 'type': chat.get('type'), 'thread_id': tid, 'text': text[:80],
                               'chat': chat.get('title') or chat.get('username') or chat.get('first_name') or '',
                               'at': time.time()}


def threads_snapshot():
    return {(k, v['chat'], TOPICS.get(k, '')) for k, v in SEEN.items()}


def save_threads():
    rows = [{'chat_id': k[0], 'thread_id': k[1], 'chat': v['chat'], 'type': v.get('type'), 'topic': TOPICS.get(k, '')}
            for k, v in SEEN.items()]
    update_config(known_threads=rows)


def load_threads():
    """Треды, которые бот видел раньше, — из конфига, чтобы список переживал перезапуск."""
    for r in load_config().get('known_threads') or []:
        k = (r['chat_id'], r['thread_id'])
        SEEN[k] = {'chat_id': r['chat_id'], 'type': r.get('type'), 'thread_id': r['thread_id'], 'text': '',
                   'chat': r.get('chat', ''), 'at': 0}
        if r.get('topic'):
            TOPICS[k] = r['topic']


def answer_id(m, tid, bot):
    words = (m.get('text') or '').split()
    chat = m['chat']
    cmds = ('/id', f'/id@{bot}'.lower()) + (('/start',) if chat.get('type') == 'private' else ())
    if not words or words[0].lower() not in cmds:
        return
    lines = [f"chat_id: <code>{chat['id']}</code>"]
    if chat.get('type') == 'private':
        lines.append('Этот id можно указать получателем бэкапов в панели.')
    else:
        lines.append(f"thread_id: <code>{tid}</code>" if tid else 'thread_id: <code>0</code> (General)')
    if TOPICS.get((chat['id'], tid)):
        lines.append(f"Тема: {e(TOPICS[(chat['id'], tid)])}")
    payload = {'chat_id': chat['id'], 'text': '\n'.join(lines), 'parse_mode': 'HTML',
               'reply_parameters': {'message_id': m['message_id'], 'allow_sending_without_reply': True}}
    if tid:
        payload['message_thread_id'] = tid
    r = tg('sendMessage', payload)
    if not r.get('ok'):
        raise RuntimeError(r.get('description'))


def updates_loop():
    """Единственный потребитель getUpdates: запоминает чаты/темы и отвечает на /id."""
    offset, bot = None, ''
    while True:
        try:
            if not load_config()['bot_token']:
                time.sleep(10)
                continue
            if not bot:
                bot = tg('getMe').get('result', {}).get('username', '')
            p = {'timeout': 25, 'allowed_updates': ['message', 'my_chat_member']}
            if offset:
                p['offset'] = offset
            r = tg('getUpdates', p, timeout=40)
            if not r.get('ok'):
                raise RuntimeError(r.get('description'))
            before = threads_snapshot()
            for u in r['result']:
                offset = u['update_id'] + 1
                if u.get('my_chat_member'):
                    mc = u['my_chat_member']
                    status = mc['new_chat_member']['status']
                    remember(mc['chat'], None, f'статус бота: {status}')
                    log_event('bot', f"бот в «{mc['chat'].get('title', mc['chat']['id'])}»: {status}")
                    continue
                m = u.get('message')
                if not m:
                    continue
                tid = m.get('message_thread_id') if m.get('is_topic_message') else None
                for src in (m, m.get('reply_to_message') or {}):
                    for k in ('forum_topic_created', 'forum_topic_edited'):
                        if (src.get(k) or {}).get('name'):
                            TOPICS[(m['chat']['id'], tid)] = src[k]['name']
                remember(m['chat'], tid, m.get('text') or m.get('caption') or '')
                try:
                    answer_id(m, tid, bot)
                except Exception as ex:
                    log_event('bot', f'ответ на /id: {ex}', False)
            if threads_snapshot() != before:
                save_threads()
        except Exception as ex:
            print(f'[updates] {ex}', flush=True)
            bot = ''
            time.sleep(5)


def find_threads():
    rows = sorted(SEEN.values(), key=lambda r: -r['at'])
    return {'ok': True, 'rows': [dict(r, topic=TOPICS.get((r['chat_id'], r['thread_id']), '')) for r in rows]}


def api_settings(b):
    cfg = load_config()
    if b.get('bot_token', '').strip():
        cfg['bot_token'] = b['bot_token'].strip()
    for k in ('chat_id', 'default_thread', 'webhook_secret', 'le_email', 'domain', 'public_ip', 'tls_mode',
              'backup_chat_id', 'fmt_firing', 'fmt_resolved', 'label_titles', 'link_titles'):
        if k in b:
            cfg[k] = str(b[k]).strip()
    if cfg['default_thread'] and not cfg['default_thread'].isdigit():
        raise ValueError('тред по умолчанию — число')
    if cfg['backup_chat_id'] and not re.fullmatch(r'-?\d+', cfg['backup_chat_id']):
        raise ValueError('получатель бэкапа — числовой id пользователя (бот пришлёт его в ответ на /start)')
    cfg['domain'] = re.sub(r'^https?://|[:/].*$', '', cfg['domain']).lower()
    if cfg['domain'] and not re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+', cfg['domain']):
        raise ValueError('домен — имя вида alerts.example.com, без https:// и порта')
    if cfg['public_ip'] and not is_ip(cfg['public_ip']):
        raise ValueError('IP сервера указан неверно')
    if cfg['tls_mode'] not in ('ip', 'domain', 'self'):
        raise ValueError('сертификат: ip, domain или self')
    if cfg['tls_mode'] == 'domain' and not cfg['domain']:
        raise ValueError('для сертификата на домен укажите домен')
    if 'tz_offset' in b:
        cfg['tz_offset'] = float(b['tz_offset'] or 0)
    if 'backup_hours' in b:
        cfg['backup_hours'] = max(0.0, float(b['backup_hours'] or 0))
    if 'hide_labels' in b:
        hl = b['hide_labels']
        cfg['hide_labels'] = [x.strip() for x in (hl.split(',') if isinstance(hl, str) else hl) if x.strip()]
    save_config(cfg)
    log_event('panel', 'сохранены настройки')


def api_routes(b):
    routes = []  # порядок списка = приоритет: сверху вниз
    for raw in b.get('routes') or []:
        conds = []
        for c in raw.get('conditions') or []:
            label = str(c.get('label', '')).strip()
            values = [str(v).strip() for v in c.get('values') or [] if str(v).strip()]
            if label:
                conds.append({'label': label, 'values': values})
        thread_id = ', '.join(t.strip() for t in str(raw.get('thread_id', '')).split(',') if t.strip())
        if thread_id and not re.fullmatch(r'\d+(, \d+)*', thread_id):
            raise ValueError(f"thread_id «{thread_id}» — числа через запятую")
        routes.append({'thread_id': thread_id, 'general': bool(raw.get('general')), 'conditions': conds})
    update_config(routes=routes)
    log_event('panel', f'сохранены маршруты ({len(routes)})')


def api_vless(b):
    v = b.get('vless', '')
    write_xray(v)
    update_config(vless=v)
    log_event('xray', 'применён VLESS' if v.strip() else 'VLESS очищен, трафик напрямую')
    time.sleep(1.5)
    try:
        return check_telegram()
    except Exception as ex:
        return {'ok': True, 'warning': str(ex)}


def api_test(b):
    tid = str(b.get('thread_id', '')).strip()
    ok, msg = deliver(tid, f'🧪 Тест TG Alerts Manager → тред <b>{e(tid or "General")}</b>', 'тест')
    if not ok:
        raise RuntimeError(msg)


def api_cert(b):
    start_cert(bool(b.get('force')))


def check_login(user, pw):
    if not re.fullmatch(r'[A-Za-z0-9._@-]{1,32}', user):
        raise ValueError('логин — латиница, цифры и . _ @ -, до 32 символов')
    if len(pw) < 8:
        raise ValueError('пароль — минимум 8 символов')


def api_password(b):
    cfg = load_config()
    user, pw = str(b.get('user') or cfg['panel_user']).strip(), str(b.get('password', ''))
    check_login(user, pw)
    # подпись сессий включает логин и хеш пароля — все сессии сбрасываются
    update_config(panel_user=user, panel_pass_hash=hash_pw(pw))


def api_backup_send(b):
    send_backup('вручную')


def api_restore(b):
    old = load_config()
    cfg = apply_restore(b.get('data'))
    moved = (cfg['panel_port'], cfg['hook_port']) != (old['panel_port'], old['hook_port'])
    # новые порты, токен и сертификат подхватываются при запуске — перезапуск через systemd (Restart=always)
    threading.Timer(1.5, lambda: os._exit(0)).start()
    return {'ok': True, 'panel_port': cfg['panel_port'], 'moved': moved}


def api_update(b):
    start_update()


def api_update_check(b):
    check_update()
    return {'ok': True, 'update': update_info()}


POST_ROUTES = {
    '/api/settings': api_settings, '/api/routes': api_routes, '/api/vless': api_vless, '/api/test': api_test,
    '/api/cert': api_cert, '/api/password': api_password, '/api/backup': api_backup_send, '/api/restore': api_restore,
    '/api/update': api_update, '/api/update/check': api_update_check,
}


# Сессия — подписанная кука «срок.подпись»; переживает перезапуск, сбрасывается сменой пароля.
def sign_session(cfg, exp):
    if not cfg.get('session_key'):
        cfg = update_config(session_key=secrets.token_hex(32))
    msg = f"{exp}:{cfg['panel_user']}:{cfg['panel_pass_hash']}".encode()
    return hmac.new(cfg['session_key'].encode(), msg, hashlib.sha256).hexdigest()


def make_session():
    exp = int(time.time()) + SESSION_TTL
    return f'{exp}.{sign_session(load_config(), exp)}'


def valid_session(cookie_header):
    c = http.cookies.SimpleCookie()
    try:
        c.load(cookie_header or '')
    except http.cookies.CookieError:
        return False
    if SESSION_COOKIE not in c:
        return False
    exp, _, sig = c[SESSION_COOKIE].value.partition('.')
    if not exp.isdigit() or int(exp) < time.time():
        return False
    return hmac.compare_digest(sig, sign_session(load_config(), int(exp)))


def login_blocked(ip):
    now = time.time()
    _FAILS[ip] = [t for t in _FAILS.get(ip, []) if now - t < 600]
    return len(_FAILS[ip]) >= 10


# ---------- HTTP ----------

class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(300)  # браузер держит запасные keep-alive соединения; рано закрытое ломает POST
        try:
            return CERTS.get().wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
        except Exception as ex:
            sock.close()
            raise OSError(str(ex))

    def handle_error(self, request, client_address):
        # в журнал панели не пишем (сканеры), только в journald для диагностики
        ex = sys.exc_info()[1]
        if not isinstance(ex, (TimeoutError, ConnectionResetError, BrokenPipeError)):
            print(f'[conn] {client_address[0]}: {type(ex).__name__}: {ex}', flush=True)


class BaseHandler(BaseHTTPRequestHandler):
    server_version = 'tgam'
    sys_version = ''
    protocol_version = 'HTTP/1.1'  # keep-alive; каждый ответ идёт с Content-Length

    def parse_request(self):
        self.body_read = False  # один обработчик живёт на всё keep-alive соединение
        return super().parse_request()

    def log_message(self, *a):
        pass

    def send_json(self, code, obj, extra=None):
        self.send_body(code, json.dumps(obj, ensure_ascii=False).encode(), 'application/json; charset=utf-8', extra)

    def send_body(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        if self.command == 'POST' and not getattr(self, 'body_read', False):
            # непрочитанное тело иначе станет началом следующего запроса в keep-alive
            self.send_header('Connection', 'close')
            self.close_connection = True
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, limit):
        n = int(self.headers.get('Content-Length') or 0)
        if n > limit:
            raise ValueError('слишком большое тело запроса')
        data = self.rfile.read(n)
        self.body_read = True
        return json.loads(data or b'{}')


class HookHandler(BaseHandler):
    def authorized(self):
        sec = load_config().get('webhook_secret', '')
        if not sec:
            return True
        h = self.headers.get('Authorization', '')
        cands = []
        if h.startswith('Bearer '):
            cands.append(h[7:].strip())
        elif h.startswith('Basic '):
            try:
                cands.append(base64.b64decode(h[6:]).decode().partition(':')[2])
            except Exception:
                pass
        cands.append(urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('token', [''])[0])
        return any(hmac.compare_digest(c.encode(), sec.encode()) for c in cands if c)

    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path == '/health':
            return self.send_json(200, {'ok': True, 'version': VERSION})
        self.send_json(404, {'ok': False})

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != HOOK_PATH:
            return self.send_json(404, {'ok': False})
        if not self.authorized():
            log_event('hook', f'отказ: неверный секрет от {self.client_address[0]}', False)
            return self.send_json(401, {'ok': False, 'error': 'unauthorized'})
        try:
            payload = self.read_json(5_000_000)
        except Exception as ex:
            log_event('hook', f'битый запрос от {self.client_address[0]}: {ex}', False)
            return self.send_json(400, {'ok': False, 'error': str(ex)})
        n = handle_payload(payload)
        self.send_json(200, {'ok': True, 'alerts': n})


def web_file(name):
    with open(os.path.join(WEB_DIR, name), 'rb') as f:
        return f.read()


class PanelHandler(BaseHandler):
    def authed(self):
        return valid_session(self.headers.get('Cookie', ''))

    def do_GET(self):
        p = urllib.parse.urlsplit(self.path).path
        if p == '/':
            page = 'panel.html' if self.authed() else 'login.html'
            return self.send_body(200, web_file(page), 'text/html; charset=utf-8')
        if p == '/favicon.svg':
            return self.send_body(200, web_file('favicon.svg'), 'image/svg+xml')
        if not self.authed():
            return self.send_json(401, {'ok': False, 'error': 'нужен вход'})
        try:
            if p == '/api/state':
                return self.send_json(200, state())
            if p == '/api/check':
                return self.send_json(200, check_telegram())
            if p == '/api/updates':
                return self.send_json(200, find_threads())
            self.send_json(404, {'ok': False, 'error': 'not found'})
        except Exception as ex:
            self.send_json(500, {'ok': False, 'error': str(ex)})

    def do_POST(self):
        if self.headers.get('X-Requested-With') != 'tgam':
            return self.send_json(403, {'ok': False, 'error': 'csrf'})
        p = urllib.parse.urlsplit(self.path).path
        if p == '/api/login':
            return self.login()
        if p == '/api/logout':
            return self.send_json(200, {'ok': True}, {'Set-Cookie': f'{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'})
        if not self.authed():
            return self.send_json(401, {'ok': False, 'error': 'нужен вход'})
        fn = POST_ROUTES.get(p)
        if not fn:
            return self.send_json(404, {'ok': False, 'error': 'not found'})
        try:
            self.send_json(200, fn(self.read_json(2_000_000)) or {'ok': True})
        except Exception as ex:
            self.send_json(400, {'ok': False, 'error': str(ex)})

    def login(self):
        ip = self.client_address[0]
        if login_blocked(ip):
            return self.send_json(429, {'ok': False, 'error': 'слишком много попыток, подождите 10 минут'})
        try:
            b = self.read_json(10_000)
        except Exception:
            b = {}
        cfg = load_config()
        user, pw = str(b.get('user', '')), str(b.get('password', ''))
        if hmac.compare_digest(user.encode(), cfg['panel_user'].encode()) and verify_pw(pw, cfg['panel_pass_hash']):
            _FAILS.pop(ip, None)
            log_event('panel', f'вход с {ip}')
            cookie = f'{SESSION_COOKIE}={make_session()}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; Secure; SameSite=Strict'
            return self.send_json(200, {'ok': True}, {'Set-Cookie': cookie})
        _FAILS.setdefault(ip, []).append(time.time())
        log_event('panel', f'неудачный вход с {ip}', False)
        time.sleep(1)
        self.send_json(401, {'ok': False, 'error': 'неверный логин или пароль'})


# ---------- запуск ----------

def serve():
    cfg = load_config()
    ensure_self_cert(public_host(cfg))
    load_threads()
    for target in (sender_loop, updates_loop, backup_loop, update_loop):
        threading.Thread(target=target, daemon=True).start()
    hook = TLSServer(('0.0.0.0', int(cfg['hook_port'])), HookHandler)
    panel = TLSServer(('0.0.0.0', int(cfg['panel_port'])), PanelHandler)
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    log_event('start', f"TG Alerts Manager {VERSION}: панель :{cfg['panel_port']}, вебхук :{cfg['hook_port']}{HOOK_PATH}")
    panel.serve_forever()


def cmd_init():
    cfg = load_config()
    env = os.environ
    for key, name in (('bot_token', 'BOT_TOKEN'), ('chat_id', 'CHAT_ID'), ('vless', 'VLESS'),
                      ('le_email', 'LE_EMAIL'), ('domain', 'DOMAIN')):
        if env.get(name):
            cfg[key] = env[name].strip()
    if env.get('PUBLIC_HOST') and not cfg['public_ip']:
        cfg['public_ip'] = env['PUBLIC_HOST'].strip()
    if env.get('TGAM_TLS'):
        if env['TGAM_TLS'] not in ('ip', 'domain', 'self'):
            sys.exit('TGAM_TLS: ip, domain или self')
        cfg['tls_mode'] = env['TGAM_TLS']
    elif env.get('DOMAIN'):
        cfg['tls_mode'] = 'domain'
    for key, name in (('panel_port', 'PANEL_PORT'), ('hook_port', 'HOOK_PORT')):
        if env.get(name):
            cfg[key] = int(env[name])
    pw = None
    if env.get('PANEL_PASS'):  # логин и пароль, заданные при установке
        user = (env.get('PANEL_USER') or cfg['panel_user']).strip()
        try:
            check_login(user, env['PANEL_PASS'])
        except ValueError as ex:
            sys.exit(str(ex))
        cfg['panel_user'], cfg['panel_pass_hash'] = user, hash_pw(env['PANEL_PASS'])
    elif not cfg['panel_pass_hash'] or env.get('RESET_PASSWORD') == '1':
        if env.get('PANEL_USER'):
            cfg['panel_user'] = env['PANEL_USER'].strip()
        pw = secrets.token_urlsafe(12)
        cfg['panel_pass_hash'] = hash_pw(pw)
    if not cfg['session_key']:
        cfg['session_key'] = secrets.token_hex(32)
    save_config(cfg)
    print(f"PANEL_URL=https://{public_host(cfg)}:{cfg['panel_port']}")
    print(f"HOOK_URL=https://{public_host(cfg)}:{cfg['hook_port']}{HOOK_PATH}")
    print(f"PANEL_USER={cfg['panel_user']}")
    if pw:
        print(f'PANEL_PASSWORD={pw}')


def cmd_xray_config():
    cfg = load_config()
    try:
        write_xray(cfg['vless'], restart=False)
    except Exception as ex:
        print(f'VLESS не применён ({ex}), xray пойдёт напрямую', file=sys.stderr)
        write_xray('', restart=False)


def cmd_restore():
    if len(sys.argv) < 3:
        sys.exit('использование: app.py restore <файл бэкапа>')
    with open(sys.argv[2], encoding='utf-8') as f:
        apply_restore(json.load(f))
    run(['systemctl', 'restart', 'tgam'])
    print('Конфиг восстановлен, панель перезапущена')


def cmd_cert_issue():
    try:
        issue_cert(force='--force' in sys.argv, if_needed='--if-needed' in sys.argv)
    except (ValueError, RuntimeError) as ex:
        sys.exit(f'!! {ex}')


def cmd_url():
    cfg = load_config()
    print(f"Панель: https://{public_host(cfg)}:{cfg['panel_port']}  (логин {cfg['panel_user']})")
    print(f"Вебхук: https://{public_host(cfg)}:{cfg['hook_port']}{HOOK_PATH}")


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'serve'
    cmds = {'serve': serve, 'init': cmd_init, 'xray-config': cmd_xray_config, 'restore': cmd_restore, 'url': cmd_url,
            'version': lambda: print(VERSION), 'cert-issue': cmd_cert_issue}
    if cmd not in cmds:
        sys.exit(f"неизвестная команда {cmd}; есть: {', '.join(cmds)}")
    cmds[cmd]()
