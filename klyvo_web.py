#!/usr/bin/env python3
"""Локальный веб-дашборд Klyvo.

Показывает в браузере перехваченные опасные команды и активность агента из
`.klyvo/*.jsonl`. Работает полностью локально: слушает только 127.0.0.1, наружу
ничего не отправляет, без внешних зависимостей (стандартная библиотека Python).

  python3 klyvo_web.py                 # проект = текущая папка, порт 8765
  python3 klyvo_web.py --project ~/app --port 9000

Опциональный вход (для хостинга дашборда за реверс-прокси). Без него — режим
без авторизации, как удобно тестерам локально:

  python3 klyvo_web.py --set-password admin   # задать пароль (спросит скрытно)
  KLYVO_WEB_AUTH=~/.klyvo-web/auth.json KLYVO_WEB_BASE=/dashboard python3 klyvo_web.py
"""
import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs


# ── Сбор данных ──────────────────────────────────────────────────────────────
def _read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def collect(project_root):
    """Собрать данные дашборда из журналов проекта. Чистая функция — тестируется."""
    kdir = os.path.join(project_root, ".klyvo")
    blocks = _read_jsonl(os.path.join(kdir, "journal.jsonl"))
    session = _read_jsonl(os.path.join(kdir, "session_log.jsonl"))

    rule_counter = Counter()
    critical = warning = 0
    for b in blocks:
        for name in b.get("rules_matched", []):
            rule_counter[name] += 1
        sevs = b.get("severities", [])
        if "critical" in sevs:
            critical += 1
        elif sevs:
            warning += 1

    return {
        "project": project_root,
        "stats": {
            "blocks_total": len(blocks),
            "critical": critical,
            "warning": warning,
            "rules_distinct": len(rule_counter),
            "session_actions": len(session),
        },
        "top_rules": rule_counter.most_common(5),
        "blocks": list(reversed(blocks))[:100],   # свежие сверху
        "session": list(reversed(session))[:100],
    }


# ── Авторизация (опциональная, на стандартной библиотеке) ────────────────────
SESSION_COOKIE = "klyvo_sess"
SESSION_TTL = 30 * 24 * 3600   # 30 дней
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


def _auth_path():
    return os.environ.get("KLYVO_WEB_AUTH") or os.path.expanduser("~/.klyvo-web/auth.json")


def load_auth():
    """Прочитать файл авторизации. Нет файла → None (режим без входа)."""
    path = _auth_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def set_password(user, password):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    data = {"user": user, "salt": salt.hex(), "hash": dk.hex(), "secret": secrets.token_hex(32)}
    path = _auth_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(path, 0o600)
    return path


def verify_password(auth, password):
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(auth["salt"]), **_SCRYPT)
    return hmac.compare_digest(dk.hex(), auth["hash"])


def make_session(auth):
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(bytes.fromhex(auth["secret"]), exp.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def valid_session(auth, token):
    if not token or "." not in token:
        return False
    exp, sig = token.rsplit(".", 1)
    good = hmac.new(bytes.fromhex(auth["secret"]), exp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good):
        return False
    try:
        return int(exp) > time.time()
    except ValueError:
        return False


# ── Страницы ─────────────────────────────────────────────────────────────────
_CSS = """
:root{color-scheme:dark;--ink:#0d1017;--panel:#141a22;--line:#222c38;--fg:#e9edf3;
 --muted:#8b95a6;--faint:#5c6675;--guard:#f5b544;--danger:#ff5b52;--safe:#57cc9a;
 --mono:"SF Mono","JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
 --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--ink);color:var(--fg);font-family:var(--sans)}
"""

LOGIN_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Вход — Klyvo</title>
<style>{css}
.wrap{{min-height:100vh;display:grid;place-items:center;padding:24px;
 background-image:radial-gradient(50rem 30rem at 70% -10%,rgba(245,181,68,.07),transparent 60%)}}
.box{{width:100%;max-width:340px;background:var(--panel);border:1px solid var(--line);
 border-radius:14px;padding:28px}}
.brand{{font-family:var(--mono);font-weight:700;font-size:20px;display:flex;align-items:center;gap:9px;margin-bottom:6px}}
.led{{width:9px;height:9px;border-radius:50%;background:var(--safe);box-shadow:0 0 10px var(--safe)}}
.hint{{color:var(--muted);font-size:14px;margin:0 0 20px}}
label{{font-family:var(--mono);font-size:12px;color:var(--muted);display:block;margin-bottom:7px}}
input{{width:100%;background:var(--ink);border:1px solid var(--line);border-radius:9px;
 color:var(--fg);font-family:var(--mono);font-size:15px;padding:11px 13px;margin-bottom:16px}}
input:focus{{outline:none;border-color:var(--guard)}}
button{{width:100%;background:var(--guard);color:#1a1205;border:none;border-radius:9px;
 font-family:var(--mono);font-weight:600;font-size:15px;padding:11px;cursor:pointer}}
button:hover{{background:#ffca6a}}
.err{{color:var(--danger);font-family:var(--mono);font-size:13px;margin:0 0 16px;
 min-height:1em}}
a.back{{display:block;text-align:center;color:var(--faint);font-size:13px;margin-top:16px;text-decoration:none}}
a.back:hover{{color:var(--muted)}}
</style></head><body><div class="wrap"><form class="box" method="post">
<div class="brand"><span class="led"></span>klyvo</div>
<p class="hint">Вход в дашборд</p>
<div class="err">{error}</div>
<label for="p">Пароль</label>
<input id="p" type="password" name="password" autofocus autocomplete="current-password">
<button type="submit">Войти</button>
<a class="back" href="/">← на главную</a>
</form></div></body></html>"""


PAGE = """<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Klyvo — дашборд</title>
<style>
:root { color-scheme: dark; --bg:#0d1017; --card:#141a22; --fg:#e9edf3; --mut:#8b95a6;
  --line:#222c38; --crit:#ff5b52; --warn:#f5b544; }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
.wrap { max-width:960px; margin:0 auto; padding:24px 16px 60px; }
header { display:flex; align-items:baseline; gap:12px; margin-bottom:4px; }
h1 { font-size:22px; margin:0; font-family:ui-monospace,Menlo,monospace; }
.proj { color:var(--mut); font-size:13px; word-break:break-all; }
.top { display:flex; align-items:center; gap:14px; margin:6px 0 8px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; margin:20px 0; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.card .n { font-size:26px; font-weight:600; } .card .l { color:var(--mut); font-size:13px; }
.card.crit .n { color:var(--crit); } .card.warn .n { color:var(--warn); }
h2 { font-size:15px; text-transform:uppercase; letter-spacing:.04em; color:var(--mut); margin:28px 0 10px; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
  border-radius:10px; overflow:hidden; font-size:13px; }
th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--mut); font-weight:500; } tr:last-child td { border-bottom:none; }
code { font-family:ui-monospace,Menlo,Consolas,monospace; word-break:break-all; }
.badge { display:inline-block; padding:1px 8px; border-radius:20px; font-size:12px; font-weight:600; }
.deny { background:rgba(255,91,82,.15); color:var(--crit); } .ask { background:rgba(245,181,68,.15); color:var(--warn); }
.empty { color:var(--mut); background:var(--card); border:1px dashed var(--line); border-radius:10px;
  padding:20px; text-align:center; } .rules { color:var(--mut); }
button { background:var(--card); color:var(--fg); border:1px solid var(--line); border-radius:8px;
  padding:6px 12px; cursor:pointer; font-size:13px; } button:hover { border-color:var(--warn); }
.foot { color:var(--mut); font-size:12px; margin-top:30px; }
.foot a { color:var(--mut); }
</style></head>
<body><div class="wrap">
<header><h1>klyvo</h1><span class="proj" id="proj"></span></header>
<div class="top"><button onclick="load()">Обновить</button><a href="logout" style="color:var(--mut);font-size:13px">Выйти</a></div>
<div class="cards" id="cards"></div>
<h2>Топ правил</h2><div id="top"></div>
<h2>Перехваченные команды</h2><div id="blocks"></div>
<h2>Активность сессии</h2><div id="session"></div>
<p class="foot">Данные читаются локально из <code>.klyvo/</code>. Ничего не отправляется наружу.</p>
</div>
<script>
const esc = s => (s??'').toString().replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load() {
  const d = await (await fetch('api/data')).json();  // относительный путь — работает и под префиксом
  document.getElementById('proj').textContent = d.project;
  const s = d.stats;
  document.getElementById('cards').innerHTML = [
    ['Перехвачено', s.blocks_total, ''], ['Критичных', s.critical, 'crit'],
    ['Предупреждений', s.warning, 'warn'], ['Правил сработало', s.rules_distinct, ''],
    ['Действий агента', s.session_actions, '']
  ].map(([l,n,c]) => `<div class="card ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

  document.getElementById('top').innerHTML = d.top_rules.length
    ? '<table><tr><th>Правило</th><th>Срабатываний</th></tr>' +
      d.top_rules.map(([r,c]) => `<tr><td><code>${esc(r)}</code></td><td>${c}</td></tr>`).join('') + '</table>'
    : '<div class="empty">Пока ничего не перехвачено.</div>';

  document.getElementById('blocks').innerHTML = d.blocks.length
    ? '<table><tr><th>Время</th><th>Решение</th><th>Команда</th><th>Правила</th></tr>' +
      d.blocks.map(b => `<tr><td>${esc((b.ts||'').slice(0,19).replace('T',' '))}</td>
        <td><span class="badge ${b.decision==='deny'?'deny':'ask'}">${esc(b.decision)}</span></td>
        <td><code>${esc(b.command)}</code></td>
        <td class="rules">${esc((b.rules_matched||[]).join(', '))}</td></tr>`).join('') + '</table>'
    : '<div class="empty">Опасных команд не перехвачено.</div>';

  document.getElementById('session').innerHTML = d.session.length
    ? '<table><tr><th>Время</th><th>Тип</th><th>Детали</th></tr>' +
      d.session.map(e => `<tr><td>${esc((e.ts||'').slice(0,19).replace('T',' '))}</td>
        <td>${esc(e.kind||e.tool)}</td><td><code>${esc(e.detail)}</code></td></tr>`).join('') + '</table>'
    : '<div class="empty">Журнал сессии пуст.</div>';
}
load();
</script></body></html>"""


# ── HTTP ─────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    project_root = "."
    auth = None          # dict или None (None → без входа)
    base = ""            # публичный префикс за прокси, напр. "/dashboard"

    # -- helpers --
    def _send(self, body, ctype, status=200, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _cookie(self, token, max_age):
        return "; ".join([
            f"{SESSION_COOKIE}={token}", f"Path={self.base or '/'}",
            f"Max-Age={max_age}", "HttpOnly", "SameSite=Lax", "Secure",
        ])

    def _session_token(self):
        raw = self.headers.get("Cookie", "")
        try:
            ck = SimpleCookie(raw)
        except Exception:
            return ""
        return ck[SESSION_COOKIE].value if SESSION_COOKIE in ck else ""

    def _authed(self):
        return self.auth is None or valid_session(self.auth, self._session_token())

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    # -- routes --
    def do_GET(self):
        path = self._path()

        if self.auth is not None:
            if path == "/login":
                self._send(LOGIN_PAGE.format(css=_CSS, error=""), "text/html; charset=utf-8")
                return
            if path == "/logout":
                self._redirect((self.base or "") + "/login", cookie=self._cookie("", 0))
                return
            if not self._authed():
                self._redirect((self.base or "") + "/login")
                return

        if path == "/api/data":
            self._send(json.dumps(collect(self.project_root), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif path == "/" or path.startswith("/index"):
            self._send(PAGE, "text/html; charset=utf-8")
        else:
            self._send("404", "text/plain; charset=utf-8", status=404)

    def do_POST(self):
        path = self._path()
        if self.auth is not None and path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            password = (parse_qs(body).get("password") or [""])[0]
            if password and verify_password(self.auth, password):
                self._redirect((self.base or "") + "/",
                               cookie=self._cookie(make_session(self.auth), SESSION_TTL))
            else:
                time.sleep(0.6)  # притормозить перебор
                self._send(LOGIN_PAGE.format(css=_CSS, error="Неверный пароль"),
                           "text/html; charset=utf-8", status=401)
            return
        self._send("404", "text/plain; charset=utf-8", status=404)

    def log_message(self, *args):
        pass  # тихо


def main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный веб-дашборд Klyvo")
    parser.add_argument("--project", default=os.getcwd(), help="корень проекта (где .klyvo/)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--set-password", metavar="USER",
                        help="задать пароль входа и выйти (пароль спросит скрытно)")
    args = parser.parse_args(argv)

    if args.set_password:
        pw = getpass.getpass("Новый пароль: ")
        if not pw or pw != getpass.getpass("Повтори пароль: "):
            print("Пароли пустые или не совпали.")
            return 1
        path = set_password(args.set_password, pw)
        print(f"Пароль задан, файл: {path}")
        return 0

    Handler.project_root = os.path.abspath(args.project)
    Handler.auth = load_auth()
    Handler.base = os.environ.get("KLYVO_WEB_BASE", "").rstrip("/")

    server = HTTPServer(("127.0.0.1", args.port), Handler)  # только локально
    mode = "вход включён" if Handler.auth else "без входа"
    print(f"Klyvo дашборд: http://127.0.0.1:{args.port}  (проект: {Handler.project_root}, {mode})")
    print("Ctrl+C — остановить.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


if __name__ == "__main__":
    sys.exit(main())
