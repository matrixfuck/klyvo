#!/usr/bin/env python3
"""Локальный веб-дашборд Klyvo.

Показывает в браузере перехваченные опасные команды и активность агента из
`.klyvo/*.jsonl`. Работает полностью локально: слушает только 127.0.0.1, наружу
ничего не отправляет, без внешних зависимостей (стандартная библиотека Python).

  python3 klyvo_web.py                 # проект = текущая папка, порт 8765
  python3 klyvo_web.py --project ~/app --port 9000
"""
import argparse
import json
import os
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer


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


PAGE = """<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Klyvo — дашборд</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1a1a1a; --mut:#666;
  --line:#e5e7eb; --crit:#c0362c; --warn:#b7791f; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1115; --card:#181b21; --fg:#e8e8ea;
  --mut:#9aa0a6; --line:#2a2e37; --crit:#ff6b5e; --warn:#f0b429; } }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; }
.wrap { max-width:960px; margin:0 auto; padding:24px 16px 60px; }
header { display:flex; align-items:baseline; gap:12px; margin-bottom:4px; }
h1 { font-size:22px; margin:0; } .proj { color:var(--mut); font-size:13px; word-break:break-all; }
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
.deny { background:rgba(192,54,44,.15); color:var(--crit); } .ask { background:rgba(183,121,31,.15); color:var(--warn); }
.empty { color:var(--mut); background:var(--card); border:1px dashed var(--line); border-radius:10px;
  padding:20px; text-align:center; } .rules { color:var(--mut); }
button { background:var(--card); color:var(--fg); border:1px solid var(--line); border-radius:8px;
  padding:6px 12px; cursor:pointer; font-size:13px; } .foot { color:var(--mut); font-size:12px; margin-top:30px; }
</style></head>
<body><div class="wrap">
<header><h1>Klyvo</h1><span class="proj" id="proj"></span></header>
<div style="margin-bottom:8px"><button onclick="load()">Обновить</button></div>
<div class="cards" id="cards"></div>
<h2>Топ правил</h2><div id="top"></div>
<h2>Перехваченные команды</h2><div id="blocks"></div>
<h2>Активность сессии</h2><div id="session"></div>
<p class="foot">Данные читаются локально из <code>.klyvo/</code>. Ничего не отправляется наружу.</p>
</div>
<script>
const esc = s => (s??'').toString().replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function load() {
  const d = await (await fetch('/api/data')).json();
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


class Handler(BaseHTTPRequestHandler):
    project_root = "."

    def _send(self, body, ctype):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/data"):
            self._send(json.dumps(collect(self.project_root), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif self.path == "/" or self.path.startswith("/index"):
            self._send(PAGE, "text/html; charset=utf-8")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # тихо


def main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный веб-дашборд Klyvo")
    parser.add_argument("--project", default=os.getcwd(), help="корень проекта (где .klyvo/)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    Handler.project_root = os.path.abspath(args.project)
    server = HTTPServer(("127.0.0.1", args.port), Handler)  # только локально
    url = f"http://127.0.0.1:{args.port}"
    print(f"Klyvo дашборд: {url}  (проект: {Handler.project_root})")
    print("Ctrl+C — остановить.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


if __name__ == "__main__":
    main()
