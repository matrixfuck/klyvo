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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from klyvo.rules import effective_rules, load_config
except Exception:  # дашборд работает и без списка правил
    effective_rules = None
    load_config = None


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
            "rules_active": len(_rules_catalog(project_root)),
        },
        "top_rules": rule_counter.most_common(5),
        "rules": _rules_with_counts(project_root, rule_counter),
        "blocks": list(reversed(blocks))[:200],   # свежие сверху
        "session": list(reversed(session))[:200],
    }


def _rules_catalog(project_root):
    """Действующие правила: [(name, severity, description)]. + 2 эвристики WHERE."""
    if effective_rules is None or load_config is None:
        return []
    try:
        cfg = load_config(project_root)
        rules = [(n, s, d) for n, s, _p, d in effective_rules(cfg)]
    except Exception:
        return []
    disabled = set((cfg.get("disabled_rules") or []))
    for name, desc in (("sql_delete_no_where", "DELETE без ограничивающего WHERE"),
                       ("sql_update_no_where", "UPDATE без ограничивающего WHERE")):
        if name not in disabled:
            rules.append((name, "critical", desc))
    return rules


def _rules_with_counts(project_root, rule_counter):
    out = [{"name": n, "severity": s, "description": d, "count": rule_counter.get(n, 0)}
           for n, s, d in _rules_catalog(project_root)]
    out.sort(key=lambda r: (-r["count"], 0 if r["severity"] == "critical" else 1, r["name"]))
    return out


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
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0d1017"><link rel="icon" href="/favicon.svg?v=2" type="image/svg+xml">
<title>Вход — Klyvo</title>
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
<meta name="theme-color" content="#0d1017">
<link rel="icon" href="/favicon.svg?v=2" type="image/svg+xml">
<title>Klyvo — дашборд</title>
<style>
:root{color-scheme:dark;--ink:#0d1017;--panel:#141a22;--panel2:#0f151d;--line:#222c38;
 --fg:#e9edf3;--mut:#8b95a6;--faint:#5c6675;--guard:#f5b544;--danger:#ff5b52;--safe:#57cc9a;
 --mono:"SF Mono","JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;
 --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--ink);color:var(--fg);font-family:var(--sans);font-size:15px;line-height:1.5}
a:focus-visible,button:focus-visible,input:focus-visible,.sw:focus-within .track{outline:2px solid var(--guard);outline-offset:2px}
button,a,.sw{touch-action:manipulation}
.card .n,.cnt .mono,.tab .c,td.t{font-variant-numeric:tabular-nums}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px 70px}
.mono{font-family:var(--mono)}
header{position:sticky;top:0;z-index:10;background:rgba(13,16,23,.82);backdrop-filter:blur(10px);
 border-bottom:1px solid var(--line);margin:0 -20px 22px;padding:0 20px}
.hbar{display:flex;align-items:center;gap:14px;height:60px;max-width:1040px;margin:0 auto}
.brand{font-family:var(--mono);font-weight:700;font-size:19px;letter-spacing:-.02em;display:flex;align-items:center;gap:9px}
.led{width:9px;height:9px;border-radius:50%;background:var(--safe);box-shadow:0 0 10px var(--safe)}
.brand small{color:var(--faint);font-weight:400;font-size:13px;letter-spacing:0}
.proj{color:var(--faint);font-family:var(--mono);font-size:12px;margin-left:2px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:32ch}
.spacer{flex:1}
.hctl{display:flex;align-items:center;gap:14px}
.sw{display:inline-flex;align-items:center;gap:8px;color:var(--mut);font-size:13px;cursor:pointer;user-select:none}
.sw input{position:absolute;opacity:0;pointer-events:none}
.track{width:34px;height:19px;border-radius:20px;background:var(--panel);border:1px solid var(--line);position:relative;transition:background .15s,border-color .15s}
.track::after{content:"";position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:var(--faint);transition:transform .15s,background .15s}
.sw input:checked + .track{background:rgba(87,204,154,.25);border-color:var(--safe)}
.sw input:checked + .track::after{transform:translateX(15px);background:var(--safe)}
.lnk{color:var(--mut);font-size:13px;text-decoration:none}.lnk:hover{color:var(--fg)}
button.btn{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;
 padding:7px 13px;cursor:pointer;font-size:13px;font-family:var(--mono)}
button.btn:hover{border-color:var(--guard);color:var(--guard)}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 17px}
.card .n{font-size:28px;font-weight:600;font-family:var(--mono);line-height:1}
.card .l{color:var(--mut);font-size:13px;margin-top:6px}
.card.crit .n{color:var(--danger)}.card.warn .n{color:var(--guard)}

.split{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 17px;margin-bottom:22px}
.split .lab{display:flex;justify-content:space-between;color:var(--mut);font-size:13px;margin-bottom:9px}
.bar{height:10px;border-radius:6px;background:var(--panel2);overflow:hidden;display:flex}
.bar i{display:block;height:100%}
.bar .d{background:var(--danger)}.bar .a{background:var(--guard)}
.legend{display:flex;gap:18px;margin-top:10px;color:var(--mut);font-size:12.5px}
.legend b{color:var(--fg);font-family:var(--mono)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}
.dot.d{background:var(--danger)}.dot.a{background:var(--guard)}.dot.c{background:var(--danger)}.dot.w{background:var(--guard)}

.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:14px}
.tab{background:none;border:none;color:var(--mut);font-family:var(--mono);font-size:14px;padding:9px 14px;
 cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab:hover{color:var(--fg)}
.tab[aria-selected="true"]{color:var(--guard);border-bottom-color:var(--guard)}
.tab .c{color:var(--faint);font-size:12px;margin-left:6px}

.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.search{flex:1;min-width:180px;background:var(--panel);border:1px solid var(--line);border-radius:9px;
 color:var(--fg);font-family:var(--mono);font-size:13px;padding:9px 12px}
.search:focus{outline:none;border-color:var(--guard)}
.chips{display:flex;gap:6px}
.chip{background:var(--panel);border:1px solid var(--line);color:var(--mut);border-radius:20px;
 padding:6px 13px;font-size:12.5px;font-family:var(--mono);cursor:pointer}
.chip[aria-pressed="true"]{color:var(--ink);background:var(--guard);border-color:var(--guard);font-weight:600}

table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:12px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:10px 13px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.02)}
td code{font-family:var(--mono);word-break:break-all;color:var(--fg)}
.t{color:var(--faint);font-family:var(--mono);font-size:12px;white-space:nowrap}
.rules{color:var(--mut);font-family:var(--mono);font-size:12px}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600;font-family:var(--mono)}
.badge.deny{background:rgba(255,91,82,.15);color:var(--danger)}
.badge.ask{background:rgba(245,181,68,.15);color:var(--guard)}
.kind{color:var(--mut);font-family:var(--mono);font-size:12px}
.cnt{display:flex;align-items:center;gap:8px}
.cnt .mini{height:6px;border-radius:4px;background:var(--guard);min-width:2px}
.cnt.crit .mini{background:var(--danger)}
.empty{color:var(--mut);background:var(--panel);border:1px dashed var(--line);border-radius:12px;padding:28px;text-align:center}
.foot{color:var(--faint);font-size:12px;margin-top:26px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
@media(max-width:600px){.proj{display:none}.hctl .rtext{display:none}}
</style></head>
<body>
<header><div class="hbar">
  <span class="brand"><span class="led"></span>klyvo <small>дашборд</small></span>
  <span class="proj mono" id="proj"></span>
  <span class="spacer"></span>
  <span class="hctl">
    <label class="sw"><input type="checkbox" id="auto"><span class="track"></span><span class="rtext">авто</span></label>
    <button class="btn" id="refresh">Обновить</button>
    <a class="lnk" href="logout">Выйти</a>
  </span>
</div></header>

<div class="wrap">
  <div class="cards" id="cards"></div>
  <div class="split" id="split"></div>
  <div class="tabs" id="tabs" role="tablist" aria-label="Разделы дашборда"></div>
  <div class="toolbar">
    <input class="search" id="q" placeholder="Поиск…" autocomplete="off" aria-label="Поиск по разделу">
    <div class="chips" id="chips"></div>
  </div>
  <div id="view"></div>
  <div class="foot">
    <span>Данные читаются локально из <code class="mono">.klyvo/</code>. Ничего не отправляется наружу.</span>
    <span id="upd" aria-live="polite"></span>
  </div>
</div>

<script>
const esc = s => (s??'').toString().replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const S = {data:null, tab:'blocks', q:'', flt:'all', auto:false, at:0};
let timer=null;

function rel(iso){
  if(!iso) return '';
  const t=Date.parse(iso.endsWith('Z')||iso.includes('+')?iso:iso+'Z');
  if(isNaN(t)) return esc(iso.slice(0,19).replace('T',' '));
  const s=Math.max(0,(Date.now()-t)/1000);
  if(s<60) return 'только что';
  if(s<3600) return Math.floor(s/60)+' мин назад';
  if(s<86400) return Math.floor(s/3600)+' ч назад';
  if(s<7*86400) return Math.floor(s/86400)+' дн назад';
  return esc(iso.slice(0,10));
}
const full = iso => (iso||'').slice(0,19).replace('T',' ');

async function fetchData(){
  try{
    const r=await fetch('api/data'); if(r.status===401||r.redirected){location.href='login';return;}
    S.data=await r.json(); S.at=Date.now(); render();
  }catch(e){}
}

function render(){
  const d=S.data; if(!d) return;
  document.getElementById('proj').textContent=d.project;
  const s=d.stats;
  document.getElementById('cards').innerHTML=[
    ['Перехвачено',s.blocks_total,''],['Критичных',s.critical,'crit'],
    ['Предупреждений',s.warning,'warn'],['Действий агента',s.session_actions,''],
    ['Правил активно',s.rules_active,'']
  ].map(([l,n,c])=>`<div class="card ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');

  const tot=s.critical+s.warning;
  document.getElementById('split').innerHTML = tot
   ? `<div class="lab"><span>Соотношение решений</span><span>${tot} перехватов</span></div>
      <div class="bar"><i class="d" style="width:${s.critical/tot*100}%"></i><i class="a" style="width:${s.warning/tot*100}%"></i></div>
      <div class="legend"><span><span class="dot d"></span>заблокировано <b>${s.critical}</b></span>
      <span><span class="dot a"></span>подтверждение <b>${s.warning}</b></span></div>`
   : `<div class="lab"><span>Соотношение решений</span></div><div class="empty">Опасных команд ещё не перехвачено.</div>`;

  const tabs=[['blocks','Перехваты',d.blocks.length],['rules','Правила',d.rules.length],['session','Активность',d.session.length]];
  document.getElementById('tabs').innerHTML=tabs.map(([k,l,c])=>
    `<button class="tab" role="tab" data-tab="${k}" aria-selected="${S.tab===k}">${l}<span class="c">${c}</span></button>`).join('');

  const chips=document.getElementById('chips');
  if(S.tab==='blocks'){chips.style.display='';chips.innerHTML=[['all','все'],['deny','deny'],['ask','ask']].map(([k,l])=>
    `<button class="chip" data-flt="${k}" aria-pressed="${S.flt===k}">${l}</button>`).join('');}
  else chips.style.display='none';

  const q=S.q.toLowerCase();
  let html='';
  if(S.tab==='blocks'){
    let rows=d.blocks.filter(b=>S.flt==='all'||b.decision===S.flt)
      .filter(b=>!q||(b.command||'').toLowerCase().includes(q)||(b.rules_matched||[]).join(' ').toLowerCase().includes(q));
    html = rows.length
     ? `<table><thead><tr><th>Время</th><th>Решение</th><th>Команда</th><th>Правила</th></tr></thead><tbody>`+
       rows.map(b=>`<tr><td class="t" title="${full(b.ts)}">${rel(b.ts)}</td>
        <td><span class="badge ${b.decision==='deny'?'deny':'ask'}">${esc(b.decision)}</span></td>
        <td><code>${esc(b.command)}</code></td>
        <td class="rules">${esc((b.rules_matched||[]).join(', '))}</td></tr>`).join('')+`</tbody></table>`
     : `<div class="empty">${d.blocks.length?'Ничего не найдено.':'Опасных команд не перехвачено.'}</div>`;
  } else if(S.tab==='rules'){
    let rows=d.rules.filter(r=>!q||r.name.toLowerCase().includes(q)||(r.description||'').toLowerCase().includes(q));
    const mx=Math.max(1,...d.rules.map(r=>r.count));
    html = rows.length
     ? `<table><thead><tr><th>Правило</th><th>Уровень</th><th>Описание</th><th>Сработало</th></tr></thead><tbody>`+
       rows.map(r=>`<tr><td><code>${esc(r.name)}</code></td>
        <td><span class="dot ${r.severity==='critical'?'c':'w'}"></span><span class="kind">${r.severity==='critical'?'critical':'warning'}</span></td>
        <td class="kind">${esc(r.description)}</td>
        <td><div class="cnt ${r.severity==='critical'?'crit':''}"><span class="mini" style="width:${r.count/mx*60}px"></span><span class="mono">${r.count}</span></div></td></tr>`).join('')+`</tbody></table>`
     : `<div class="empty">Правил не найдено.</div>`;
  } else {
    let rows=d.session.filter(e=>!q||(e.detail||'').toLowerCase().includes(q)||(e.kind||e.tool||'').toLowerCase().includes(q));
    html = rows.length
     ? `<table><thead><tr><th>Время</th><th>Тип</th><th>Детали</th></tr></thead><tbody>`+
       rows.map(e=>`<tr><td class="t" title="${full(e.ts)}">${rel(e.ts)}</td>
        <td class="kind">${esc(e.kind||e.tool)}</td><td><code>${esc(e.detail)}</code></td></tr>`).join('')+`</tbody></table>`
     : `<div class="empty">${d.session.length?'Ничего не найдено.':'Журнал сессии пуст.'}</div>`;
  }
  document.getElementById('view').innerHTML=html;
  document.getElementById('upd').textContent='обновлено '+rel(new Date(S.at).toISOString());
}

document.getElementById('tabs').addEventListener('click',e=>{
  const b=e.target.closest('[data-tab]'); if(!b)return; S.tab=b.dataset.tab; S.q=''; document.getElementById('q').value=''; render();});
document.getElementById('chips').addEventListener('click',e=>{
  const b=e.target.closest('[data-flt]'); if(!b)return; S.flt=b.dataset.flt; render();});
document.getElementById('q').addEventListener('input',e=>{S.q=e.target.value; render();});
document.getElementById('refresh').addEventListener('click',fetchData);
document.getElementById('auto').addEventListener('change',e=>{
  S.auto=e.target.checked; clearInterval(timer);
  if(S.auto) timer=setInterval(fetchData,6000);});
fetchData();
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
