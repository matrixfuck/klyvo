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
:root{color-scheme:dark;--void:#0a0a0b;--void-2:#100f10;--cell:#141312;
 --bone:#e8e6e0;--dim:#9d9a92;--faint:#615e56;--line:#2b2a25;--line-2:#403e37;
 --amber:#ffb000;--block:#ff453a;--pass:#4ec26f;
 --mono:ui-monospace,"JetBrains Mono","SF Mono","Cascadia Code",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--void);color:var(--bone);font-family:var(--mono);
 -webkit-font-smoothing:antialiased}
::selection{background:var(--amber);color:var(--void)}
"""

LOGIN_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0d1017"><link rel="icon" href="/favicon.ico?v=3" sizes="any"><link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png?v=3"><link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png?v=3"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v=3">
<title>Вход — Klyvo</title>
<style nonce="__NONCE__">{css}
body{{font-size:15px}}
.wrap{{min-height:100vh;display:grid;place-items:center;padding:24px;
 background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.014) 0 1px,transparent 1px 3px)}}
.box{{width:100%;max-width:340px;background:var(--void-2);border:1px solid var(--line-2);padding:30px 28px}}
.brand{{font-weight:700;font-size:18px;letter-spacing:.06em;text-transform:uppercase;
 display:flex;align-items:center;gap:10px;margin-bottom:4px}}
.led{{width:8px;height:8px;background:var(--pass);box-shadow:0 0 9px var(--pass)}}
.hint{{color:var(--faint);font-size:12px;letter-spacing:.14em;text-transform:uppercase;margin:0 0 22px}}
label{{font-size:12px;letter-spacing:.06em;color:var(--dim);display:block;margin-bottom:8px}}
input{{width:100%;background:var(--void);border:1px solid var(--line-2);
 color:var(--bone);font-family:var(--mono);font-size:15px;padding:11px 13px;margin-bottom:18px}}
input:focus{{outline:none;border-color:var(--amber)}}
button{{width:100%;background:var(--amber);color:var(--void);border:1px solid var(--amber);
 font-family:var(--mono);font-weight:700;font-size:14px;letter-spacing:.06em;text-transform:uppercase;padding:12px;cursor:pointer}}
button:hover{{background:var(--bone);border-color:var(--bone)}}
.err{{color:var(--block);font-size:13px;margin:0 0 16px;min-height:1em}}
a.back{{display:block;text-align:center;color:var(--faint);font-size:12px;
 letter-spacing:.06em;margin-top:18px;text-decoration:none}}
a.back:hover{{color:var(--amber)}}
.sub{{display:block;text-align:center;color:var(--faint);font-size:12px;letter-spacing:.06em;
 margin-top:14px;text-decoration:none}}
.sub a{{color:var(--amber);text-decoration:none}}
.sub a:hover{{color:var(--bone)}}
</style></head><body><div class="wrap"><form class="box" method="post">
<div class="brand"><span class="led"></span>klyvo</div>
<p class="hint">вход в дашборд</p>
<div class="err">{error}</div>
{ufield}<label for="p">Пароль</label>
<input id="p" type="password" name="password" autocomplete="current-password">
<button type="submit">Войти</button>
<a class="back" href="/">← на главную</a>
{below}</form></div></body></html>"""

# Подстановка в PAGE (single-режим — локальный дашборд).
_FOOT_LOCAL = 'Данные читаются локально из <code class="mono">.klyvo/</code>. Ничего не отправляется наружу.'


PAGE = """<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0d1017">
<link rel="icon" href="/favicon.ico?v=3" sizes="any"><link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png?v=3"><link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png?v=3"><link rel="apple-touch-icon" href="/apple-touch-icon.png?v=3">
<title>Klyvo — дашборд</title>
<style nonce="__NONCE__">
:root{color-scheme:dark;--void:#0a0a0b;--void-2:#100f10;--cell:#141312;
 --bone:#e8e6e0;--mut:#9d9a92;--faint:#615e56;--line:#2b2a25;--line-2:#403e37;
 --amber:#ffb000;--amber-wash:rgba(255,176,0,.10);--block:#ff453a;--block-wash:rgba(255,69,58,.10);--pass:#4ec26f;
 --mono:ui-monospace,"JetBrains Mono","SF Mono","Cascadia Code",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--void);color:var(--bone);font-family:var(--mono);font-size:14px;line-height:1.55;
 -webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
 background:repeating-linear-gradient(0deg,rgba(255,255,255,.013) 0 1px,transparent 1px 3px);mix-blend-mode:overlay}
::selection{background:var(--amber);color:var(--void)}
a:focus-visible,button:focus-visible,input:focus-visible,.sw:focus-within .track{outline:2px solid var(--amber);outline-offset:2px}
button,a,.sw{touch-action:manipulation}
.card .n,.cnt .mono,.tab .c,td.t{font-variant-numeric:tabular-nums}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 70px;position:relative;z-index:1}
.mono{font-family:var(--mono)}

header{position:sticky;top:0;z-index:10;background:rgba(10,10,11,.88);backdrop-filter:blur(8px);
 border-bottom:1px solid var(--line);margin:0 -20px 24px;padding:0 20px}
.hbar{display:flex;align-items:center;gap:14px;height:56px;max-width:1080px;margin:0 auto}
.brand{font-weight:700;font-size:16px;letter-spacing:.05em;text-transform:uppercase;display:flex;align-items:center;gap:10px}
.led{width:8px;height:8px;background:var(--pass);box-shadow:0 0 9px var(--pass)}
.brand small{color:var(--faint);font-weight:400;font-size:12px;letter-spacing:.06em;text-transform:none}
.proj{color:var(--faint);font-size:12px;letter-spacing:.02em;margin-left:2px;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:34ch}
.proj::before{content:"~ ";color:var(--line-2)}
.spacer{flex:1}
.hctl{display:flex;align-items:center;gap:14px}
.sw{display:inline-flex;align-items:center;gap:8px;color:var(--mut);font-size:12px;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;user-select:none}
.sw input{position:absolute;opacity:0;pointer-events:none}
.track{width:32px;height:18px;background:var(--void-2);border:1px solid var(--line-2);position:relative;transition:background .15s,border-color .15s}
.track::after{content:"";position:absolute;top:2px;left:2px;width:12px;height:12px;background:var(--faint);transition:transform .15s,background .15s}
.sw input:checked + .track{background:var(--amber-wash);border-color:var(--amber)}
.sw input:checked + .track::after{transform:translateX(14px);background:var(--amber)}
.lnk{color:var(--mut);font-size:12px;letter-spacing:.06em;text-transform:uppercase;text-decoration:none}.lnk:hover{color:var(--amber)}
button.btn{background:transparent;color:var(--bone);border:1px solid var(--line-2);
 padding:8px 13px;cursor:pointer;font-size:12px;letter-spacing:.06em;text-transform:uppercase;font-family:var(--mono)}
button.btn:hover{border-color:var(--amber);color:var(--amber)}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));border:1px solid var(--line-2);margin-bottom:20px}
.card{padding:16px 18px;border-right:1px solid var(--line)}
.card:last-child{border-right:none}
.card .n{font-size:30px;font-weight:700;line-height:1;letter-spacing:-.02em}
.card .l{color:var(--faint);font-size:11px;letter-spacing:.14em;text-transform:uppercase;margin-top:9px}
.card.crit .n{color:var(--block)}.card.warn .n{color:var(--amber)}

.split{border:1px solid var(--line-2);padding:16px 18px;margin-bottom:24px}
.split .lab{display:flex;justify-content:space-between;color:var(--faint);font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin-bottom:11px}
.bar{height:12px;background:var(--void-2);border:1px solid var(--line);overflow:hidden;display:flex}
.bar i{display:block;height:100%}
.bar .d{background:var(--block)}.bar .a{background:var(--amber)}
.legend{display:flex;gap:22px;margin-top:12px;color:var(--mut);font-size:12px;letter-spacing:.04em}
.legend b{color:var(--bone);font-weight:700}
.dot{display:inline-block;width:8px;height:8px;margin-right:7px;vertical-align:1px}
.dot.d{background:var(--block)}.dot.a{background:var(--amber)}.dot.c{background:var(--block)}.dot.w{background:var(--amber)}

.tabs{display:flex;gap:0;border-bottom:1px solid var(--line-2);margin-bottom:16px}
.tab{background:none;border:none;border-bottom:2px solid transparent;color:var(--mut);font-family:var(--mono);
 font-size:12px;letter-spacing:.08em;text-transform:uppercase;padding:11px 16px;cursor:pointer;margin-bottom:-1px}
.tab:hover{color:var(--bone)}
.tab[aria-selected="true"]{color:var(--amber);border-bottom-color:var(--amber)}
.tab .c{color:var(--faint);font-size:11px;margin-left:8px}
.tab[aria-selected="true"] .c{color:var(--amber)}

.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.search{flex:1;min-width:180px;background:var(--void-2);border:1px solid var(--line-2);
 color:var(--bone);font-family:var(--mono);font-size:13px;padding:10px 13px;letter-spacing:.02em}
.search::placeholder{color:var(--faint)}
.search:focus{outline:none;border-color:var(--amber)}
.chips{display:flex;gap:0;border:1px solid var(--line-2)}
.chip{background:transparent;border:none;border-right:1px solid var(--line-2);color:var(--mut);
 padding:9px 15px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;font-family:var(--mono);cursor:pointer}
.chip:last-child{border-right:none}
.chip[aria-pressed="true"]{color:var(--void);background:var(--amber);font-weight:700}

table{width:100%;border-collapse:collapse;border:1px solid var(--line-2);font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--faint);font-weight:400;font-size:11px;text-transform:uppercase;letter-spacing:.14em;background:var(--void-2)}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.015)}
td code{font-family:var(--mono);word-break:break-all;color:var(--bone)}
.t{color:var(--faint);font-size:12px;white-space:nowrap}
.rules{color:var(--mut);font-size:12px}
.badge{display:inline-block;padding:3px 9px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-family:var(--mono);border:1px solid transparent}
.badge::before{content:"["}.badge::after{content:"]"}
.badge.deny{color:var(--block);border-color:var(--block);background:var(--block-wash)}
.badge.ask{color:var(--amber);border-color:var(--amber);background:var(--amber-wash)}
.kind{color:var(--mut);font-size:12px}
.cnt{display:flex;align-items:center;gap:9px}
.cnt .mini{height:8px;background:var(--amber);min-width:2px}
.cnt.crit .mini{background:var(--block)}
.empty{color:var(--faint);background:var(--void-2);border:1px solid var(--line);padding:30px;text-align:center;letter-spacing:.04em}
.empty::before{content:"// "}
.foot{color:var(--faint);font-size:11px;letter-spacing:.06em;margin-top:28px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
.foot code{color:var(--mut)}
@media(max-width:600px){.proj{display:none}.hctl .rtext{display:none}.card{border-right:none;border-bottom:1px solid var(--line)}}
</style></head>
<body>
<header><div class="hbar">
  <span class="brand"><span class="led"></span>klyvo <small>дашборд</small></span>
  <span class="proj mono" id="proj"></span>
  <span class="spacer"></span>
  <span class="hctl">
    <label class="sw"><input type="checkbox" id="auto"><span class="track"></span><span class="rtext">авто</span></label>
    <button class="btn" id="refresh">Обновить</button>
    __EXTRA_NAV__<a class="lnk" href="logout">Выйти</a>
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
    <span>__FOOT_NOTE__</span>
    <span id="upd" aria-live="polite"></span>
  </div>
</div>

<script nonce="__NONCE__">
const esc = s => (s??'').toString().replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
       rows.map(b=>`<tr><td class="t" title="${esc(full(b.ts))}">${rel(b.ts)}</td>
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
       rows.map(e=>`<tr><td class="t" title="${esc(full(e.ts))}">${rel(e.ts)}</td>
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
    project_root = "."    # корень проекта (где .klyvo/)
    auth = None           # dict или None (режим без входа)
    base = ""             # публичный префикс за прокси, напр. "/dashboard"
    server_version = "klyvo"   # не раскрывать версию BaseHTTP/Python в Server-заголовке
    sys_version = ""

    SEC_HEADERS = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ]

    # -- helpers --
    def _send(self, body, ctype, status=200, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in self.SEC_HEADERS:
            self.send_header(k, v)
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_html(self, template, status=200):
        """Отдать HTML с CSP на nonce (инлайновые script/style разрешены только по nonce)."""
        nonce = secrets.token_urlsafe(16)
        page = template.replace("__NONCE__", nonce)
        # script — строго по nonce (главная защита от XSS); style — 'unsafe-inline',
        # т.к. дашборд использует инлайновые style-атрибуты для полосок (CSS-инъекция
        # некритична, выполнение скриптов при этом остаётся заблокированным).
        csp = ("default-src 'self'; "
               f"script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
               "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
               "base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        self._send(page, "text/html; charset=utf-8", status,
                   extra_headers=[("Content-Security-Policy", csp)])

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
            f"Max-Age={max_age}", "HttpOnly", "SameSite=Strict", "Secure",
        ])

    def _session_token(self):
        raw = self.headers.get("Cookie", "")
        try:
            ck = SimpleCookie(raw)
        except Exception:
            return ""
        return ck[SESSION_COOKIE].value if SESSION_COOKIE in ck else ""

    def _authed(self):
        """Режим single."""
        return self.auth is None or valid_session(self.auth, self._session_token())

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    # -- routes: single (как было всегда, без единого изменения поведения) --
    def do_GET(self):
        path = self._path()

        if self.auth is not None:
            if path == "/login":
                self._send_html(LOGIN_PAGE.format(css=_CSS, error="", ufield="", below=""))
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
            self._send_html(PAGE.replace("__EXTRA_NAV__", "").replace("__FOOT_NOTE__", _FOOT_LOCAL))
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
                self._send_html(LOGIN_PAGE.format(css=_CSS, error="Неверный пароль", ufield="", below=""), status=401)
            return
        self._send("404", "text/plain; charset=utf-8", status=404)

    def log_message(self, *args):
        pass  # тихо


def main(argv=None):
    parser = argparse.ArgumentParser(description="Веб-дашборд Klyvo")
    parser.add_argument("--project", default=os.getcwd(), help="корень проекта (где .klyvo/)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--set-password", metavar="USER",
                        help="задать пароль входа и выйти (режим single, пароль спросит скрытно)")
    args = parser.parse_args(argv)

    if args.set_password:
        pw = getpass.getpass("Новый пароль: ")
        if not pw or pw != getpass.getpass("Повтори пароль: "):
            print("Пароли пустые или не совпали.")
            return 1
        path = set_password(args.set_password, pw)
        print(f"Пароль задан, файл: {path}")
        return 0

    Handler.base = os.environ.get("KLYVO_WEB_BASE", "").rstrip("/")
    Handler.project_root = os.path.abspath(args.project)
    Handler.auth = load_auth()
    mode_label = "вход включён" if Handler.auth else "без входа"

    server = HTTPServer(("127.0.0.1", args.port), Handler)  # только локально
    print(f"Klyvo дашборд: http://127.0.0.1:{args.port}  ({mode_label})")
    print("Ctrl+C — остановить.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


if __name__ == "__main__":
    sys.exit(main())
