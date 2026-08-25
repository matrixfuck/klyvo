#!/usr/bin/env python3
"""Тесты адаптеров/установщиков Codex, Kimi, opencode + CLI scan."""
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
import install_hooks  # noqa: E402

CODEX_HOOK = os.path.join(REPO_ROOT, "adapters", "codex_guard.py")
RULES = os.path.join(REPO_ROOT, "klyvo_rules.py")
DROP = "DROP" + " TABLE users"          # без литерала целиком — на всякий
failures = 0


def check(desc, ok):
    global failures
    print(f"[{'OK' if ok else 'FAIL'}] {desc}")
    if not ok:
        failures += 1


def run_codex(command, cwd):
    payload = {"tool_input": {"command": command}, "cwd": cwd, "session_id": "s1"}
    r = subprocess.run(["python3", CODEX_HOOK], input=json.dumps(payload),
                       capture_output=True, text=True)
    out = json.loads(r.stdout) if r.stdout.strip() else None
    return out, r.returncode


# ── Codex-адаптер: плоский deny, без hookSpecificOutput ──
with tempfile.TemporaryDirectory() as tmp:
    out, code = run_codex(f"psql -c \"{DROP}\"", tmp)
    check("codex: критичная → exit 0", code == 0)
    # Контракт сверен с исходниками openai/codex (codex-rs/hooks/src/schema.rs,
    # PreToolUseHookSpecificOutputWire): camelCase, обязательный hookEventName и
    # deny_unknown_fields. Раньше здесь закреплялся плоский ответ без обёртки —
    # его Codex молча отбрасывал, и адаптер не блокировал ничего.
    hso = out.get("hookSpecificOutput") if isinstance(out, dict) else None
    check("codex: решение в обёртке hookSpecificOutput",
          isinstance(hso, dict) and hso.get("permissionDecision") == "deny")
    check("codex: hookEventName=PreToolUse внутри обёртки",
          isinstance(hso, dict) and hso.get("hookEventName") == "PreToolUse")
    check("codex: есть текст причины", bool((hso or {}).get("permissionDecisionReason")))
    # deny_unknown_fields: любой лишний ключ роняет разбор всего ответа.
    check("codex: на верхнем уровне нет посторонних ключей",
          isinstance(out, dict) and set(out) == {"hookSpecificOutput"})
    check("codex: внутри обёртки только известные схеме ключи",
          isinstance(hso, dict) and set(hso) <= {
              "hookEventName", "permissionDecision", "permissionDecisionReason",
              "updatedInput", "additionalContext"})

    # warning → без вывода (Codex не умеет ask), но журнал записан
    out_w, _ = run_codex("ALTER TABLE users DROP COLUMN email", tmp)
    check("codex: warning без вывода (проходит)", out_w is None)

    # безопасная → без вывода
    out_s, _ = run_codex("npm test", tmp)
    check("codex: безопасная без вывода", out_s is None)

    jpath = os.path.join(tmp, ".klyvo", "journal.jsonl")
    check("codex: журнал записан", os.path.exists(jpath))
    if os.path.exists(jpath):
        entries = [json.loads(l) for l in open(jpath, encoding="utf-8").read().splitlines()]
        check("codex: tool=codex в журнале", all(e.get("tool") == "codex" for e in entries))
        check("codex: и deny, и warning записаны",
              any(e["decision"] == "deny" for e in entries) and any(e["decision"] == "ask" for e in entries))


# ── Установщик Codex (hooks.json + флаг) ──
with tempfile.TemporaryDirectory() as tmp:
    hooks = os.path.join(tmp, "hooks.json")
    rc = install_hooks.main(["--tool", "codex", "--path", hooks])
    check("codex-install: rc=0 и файл создан", rc == 0 and os.path.exists(hooks))
    cfg = json.load(open(hooks, encoding="utf-8"))
    cmds = [h["command"] for ev in cfg["hooks"].values() for b in ev for h in b["hooks"]]
    check("codex-install: подключён codex_guard.py", any(c.endswith("codex_guard.py") for c in cmds))
    check("codex-install: подключён journal.py", any(c.endswith("journal.py") for c in cmds))
    toml = os.path.join(tmp, "config.toml")
    check("codex-install: флаг codex_hooks включён",
          os.path.exists(toml) and "codex_hooks = true" in open(toml, encoding="utf-8").read())


# ── Установщик Kimi (TOML [[hooks]]) ──
with tempfile.TemporaryDirectory() as tmp:
    conf = os.path.join(tmp, "config.toml")
    install_hooks.main(["--tool", "kimi", "--path", conf])
    text = open(conf, encoding="utf-8").read()
    check("kimi-install: есть [[hooks]]", "[[hooks]]" in text)
    check("kimi-install: guard.py и journal.py", "guard.py" in text and "journal.py" in text)
    # Матчер фильтрует по tool_name, а shell-инструмент в Kimi называется Shell —
    # см. docs/en/customization/hooks.md у MoonshotAI/kimi-cli. С matcher = "Bash"
    # хук не срабатывал вообще, потому что инструмента с таким именем там нет.
    check("kimi-install: PreToolUse и матчер ловит Shell",
          'event = "PreToolUse"' in text and 'Shell' in text)
    install_hooks.main(["--tool", "kimi", "--path", conf])  # повтор
    check("kimi-install: идемпотентно (2 блока)", open(conf, encoding="utf-8").read().count("[[hooks]]") == 2)
    install_hooks.main(["--tool", "kimi", "--path", conf, "--uninstall"])
    check("kimi-uninstall: наши блоки убраны", "/klyvo/" not in open(conf, encoding="utf-8").read())

# сохранность чужого содержимого в config.toml
with tempfile.TemporaryDirectory() as tmp:
    conf = os.path.join(tmp, "config.toml")
    with open(conf, "w", encoding="utf-8") as f:
        f.write('[model]\nname = "k2"\n')
    install_hooks.main(["--tool", "kimi", "--path", conf])
    install_hooks.main(["--tool", "kimi", "--path", conf, "--uninstall"])
    left = open(conf, encoding="utf-8").read()
    check("kimi: чужая секция [model] сохранена", '[model]' in left and 'name = "k2"' in left)


# ── Установщик opencode (JS-плагин) ──
with tempfile.TemporaryDirectory() as tmp:
    plug = os.path.join(tmp, "plugin", "klyvo.js")
    install_hooks.main(["--tool", "opencode", "--path", plug])
    check("opencode-install: файл создан", os.path.exists(plug))
    src = open(plug, encoding="utf-8").read()
    check("opencode-install: экспорт KlyvoGuard", "KlyvoGuard" in src)
    check("opencode-install: хук tool.execute.before", "tool.execute.before" in src)
    check("opencode-install: зовёт klyvo_rules.py", "klyvo_rules.py" in src)
    install_hooks.main(["--tool", "opencode", "--path", plug, "--uninstall"])
    check("opencode-uninstall: файл удалён", not os.path.exists(plug))


# ── CLI scan --json ──
def scan(cmd):
    r = subprocess.run(["python3", RULES, "scan", cmd], capture_output=True, text=True)
    return json.loads(r.stdout)


check("scan: критичная → deny", scan(f"psql -c '{DROP}'")["decision"] == "deny")
check("scan: warning → ask", scan("ALTER TABLE users DROP COLUMN x")["decision"] == "ask")
check("scan: безопасная → allow", scan("npm run build")["decision"] == "allow")
check("scan: findings присутствуют для deny", len(scan(f"psql -c '{DROP}'")["findings"]) >= 1)

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
