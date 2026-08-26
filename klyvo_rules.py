#!/usr/bin/env python3
"""CLI для правил Klyvo — посмотреть список и проверить команду.

  python3 klyvo_rules.py list                 # все действующие правила
  python3 klyvo_rules.py test "DROP TABLE x"  # что сработает на команде и почему
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from klyvo.rules import (  # noqa: E402
    BASE_RULES, CRITICAL, effective_rules, load_config, scan,
)

SEV_MARK = {CRITICAL: "🔴", "warning": "🟡"}


def base_dir():
    return os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())


def cmd_list(args):
    config = load_config(base_dir())
    rules = effective_rules(config)
    disabled = set(config.get("disabled_rules", []) or [])
    active_names = {r[0] for r in rules}

    print(f"Действующих правил: {len(rules)} (+ 2 эвристики WHERE)\n")
    for name, severity, _pattern, description in rules:
        print(f"  {SEV_MARK.get(severity, '•')} {name:<26} {description}")

    off = [r[0] for r in BASE_RULES if r[0] in disabled] + \
          [n for n in ("sql_delete_no_where", "sql_update_no_where") if n in disabled]
    if off:
        print("\nВыключены через .klyvo/config.json:")
        for n in off:
            print(f"  ✗ {n}")
    custom = [r for r in rules if r[0] not in {b[0] for b in BASE_RULES}]
    if custom:
        print("\nСвои правила из config:")
        for name, severity, _p, description in custom:
            print(f"  + {name} — {description}")
    return 0


def cmd_test(args):
    config = load_config(base_dir())
    findings = scan(args.command, config)
    if not findings:
        print("✓ чисто — правила не сработали")
        return 0
    has_critical = any(sev == CRITICAL for _, sev, _ in findings)
    print(f"{'🔴 КРИТИЧНО' if has_critical else '🟡 Внимание'} — сработало правил: {len(findings)}")
    for name, severity, description in findings:
        print(f"  {SEV_MARK.get(severity, '•')} {name}: {description}")
    return 0


def cmd_scan(args):
    """Машиночитаемый результат для адаптеров (напр. плагина opencode).

    С --log находка ещё и попадает в журнал проекта. Без этого у адаптеров,
    которые ходят через CLI, работает только блокировка: сводка сессии,
    дашборд и --export остаются пустыми, хотя команды перехватывались.
    """
    root = base_dir()
    findings = scan(args.command, load_config(root))
    decision = "allow"
    if findings:
        decision = "deny" if any(sev == CRITICAL for _, sev, _ in findings) else "ask"
    print(json.dumps({
        "decision": decision,
        "findings": [{"name": n, "severity": s, "description": d} for n, s, d in findings],
    }, ensure_ascii=False))
    if findings and getattr(args, "log", False):
        try:
            from klyvo.adapter import log_finding
            log_finding(root, args.command, findings, tool=args.tool,
                        decision=decision, cwd=os.getcwd())
        except Exception as e:
            # Журнал не критичен: решение уже напечатано и адаптер его получил.
            sys.stderr.write(f"klyvo: не смог записать журнал ({e})\n")
    return 0


AGENT_CONFIGS = [
    ("Claude Code", "~/.claude/settings.json"),
    ("Codex", "~/.codex/hooks.json"),
    ("Cursor", "~/.cursor/hooks.json"),
    ("Kimi Code", "~/.kimi-code/config.toml"),
    ("opencode", "~/.config/opencode/plugin/klyvo.js"),
    ("DeepSeek-Code", "~/.deepseek-code/settings.json"),
]


def cmd_doctor(args):
    """Сквозная самопроверка: жив ли guard на самом деле.

    Хук намеренно fail-open, поэтому «ничего не происходит» выглядит одинаково и
    когда всё хорошо, и когда защита отвалилась. Эта команда различает два случая.
    """
    import json as _json
    import subprocess
    ok = True
    here = os.path.dirname(os.path.abspath(__file__))

    print("Klyvo — самопроверка\n")

    # 1. ядро
    try:
        n = len(BASE_RULES)
        print(f"[✓] ядро правил загружается: {n} правил")
    except Exception as e:
        print(f"[✗] ядро правил не загружается: {e}")
        return 1

    # 2. реальный хук на заведомо опасной команде — самый важный шаг:
    # проверяем не функцию scan(), а тот файл, который вызывает агент.
    hook = os.path.join(here, ".claude", "hooks", "guard.py")
    probe = "psql -c '" + "DR" + "OP DATABASE prod;'"
    if not os.path.exists(hook):
        print(f"[✗] файл хука не найден: {hook}")
        ok = False
    else:
        try:
            r = subprocess.run(
                [sys.executable, hook],
                input=_json.dumps({"tool_name": "Bash", "tool_input": {"command": probe}}),
                capture_output=True, text=True, timeout=30)
            out = _json.loads(r.stdout) if r.stdout.strip() else {}
            got = (out.get("hookSpecificOutput") or {}).get("permissionDecision")
            if got == "deny":
                print("[✓] хук отвечает deny на разрушительную команду")
            else:
                print(f"[✗] хук НЕ заблокировал разрушительную команду (ответ: {got or 'пусто'})")
                if r.stderr.strip():
                    print("    stderr: " + r.stderr.strip()[:200])
                ok = False
        except Exception as e:
            print(f"[✗] не удалось выполнить хук: {e}")
            ok = False

    # 3. прописан ли хук у агентов — иначе он есть на диске, но никем не зовётся
    found = []
    for name, rel in AGENT_CONFIGS:
        path = os.path.expanduser(rel)
        if not os.path.exists(path):
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        if "klyvo" in text.lower():
            found.append(name)
    if found:
        print("[✓] хук прописан в конфигах: " + ", ".join(found))
    else:
        print("[✗] ни в одном конфиге агента хук не найден — он никем не вызывается")
        print("    поставить: python3 " + os.path.join(here, "tools", "install_hooks.py"))
        ok = False

    # 4. недавние сбои
    health = os.path.join(os.path.expanduser("~"), ".klyvo", "health.jsonl")
    rows = []
    if os.path.exists(health):
        for ln in open(health, encoding="utf-8"):
            ln = ln.strip()
            if ln:
                try:
                    rows.append(_json.loads(ln))
                except ValueError:
                    pass
    if rows:
        print(f"[!] guard давал сбой {len(rows)} раз(а), последний — {rows[-1].get('ts', '?')[:19]}")
        print(f"    {rows[-1].get('stage')}: {rows[-1].get('error')}")
        print(f"    подробности: {health}")
        ok = False
    else:
        print("[✓] сбоев guard не зафиксировано")

    print("\n" + ("Всё работает." if ok else "Есть проблемы — см. отметки [✗] и [!] выше."))
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Правила Klyvo")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="показать действующие правила")
    t = sub.add_parser("test", help="проверить команду")
    t.add_argument("command", help="команда для проверки")
    s = sub.add_parser("scan", help="проверить команду, вывести JSON (decision + findings)")
    s.add_argument("command", help="команда для проверки")
    s.add_argument("--log", action="store_true",
                   help="записать находку в журнал проекта (.klyvo/journal.jsonl)")
    s.add_argument("--tool", default="cli",
                   help="каким инструментом вызвано (попадёт в журнал)")
    sub.add_parser("doctor", help="самопроверка: действительно ли guard работает")
    args = parser.parse_args(argv)

    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "test":
        return cmd_test(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "doctor":
        return cmd_doctor(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
