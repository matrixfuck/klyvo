#!/usr/bin/env python3
"""CLI для правил Klyvo — посмотреть список и проверить команду.

  python3 klyvo_rules.py list                 # все действующие правила
  python3 klyvo_rules.py test "DROP TABLE x"  # что сработает на команде и почему
"""
import argparse
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Правила Klyvo")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="показать действующие правила")
    t = sub.add_parser("test", help="проверить команду")
    t.add_argument("command", help="команда для проверки")
    args = parser.parse_args(argv)

    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "test":
        return cmd_test(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
