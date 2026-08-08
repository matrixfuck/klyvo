#!/usr/bin/env python3
"""Реплей-харнесс для обкатки правил (Фаза 0).

Извлекает реальные команды из репозиториев (package.json scripts, Makefile,
CI-воркфлоу, *.sh) и прогоняет через klyvo.rules.scan. Помеченные команды из
такого корпуса — кандидаты в ложные срабатывания (нормальные проектные
команды) либо честные опасные (напр. `db:reset`-скрипты). Разметка вручную.

  python3 tools/replay.py <dir1> <dir2> ...
"""
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from klyvo.rules import scan, CRITICAL  # noqa: E402

SPLIT = re.compile(r"&&|\|\||[|;]")


def atomize(command: str):
    for part in SPLIT.split(command):
        part = part.strip()
        if part:
            yield part


def from_package_json(path):
    out = []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for name, body in scripts.items():
            if isinstance(body, str):
                for cmd in atomize(body):
                    out.append((cmd, f"{path}::scripts.{name}"))
    return out


def from_makefile(path):
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            if line.startswith("\t"):
                cmd = line.strip().lstrip("@-").strip()
                for c in atomize(cmd):
                    out.append((c, f"{path}::recipe"))
    except OSError:
        pass
    return out


def from_workflow(path):
    out = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return out
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.search(r"\brun:\s*(\S.*)?$", line)
        if m:
            inline = (m.group(1) or "").strip()
            if inline in ("|", ">", "|-", ">-", ""):
                base_indent = len(line) - len(line.lstrip())
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= base_indent:
                        break
                    for c in atomize(nxt.strip()):
                        out.append((c, f"{path}::run"))
                    i += 1
                continue
            else:
                for c in atomize(inline):
                    out.append((c, f"{path}::run"))
        i += 1
    return out


def from_shell(path):
    out = []
    try:
        for line in open(path, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line and not line.startswith("#"):
                for c in atomize(line):
                    out.append((c, f"{path}::sh"))
    except OSError:
        pass
    return out


def collect(root):
    commands = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".next", "dist", "build")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if fn == "package.json":
                commands += from_package_json(p)
            elif fn == "Makefile" or fn.endswith(".mk"):
                commands += from_makefile(p)
            elif fn.endswith((".yml", ".yaml")) and ".github" in dirpath:
                commands += from_workflow(p)
            elif fn.endswith(".sh"):
                commands += from_shell(p)
    return commands


def main(argv):
    if not argv:
        print("usage: replay.py <dir> [<dir> ...]")
        return 2

    all_cmds = []
    for root in argv:
        all_cmds += collect(root)

    # уникализируем по тексту команды, чтобы одинаковые скрипты не раздували цифры
    seen = {}
    for cmd, src in all_cmds:
        seen.setdefault(cmd, src)
    unique = list(seen.items())

    flagged = []
    for cmd, src in unique:
        findings = scan(cmd)
        if findings:
            flagged.append((cmd, src, findings))

    total = len(unique)
    print(f"Просканировано уникальных команд: {total}")
    print(f"Помечено: {len(flagged)} ({100*len(flagged)/total:.1f}%)\n" if total else "нет команд\n")

    by_rule = Counter()
    for _, _, findings in flagged:
        for name, _, _ in findings:
            by_rule[name] += 1
    if by_rule:
        print("Срабатывания по правилам:")
        for name, n in by_rule.most_common():
            print(f"  {name}: {n}")
        print()

    print("Помеченные команды (для ручной разметки FP / настоящая опасность):")
    for cmd, src, findings in flagged:
        sev = "🔴" if any(s == CRITICAL for _, s, _ in findings) else "🟡"
        rules = ", ".join(n for n, _, _ in findings)
        short = cmd if len(cmd) <= 90 else cmd[:87] + "..."
        print(f"  {sev} [{rules}] {short}")
        print(f"      src: {src}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
