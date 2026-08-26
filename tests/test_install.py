#!/usr/bin/env python3
"""Тесты установщика хуков для Claude-совместимых форков (DeepSeek-Code и др.)."""
import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
import install_hooks  # noqa: E402

failures = 0


def check(desc, condition):
    global failures
    print(f"[{'OK' if condition else 'FAIL'}] {desc}")
    if not condition:
        failures += 1


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def commands(cfg):
    out = []
    for event in cfg.get("hooks", {}).values():
        for block in event:
            for h in block.get("hooks", []):
                out.append(h.get("command", ""))
    return out


with tempfile.TemporaryDirectory() as tmp:
    # ── DeepSeek-Code: ставится теми же guard.py/journal.py, что и Claude Code ──
    p = os.path.join(tmp, "ds", "settings.json")
    rc = install_hooks.main(["--tool", "deepseek-code", "--path", p])
    check("deepseek-code: установка вернула 0", rc == 0)
    check("deepseek-code: конфиг создан", os.path.exists(p))
    cmds = commands(load(p))
    check("deepseek-code: подключён guard.py", any(c.endswith("guard.py") for c in cmds))
    check("deepseek-code: подключён journal.py", any(c.endswith("journal.py") for c in cmds))
    check("deepseek-code: команды указывают в репо klyvo", all("/klyvo/" in c for c in cmds))

    # PreToolUse-хук навешен на Bash
    pre = load(p)["hooks"]["PreToolUse"]
    check("deepseek-code: guard на matcher=Bash",
          any(b.get("matcher") == "Bash" for b in pre))

    # Идемпотентность — повторная установка ничего не дублирует
    install_hooks.main(["--tool", "deepseek-code", "--path", p])
    check("deepseek-code: повтор не дублирует guard",
          sum(c.endswith("guard.py") for c in commands(load(p))) == 1)

    # Удаление
    rc = install_hooks.main(["--tool", "deepseek-code", "--path", p, "--uninstall"])
    check("deepseek-code: удаление вернуло 0", rc == 0)
    check("deepseek-code: наши хуки убраны",
          not any("/klyvo/" in c for c in commands(load(p))))

    # ── claude-compatible: требует --path ──
    rc = install_hooks.main(["--tool", "claude-compatible"])
    check("claude-compatible без --path: ошибка (rc=1)", rc == 1)

    p2 = os.path.join(tmp, "fork", "settings.json")
    rc = install_hooks.main(["--tool", "claude-compatible", "--path", p2])
    check("claude-compatible с --path: установка ок", rc == 0 and os.path.exists(p2))
    check("claude-compatible: guard подключён",
          any(c.endswith("guard.py") for c in commands(load(p2))))

    # ── не ломаем чужие настройки в конфиге ──
    p3 = os.path.join(tmp, "existing.json")
    with open(p3, "w", encoding="utf-8") as f:
        json.dump({"model": "custom", "env": {"FOO": "bar"}}, f)
    install_hooks.main(["--tool", "deepseek-code", "--path", p3])
    cfg3 = load(p3)
    check("существующие ключи сохранены", cfg3.get("model") == "custom" and cfg3["env"]["FOO"] == "bar")

    # ── имя агента: то, что человек напечатал, а не то, что в README ──
    # `curl … | sh -s -- deepseek` раньше отдавал argparse-usage и код 2 —
    # в первые тридцать секунд знакомства это читается как поломка установщика.
    check("«deepseek» понимается как deepseek-code",
          install_hooks.resolve_tool("deepseek") == "deepseek-code")
    check("«claude-code» понимается как claude",
          install_hooks.resolve_tool("Claude-Code") == "claude")
    check("«kimi-code» понимается как kimi",
          install_hooks.resolve_tool("kimi-code") == "kimi")
    check("каноническое имя не ломается",
          install_hooks.resolve_tool("cursor") == "cursor")
    check("незнакомый агент честно не узнаётся",
          install_hooks.resolve_tool("windsurf") is None)

    rc = install_hooks.main(["--tool", "windsurf"])
    check("незнакомый агент: код 1, а не падение argparse", rc == 1)

    p4 = os.path.join(tmp, "alias", "settings.json")
    rc = install_hooks.main(["--tool", "deepseek", "--path", p4])
    check("установка по псевдониму работает", rc == 0 and os.path.exists(p4))
    check("по псевдониму подключён тот же guard",
          any(c.endswith("guard.py") for c in commands(load(p4))))

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
