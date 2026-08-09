#!/usr/bin/env python3
"""Идемпотентная установка/удаление хуков Klyvo в конфиг инструмента.

Пути к скриптам вычисляются от расположения этого файла, поэтому корректно
работает и на сервере, и на Маке (в синхронизированной копии репо).

  python3 tools/install_hooks.py                        # Claude Code (~/.claude/settings.json)
  python3 tools/install_hooks.py --tool deepseek-code   # DeepSeek-Code (~/.deepseek-code/settings.json)
  python3 tools/install_hooks.py --tool cursor          # Cursor (~/.cursor/hooks.json)
  python3 tools/install_hooks.py --tool claude-compatible --path <settings.json>
  python3 tools/install_hooks.py --tool cursor --uninstall
  python3 tools/install_hooks.py --dry-run

Claude-совместимые форки (DeepSeek-Code, Langcli, Crush, Oh My Pi и т.п.)
используют тот же контракт хуков, что и Claude Code, поэтому ставятся тем же
guard.py/journal.py — отличается только путь к конфигу. Для форка с нестандартным
путём: --tool claude-compatible --path /путь/к/settings.json
"""
import argparse
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAUDE_GUARD = f"python3 {os.path.join(REPO_ROOT, '.claude', 'hooks', 'guard.py')}"
CLAUDE_JOURNAL = f"python3 {os.path.join(REPO_ROOT, '.claude', 'hooks', 'journal.py')}"
CURSOR_GUARD = f"python3 {os.path.join(REPO_ROOT, 'adapters', 'cursor_guard.py')}"

DEFAULT_PATH = {
    "claude": os.path.expanduser("~/.claude/settings.json"),
    "deepseek-code": os.path.expanduser("~/.deepseek-code/settings.json"),
    "cursor": os.path.expanduser("~/.cursor/hooks.json"),
    # claude-compatible — без дефолта: путь к конфигу форка задаётся через --path
    "claude-compatible": None,
}


def _is_ours(cmd: str) -> bool:
    return "/klyvo/" in cmd and cmd.rstrip().endswith(("guard.py", "journal.py"))


def _has(blocks, command):
    return any(h.get("command") == command for b in blocks for h in b.get("hooks", []))


# ── Claude Code ─────────────────────────────────────────────────────────────
def install_claude(cfg):
    changed = False
    hooks = cfg.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    if not _has(pre, CLAUDE_GUARD):
        pre.append({"matcher": "Bash", "hooks": [{"type": "command", "command": CLAUDE_GUARD}]})
        changed = True
    post = hooks.setdefault("PostToolUse", [])
    if not _has(post, CLAUDE_JOURNAL):
        post.append({"hooks": [{"type": "command", "command": CLAUDE_JOURNAL}]})
        changed = True
    return changed


def uninstall_claude(cfg):
    changed = False
    hooks = cfg.get("hooks", {})
    for event in ("PreToolUse", "PostToolUse"):
        blocks = hooks.get(event)
        if not blocks:
            continue
        new_blocks = []
        for b in blocks:
            kept = [h for h in b.get("hooks", []) if not _is_ours(h.get("command", ""))]
            if kept:
                b["hooks"] = kept
                new_blocks.append(b)
            else:
                changed = True
        if len(new_blocks) != len(blocks):
            changed = True
        if new_blocks:
            hooks[event] = new_blocks
        else:
            hooks.pop(event, None)
            changed = True
    if "hooks" in cfg and not cfg["hooks"]:
        cfg.pop("hooks")
    return changed


# ── Cursor ──────────────────────────────────────────────────────────────────
def install_cursor(cfg):
    cfg.setdefault("version", 1)
    hooks = cfg.setdefault("hooks", {})
    lst = hooks.setdefault("beforeShellExecution", [])
    if any(h.get("command") == CURSOR_GUARD for h in lst):
        return False
    lst.append({"command": CURSOR_GUARD})
    return True


def uninstall_cursor(cfg):
    hooks = cfg.get("hooks", {})
    lst = hooks.get("beforeShellExecution")
    if not lst:
        return False
    kept = [h for h in lst if not _is_ours(h.get("command", ""))]
    if len(kept) == len(lst):
        return False
    if kept:
        hooks["beforeShellExecution"] = kept
    else:
        hooks.pop("beforeShellExecution", None)
    return True


# Claude-совместимые форки ставятся тем же guard.py/journal.py, что и Claude Code.
HANDLERS = {
    "claude": (install_claude, uninstall_claude),
    "deepseek-code": (install_claude, uninstall_claude),
    "claude-compatible": (install_claude, uninstall_claude),
    "cursor": (install_cursor, uninstall_cursor),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Установка хуков Klyvo")
    parser.add_argument("--tool", choices=list(HANDLERS), default="claude")
    parser.add_argument("--path")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    path = args.path or DEFAULT_PATH.get(args.tool)
    if not path:
        print(f"✗ Для --tool {args.tool} укажи путь к конфигу форка через --path "
              f"(например: --path ~/.мой-агент/settings.json)")
        return 1

    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError as e:
            print(f"✗ {path} — невалидный JSON ({e}). Не трогаю.")
            return 1
    else:
        cfg = {}

    install_fn, uninstall_fn = HANDLERS[args.tool]
    changed = uninstall_fn(cfg) if args.uninstall else install_fn(cfg)

    if not changed:
        state = "отсутствуют" if args.uninstall else "уже установлены"
        print(f"Ничего не меняю — хуки Klyvo ({args.tool}) {state} в {path}")
        return 0

    rendered = json.dumps(cfg, ensure_ascii=False, indent=2)
    if args.dry_run:
        print(f"— dry-run, {path} НЕ изменён. Результат был бы:\n\n{rendered}")
        return 0

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(rendered + "\n")
    print(f"✓ Хуки Klyvo ({args.tool}) {'удалены' if args.uninstall else 'установлены'} в {path}")
    print("  Перезапусти инструмент — хуки читаются при старте.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
