#!/usr/bin/env python3
"""Идемпотентная установка/удаление хуков Klyvo в конфиг инструмента.

Пути к скриптам вычисляются от расположения этого файла, поэтому корректно
работает из любой копии репозитория.

  python3 tools/install_hooks.py                        # Claude Code (~/.claude/settings.json)
  python3 tools/install_hooks.py --tool deepseek-code   # DeepSeek-Code (~/.deepseek-code/settings.json)
  python3 tools/install_hooks.py --tool codex           # Codex CLI (~/.codex/hooks.json + флаг)
  python3 tools/install_hooks.py --tool kimi            # Kimi Code (~/.kimi-code/config.toml)
  python3 tools/install_hooks.py --tool cursor          # Cursor (~/.cursor/hooks.json)
  python3 tools/install_hooks.py --tool opencode        # opencode (плагин)
  python3 tools/install_hooks.py --tool claude-compatible --path <settings.json>
  python3 tools/install_hooks.py --tool <t> --uninstall
  python3 tools/install_hooks.py --dry-run

Claude-совместимые форки (DeepSeek-Code, Langcli, Crush, Oh My Pi) и Kimi Code
используют тот же контракт хуков, что и Claude Code, поэтому ставятся тем же
guard.py/journal.py. Codex требует плоского ответа (только deny) — у него свой
адаптер. opencode использует плагин на JS.
"""
import argparse
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAUDE_GUARD = f"python3 {os.path.join(REPO_ROOT, '.claude', 'hooks', 'guard.py')}"
CLAUDE_JOURNAL = f"python3 {os.path.join(REPO_ROOT, '.claude', 'hooks', 'journal.py')}"
CURSOR_GUARD = f"python3 {os.path.join(REPO_ROOT, 'adapters', 'cursor_guard.py')}"
CODEX_GUARD = f"python3 {os.path.join(REPO_ROOT, 'adapters', 'codex_guard.py')}"
KLYVO_RULES = os.path.join(REPO_ROOT, "klyvo_rules.py")

DEFAULT_PATH = {
    "claude": os.path.expanduser("~/.claude/settings.json"),
    "deepseek-code": os.path.expanduser("~/.deepseek-code/settings.json"),
    "claude-compatible": None,   # путь задаётся через --path
    "codex": os.path.expanduser("~/.codex/hooks.json"),
    "kimi": os.path.expanduser("~/.kimi-code/config.toml"),
    "cursor": os.path.expanduser("~/.cursor/hooks.json"),
    "opencode": os.path.expanduser("~/.config/opencode/plugin/klyvo.js"),
}

# Какой guard-скрипт у JSON-хуковых инструментов (journal у всех общий).
GUARD_FOR = {
    "claude": CLAUDE_GUARD,
    "deepseek-code": CLAUDE_GUARD,
    "claude-compatible": CLAUDE_GUARD,
    "codex": CODEX_GUARD,
}


def _is_ours(cmd: str) -> bool:
    return "/klyvo/" in cmd and cmd.rstrip().endswith(("guard.py", "journal.py"))


def _has(blocks, command):
    return any(h.get("command") == command for b in blocks for h in b.get("hooks", []))


# ── JSON-хуки (Claude Code, форки, Codex) ────────────────────────────────────
def install_json(cfg, guard_cmd):
    changed = False
    hooks = cfg.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    if not _has(pre, guard_cmd):
        pre.append({"matcher": "Bash", "hooks": [{"type": "command", "command": guard_cmd}]})
        changed = True
    post = hooks.setdefault("PostToolUse", [])
    if not _has(post, CLAUDE_JOURNAL):
        post.append({"hooks": [{"type": "command", "command": CLAUDE_JOURNAL}]})
        changed = True
    return changed


def uninstall_json(cfg):
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


# ── Cursor ───────────────────────────────────────────────────────────────────
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


def _run_json(path, tool, uninstall, dry_run):
    """Общий поток для JSON-конфигов (claude/форки/codex/cursor)."""
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except json.JSONDecodeError as e:
            print(f"✗ {path} — невалидный JSON ({e}). Не трогаю.")
            return 1
    else:
        cfg = {}

    if tool == "cursor":
        changed = uninstall_cursor(cfg) if uninstall else install_cursor(cfg)
    else:
        changed = uninstall_json(cfg) if uninstall else install_json(cfg, GUARD_FOR[tool])

    if not changed:
        state = "отсутствуют" if uninstall else "уже установлены"
        print(f"Ничего не меняю — хуки Klyvo ({tool}) {state} в {path}")
    else:
        rendered = json.dumps(cfg, ensure_ascii=False, indent=2)
        if dry_run:
            print(f"— dry-run, {path} НЕ изменён. Результат был бы:\n\n{rendered}")
            return 0
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
        print(f"✓ Хуки Klyvo ({tool}) {'удалены' if uninstall else 'установлены'} в {path}")

    if tool == "codex" and not uninstall and not dry_run:
        _ensure_codex_flag(os.path.join(os.path.dirname(path), "config.toml"))
    if not dry_run:
        print("  Перезапусти инструмент — хуки читаются при старте.")
    return 0


def _ensure_codex_flag(config_toml):
    """Codex не запускает хуки без [features] codex_hooks = true."""
    text = ""
    if os.path.exists(config_toml):
        with open(config_toml, encoding="utf-8") as f:
            text = f.read()
    if "codex_hooks" in text:
        return
    if "[features]" in text:
        print(f"  ⚠ Добавь вручную в {config_toml}, в секцию [features]:  codex_hooks = true")
        return
    os.makedirs(os.path.dirname(config_toml), exist_ok=True)
    with open(config_toml, "a", encoding="utf-8") as f:
        f.write(("" if text.endswith("\n") or not text else "\n") + "\n[features]\ncodex_hooks = true\n")
    print(f"  ✓ Включил хуки Codex в {config_toml} ([features] codex_hooks = true)")


# ── Kimi Code (TOML [[hooks]]) ───────────────────────────────────────────────
_KIMI_BLOCKS = (
    f'\n[[hooks]]\nevent = "PreToolUse"\nmatcher = "Shell|Bash"\ncommand = "{CLAUDE_GUARD}"\n'
    f'\n[[hooks]]\nevent = "PostToolUse"\ncommand = "{CLAUDE_JOURNAL}"\n'
)


def _kimi_split_blocks(text):
    """Разбить TOML на куски: (is_hooks_block, text). Грубо, но по [[hooks]]."""
    lines = text.splitlines(keepends=True)
    chunks, cur, cur_is_hooks = [], [], False
    for ln in lines:
        stripped = ln.strip()
        if stripped.startswith("[[") or (stripped.startswith("[") and stripped.endswith("]")):
            if cur:
                chunks.append((cur_is_hooks, "".join(cur)))
            cur, cur_is_hooks = [ln], stripped.startswith("[[hooks]]")
        else:
            cur.append(ln)
    if cur:
        chunks.append((cur_is_hooks, "".join(cur)))
    return chunks


def run_kimi(path, uninstall, dry_run):
    text = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            text = f.read()

    if uninstall:
        chunks = _kimi_split_blocks(text)
        kept = [c for is_h, c in chunks if not (is_h and "/klyvo/" in c)]
        new_text = "".join(kept)
        changed = new_text != text
    else:
        if CLAUDE_GUARD in text:
            changed = False
            new_text = text
        else:
            changed = True
            sep = "" if text.endswith("\n") or not text else "\n"
            new_text = text + sep + _KIMI_BLOCKS

    if not changed:
        state = "отсутствуют" if uninstall else "уже установлены"
        print(f"Ничего не меняю — хуки Klyvo (kimi) {state} в {path}")
        return 0
    if dry_run:
        print(f"— dry-run, {path} НЕ изменён. Результат был бы:\n\n{new_text}")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
    print(f"✓ Хуки Klyvo (kimi) {'удалены' if uninstall else 'установлены'} в {path}")
    print("  Перезапусти Kimi Code — хуки читаются при старте.")
    return 0


# ── opencode (JS-плагин) ─────────────────────────────────────────────────────
def _opencode_plugin_src():
    return (
        "// Klyvo guard для opencode — блокирует разрушительные команды с БД.\n"
        "// Сгенерировано tools/install_hooks.py. Зовёт ядро правил Klyvo.\n"
        'import { execFileSync } from "node:child_process";\n'
        f'const KLYVO_RULES = {json.dumps(KLYVO_RULES)};\n'
        "export const KlyvoGuard = async () => ({\n"
        '  "tool.execute.before": async (input, output) => {\n'
        "    try {\n"
        '      if (!input || input.tool !== "bash") return;\n'
        "      const cmd = output && output.args && output.args.command;\n"
        "      if (!cmd) return;\n"
        '      const out = execFileSync("python3", [KLYVO_RULES, "scan", cmd], { encoding: "utf8" });\n'
        "      const res = JSON.parse(out);\n"
        '      if (res.decision === "deny") {\n'
        '        const why = (res.findings || []).map((f) => f.description).join("; ");\n'
        '        throw new Error("Klyvo заблокировал разрушительную команду: " + why);\n'
        "      }\n"
        "    } catch (e) {\n"
        '      if (e && e.message && e.message.indexOf("Klyvo") === 0) throw e; // прокинуть блок\n'
        "      // прочие ошибки — fail-open, не ломаем opencode\n"
        "    }\n"
        "  },\n"
        "});\n"
    )


def run_opencode(path, uninstall, dry_run):
    if uninstall:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                if "KlyvoGuard" not in f.read():
                    print(f"Ничего не меняю — плагин по пути {path} не наш.")
                    return 0
            if not dry_run:
                os.remove(path)
            print(f"✓ Плагин Klyvo (opencode) удалён: {path}")
        else:
            print(f"Ничего не меняю — плагина нет: {path}")
        return 0

    src = _opencode_plugin_src()
    if dry_run:
        print(f"— dry-run, {path} НЕ изменён. Записал бы плагин:\n\n{src}")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    print(f"✓ Плагин Klyvo (opencode) установлен: {path}")
    print("  Если opencode не подхватил — проверь его папку плагинов и перенеси файл туда.")
    print("  Перезапусти opencode.")
    return 0


# Как агента называет человек → как он называется здесь. Список не про полноту,
# а про то, что люди печатают по памяти, не сверяясь с README.
TOOL_ALIASES = {
    "claude-code": "claude", "claudecode": "claude", "cc": "claude",
    "deepseek": "deepseek-code", "deepseek_code": "deepseek-code",
    "kimi-code": "kimi", "kimicode": "kimi",
    "codex-cli": "codex",
    "cursor-agent": "cursor", "cursor-cli": "cursor",
    "open-code": "opencode", "sst-opencode": "opencode",
    "compatible": "claude-compatible", "fork": "claude-compatible",
}


def resolve_tool(name):
    """Привести написание агента к каноническому. None — если не узнали."""
    key = (name or "").strip().lower().replace(" ", "-")
    if key in DEFAULT_PATH:
        return key
    return TOOL_ALIASES.get(key)


HANDLERS_SPECIAL = {"kimi": run_kimi, "opencode": run_opencode}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Установка хуков Klyvo")
    # choices специально не задаём: argparse на незнакомое значение печатает
    # usage и выходит с кодом 2, а из `curl … | sh` это читается как поломка
    # установщика. Разбираем сами и объясняем по-человечески.
    parser.add_argument("--tool", default="claude")
    parser.add_argument("--path")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    tool = resolve_tool(args.tool)
    if tool is None:
        print(f"✗ Не знаю агента «{args.tool}».")
        print("  Поддерживаются: " + ", ".join(DEFAULT_PATH))
        print("  Если ваш агент — форк Claude Code, поставьте так:")
        print("    --tool claude-compatible --path ~/.ваш-агент/settings.json")
        return 1
    if tool != args.tool:
        print(f"(«{args.tool}» — это {tool})")
    args.tool = tool

    path = args.path or DEFAULT_PATH.get(args.tool)
    if not path:
        print(f"✗ Для --tool {args.tool} укажи путь к конфигу через --path "
              f"(например: --path ~/.мой-агент/settings.json)")
        return 1

    if args.tool in HANDLERS_SPECIAL:
        return HANDLERS_SPECIAL[args.tool](path, args.uninstall, args.dry_run)
    return _run_json(path, args.tool, args.uninstall, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
