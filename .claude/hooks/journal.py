#!/usr/bin/env python3
"""PostToolUse hook: записывает каждое действие агента в session_log.jsonl.

Детерминированно, без нейросети. Из этого лога klyvo_journal.py собирает
человекочитаемую сводку сессии.
"""
import datetime
import json
import os
import sys


def session_log_path(data=None):
    # Claude Code задаёт CLAUDE_PROJECT_DIR; форки (DeepSeek-Code и др.) — нет,
    # поэтому падаем на cwd из payload, затем на текущую директорию.
    base = os.environ.get("CLAUDE_PROJECT_DIR")
    if not base and data:
        base = data.get("cwd")
    base = base or os.getcwd()
    directory = os.path.join(base, ".klyvo")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "session_log.jsonl")


def summarize(tool_name: str, tool_input: dict):
    """Короткое человекочитаемое описание одного действия."""
    if tool_name == "Bash":
        return {"kind": "command", "detail": tool_input.get("command", "")}
    if tool_name in ("Edit", "MultiEdit"):
        return {"kind": "edit", "detail": tool_input.get("file_path", "")}
    if tool_name == "Write":
        return {"kind": "write", "detail": tool_input.get("file_path", "")}
    if tool_name in ("Read", "NotebookEdit"):
        return {"kind": tool_name.lower(), "detail": tool_input.get("file_path", "")}
    return {"kind": tool_name.lower(), "detail": ""}


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)  # никогда не ломаем агента из-за бага в журнале

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {}) or {}
    summary = summarize(tool_name, tool_input)

    # успех/ошибку берём из tool_response, если есть (имя поля бывает разным)
    response = data.get("tool_response", data.get("tool_result", {}))
    success = None
    if isinstance(response, dict):
        if "error" in response or response.get("is_error"):
            success = False
        elif response:
            success = True

    event = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "session_id": data.get("session_id"),
        "tool": tool_name,
        "kind": summary["kind"],
        "detail": summary["detail"],
        "success": success,
    }
    with open(session_log_path(data), "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
