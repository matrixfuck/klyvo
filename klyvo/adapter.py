#!/usr/bin/env python3
"""Общий слой для адаптеров хуков (Claude Code / Cursor / Codex).

Каждый адаптер — тонкая обёртка: разобрать формат конкретного инструмента,
позвать `evaluate()`, при находках — `log_finding()` + отдать ответ в формате
инструмента. Детекция и журнал — здесь и в klyvo.rules, едины для всех.
"""
import datetime
import json
import os

from klyvo.rules import scan, load_config, CRITICAL
from klyvo.redact import redact


def evaluate(command: str, project_root: str):
    """Прогнать команду через правила с учётом config проекта."""
    return scan(command, load_config(project_root))


def decision_for(findings) -> str:
    """critical → 'deny' (жёсткий блок, работает и в YOLO/auto), warning → 'ask'.

    Пустой список — 'allow'. Все адаптеры и так отсекают его раньше, но функция
    публичная: если автор следующего адаптера забудет проверку, а мы вернём
    'ask', каждая безобидная команда начнёт спрашивать подтверждение. Это худший
    возможный отказ — инструмент станет невыносимым и его снесут.
    """
    if not findings:
        return "allow"
    return "deny" if any(sev == CRITICAL for _, sev, _ in findings) else "ask"


def _journal_path(project_root: str) -> str:
    directory = os.path.join(project_root, ".klyvo")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "journal.jsonl")


def log_finding(project_root, command, findings, tool, decision, session_id=None, cwd=None):
    """Записать перехваченную опасную команду в общий журнал проекта."""
    event = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": tool,
        "session_id": session_id,
        "cwd": cwd,
        "command": redact(command),  # секреты не должны оседать в журнале
        "rules_matched": [name for name, _, _ in findings],
        "severities": [sev for _, sev, _ in findings],
        "reasons": [desc for _, _, desc in findings],
        "decision": decision,
    }
    with open(_journal_path(project_root), "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def reason_text(findings, decision) -> str:
    """Единый человекочитаемый текст для всех инструментов, зависит от решения."""
    reasons = "; ".join(desc for _, _, desc in findings)
    if decision == "deny":
        return (
            f"Klyvo 🔴 ЗАБЛОКИРОВАНО: разрушительная операция с данными — {reasons}. "
            "Если это намеренно — добавьте команду в allowlist или отключите правило "
            "в .klyvo/config.json, затем повторите."
        )
    return (
        f"Klyvo 🟡 Внимание: {reasons}. Подтвердите явно, что это сделано намеренно."
    )
