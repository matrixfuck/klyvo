#!/usr/bin/env python3
"""Маскировка секретов в тексте команд перед записью в журнал.

Журнал Klyvo хранит текст команд целиком, а в команде может оказаться секрет
(пароль в строке подключения, токен, ключ). Перед записью прогоняем текст через
`redact()` — очевидные секреты заменяются на `***`, форма команды сохраняется.

Консервативно по замыслу: маскируем только явно секретные фрагменты, чтобы не
портить читаемость команды. Всё локально, без сети.
"""
import re

MASK = "***"

# Паттерны с именованной группой `secret` — маскируется только она, остальное
# (схема, имя пользователя, хост, имя переменной) остаётся для читаемости.
_SECRET_GROUP_PATTERNS = [
    # scheme://user:PASSWORD@host  → пароль в строке подключения
    re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.\-]*://[^:@/\s]+:)(?P<secret>[^@/\s]+)(?P<post>@)"),
    # KEY=value / export KEY=value / KEY: value для секретных имён
    re.compile(
        r"(?P<pre>\b[A-Za-z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|"
        r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH_?TOKEN)[A-Za-z_]*\s*[=:]\s*)"
        r"(?P<secret>'[^']*'|\"[^\"]*\"|[^\s;|&]+)",
        re.IGNORECASE,
    ),
    # Authorization: Bearer|Basic|Token <секрет>
    re.compile(r"(?P<pre>[Aa]uthorization:\s*(?:Bearer|Basic|Token)\s+)(?P<secret>[^\s\"']+)"),
]

# Известные форматы ключей — маскируются целиком.
_WHOLE_PATTERNS = [
    re.compile(
        r"\b("
        r"sk-[A-Za-z0-9]{16,}"                 # OpenAI-подобные
        r"|ghp_[A-Za-z0-9]{20,}"               # GitHub PAT (classic)
        r"|github_pat_[A-Za-z0-9_]{20,}"       # GitHub PAT (fine-grained)
        r"|xox[baprs]-[A-Za-z0-9-]{10,}"       # Slack
        r"|AKIA[0-9A-Z]{16}"                   # AWS access key id
        r"|AIza[0-9A-Za-z\-_]{20,}"            # Google API key
        r")\b"
    ),
]


def _mask_secret_group(m):
    whole = m.group(0)
    start = m.start("secret") - m.start(0)
    end = m.end("secret") - m.start(0)
    return whole[:start] + MASK + whole[end:]


def redact(text):
    """Вернуть text с замаскированными секретами. Пустое/не-строку возвращаем как есть."""
    if not text or not isinstance(text, str):
        return text
    for pattern in _SECRET_GROUP_PATTERNS:
        text = pattern.sub(_mask_secret_group, text)
    for pattern in _WHOLE_PATTERNS:
        text = pattern.sub(MASK, text)
    return text
