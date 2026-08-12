#!/usr/bin/env python3
"""Маскировка секретов в тексте команд перед записью в журнал.

Журнал Klyvo хранит текст команд целиком, а в команде может оказаться секрет
(пароль в строке подключения, токен, ключ). Перед записью прогоняем текст через
`redact()` — очевидные секреты заменяются на `***`, форма команды сохраняется.

Консервативно по замыслу: маскируем только явно секретные фрагменты, чтобы не
портить читаемость команды. Всё локально, без сети.

Это блок-лист по известным форматам/синтаксису, не универсальный детектор
секретов — гарантий 100% нет. Осознанно не покрыто (нужна была бы эвристика
по энтропии строки, а это отдельный риск ложных срабатываний на хешах/SHA):
- `mysql -pSECRET` слитно с флагом, без пробела и разделителя;
- секрет, вставленный как обычное значение без опознаваемого имени/флага/формата;
- PEM-блоки приватных ключей (`-----BEGIN ... PRIVATE KEY-----`).
При экспорте логов для отправки — глазами проверить файл, автоматика тут
снижает риск, а не снимает его целиком.
"""
import re

MASK = "***"

# Паттерны с именованной группой `secret` — маскируется только она, остальное
# (схема, имя пользователя, хост, имя переменной) остаётся для читаемости.
_SECRET_GROUP_PATTERNS = [
    # scheme://user:PASSWORD@host  → пароль в строке подключения
    re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.\-]*://[^:@/\s]+:)(?P<secret>[^@/\s]+)(?P<post>@)"),
    # KEY=value / export KEY=value / KEY: value / "key": "value" (в т.ч. JSON-тела)
    re.compile(
        r"(?P<pre>\b[A-Za-z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|"
        r"ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH_?TOKEN)[A-Za-z_]*[\"']?\s*[=:]\s*)"
        r"(?P<secret>'[^']*'|\"[^\"]*\"|[^\s;|&,}]+)",
        re.IGNORECASE,
    ),
    # --password X / --with-token X / --api-key X  (флаг + пробел, без = и без :)
    re.compile(
        r"(?P<pre>--?[a-z-]*(?:password|passwd|secret|token|api[_-]?key|"
        r"access[_-]?key|private[_-]?key|auth[_-]?token)[a-z-]*\s+)"
        r"(?P<secret>\S+)",
        re.IGNORECASE,
    ),
    # Authorization: Bearer|Basic|Token <секрет>
    re.compile(r"(?P<pre>[Aa]uthorization:\s*(?:Bearer|Basic|Token)\s+)(?P<secret>[^\s\"']+)"),
    # curl -u user:pass / --user user:pass  → Basic auth флагом, не в URL
    re.compile(r"(?P<pre>(?:-u|--user)\s+[^\s:@'\"]+:)(?P<secret>[^\s'\"]+)"),
]

# Известные форматы ключей — маскируются целиком, независимо от контекста вокруг.
_WHOLE_PATTERNS = [
    re.compile(
        r"\b("
        r"sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}"       # Anthropic (ключ самого Claude)
        r"|sk-[A-Za-z0-9]{16,}"                          # OpenAI-подобные
        r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"     # Stripe secret/restricted key
        r"|ghp_[A-Za-z0-9]{20,}"                         # GitHub PAT (classic)
        r"|github_pat_[A-Za-z0-9_]{20,}"                 # GitHub PAT (fine-grained)
        r"|glpat-[A-Za-z0-9_-]{20,}"                     # GitLab PAT
        r"|xox[baprs]-[A-Za-z0-9-]{10,}"                 # Slack
        r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"   # SendGrid
        r"|npm_[A-Za-z0-9]{36}"                          # npm token
        r"|AKIA[0-9A-Z]{16}"                             # AWS access key id
        r"|AIza[0-9A-Za-z\-_]{20,}"                      # Google API key
        r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"  # JWT (Bearer-токен целиком)
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
