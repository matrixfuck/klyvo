#!/usr/bin/env python3
"""Развернуть команду в несколько представлений, на которых сигнатуры ещё видны.

Движок читает текст команды, поэтому его обходят, не меняя её смысла: склейка
кавычками (`"DR""OP TABLE"`), сборка через переменную, `bash -c "$CMD"`, base64.
Здесь команда разворачивается в набор представлений, а `scan()` проверяет каждое
и объединяет находки.

Два принципа, из которых всё следует:

1. **Оригинал проверяется всегда и первым.** Нормализация может не только
   открыть находку, но и спрятать её: снятие кавычек ломает `WHERE 'a'='a'`.
   Поэтому представления добавляются к оригиналу, а не заменяют его.
2. **Это не эмуляция shell.** Здесь нет подстановки команд, арифметики, циклов и
   разбора кавычек по правилам bash. Цель — закрыть дешёвые обходы, до которых
   агент доходит по инерции, а не все возможные. Обойти это по-прежнему можно, и
   README про это говорит прямо.
"""
import base64
import binascii
import re

# Длиннее — это уже не команда, а данные в аргументе. Разворачивать их дорого и
# бессмысленно: оригинал всё равно проверяется.
MAX_INPUT = 20000
MAX_VIEWS = 8
MAX_VALUE = 4000     # предел на длину значения переменной, защита от склейки
MAX_PAYLOADS = 3     # сколько base64-кусков разбирать

_QUOTES = re.compile(r"""['"]""")
_ESCAPED = re.compile(r"\\([A-Za-z0-9\"'])")

# NAME=значение — в начале команды, после разделителя или пробела.
_ASSIGN = re.compile(
    r"""(?:^|[;&|(]|\s)(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)="""
    r"""("(?:[^"\\]|\\.)*"|'[^']*'|[^\s;&|)]*)""")
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")

# Кандидат в base64: только длинные куски, иначе в выборку попадает каждое слово.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def unquote(text: str) -> str:
    """Снять кавычки и экранирование: `"DR""OP"` → `DROP`, `DR\\OP` → `DROP`.

    Кавычки удаляются, а не разбираются по правилам shell. Для склейки этого
    достаточно, а разделение слов сохраняется: `"DR" "OP"` (с пробелом) так и
    останется двумя словами и ни на что не сработает.
    """
    return _QUOTES.sub("", _ESCAPED.sub(r"\1", text))


def _subst(text: str, env: dict) -> str:
    def repl(m):
        name = m.group(1) or m.group(2)
        # Неизвестные переменные оставляем как есть: `$HOME` должен дойти до
        # правил в исходном виде, они на него и рассчитаны.
        return env.get(name, m.group(0))
    return _VAR.sub(repl, text)


def expand_vars(command: str) -> str:
    """Подставить переменные, присвоенные в самой команде.

    Закрывает сборку по частям: `CMD="DR"; CMD="${CMD}OP TABLE users"; psql -c "$CMD"`.
    Присваивания читаются по порядку, поэтому `CMD="$CMD ..."` работает.
    """
    env = {}
    for m in _ASSIGN.finditer(command):
        name, raw = m.group(1), m.group(2)
        value = _subst(unquote(raw), env)
        env[name] = value[:MAX_VALUE]
    if not env:
        return command
    out = command
    for _ in range(3):  # хватает на цепочку из нескольких присваиваний
        new = _subst(out, env)
        if new == out:
            break
        out = new
    return out


def b64_payloads(command: str):
    """Куски base64, которые расшифровываются в осмысленный текст.

    `echo RFJPUCBUQUJMRSB1c2VyczsK | base64 -d | psql` — текст команды чист, вся
    начинка в аргументе. Расшифрованное проверяется как ещё одно представление.
    """
    out = []
    for m in _B64_TOKEN.finditer(command):
        if len(out) >= MAX_PAYLOADS:
            break
        token = m.group(0)
        token += "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < 8:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue  # это не текст команды, а бинарь — разбирать нечего
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t\r")
        if printable < len(text) * 0.9:
            continue
        out.append(text)
    return out


def views(command: str):
    """Оригинал плюс развёрнутые представления. Без дублей, оригинал первый."""
    result = [command]
    if not command or len(command) > MAX_INPUT:
        return result

    def add(text):
        if text and text not in result and len(result) < MAX_VIEWS:
            result.append(text)

    expanded = expand_vars(command)
    add(expanded)
    add(unquote(command))
    if expanded != command:
        add(unquote(expanded))
    for payload in b64_payloads(expanded):
        add(payload)
    return result
