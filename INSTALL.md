# Установка Klyvo на Claude Code

Klyvo перехватывает разрушительные команды с базой данных (`DROP TABLE`,
`TRUNCATE`, `DELETE` без `WHERE`, сброс миграций и т.п.) до того, как их
выполнит AI-агент, и ведёт журнал того, что агент делал. Работает полностью
локально, без сети.

## Требования
- Установленный **Claude Code**
- **Python 3** (проверить: `python3 --version`)
- macOS или Linux

## 1. Скачать код
```bash
git clone https://github.com/matrixfuck/klyvo.git ~/klyvo
```
Папку `~/klyvo` не удаляй — хук ссылается на скрипты внутри неё.
Обновление: `cd ~/klyvo && git pull`.

## 2. Установить хук
```bash
python3 ~/klyvo/tools/install_hooks.py
```
Аккуратно дописывает хуки в `~/.claude/settings.json`, остальные твои
настройки не трогает. Посмотреть без записи — добавь `--dry-run`.

## 3. Перезапустить Claude Code
Закрой и открой заново (в VS Code: Cmd+Shift+P → **Developer: Reload Window**).
Хуки читаются при старте.

## 4. Проверить
Попроси агента в Claude Code выполнить безобидную команду с триггером:
```
выполни: echo "klyvo test: TRUNCATE demo"
```
Klyvo должен перехватить её:
> 🔴 ЗАБЛОКИРОВАНО: разрушительная операция с данными — Полная очистка таблицы (TRUNCATE)…

Значит guard активен.

## Как это ведёт себя
- **Критичное** (удаление таблицы/базы, массовое удаление, сброс миграций) —
  жёстко блокируется (работает даже в auto/YOLO-режиме).
- **Предупреждения** (удаление индекса, колонки) — запрашивают подтверждение.
- Каждое срабатывание пишется в `<проект>/.klyvo/journal.jsonl`.

Сводка по сессии:
```bash
python3 ~/klyvo/klyvo_journal.py     # запускать в папке проекта
```

## Настройка (по желанию)
Если безопасная команда мешает — в корне проекта создай `.klyvo/config.json`:
```json
{
  "allowlist": ["^scripts/reset_dev\\.sh"],
  "disabled_rules": ["sql_drop_index"]
}
```
Посмотреть правила и проверить команду:
```bash
python3 ~/klyvo/klyvo_rules.py list
python3 ~/klyvo/klyvo_rules.py test "любая команда"
```

## Удалить
```bash
python3 ~/klyvo/tools/install_hooks.py --uninstall
```
