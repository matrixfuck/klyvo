# Klyvo — guard для вайб-кодинга

Перехватывает разрушительные для базы данных команды до того, как их выполнит
агент (Claude Code). Критичное (удаление таблиц, массовое удаление, сброс
миграций) блокирует, на остальное просит подтверждение. Работает даже когда
агент запущен в режиме автоодобрения. Каждую перехваченную команду пишет в журнал.

Установка за три шага: [INSTALL.md](INSTALL.md).

## Почему не хватает встроенных чекпоинтов

У Claude Code (`/rewind`) и Cursor (Checkpoints) есть свой откат, но у него две дыры:

1. он не видит команды, выполненные через bash, а миграции, `psql` и прочий CLI — это почти всегда bash;
2. он не трогает ничего за пределами файлов: удалённую строку в БД, отправленный API-запрос или уже прошедший деплой откат файлов не вернёт.

Klyvo срабатывает до выполнения команды, поэтому закрывает этот пробел.

## Как это работает

`.claude/hooks/guard.py` подключается как `PreToolUse`-хук на инструмент `Bash`
(см. `.claude/settings.json`). Сам хук тонкий: логика детекции лежит в общем
ядре `klyvo/rules.py` (36 правил и 2 эвристики), чтобы её можно было
переиспользовать в адаптерах под Cursor и Codex.

Что покрывают правила: чистый SQL (`DROP`/`TRUNCATE`/`ALTER ... DROP COLUMN`),
`DELETE`/`UPDATE` без ограничивающего `WHERE` (включая обманки `WHERE 1=1` и
`WHERE true`), CLI СУБД (`dropdb`, `mysqladmin drop`), миграционные фреймворки
(Prisma, Rails, Django, Alembic, Knex, Sequelize, Goose, TypeORM, dbmate),
облачные БД (`supabase db reset`, D1, Turso), NoSQL (`.drop()`, `dropDatabase()`,
`deleteMany({})`, `FLUSHALL`) и инфраструктуру с данными (удаление
`.sqlite`-файлов, `docker volume rm`, `kubectl delete pvc`, `terraform destroy`).

У каждого правила есть уровень. Критичное хук блокирует жёстко: команда не
выполнится даже в режиме автоодобрения. Предупреждение (удаление индекса,
колонки) вызывает запрос подтверждения. Любое срабатывание пишется в
`.klyvo/journal.jsonl`.

Ограничение, выбранное осознанно в пользу безопасности: правила смотрят на текст
команды, поэтому ключевое слово в строке или комментарии (например
`git commit -m "... drop table ..."`) тоже вызовет реакцию. Если конкретная
команда в проекте безопасна, занесите её в `allowlist`; так и убирают ложные
срабатывания.

## Настройка (`.klyvo/config.json`)

Поведение правил настраивается файлом `.klyvo/config.json` в корне проекта, все
поля необязательны:

```json
{
  "disabled_rules": ["sql_drop_index"],
  "allowlist": ["^scripts/reset_dev\\.sh"],
  "custom_rules": [
    {"name": "no_prod_seed", "severity": "critical",
     "pattern": "seed\\.py --env=prod", "description": "Сид прод-базы"}
  ]
}
```

- `disabled_rules` — правила и эвристики (`sql_delete_no_where`, `sql_update_no_where`), которые нужно выключить.
- `allowlist` — список regex. Если команда совпала хоть с одним, Klyvo её не сканирует.
- `custom_rules` — свои паттерны под проект. Битое правило игнорируется, скан не падает.

Если config битый или отсутствует, Klyvo работает на базовых правилах.

## CLI правил

```
python3 klyvo_rules.py list                 # действующие правила (с учётом config)
python3 klyvo_rules.py test "DROP TABLE x"  # что сработает на команде и почему
```

## Сквозной журнал сессии

`.claude/hooks/journal.py` подключается как `PostToolUse`-хук на все инструменты
и пишет каждое действие агента (команды, правки файлов) в
`.klyvo/session_log.jsonl`. Всё остаётся локально на диске, никуда не отправляется.
Перед записью текст команд проходит маскировку секретов (`klyvo/redact.py`):
пароли, токены и ключи заменяются на `***`, чтобы не оседать в журнале. Отдельная
команда собирает из этого сводку, без нейросети:

```
python3 klyvo_journal.py            # последняя сессия
python3 klyvo_journal.py --all      # все сессии
python3 klyvo_journal.py --session <id>
```

Пример вывода:

```
═══ Сводка сессии Klyvo ═══
Всего действий агента: 6
Изменённые файлы (2):
  • app/main.py — 2 правки
  • app/db.py — 1 правка
Выполненные команды (2):
  • npm install
  • npm test
⚠ Перехвачено опасных операций с данными: 1
  • psql -c 'DROP TABLE users;'
    └ Удаление таблицы/базы/схемы (DROP) — потребовано подтверждение
```

## Тесты

```
python3 tests/run_tests.py     # guard: 25 опасных + 14 безопасных команд
python3 tests/test_journal.py  # журнал: запись событий + рендер сводки
python3 tests/test_config.py   # правила: config (disable/allowlist/custom) + многострочный WHERE
```

Тесты симулируют формат `PreToolUse`/`PostToolUse`-событий из
`code.claude.com/docs/en/hooks`. Оба хука проверены и живым запуском в
headless-сессии Claude Code.

## Версия

Klyvo в бете, v0.3.0. Основное уже работает: перехват с блокировкой критичного,
запрос подтверждения на предупреждения, журнал сессии. Дальше будет много
обновлений. Историю версий смотрите в [CHANGELOG.md](CHANGELOG.md).

## Поддерживаемые агенты

Ядро детекции (`klyvo/rules.py`) и слой журнала и подтверждения
(`klyvo/adapter.py`) общие, под каждый инструмент нужна лишь тонкая обёртка.
Важное следствие: **Klyvo перехватывает инструмент, а не модель**. Если DeepSeek
(или любая другая модель) работает *внутри* Claude Code, Cursor или их форка —
он уже под защитой, отдельная поддержка не нужна.

| Агент | Как | Статус |
|---|---|---|
| Claude Code | `PreToolUse`/`PostToolUse`, `install_hooks.py` | ✅ проверено вживую |
| DeepSeek-Code и другие форки Claude Code (Langcli, Crush, Oh My Pi) | тот же контракт хуков, `install_hooks.py --tool deepseek-code` или `--tool claude-compatible --path <settings.json>` | 🟡 формат совпадает с Claude Code, живой тест на форке ещё не проводился |
| Cursor | `beforeShellExecution`, `install_hooks.py --tool cursor` | 🟡 адаптер по офиц. спеке, живьём не проверен |
| Агенты на Codex-архитектуре (DeepSeek-TUI, Reasonix) | свой формат хуков | ⛔ пока не поддержаны — нужен их спек хуков |

Установщик вычисляет пути от расположения репозитория, поэтому работает из любой
копии — локальной или синхронизированной между машинами:

```
python3 tools/install_hooks.py                             # Claude Code → ~/.claude/settings.json
python3 tools/install_hooks.py --tool deepseek-code        # DeepSeek-Code → ~/.deepseek-code/settings.json
python3 tools/install_hooks.py --tool cursor               # Cursor → ~/.cursor/hooks.json
python3 tools/install_hooks.py --tool claude-compatible --path ~/.мой-форк/settings.json
# --uninstall убрать, --dry-run посмотреть без записи
```

Почему форки Claude Code работают тем же хуком: они наследуют формат
`PreToolUse`/`PostToolUse` (команда в `tool_input.command`, ответ через
`permissionDecision`). Отличается только путь к конфигу и то, что форки не
задают `CLAUDE_PROJECT_DIR` — поэтому guard берёт корень проекта из `cwd`.
