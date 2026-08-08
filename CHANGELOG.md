# История версий

Формат — [SemVer](https://semver.org/lang/ru/): `major.minor.patch`.
Пока версия ниже 1.0.0, ломающие изменения возможны в любом `minor`.

## v0.1.0 — 2026-08-08

Первая публичная бета.

- Перехват разрушительных команд с базой данных до выполнения агентом.
  Критичное блокируется (работает даже в режиме автоодобрения), на
  предупреждения запрашивается подтверждение.
- Ядро правил `klyvo/rules.py`: 36 правил и 2 эвристики (SQL, CLI СУБД,
  миграции, облачные БД, NoSQL, инфраструктура с данными), уровни
  critical/warning, ловля обхода `WHERE`.
- Журнал перехваченных попыток в `.klyvo/journal.jsonl`.
- Сквозной журнал сессии: `journal.py` + `klyvo_journal.py`, сводка без нейросети.
- Настройка через `.klyvo/config.json`: `disabled_rules`, `allowlist`,
  `custom_rules`. CLI `klyvo_rules.py` (`list`, `test`).
- Адаптеры: Claude Code (`PreToolUse`/`PostToolUse`) и Cursor
  (`beforeShellExecution`). Установщик `tools/install_hooks.py`.
