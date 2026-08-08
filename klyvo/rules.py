#!/usr/bin/env python3
"""Общее ядро детекции опасных операций с данными.

Не зависит от конкретного инструмента (Claude Code / Cursor / Codex) — адаптеры
хуков импортируют отсюда `scan()`. Всё детерминированно, без нейросети.

severity:
  "critical" — необратимая массовая потеря данных (удаление таблицы/базы,
               массовое удаление/обновление, сброс миграций до нуля)
  "warning"  — потенциально опасно, но уже́, обратимо или требует контекста

Поведение можно настроить через `.klyvo/config.json` в корне проекта:
  {
    "disabled_rules": ["sql_drop_index"],       // выключить конкретные правила
    "allowlist": ["^pg_dump\\\\b"],              // команды, которые никогда не трогаем
    "custom_rules": [                            // свои проектные правила
      {"name": "no_prod_seed", "severity": "critical",
       "pattern": "seed\\\\.py --env=prod", "description": "Сид прод-базы"}
    ]
  }
"""
import json
import os
import re

CRITICAL = "critical"
WARNING = "warning"

# (name, severity, pattern, human-readable description)
_RULES_RAW = [
    # ── Чистый SQL ──────────────────────────────────────────────────────────
    ("sql_drop_database", CRITICAL, r"\bDROP\s+DATABASE\b", "Удаление базы данных (DROP DATABASE)"),
    ("sql_drop_table", CRITICAL, r"\bDROP\s+TABLE\b", "Удаление таблицы (DROP TABLE)"),
    ("sql_drop_schema", CRITICAL, r"\bDROP\s+SCHEMA\b", "Удаление схемы (DROP SCHEMA)"),
    ("sql_truncate", CRITICAL, r"\bTRUNCATE\s+(TABLE\s+)?\S+", "Полная очистка таблицы (TRUNCATE)"),
    ("sql_drop_index", WARNING, r"\bDROP\s+INDEX\b", "Удаление индекса (DROP INDEX)"),
    ("sql_alter_drop_column", WARNING, r"\bALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\b",
     "Удаление колонки (ALTER TABLE ... DROP COLUMN)"),

    # ── CLI СУБД ────────────────────────────────────────────────────────────
    ("pg_dropdb", CRITICAL, r"\bdropdb\b", "Удаление базы Postgres (dropdb)"),
    ("mysql_drop", CRITICAL, r"\bmysqladmin\b.*\bdrop\b", "Удаление базы MySQL (mysqladmin drop)"),

    # ── Миграционные фреймворки / ORM ───────────────────────────────────────
    ("prisma_migrate_reset", CRITICAL, r"\bprisma\s+migrate\s+reset\b", "Сброс базы (Prisma migrate reset)"),
    ("prisma_force_reset", CRITICAL, r"\bprisma\s+db\s+push\b.*--force-reset\b",
     "Пересоздание базы (Prisma db push --force-reset)"),
    ("rails_db_drop", CRITICAL, r"\brails\s+db:(drop|reset|purge)\b", "Удаление/сброс базы Rails"),
    ("django_flush", CRITICAL, r"\bmanage\.py\s+flush\b", "Очистка всех данных Django (flush)"),
    ("alembic_downgrade_base", CRITICAL, r"\balembic\s+downgrade\s+base\b",
     "Откат всех миграций Alembic до пустой базы"),
    ("flask_downgrade", WARNING, r"\bflask\s+db\s+downgrade\b", "Откат миграции Flask-Migrate"),
    ("knex_rollback_all", CRITICAL, r"\bknex\s+migrate:rollback\s+--all\b", "Откат всех миграций Knex"),
    ("knex_rollback", WARNING, r"\bknex\s+migrate:rollback\b", "Откат миграции Knex"),
    ("sequelize_undo_all", CRITICAL, r"\bsequelize\s+db:migrate:undo:all\b", "Откат всех миграций Sequelize"),
    ("goose_down_zero", CRITICAL, r"\bgoose\b.*\bdown-to\s+0\b", "Откат всех миграций Goose до нуля"),
    ("typeorm_schema_drop", CRITICAL, r"\btypeorm\s+schema:drop\b", "Удаление всей схемы (TypeORM schema:drop)"),
    ("dbmate_drop", CRITICAL, r"\bdbmate\s+drop\b", "Удаление базы (dbmate drop)"),

    # ── Управляемые/облачные БД CLI ─────────────────────────────────────────
    ("supabase_db_reset", CRITICAL, r"\bsupabase\s+db\s+reset\b", "Полный сброс локальной Supabase БД"),
    ("supabase_projects_delete", CRITICAL, r"\bsupabase\s+projects\s+delete\b", "Удаление проекта Supabase"),
    ("wrangler_d1_drop", CRITICAL, r"\bwrangler\s+d1\b.*\bDROP\b", "Удаление таблицы Cloudflare D1"),
    ("turso_db_destroy", CRITICAL, r"\bturso\s+db\s+destroy\b", "Удаление базы Turso"),

    # ── NoSQL ───────────────────────────────────────────────────────────────
    ("mongo_drop_database", CRITICAL, r"\bdropDatabase\s*\(", "Удаление базы MongoDB (dropDatabase())"),
    ("mongo_drop_collection", CRITICAL, r"\.drop\s*\(\s*\)", "Удаление коллекции MongoDB (.drop())"),
    ("mongo_delete_all", CRITICAL, r"\bdeleteMany\s*\(\s*\{\s*\}\s*\)",
     "Удаление всех документов MongoDB (deleteMany({}))"),
    ("mongo_remove_all", CRITICAL, r"\.remove\s*\(\s*\{\s*\}\s*\)",
     "Удаление всех документов MongoDB (remove({}))"),
    ("redis_flush", CRITICAL, r"\bFLUSH(ALL|DB)\b", "Полная очистка Redis (FLUSHALL/FLUSHDB)"),

    # ── Файловая система / инфраструктура с данными ─────────────────────────
    ("rm_db_file", CRITICAL, r"\brm\s+.*\.(db|sqlite3?|rdb|dump|bak)\b",
     "Удаление файла базы данных / бэкапа через rm"),
    ("rm_data_dir", WARNING, r"\brm\s+-rf?\b.*(pgdata|/var/lib/(postgresql|mysql)|/data/db)\b",
     "Удаление каталога данных БД через rm -rf"),
    ("truncate_db_redirect", WARNING, r">\s*\S+\.(db|sqlite3?)\b",
     "Перезапись файла базы через > (обнуление .db/.sqlite)"),
    ("docker_volume_rm", CRITICAL, r"\bdocker(\s+compose|-compose)?\s+(down\s+-v\b|volume\s+rm\b|volume\s+prune\b)",
     "Удаление Docker-тома (может содержать данные БД)"),
    ("docker_prune_volumes", CRITICAL, r"\bdocker\s+system\s+prune\b.*--volumes\b",
     "Очистка Docker с томами (docker system prune --volumes)"),
    ("kubectl_delete_pvc", CRITICAL, r"\bkubectl\s+delete\s+(pvc|persistentvolumeclaim)\b",
     "Удаление тома Kubernetes (kubectl delete pvc)"),
    ("terraform_destroy", CRITICAL, r"\bterraform\s+destroy\b", "Уничтожение инфраструктуры (terraform destroy)"),
]

BASE_RULES = [(name, sev, re.compile(pat, re.I), desc) for name, sev, pat, desc in _RULES_RAW]

# Имена «правил»-эвристик — чтобы их тоже можно было выключить через config.
HEURISTIC_DELETE = "sql_delete_no_where"
HEURISTIC_UPDATE = "sql_update_no_where"

# Предикаты WHERE, которые фактически ничего не фильтруют (истинны всегда).
_TRIVIAL_WHERE = re.compile(
    r"\bWHERE\s+(1\s*=\s*1|true|'?1'?\s*=\s*'?1'?|'([^']*)'\s*=\s*'\2')\b", re.I)


def load_config(base_dir):
    """Читает .klyvo/config.json, если он есть. Любая ошибка → пустой конфиг."""
    if not base_dir:
        return {}
    path = os.path.join(base_dir, ".klyvo", "config.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _compile_custom(config):
    rules = []
    for item in config.get("custom_rules", []) or []:
        try:
            rules.append((
                item["name"],
                CRITICAL if item.get("severity", CRITICAL) == CRITICAL else WARNING,
                re.compile(item["pattern"], re.I),
                item.get("description", item["name"]),
            ))
        except (KeyError, re.error):
            continue  # битое правило игнорируем, не роняем весь скан
    return rules


def effective_rules(config=None):
    """Список действующих правил с учётом disabled_rules и custom_rules."""
    config = config or {}
    disabled = set(config.get("disabled_rules", []) or [])
    rules = [r for r in BASE_RULES if r[0] not in disabled]
    rules.extend(r for r in _compile_custom(config) if r[0] not in disabled)
    return rules


def _is_allowlisted(command, config):
    for pat in config.get("allowlist", []) or []:
        try:
            if re.search(pat, command, re.I):
                return True
        except re.error:
            continue
    return False


def _has_effective_where(stmt: str) -> bool:
    if not re.search(r"\bWHERE\b", stmt, re.I):
        return False
    if _TRIVIAL_WHERE.search(stmt):
        return False  # WHERE 1=1 / WHERE true — фильтр-обманка
    return True


def _scan_where_heuristics(command: str, disabled):
    findings = []
    # Разбиваем только по ';' — по '\n' нельзя, иначе многострочный
    # `DELETE FROM x\n WHERE ...` ложно определится как «без WHERE».
    for stmt in command.split(";"):
        if HEURISTIC_DELETE not in disabled:
            if re.search(r"\bDELETE\s+FROM\s+\S+", stmt, re.I) and not _has_effective_where(stmt):
                findings.append((HEURISTIC_DELETE, CRITICAL,
                                 "Удаление строк без ограничивающего WHERE (сотрёт всю таблицу)"))
        if HEURISTIC_UPDATE not in disabled:
            if re.search(r"\bUPDATE\s+\S+\s+SET\b", stmt, re.I) and not _has_effective_where(stmt):
                findings.append((HEURISTIC_UPDATE, CRITICAL,
                                 "Массовое обновление без ограничивающего WHERE"))
    return findings


def scan(command: str, config=None):
    """Возвращает список находок: (name, severity, description).

    config — dict из load_config(). Команды из allowlist не сканируются.
    """
    config = config or {}
    if _is_allowlisted(command, config):
        return []
    disabled = set(config.get("disabled_rules", []) or [])
    findings = []
    for name, severity, pattern, description in effective_rules(config):
        if pattern.search(command):
            findings.append((name, severity, description))
    findings.extend(_scan_where_heuristics(command, disabled))
    return findings
