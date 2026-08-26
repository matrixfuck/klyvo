#!/bin/sh
# Klyvo — установка в одну команду.
#
#   curl -fsSL https://klyvo.tech/install.sh | sh
#   curl -fsSL https://klyvo.tech/install.sh | sh -s -- cursor      # другой агент
#
# Скрипт намеренно короткий, чтобы его можно было прочитать целиком перед
# запуском: это инструмент безопасности, и «запусти вслепую из интернета» —
# ровно тот сценарий, от которого он защищает. Всё, что он делает: проверяет
# python3 и git, кладёт репозиторий в ~/klyvo и запускает штатный установщик
# хуков. Ничего не удаляет и никуда не ходит, кроме GitHub.
#
# Переменные: KLYVO_DIR (куда класть, по умолчанию ~/klyvo),
#             KLYVO_TOOL (агент, по умолчанию claude).
set -eu

REPO="https://github.com/matrixfuck/klyvo.git"
DIR="${KLYVO_DIR:-$HOME/klyvo}"
TOOL="${1:-${KLYVO_TOOL:-claude}}"

die() { echo "Klyvo: $1" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "нужен git, поставь его и повтори."
command -v python3 >/dev/null 2>&1 || die "нужен python3, поставь его и повтори."

if [ -d "$DIR/.git" ]; then
    echo "Klyvo уже есть в $DIR — обновляю."
    git -C "$DIR" pull --ff-only --quiet || die "не смог обновить $DIR — обнови вручную: git -C $DIR pull"
elif [ -e "$DIR" ]; then
    die "$DIR уже существует и это не репозиторий Klyvo. Укажи другой путь: KLYVO_DIR=~/другой-путь"
else
    echo "Ставлю Klyvo в $DIR"
    git clone --quiet --depth 1 "$REPO" "$DIR" || die "не смог склонировать репозиторий."
fi

# Установщик сам печатает, какой файл он изменил и что именно дописал.
python3 "$DIR/tools/install_hooks.py" --tool "$TOOL"

cat <<EOF

Готово. Дальше:
  1. Перезапусти агента — хуки читаются при старте.
  2. Убедись, что защита реально работает:

       python3 $DIR/klyvo_rules.py doctor

     Проверяет весь путь: грузится ли ядро правил, отвечает ли хук отказом на
     разрушительную команду и вызывает ли его вообще твой агент.

Сводка по сессии:  python3 $DIR/klyvo_journal.py   (запускать в папке проекта)
Обновление:        git -C $DIR pull
Удалить хуки:      python3 $DIR/tools/install_hooks.py --tool $TOOL --uninstall
EOF
