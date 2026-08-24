#!/usr/bin/env python3
"""Прогнать все наборы тестов разом и показать сводку.

Каждый файл в tests/ — самостоятельный скрипт со своим main и кодом возврата.
Запускать их по одному легко забыть: новый набор просто тихо не попадает в
прогон. Здесь они находятся по маске, поэтому забыть нельзя.

Набор, который печатает SKIP и выходит с нулём (нет node, нет Postgres),
считается пройденным — это осознанный пропуск, а не провал.
"""
import glob
import os
import subprocess
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

files = sorted(glob.glob(os.path.join(TESTS_DIR, "test_*.py")))
files.append(os.path.join(TESTS_DIR, "run_tests.py"))   # исторически без префикса test_

failed, skipped = [], []
for path in files:
    name = os.path.basename(path)
    proc = subprocess.run([sys.executable, path], capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        failed.append((name, out))
        mark = "ПРОВАЛ"
    elif "SKIP" in out:
        skipped.append(name)
        mark = "пропущен"
    else:
        mark = "ок"
    print(f"{name:32} {mark}")

if skipped:
    print("\nПропущено (не было чем проверять): " + ", ".join(skipped))

if failed:
    for name, out in failed:
        print(f"\n{'=' * 60}\n{name}\n{'=' * 60}\n{out.strip()[-3000:]}")
    print(f"\nПРОВАЛЕНО НАБОРОВ: {len(failed)} из {len(files)}")
    sys.exit(1)

print(f"\nВСЕ НАБОРЫ ПРОШЛИ: {len(files)}")
