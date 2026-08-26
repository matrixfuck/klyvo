#!/usr/bin/env python3
"""JS-плагин opencode — исполняется по-настоящему, а не сверяется по тексту.

Остальные тесты по opencode проверяют только, что в сгенерированном файле есть
нужные строки. Это ничего не говорит о поведении: плагин может не парситься,
звать ядро правил не так или проглатывать блокировку в своём catch. Здесь плагин
импортируется в node и вызывается с полезной нагрузкой той формы, которую
передаёт opencode в хук tool.execute.before.

Чего этот тест НЕ доказывает: что opencode действительно шлёт именно такую
нагрузку и что брошенное исключение реально отменяет команду. Это проверяется
только живым запуском opencode.

Пропускается, если в системе нет node.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import install_hooks  # noqa: E402

fail = 0


def check(desc, cond):
    global fail
    print(f"[{'OK' if cond else 'FAIL'}] {desc}")
    if not cond:
        fail += 1


NODE = shutil.which("node")
if not NODE:
    print("SKIP: node не найден — тест JS-плагина opencode пропущен")
    sys.exit(0)

work = tempfile.mkdtemp(prefix="klyvo-opencode-")
plugin = os.path.join(work, "klyvo.mjs")   # .mjs, чтобы node принял ESM-импорты
install_hooks.main(["--tool", "opencode", "--path", plugin])
check("плагин сгенерирован", os.path.exists(plugin))

# Драйвер прогоняет плагин по набору случаев и печатает результат построчно.
driver = os.path.join(work, "run.mjs")
with open(driver, "w", encoding="utf-8") as f:
    f.write(
        'import { KlyvoGuard } from "%s";\n'
        "const hook = (await KlyvoGuard())[\"tool.execute.before\"];\n"
        "const cases = JSON.parse(process.argv[2]);\n"
        "for (const c of cases) {\n"
        "  let verdict = 'passed';\n"
        "  try { await hook(c.input, c.output); }\n"
        "  catch (e) { verdict = 'blocked: ' + String(e && e.message).slice(0, 120); }\n"
        "  console.log(c.name + '\\t' + verdict);\n"
        "}\n" % plugin
    )


def bash(cmd):
    return {"input": {"tool": "bash"}, "output": {"args": {"command": cmd}}}


cases = [
    dict(name="critical", **bash("psql -c 'DR" + "OP TABLE users'")),
    dict(name="safe", **bash("ls -la /tmp")),
    dict(name="warning", **bash("rm -rf .")),
    dict(name="other_tool", input={"tool": "read"}, output={"args": {"command": "psql -c 'DR" + "OP TABLE users'"}}),
    dict(name="no_command", input={"tool": "bash"}, output={"args": {}}),
    dict(name="empty_input", input=None, output=None),
]

# cwd задаём явно: плагин зовёт ядро с --log, и журнал ляжет туда, откуда
# запущен node. Без этого прогон тестов дописывал бы записи в настоящий журнал
# того, кто их запускает.
project = os.path.join(work, "project")
os.makedirs(project, exist_ok=True)
env = dict(os.environ)
env.pop("CLAUDE_PROJECT_DIR", None)   # иначе корнем станет чужой проект
proc = subprocess.run([NODE, driver, json.dumps(cases)], cwd=project, env=env,
                      capture_output=True, text=True, timeout=60)
if proc.returncode != 0:
    print("[FAIL] плагин не исполнился в node")
    print(proc.stderr[:1500])
    sys.exit(1)

res = dict(line.split("\t", 1) for line in proc.stdout.strip().splitlines())
check("плагин импортируется и хук вызывается", len(res) == len(cases))
check("разрушительная команда заблокирована", res.get("critical", "").startswith("blocked"))
check("в тексте блокировки названа причина",
      "Klyvo" in res.get("critical", "") and len(res.get("critical", "")) > len("blocked: Klyvo заблокировал разрушительную команду: "))
check("безопасная команда проходит", res.get("safe") == "passed")
# В tool.execute.before подтверждение не выразить — только пропустить или
# прервать. Прерывать warning слишком грубо, поэтому он проходит, но не молча.
check("warning проходит, а не блокируется", res.get("warning") == "passed")
check("про warning сказано в stderr", "Klyvo" in proc.stderr)

# Журнал: без него у opencode работала бы только блокировка, а измерение — нет.
jpath = os.path.join(project, ".klyvo", "journal.jsonl")
check("журнал создан в проекте", os.path.exists(jpath))
entries = ([json.loads(l) for l in open(jpath, encoding="utf-8").read().splitlines() if l.strip()]
           if os.path.exists(jpath) else [])
check("в журнале указан инструмент opencode",
      bool(entries) and all(e.get("tool") == "opencode" for e in entries))
check("в журнал попали и блокировка, и предупреждение",
      {e.get("decision") for e in entries} == {"deny", "ask"})
check("чужой инструмент (не bash) не трогаем", res.get("other_tool") == "passed")
check("вызов без команды не роняет плагин", res.get("no_command") == "passed")
# Хук стоит в горячем пути агента: любая наша ошибка не должна валить чужую сессию.
check("мусорная нагрузка не роняет плагин (fail-open)", res.get("empty_input") == "passed")

shutil.rmtree(work, ignore_errors=True)
print("ВСЕ ТЕСТЫ ПРОШЛИ" if fail == 0 else f"{fail} ПРОВАЛЕННЫХ ТЕСТОВ")
sys.exit(1 if fail else 0)
