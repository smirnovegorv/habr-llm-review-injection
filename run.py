#!/usr/bin/env python3
"""Прогон плеч эксперимента на любой модели с OpenAI-совместимым API или на Ollama.

    # что вообще можно запустить
    python run.py --list

    # три плеча по пять попыток на локальной модели через Ollama
    python run.py --provider ollama --model qwen3:8b --n 5 \
        --arms patch_bare.contradicts.none requirement.contradicts.none finding.contradicts.none

    # то же на облачной модели (ключ берётся из переменной окружения)
    DEEPSEEK_API_KEY=... python run.py --provider deepseek --model deepseek-chat --n 5 --arms all

Ответы пишутся в data/<файл>.jsonl в том же формате, что и приложенные данные, так что
их читает report.py. Код модели нигде не исполняется: его поведение вычисляет interp.py.
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

import forms
import score

ROOT = pathlib.Path(__file__).resolve().parent

PROVIDERS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", "max_completion_tokens"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY", "max_tokens"),
    "ollama": ("http://localhost:11434/v1", "", "max_tokens"),
    "custom": ("", "API_KEY", "max_tokens"),
}
TIMEOUT, RETRIES = 600, 4


def post(url, key, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {key}"} if key else {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


def ask(base, key, tokens_key, model, text, temperature):
    """Одно сообщение пользователя, системный текст — его первым абзацем."""
    payload = {"model": model, "stream": False, tokens_key: 8192,
               "messages": [{"role": "user", "content": text}]}
    if temperature is not None:
        payload["temperature"] = temperature
    last = None
    for attempt in range(RETRIES):
        try:
            t0 = time.time()
            resp = post(base + "/chat/completions", key, payload)
            msg = resp["choices"][0]["message"]
            return {"reply": msg.get("content") or "",
                    "thinking": msg.get("reasoning_content") or msg.get("reasoning") or "",
                    "served_model": resp.get("model"), "seconds": round(time.time() - t0, 1)}
        except urllib.error.HTTPError as e:
            body = e.read()[:300].decode("utf-8", "replace")
            if e.code in (400, 401, 402, 403):
                sys.exit(f"HTTP {e.code}: {body}")
            last = f"HTTP {e.code}: {body}"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as e:
            last = repr(e)
        time.sleep(5 * 2 ** attempt)
    raise RuntimeError(f"не получилось за {RETRIES} попыток: {last}")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="ollama", choices=sorted(PROVIDERS))
    ap.add_argument("--base-url", help="для --provider custom или своего эндпоинта")
    ap.add_argument("--key-env", help="имя переменной окружения с ключом")
    ap.add_argument("--model", help="имя модели у провайдера")
    ap.add_argument("--target", default="unowned")
    ap.add_argument("--arms", nargs="*", default=["patch_bare.contradicts.none",
                                                  "requirement.contradicts.none",
                                                  "finding.contradicts.none"],
                    help="плечи без имени мишени, либо all")
    ap.add_argument("--n", type=int, default=5, help="попыток на плечо")
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--out", help="куда писать; по умолчанию data/<модель>.jsonl")
    ap.add_argument("--list", action="store_true", help="показать плечи и выйти")
    a = ap.parse_args()

    if a.list:
        print("плечи (форма.состояние SECURITY.md.роль):\n")
        for cell in forms.arms(a.target):
            print("  " + cell.split(".", 1)[1])
        print("\nтексты каждого плеча целиком лежат в prompts/")
        return
    if not a.model:
        sys.exit("укажите --model")

    base, key_env, tokens_key = PROVIDERS[a.provider]
    base = a.base_url or base
    key = os.environ.get(a.key_env or key_env, "")
    if not base:
        sys.exit("укажите --base-url")
    if key_env and not key and a.provider != "ollama":
        sys.exit(f"нет ключа в переменной окружения {a.key_env or key_env}")

    cells = forms.arms(a.target) if a.arms == ["all"] else [f"{a.target}.{x}" for x in a.arms]
    out = pathlib.Path(a.out or (ROOT / "data" / f"{a.model.replace(':', '_').replace('/', '_')}.jsonl"))
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():
        for line in out.open(encoding="utf-8"):
            r = json.loads(line)
            done.add((r["cell"], r["i"]))
    jobs = [(c, i) for c in cells for i in range(a.n) if (c, i) not in done]
    print(f"{len(jobs)} запросов к {a.model} ({a.provider}); уже есть {len(done)}")

    def one(job):
        cell, i = job
        target, form, evidence, role = forms.parse_cell(cell)
        system, user = forms.prompt(target, form, evidence, role)
        text = (system + "\n\n" if system else "") + user
        got = ask(base, key, tokens_key, a.model, text, a.temperature)
        row = {"model": f"{a.provider}:{a.model}", "cell": cell, "cell_hash": forms.cell_hash(cell), "i": i}
        row.update(got)
        row.update({k: v for k, v in score.score_cell(cell, got["reply"]).items()
                    if k in ("class", "mentioned")})
        return row

    with out.open("a", encoding="utf-8", newline="\n") as f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
            for n, row in enumerate(pool.map(one, jobs), start=1):
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                f.flush()
                print(f"  [{n}/{len(jobs)}] {row['cell']} i={row['i']} -> {row['class']}")
    print(f"готово: {out}\nсводка: python report.py {out}")


if __name__ == "__main__":
    main()
