import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import quote


DEFAULT_TOPIC_URL = "https://linux.do/t/topic/1884177"
DEFAULT_ANSWER = "zy066"
DEFAULT_HOTARU = "mazhichen8780"
DEFAULT_ANSWER_PATH = "/api/levels/13/answer"
DEFAULT_CAPTCHA_PATH = "/api/captcha"
DEFAULT_REQUEST_TIMEOUT_MS = 30000


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
        [resolve_agent_browser(), "--auto-connect", *args],
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


def switch_tab(tab: int | None) -> int:
    target = tab if tab is not None else find_ctf_tab()
    if target is None:
        raise RuntimeError("CTF tab not found")
    run_agent("tab", str(target))
    return target


def browser_eval(js: str) -> str:
    return run_agent("eval", js)


def browser_request_json(
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    timeout_ms: int = DEFAULT_REQUEST_TIMEOUT_MS,
) -> dict[str, Any]:
    body_json = json.dumps(body, ensure_ascii=False) if body is not None else None
    body_assignment = f"options.body=JSON.stringify({body_json});" if body_json is not None else ""

    js = (
        "(async()=>{"
        f"const controller=new AbortController();"
        f"const timer=setTimeout(()=>controller.abort('timeout'),{timeout_ms});"
        "try{"
        f"const options={{method:{json.dumps(method)},headers:{{'Content-Type':'application/json'}},credentials:'same-origin',signal:controller.signal}};"
        f"{body_assignment}"
        f"const response=await fetch({json.dumps(path)},options);"
        "const text=await response.text();"
        "let data=text;"
        "try{data=JSON.parse(text);}catch(_error){}"
        "return JSON.stringify({status:response.status,ok:response.ok,headers:Object.fromEntries(response.headers.entries()),data});"
        "}catch(error){"
        "return JSON.stringify({status:0,ok:false,headers:{},error:String(error),data:null});"
        "}finally{clearTimeout(timer);}"
        "})()"
    )
    raw = browser_eval(js)
    parsed = json.loads(raw)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


def coerce_json_object(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


def solve_captcha(question: str) -> int:
    normalized = (
        question.replace("−", "-")
        .replace("—", "-")
        .replace("–", "-")
        .replace("﹣", "-")
        .replace("－", "-")
        .replace("×", "*")
        .replace("÷", "/")
        .replace("��", "-")
    )
    match = re.search(r"(-?\d+)\s*([+\-*/xX])\s*(-?\d+)", normalized)
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


def build_level13_answer_path(answer_path: str, hotaru: str | None) -> str:
    normalized_path = answer_path.strip()
    if not hotaru:
        return normalized_path

    separator = "&" if "?" in normalized_path else "?"
    return f"{normalized_path}{separator}hotaru={quote(hotaru, safe='')}"


def submit_level_answer(
    *,
    answer: str,
    captcha_path: str,
    answer_path: str,
    timeout_ms: int,
) -> dict[str, Any]:
    captcha_response = browser_request_json(captcha_path, timeout_ms=timeout_ms)
    captcha_data = coerce_json_object(captcha_response["data"])
    if not isinstance(captcha_data, dict):
        raise TypeError(f"unexpected captcha payload: {captcha_data!r}")
    captcha_answer = solve_captcha(captcha_data["question"])
    submit_response = browser_request_json(
        answer_path,
        method="POST",
        body={
            "answer": f"muyuan{{{normalize_flag(answer)}}}",
            "captchaId": captcha_data["id"],
            "captchaAnswer": captcha_answer,
        },
        timeout_ms=timeout_ms,
    )
    submit_response["data"] = coerce_json_object(submit_response["data"])
    return {"captcha": captcha_response, "submit": submit_response}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 13 Hotaru helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--answer", default=DEFAULT_ANSWER)
    parser.add_argument("--hotaru", default=DEFAULT_HOTARU)
    parser.add_argument("--topic-url", default=DEFAULT_TOPIC_URL)
    parser.add_argument("--answer-path", default=DEFAULT_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_REQUEST_TIMEOUT_MS)
    parser.add_argument("--submit-level-answer", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    output: dict[str, Any] = {
        "topicUrl": args.topic_url,
        "answer": normalize_flag(args.answer),
        "hotaru": args.hotaru,
    }

    if args.submit_level_answer:
        output["levelSubmit"] = submit_level_answer(
            answer=normalize_flag(args.answer),
            captcha_path=args.captcha_path,
            answer_path=build_level13_answer_path(args.answer_path, args.hotaru),
            timeout_ms=args.timeout_ms,
        )

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
