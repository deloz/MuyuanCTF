import argparse
import base64
import codecs
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys


DEFAULT_LEVEL_PATH = "/api/levels/8"
DEFAULT_VERIFY_PATH = "/api/levels/8/verify-stage"
DEFAULT_ANSWER_PATH = "/api/levels/8/answer"
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


def solve_caesar_cipher(challenge: str) -> str:
    return codecs.decode(challenge, "rot_13")


def solve_multi_encoding(challenge: str) -> str:
    step1 = base64.b64decode(challenge).decode("utf-8")
    step2 = step1[::-1]
    step3 = bytes.fromhex(step2).decode("utf-8")
    return base64.b64decode(step3).decode("utf-8")


def solve_hash_crack(challenge: str) -> str:
    for value in range(10_000):
        pin = f"{value:04d}"
        if hashlib.md5(pin.encode("utf-8")).hexdigest() == challenge:
            return pin
    raise ValueError(f"hash not cracked: {challenge}")


def solve_stage(stage_type: str, challenge: str) -> str:
    if stage_type == "caesar_cipher":
        return solve_caesar_cipher(challenge)
    if stage_type == "multi_encoding":
        return solve_multi_encoding(challenge)
    if stage_type == "hash_crack":
        return solve_hash_crack(challenge)
    raise ValueError(f"unsupported stage type: {stage_type}")


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


def verify_stage(verify_path: str, stage: int, answer: str) -> dict:
    return browser_fetch_json(verify_path, method="POST", body={"stage": stage, "answer": answer})


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
    parser = argparse.ArgumentParser(description="Level 8 crypto gauntlet helper")
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
    stages = level_data["challenge"]["data"]["stages"]
    verifications: list[dict] = []

    final_flag = None
    for stage in stages:
        answer = solve_stage(stage["type"], stage["challenge"])
        result = verify_stage(args.verify_path, stage["id"], answer)
        verifications.append(
            {
                "stage": stage["id"],
                "type": stage["type"],
                "challenge": stage["challenge"],
                "answer": answer,
                "result": result,
            }
        )
        if result.get("flag"):
            final_flag = result["flag"]

    output: dict = {"verifications": verifications}
    if final_flag:
        output["flag"] = final_flag

    if args.submit_level_answer and final_flag:
        output["levelSubmit"] = submit_answer(final_flag, args.captcha_path, args.answer_path)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
