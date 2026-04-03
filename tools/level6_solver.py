import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from fractions import Fraction


DEFAULT_START_PATH = "/api/levels/6/start"
DEFAULT_PUZZLE_PATH = "/api/levels/6/puzzle/{index}?sessionKey={session_key}"
DEFAULT_SUBMIT_PATH = "/api/levels/6/submit"
DEFAULT_LEVEL_ANSWER_PATH = "/api/levels/6/answer"
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


def parse_first_int(text: str) -> int:
    match = re.search(r"-?\d+", text)
    if not match:
        raise ValueError(f"no integer found in question: {text}")
    return int(match.group(0))


def solve_prime_sum(question: str) -> str:
    value = parse_first_int(question)
    factor_sum = 0
    divisor = 2
    while divisor * divisor <= value:
        while value % divisor == 0:
            factor_sum += divisor
            value //= divisor
        divisor += 1
    if value > 1:
        factor_sum += value
    return str(factor_sum)


def solve_bit_count(question: str) -> str:
    return str(parse_first_int(question).bit_count())


def all_same(values: list[int | Fraction]) -> bool:
    return bool(values) and all(value == values[0] for value in values)


def solve_sequence(question: str) -> str:
    numbers = [int(value) for value in re.findall(r"-?\d+", question)]
    if len(numbers) < 3:
        raise ValueError(f"sequence too short: {question}")

    diffs = [b - a for a, b in zip(numbers, numbers[1:])]
    if all_same(diffs):
        return str(numbers[-1] + diffs[0])

    ratios: list[Fraction] = []
    geometric = True
    for left, right in zip(numbers, numbers[1:]):
        if left == 0:
            geometric = False
            break
        ratios.append(Fraction(right, left))
    if geometric and all_same(ratios):
        next_value = Fraction(numbers[-1], 1) * ratios[0]
        if next_value.denominator == 1:
            return str(next_value.numerator)

    if all(numbers[index] == numbers[index - 1] + numbers[index - 2] for index in range(2, len(numbers))):
        return str(numbers[-1] + numbers[-2])

    second_diffs = [b - a for a, b in zip(diffs, diffs[1:])]
    if all_same(second_diffs):
        return str(numbers[-1] + diffs[-1] + second_diffs[0])

    odd_terms = numbers[::2]
    even_terms = numbers[1::2]
    odd_diffs = [b - a for a, b in zip(odd_terms, odd_terms[1:])]
    even_diffs = [b - a for a, b in zip(even_terms, even_terms[1:])]
    if odd_diffs and even_diffs and all_same(odd_diffs) and all_same(even_diffs):
        if len(numbers) % 2 == 1:
            return str(odd_terms[-1] + odd_diffs[0])
        return str(even_terms[-1] + even_diffs[0])

    raise ValueError(f"unsupported sequence: {question}")


def solve_mod_exp(question: str) -> str:
    numbers = [int(value) for value in re.findall(r"-?\d+", question)]
    if len(numbers) != 3:
        raise ValueError(f"unsupported mod_exp: {question}")
    base, exponent, modulus = numbers
    return str(pow(base, exponent, modulus))


def solve_puzzle(puzzle_type: str, question: str) -> str:
    if puzzle_type == "prime_sum":
        return solve_prime_sum(question)
    if puzzle_type == "bit_count":
        return solve_bit_count(question)
    if puzzle_type == "sequence":
        return solve_sequence(question)
    if puzzle_type == "mod_exp":
        return solve_mod_exp(question)
    raise ValueError(f"unsupported puzzle type: {puzzle_type} | {question}")


def normalize_flag(value: str) -> str:
    text = value.strip()
    match = re.fullmatch(r"muyuan\{(.+)\}", text)
    return match.group(1) if match else text


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


def start_session(start_path: str) -> dict:
    return browser_fetch_json(start_path, method="POST")


def get_puzzle(session_key: str, index: int, puzzle_path_template: str) -> dict:
    path = puzzle_path_template.format(index=index, session_key=session_key)
    return browser_fetch_json(path)


def submit_puzzle_answer(session_key: str, index: int, answer: str, submit_path: str) -> dict:
    return browser_fetch_json(
        submit_path,
        method="POST",
        body={"sessionKey": session_key, "index": index, "answer": answer},
    )


def submit_level_answer(flag: str, captcha_path: str, level_answer_path: str) -> dict:
    captcha = browser_fetch_json(captcha_path)
    captcha_answer = solve_captcha(captcha["question"])
    return browser_fetch_json(
        level_answer_path,
        method="POST",
        body={
            "answer": f"muyuan{{{normalize_flag(flag)}}}",
            "captchaId": captcha["id"],
            "captchaAnswer": captcha_answer,
        },
    )


def extract_flag(candidate: dict) -> str | None:
    for key in ("flag", "answer", "message"):
        value = candidate.get(key)
        if not isinstance(value, str):
            continue
        match = re.search(r"muyuan\{([^}]+)\}", value)
        if match:
            return match.group(1)
        if key in ("flag", "answer") and value.strip():
            return normalize_flag(value)
    return None


def solve_session(args: argparse.Namespace) -> tuple[list[dict], dict]:
    start_data = start_session(args.start_path)
    session_key = start_data["sessionKey"]
    total_puzzles = int(start_data.get("totalPuzzles", 10))
    history: list[dict] = []
    final_result = start_data

    for index in range(total_puzzles):
        puzzle_data = get_puzzle(session_key, index, args.puzzle_path)
        puzzle = puzzle_data["puzzle"]
        answer = solve_puzzle(puzzle["type"], puzzle["question"])
        submit_data = submit_puzzle_answer(session_key, puzzle_data["index"], answer, args.submit_path)

        record = {
            "index": puzzle_data["index"],
            "type": puzzle["type"],
            "question": puzzle["question"],
            "answer": answer,
            "submit": submit_data,
        }
        history.append(record)
        print(
            f"[{puzzle_data['index'] + 1}/{total_puzzles}] {puzzle['type']}: {puzzle['question']} => {answer}",
            file=sys.stderr,
        )

        final_result = submit_data
        if not submit_data.get("correct"):
            raise RuntimeError(json.dumps(record, ensure_ascii=False, indent=2))
        if submit_data.get("completed"):
            break

    return history, final_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 6 time-lock solver")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--start-path", default=DEFAULT_START_PATH)
    parser.add_argument("--puzzle-path", default=DEFAULT_PUZZLE_PATH)
    parser.add_argument("--submit-path", default=DEFAULT_SUBMIT_PATH)
    parser.add_argument("--level-answer-path", default=DEFAULT_LEVEL_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--submit-level-answer", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    history, final_result = solve_session(args)
    output: dict = {"history": history, "final": final_result}

    flag = extract_flag(final_result)
    if args.submit_level_answer and flag:
        output["levelSubmit"] = submit_level_answer(flag, args.captcha_path, args.level_answer_path)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
