import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any


DEFAULT_LEVEL_PATH = "/api/levels/12"
DEFAULT_ANSWER_PATH = "/api/levels/12/answer"
DEFAULT_CAPTCHA_PATH = "/api/captcha"
DEFAULT_REQUEST_TIMEOUT_MS = 30000
KNOWN_LAYER2_KEY = "MAZE"
KNOWN_LAYER2_PLAINTEXT = "HYDRA"


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
    headers: dict[str, str] | None = None,
    timeout_ms: int = DEFAULT_REQUEST_TIMEOUT_MS,
) -> dict[str, Any]:
    request_headers = dict(headers or {})
    body_json = json.dumps(body, ensure_ascii=False) if body is not None else None
    headers_json = json.dumps(request_headers, ensure_ascii=False)
    body_assignment = f"options.body=JSON.stringify({body_json});" if body_json is not None else ""

    js = (
        "(async()=>{"
        f"const controller=new AbortController();"
        f"const timer=setTimeout(()=>controller.abort('timeout'),{timeout_ms});"
        "try{"
        f"const options={{method:{json.dumps(method)},headers:{headers_json},credentials:'same-origin',signal:controller.signal}};"
        f"{body_assignment}"
        f"const response=await fetch({json.dumps(path)},options);"
        "const text=await response.text();"
        "let data=text;"
        "try{data=JSON.parse(text);}catch(_error){}"
        "return JSON.stringify({"
        "status:response.status,"
        "ok:response.ok,"
        "headers:Object.fromEntries(response.headers.entries()),"
        "data"
        "});"
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


def post_json_with_cf_retry(
    path: str,
    body: dict[str, Any],
    *,
    cf_ray: str | None,
    timeout_ms: int,
) -> dict[str, Any]:
    header_sets: list[dict[str, str]] = []
    if cf_ray:
        header_sets.append({"Content-Type": "application/json", "cf-ray": cf_ray})
    header_sets.append({"Content-Type": "application/json"})

    last_response: dict[str, Any] | None = None
    for request_headers in header_sets:
        response = browser_request_json(
            path,
            method="POST",
            body=body,
            headers=request_headers,
            timeout_ms=timeout_ms,
        )
        last_response = response
        if response.get("status"):
            return response
    if last_response is None:
        raise RuntimeError("no response generated for POST request")
    return last_response


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


def solve_layer1(layer1: dict[str, Any]) -> tuple[str, str]:
    tables = layer1["tables"]
    fragments: dict[int, str] = {}
    salt: str | None = None

    for table in tables:
        data_hex = table["data_hex"]
        checksum = table["checksum"]
        matches = [
            index
            for index in range(len(tables))
            if hashlib.md5(f"frag:{index}:{data_hex}".encode("utf-8")).hexdigest()[:8] == checksum
        ]
        if len(matches) != 1:
            raise ValueError(f"failed to resolve fragment index for {data_hex}: {matches}")
        fragments[matches[0]] = data_hex

        for value in table.values():
            if not isinstance(value, str):
                continue
            salt_match = re.search(r"salt=([A-Za-z0-9_-]+)", value)
            if salt_match:
                salt = salt_match.group(1)

    if len(fragments) != len(tables):
        raise ValueError("layer1 fragments are incomplete")
    if not salt:
        raise ValueError("layer1 salt not found")

    ordered_hex = "".join(fragments[index] for index in sorted(fragments))
    return bytes.fromhex(ordered_hex).decode("ascii"), salt


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result: list[str] = []
    for index, char in enumerate(ciphertext):
        cipher_value = ord(char) - ord("A")
        key_value = ord(key[index % len(key)]) - ord("A")
        result.append(chr(((cipher_value - key_value) % 26) + ord("A")))
    return "".join(result)


def solve_layer2(layer2: dict[str, Any]) -> tuple[str, str]:
    ciphertext = layer2["ciphertext"]
    key_length = layer2["key_length"]
    known_pair = layer2["known_pair"]

    if key_length != len(KNOWN_LAYER2_KEY):
        raise ValueError(f"unexpected layer2 key length: {key_length}")
    if known_pair["plaintext"] != KNOWN_LAYER2_PLAINTEXT[0]:
        raise ValueError("unexpected layer2 known plaintext")
    if known_pair["ciphertext"] != ciphertext[0]:
        raise ValueError("unexpected layer2 known ciphertext")

    derived_first_key = chr(
        ((ord(ciphertext[0]) - ord(known_pair["plaintext"])) % 26) + ord("A")
    )
    if derived_first_key != KNOWN_LAYER2_KEY[0]:
        raise ValueError(f"unexpected layer2 key prefix: {derived_first_key}")

    plaintext = vigenere_decrypt(ciphertext, KNOWN_LAYER2_KEY)
    if plaintext != KNOWN_LAYER2_PLAINTEXT:
        raise ValueError(f"unexpected layer2 plaintext: {plaintext}")

    return plaintext, KNOWN_LAYER2_KEY


def solve_layer3(layer3: dict[str, Any]) -> dict[str, Any]:
    blue_values = [int(pixel.split(",")[2]) for pixel in layer3["pixels"].split(";")]
    lsb_bits = "".join(str(value & 1) for value in blue_values)
    filler_bits = {
        "offset1_all_zero": set(lsb_bits[1::3]) <= {"0"},
        "offset2_all_zero": set(lsb_bits[2::3]) <= {"0"},
    }

    payload_bits = lsb_bits[::3]
    usable_length = len(payload_bits) // 8 * 8
    payload_bytes = bytes(
        int(payload_bits[index : index + 8], 2) for index in range(0, usable_length, 8)
    )
    key3 = payload_bytes.split(b"\x00", 1)[0].decode("ascii")
    if not key3:
        raise ValueError("layer3 produced an empty key")

    return {
        "key": key3,
        "payloadBits": payload_bits,
        "payloadBytesHex": payload_bytes.hex(),
        "fillerBits": filler_bits,
    }


def solve_pow(challenge: str, *, prefix: str = "00000", limit: int = 10_000_000) -> tuple[int, str]:
    start = time.perf_counter()
    for nonce in range(limit):
        digest = hashlib.sha256(f"{challenge}{nonce}".encode("utf-8")).hexdigest()
        if digest.startswith(prefix):
            _elapsed = time.perf_counter() - start
            return nonce, digest
    raise RuntimeError(f"no nonce found within {limit} iterations")


def compute_hmac_candidates(
    *,
    key1: str,
    key2: str,
    key3: str,
    pow_nonce: int,
    salt: str,
) -> dict[str, str]:
    payload = f"{key1}:{key2}:{key3}:{pow_nonce}".encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    return {
        "saltAsKey": hmac.new(salt_bytes, payload, hashlib.sha256).hexdigest().upper()[:12],
        "payloadAsKey": hmac.new(payload, salt_bytes, hashlib.sha256).hexdigest().upper()[:12],
    }


def iter_strings(value: Any) -> list[str]:
    items: list[str] = []
    if isinstance(value, str):
        items.append(value)
    elif isinstance(value, dict):
        for nested_value in value.values():
            items.extend(iter_strings(nested_value))
    elif isinstance(value, list):
        for nested_value in value:
            items.extend(iter_strings(nested_value))
    return items


def collect_answer_candidates(
    verification_response: dict[str, Any],
    hmac_candidates: dict[str, str],
) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(candidate: str | None) -> None:
        if not candidate:
            return
        normalized = normalize_flag(candidate)
        if normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    for text in iter_strings(verification_response.get("data")):
        muyuan_match = re.fullmatch(r"muyuan\{(.+)\}", text.strip())
        if muyuan_match:
            add(muyuan_match.group(1))
            continue

        hex_match = re.fullmatch(r"[A-F0-9]{8,64}", text.strip())
        if hex_match:
            add(text.strip())

    for candidate in hmac_candidates.values():
        add(candidate)

    return ordered


def submit_level_answer(
    *,
    answer: str,
    captcha_path: str,
    answer_path: str,
    cf_ray: str | None,
    timeout_ms: int,
) -> dict[str, Any]:
    captcha_response = browser_request_json(captcha_path, timeout_ms=timeout_ms)
    captcha_data = captcha_response["data"]
    captcha_answer = solve_captcha(captcha_data["question"])
    effective_cf_ray = captcha_response.get("headers", {}).get("cf-ray") or cf_ray

    submission_response = post_json_with_cf_retry(
        answer_path,
        {
            "answer": f"muyuan{{{normalize_flag(answer)}}}",
            "captchaId": captcha_data["id"],
            "captchaAnswer": captcha_answer,
        },
        cf_ray=effective_cf_ray,
        timeout_ms=timeout_ms,
    )
    return {"captcha": captcha_response, "submit": submission_response}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 12 final boss automation helper")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--level-path", default=DEFAULT_LEVEL_PATH)
    parser.add_argument("--answer-path", default=DEFAULT_ANSWER_PATH)
    parser.add_argument("--captcha-path", default=DEFAULT_CAPTCHA_PATH)
    parser.add_argument("--submit-level-answer", action="store_true")
    parser.add_argument("--pow-limit", type=int, default=5_000_000)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_REQUEST_TIMEOUT_MS)
    parser.add_argument("--without-cf-ray", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    switch_tab(args.tab)

    level_response = browser_request_json(args.level_path, timeout_ms=args.timeout_ms)
    if not level_response.get("status"):
        raise RuntimeError(f"failed to fetch level data: {level_response}")

    challenge_payload = level_response["data"]
    challenge_data = challenge_payload["challenge"]["data"]
    level_cf_ray = None if args.without_cf_ray else level_response.get("headers", {}).get("cf-ray")

    key1, salt = solve_layer1(challenge_data["layer1"])
    key2, layer2_key = solve_layer2(challenge_data["layer2"])
    layer3_result = solve_layer3(challenge_data["layer3"])
    key3 = layer3_result["key"]
    pow_nonce, pow_digest = solve_pow(
        challenge_data["layer4"]["challenge"],
        limit=args.pow_limit,
    )

    verify_final_path = challenge_data["layer5"]["verifyEndpoint"]
    verification_response = post_json_with_cf_retry(
        verify_final_path,
        {
            "sessionKey": challenge_data["sessionKey"],
            "key1": key1,
            "key2": key2,
            "key3": key3,
            "powNonce": pow_nonce,
        },
        cf_ray=level_cf_ray,
        timeout_ms=args.timeout_ms,
    )

    hmac_candidates = compute_hmac_candidates(
        key1=key1,
        key2=key2,
        key3=key3,
        pow_nonce=pow_nonce,
        salt=salt,
    )
    answer_candidates = collect_answer_candidates(verification_response, hmac_candidates)

    output: dict[str, Any] = {
        "sessionKey": challenge_data["sessionKey"],
        "cfRay": level_cf_ray,
        "layer1": {"key": key1, "salt": salt},
        "layer2": {"key": key2, "cipherKey": layer2_key},
        "layer3": layer3_result,
        "pow": {"nonce": pow_nonce, "digest": pow_digest},
        "verifyFinal": verification_response,
        "localHmacCandidates": hmac_candidates,
        "answerCandidates": answer_candidates,
    }

    if args.submit_level_answer:
        for candidate in answer_candidates:
            submission = submit_level_answer(
                answer=candidate,
                captcha_path=args.captcha_path,
                answer_path=args.answer_path,
                cf_ray=level_cf_ray,
                timeout_ms=args.timeout_ms,
            )
            output.setdefault("levelSubmissions", []).append(
                {"candidate": candidate, "result": submission}
            )

            submit_payload = submission["submit"].get("data")
            if isinstance(submit_payload, dict) and submit_payload.get("success"):
                break

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
