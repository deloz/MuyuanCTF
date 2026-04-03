import argparse
import base64
import hashlib
import hmac
import itertools
import json
import math
import multiprocessing as mp
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from typing import Any


DEFAULT_ENTER_DREAM_PATH = "/api/levels/14/enter-dream"
DEFAULT_SOLVE_LAYER_PATH = "/api/levels/14/solve-layer"
DEFAULT_CAPTCHA_PATH = "/api/captcha"
DEFAULT_ANSWER_PATH = "/api/levels/14/answer"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_STOP_AFTER_LAYER = 7
DEFAULT_WORD_LIMIT = 120000
DEFAULT_POW_LIMIT = 50000000
BASE_URL = "https://ctf.centos.hk"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
LAYER2_PARTIAL_KEY = "4d415a??"
LAYER2_KNOWN_PREFIX = "LAYER2:"
LAYER1_EXPECTED_KEYS = {"cipher", "partialKey", "knownPrefix", "salt", "decoy1", "decoy2"}
LAYER5_BONUS_WORDS = {
    "A",
    "ABOUT",
    "AFTER",
    "AND",
    "ARE",
    "BEFORE",
    "BUT",
    "CAN",
    "DATA",
    "FINAL",
    "FOR",
    "FROM",
    "GET",
    "HAS",
    "HAVE",
    "HER",
    "HIDDEN",
    "HOW",
    "I",
    "IN",
    "IS",
    "IT",
    "LAYERS",
    "NETWORK",
    "NEURAL",
    "NOT",
    "OF",
    "ONE",
    "OUTPUT",
    "REALITY",
    "SHE",
    "SIGNAL",
    "THE",
    "THEIR",
    "THIS",
    "THROUGH",
    "TO",
    "WAS",
    "WHO",
    "WITH",
    "WITHOUT",
    "WORLD",
    "YOU",
}
LAYER5_EXTRA_WORDS = [
    "ALGORITHM",
    "ALGORITHMS",
    "ANOTHER",
    "BECOME",
    "BEFORE",
    "COMPUTER",
    "DATA",
    "DECODES",
    "DEEP",
    "DREAM",
    "DREAMS",
    "ENCODED",
    "FINAL",
    "FICTION",
    "FREQUENCY",
    "HIDDEN",
    "INCEPTION",
    "LANGUAGE",
    "LAYERS",
    "LEARNING",
    "MACHINE",
    "MEANING",
    "MEMORIES",
    "MEMORY",
    "MESSAGE",
    "MESSAGES",
    "MULTIPLE",
    "NETWORK",
    "NEURAL",
    "OUTPUT",
    "PATTERN",
    "PHRASE",
    "PROCESSES",
    "PROCESSING",
    "PRODUCING",
    "PRODUCTION",
    "QUANTUM",
    "REALITY",
    "SECRETS",
    "SECURE",
    "SECURITY",
    "SIGNAL",
    "SILENCE",
    "SILENT",
    "STRATEGY",
    "SYSTEM",
    "SYSTEMS",
    "THOUGHT",
    "THROUGH",
    "UNKNOWN",
    "VALID",
    "WITHOUT",
    "WITHIN",
    "WORLD",
    "WORDS",
]


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
    candidates: list[int] = []
    for line in list_tabs().splitlines():
        text = line.strip()
        if not (text.startswith("[") or text.startswith("→ [")):
            continue
        if "https://ctf.centos.hk/" not in text:
            continue
        start = text.find("[")
        end = text.find("]", start + 1)
        if start == -1 or end == -1:
            continue
        candidates.append(int(text[start + 1 : end]))
    return candidates[-1] if candidates else None


def switch_tab(tab: int | None) -> int:
    target = tab if tab is not None else find_ctf_tab()
    if target is None:
        raise RuntimeError("CTF tab not found")
    run_agent("tab", str(target))
    return target


def parse_cookie_lines(text: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        cookies[name] = value
    return cookies


def get_browser_cookies() -> dict[str, str]:
    cookies = parse_cookie_lines(run_agent("cookies", "get"))
    if "session" not in cookies:
        raise RuntimeError("session cookie not found")
    if "cf_clearance" not in cookies:
        raise RuntimeError("cf_clearance cookie not found")
    return cookies


def build_cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


class BrowserBackedClient:
    def __init__(self, *, cookie_header: str, timeout_seconds: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.base_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Cookie": cookie_header,
            "Origin": BASE_URL,
            "Referer": BASE_URL + "/",
        }

    def request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        url = urllib.parse.urljoin(BASE_URL, path)
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=self.base_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read().decode("utf-8")
                return response.status, dict(response.headers.items()), json.loads(payload)
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8")
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                data = payload
            return exc.code, dict(exc.headers.items()), data


def load_common_words(limit: int) -> list[str]:
    try:
        from wordfreq import top_n_list
    except ImportError as exc:
        raise RuntimeError(
            "wordfreq is required. Run with: uv run --with wordfreq python tools\\level14_inception.py"
        ) from exc

    words = [word.upper() for word in top_n_list("en", limit) if word.isalpha()]
    for extra in LAYER5_EXTRA_WORDS:
        if extra not in words:
            words.append(extra)
    return words


def word_pattern(word: str) -> str:
    seen: dict[str, str] = {}
    next_id = 0
    parts: list[str] = []
    for char in word:
        if char not in seen:
            seen[char] = str(next_id)
            next_id += 1
        parts.append(seen[char])
    return ".".join(parts)


def build_words_by_key(common_words: list[str]) -> dict[str, list[str]]:
    words_by_key: dict[str, list[str]] = {}
    for word in common_words:
        key = f"{len(word)}:{word_pattern(word)}"
        words_by_key.setdefault(key, []).append(word)
    return words_by_key


def rank_score(word: str, word_rank: dict[str, int]) -> float:
    rank = word_rank.get(word)
    if rank is None:
        return -8.0
    return max(0.2, 12.0 - math.log2(rank + 2))


def prioritize_candidates(cipher_word: str, repeated_count: int, candidates: list[str]) -> list[str]:
    prioritized: list[str] = []
    seen: set[str] = set()

    def add(word: str) -> None:
        if not word or word in seen:
            return
        seen.add(word)
        prioritized.append(word)

    if len(cipher_word) == 1:
        add("A")
        add("I")
    if len(cipher_word) == 2:
        for word in ("OF", "TO", "IN", "IS", "IT", "ON", "AS", "AT"):
            add(word)
    if len(cipher_word) == 3 and repeated_count >= 2:
        for word in ("THE", "AND", "FOR"):
            add(word)

    for word in candidates:
        add(word)
    return prioritized[:3000]


def candidate_words(
    cipher_word: str,
    repeated_count: int,
    words_by_key: dict[str, list[str]],
) -> list[str]:
    key = f"{len(cipher_word)}:{word_pattern(cipher_word)}"
    return prioritize_candidates(cipher_word, repeated_count, words_by_key.get(key, []))


def try_add_word(
    cipher_word: str,
    plain_word: str,
    c2p: dict[str, str],
    p2c: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]] | None:
    next_c2p = dict(c2p)
    next_p2c = dict(p2c)
    for cipher_char, plain_char in zip(cipher_word, plain_word):
        existing_plain = next_c2p.get(cipher_char)
        if existing_plain and existing_plain != plain_char:
            return None
        existing_cipher = next_p2c.get(plain_char)
        if existing_cipher and existing_cipher != cipher_char:
            return None
        next_c2p[cipher_char] = plain_char
        next_p2c[plain_char] = cipher_char
    return next_c2p, next_p2c


def solve_layer5(ciphertext: str, common_words: list[str]) -> str:
    cipher_words = ciphertext.strip().split()
    counts = Counter(cipher_words)
    unique_words = list(dict.fromkeys(cipher_words))
    word_rank = {word: index + 1 for index, word in enumerate(common_words)}
    words_by_key = build_words_by_key(common_words)
    candidate_map = {
        word: candidate_words(word, counts[word], words_by_key)
        for word in unique_words
    }

    ordered_words = sorted(
        unique_words,
        key=lambda word: (len(candidate_map[word]), -counts[word], -len(word)),
    )

    states: list[dict[str, Any]] = [
        {"score": 0.0, "assignments": {}, "c2p": {}, "p2c": {}}
    ]
    beam_size = 800
    for cipher_word in ordered_words:
        next_states: list[dict[str, Any]] = []
        for state in states:
            for plain_word in candidate_map[cipher_word]:
                mapping = try_add_word(cipher_word, plain_word, state["c2p"], state["p2c"])
                if mapping is None:
                    continue
                next_c2p, next_p2c = mapping
                score = state["score"] + rank_score(plain_word, word_rank) + len(next_c2p) * 0.05
                if plain_word in LAYER5_BONUS_WORDS:
                    score += 1.0
                next_states.append(
                    {
                        "score": score,
                        "assignments": {**state["assignments"], cipher_word: plain_word},
                        "c2p": next_c2p,
                        "p2c": next_p2c,
                    }
                )
        if not next_states:
            raise RuntimeError(f"layer5 beam search exhausted on {cipher_word}")
        next_states.sort(key=lambda item: item["score"], reverse=True)
        states = next_states[:beam_size]

    best_state = states[0]
    return " ".join(best_state["assignments"][word] for word in cipher_words)


def xor_hex(cipher_hex: str, key: bytes) -> str:
    cipher_bytes = bytes.fromhex(cipher_hex)
    plain_bytes = bytes(value ^ key[index % len(key)] for index, value in enumerate(cipher_bytes))
    return plain_bytes.decode("utf-8")


def repair_layer1_candidates(corrupted_data: str, session_key: str) -> list[dict[str, Any]]:
    expected_plain = f"LAYER2:{session_key[:8]}:PROCEED"
    fixed_key = bytes.fromhex("4d415a45")
    candidates: list[dict[str, Any]] = []
    for replacement in itertools.product(BASE64_ALPHABET, repeat=3):
        fixed = (
            corrupted_data.replace("!", replacement[0])
            .replace("@", replacement[1])
            .replace("#", replacement[2])
        )
        try:
            decoded = json.loads(base64.b64decode(fixed, validate=True))
        except Exception:
            continue
        if set(decoded) != LAYER1_EXPECTED_KEYS:
            continue
        if decoded["partialKey"] != LAYER2_PARTIAL_KEY or decoded["knownPrefix"] != LAYER2_KNOWN_PREFIX:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", decoded["cipher"]):
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", decoded["decoy2"]):
            continue
        try:
            plaintext = xor_hex(decoded["cipher"], fixed_key)
        except UnicodeDecodeError:
            continue
        if plaintext != expected_plain:
            continue
        candidates.append(
            {
                "replacement": "".join(replacement),
                "answer": fixed,
                "decoded": decoded,
                "plaintext": plaintext,
            }
        )
    if not candidates:
        raise RuntimeError("no valid layer1 candidates found")
    return candidates


def solve_layer1(client: BrowserBackedClient, session_key: str, layer1: dict[str, Any]) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    for candidate in repair_layer1_candidates(layer1["corruptedData"], session_key):
        _status, _headers, payload = client.request_json(
            DEFAULT_SOLVE_LAYER_PATH,
            method="POST",
            body={"sessionKey": session_key, "layer": 1, "answer": candidate["answer"]},
        )
        attempts.append({"replacement": candidate["replacement"], "result": payload})
        if isinstance(payload, dict) and payload.get("success"):
            return {"answer": candidate["answer"], "decoded": candidate["decoded"], "result": payload}
    raise RuntimeError(f"layer1 failed: {json.dumps(attempts, ensure_ascii=False)}")


def derive_layer2_key(cipher_hex: str) -> bytes:
    ciphertext = bytes.fromhex(cipher_hex)
    known_prefix = b"LAYE"
    return bytes(value ^ known_prefix[index] for index, value in enumerate(ciphertext[:4]))


def solve_layer2(layer2: dict[str, Any]) -> str:
    if layer2["partialKey"] != LAYER2_PARTIAL_KEY:
        raise ValueError(f"unexpected layer2 partialKey: {layer2['partialKey']!r}")
    if layer2["knownPrefix"] != LAYER2_KNOWN_PREFIX:
        raise ValueError(f"unexpected layer2 knownPrefix: {layer2['knownPrefix']!r}")
    return xor_hex(layer2["cipher"], derive_layer2_key(layer2["cipher"]))


def enumerate_layer3_paths(layer3: dict[str, Any]) -> list[str]:
    labels = {node["id"]: node["label"] for node in layer3["graph"]}
    edges = {node["id"]: node["edges"] for node in layer3["graph"]}
    answers: list[str] = []
    queue: deque[tuple[int, int, str, frozenset[int]]] = deque(
        [(layer3["start"], 0, labels[layer3["start"]], frozenset({layer3["start"]}))]
    )
    while queue:
        node_id, total, path, visited = queue.popleft()
        if node_id == layer3["end"] and total == layer3["target"]:
            answers.append(path)
            continue
        if total >= layer3["target"]:
            continue
        for edge in edges[node_id]:
            next_id = edge["to"]
            next_total = total + edge["weight"]
            if next_total > layer3["target"]:
                continue
            if next_id in visited:
                continue
            queue.append(
                (next_id, next_total, path + labels[next_id], visited | {next_id})
            )
    return answers


def crt(moduli: list[int], remainders: list[int]) -> int:
    modulus = math.prod(moduli)
    result = 0
    for divisor, remainder in zip(moduli, remainders):
        partial = modulus // divisor
        inverse = pow(partial, -1, divisor)
        result += remainder * partial * inverse
    return result % modulus


def pow_worker(
    challenge: str,
    difficulty: str,
    start_nonce: int,
    step: int,
    limit: int,
    found_event: Any,
    result_queue: Any,
) -> None:
    challenge_bytes = challenge.encode("utf-8")
    nonce = start_nonce
    while nonce < limit and not found_event.is_set():
        digest = hashlib.sha256(challenge_bytes + str(nonce).encode("utf-8")).hexdigest()
        if digest.startswith(difficulty):
            if not found_event.is_set():
                found_event.set()
                result_queue.put((nonce, digest))
            return
        nonce += step


def solve_pow(challenge: str, difficulty: str, *, limit: int) -> tuple[int, str]:
    workers = max(1, min(8, os.cpu_count() or 1))
    ctx = mp.get_context("spawn")
    found_event = ctx.Event()
    result_queue: mp.Queue = ctx.Queue()
    processes = [
        ctx.Process(
            target=pow_worker,
            args=(challenge, difficulty, worker_id, workers, limit, found_event, result_queue),
        )
        for worker_id in range(workers)
    ]
    for process in processes:
        process.start()

    try:
        nonce, digest = result_queue.get(timeout=600)
        return int(nonce), str(digest)
    except Exception as error:
        raise RuntimeError(f"pow not found within limit {limit}") from error
    finally:
        found_event.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)


def solve_captcha(question: str) -> int:
    normalized = (
        question.replace("−", "-")
        .replace("—", "-")
        .replace("–", "-")
        .replace("﹣", "-")
        .replace("－", "-")
        .replace("×", "*")
        .replace("÷", "/")
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


def submit_level_answer(client: BrowserBackedClient, answer: str) -> dict[str, Any]:
    _status, _headers, captcha = client.request_json(DEFAULT_CAPTCHA_PATH)
    if not isinstance(captcha, dict):
        raise TypeError(f"unexpected captcha payload: {captcha!r}")

    _status, _headers, result = client.request_json(
        DEFAULT_ANSWER_PATH,
        method="POST",
        body={
            "answer": f"muyuan{{{answer}}}",
            "captchaId": captcha["id"],
            "captchaAnswer": solve_captcha(captcha["question"]),
        },
    )
    return {"captcha": captcha, "submit": result}


def solve_layer7(collected_keys: list[str], salt: str) -> str:
    message = ":".join(collected_keys).encode("utf-8")
    return hmac.new(salt.encode("utf-8"), message, hashlib.sha256).hexdigest().upper()[:16]


def fetch_me(client: BrowserBackedClient) -> dict[str, Any]:
    _status, _headers, payload = client.request_json("/api/me")
    if not isinstance(payload, dict):
        raise TypeError(f"unexpected /api/me payload: {payload!r}")
    return payload


def redeem_reward(client: BrowserBackedClient, code: str) -> dict[str, Any]:
    _status, _headers, payload = client.request_json(
        "/api/redeem",
        method="POST",
        body={"code": code},
    )
    if not isinstance(payload, dict):
        raise TypeError(f"unexpected /api/redeem payload: {payload!r}")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Level 14 inception solver")
    parser.add_argument("--tab", type=int)
    parser.add_argument("--stop-after-layer", type=int, default=DEFAULT_STOP_AFTER_LAYER)
    parser.add_argument("--word-limit", type=int, default=DEFAULT_WORD_LIMIT)
    parser.add_argument("--pow-limit", type=int, default=DEFAULT_POW_LIMIT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    switch_tab(args.tab)

    client = BrowserBackedClient(
        cookie_header=build_cookie_header(get_browser_cookies()),
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    )
    common_words = load_common_words(args.word_limit)

    _status, headers, dream = client.request_json(DEFAULT_ENTER_DREAM_PATH, method="POST", body={})
    if not isinstance(dream, dict) or "sessionKey" not in dream:
        raise RuntimeError(f"failed to enter dream: {dream}")

    session_key = dream["sessionKey"]
    output: dict[str, Any] = {"sessionKey": session_key, "cfRay": headers.get("cf-ray"), "layers": {}}

    layer1 = solve_layer1(client, session_key, dream["layer1"])
    output["layers"]["1"] = {
        "answer": layer1["answer"],
        "key": layer1["result"]["key"],
        "decoded": layer1["decoded"],
    }
    if args.stop_after_layer <= 1:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    layer2_data = layer1["result"]["nextLayer"]
    layer2_answer = solve_layer2(layer2_data)
    _status, _headers, solve2 = client.request_json(
        DEFAULT_SOLVE_LAYER_PATH,
        method="POST",
        body={"sessionKey": session_key, "layer": 2, "answer": layer2_answer},
    )
    if not isinstance(solve2, dict) or not solve2.get("success"):
        raise RuntimeError(f"layer2 failed: {solve2}")
    output["layers"]["2"] = {
        "answer": layer2_answer,
        "key": solve2["key"],
        "cipherKey": derive_layer2_key(layer2_data["cipher"]).decode("utf-8"),
    }
    if args.stop_after_layer <= 2:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    layer3_data = solve2["nextLayer"]
    layer3_candidates = enumerate_layer3_paths(layer3_data)
    solve3 = None
    layer3_answer = None
    for candidate in layer3_candidates:
        _status, _headers, payload = client.request_json(
            DEFAULT_SOLVE_LAYER_PATH,
            method="POST",
            body={"sessionKey": session_key, "layer": 3, "answer": candidate},
        )
        if isinstance(payload, dict) and payload.get("success"):
            solve3 = payload
            layer3_answer = candidate
            break
    if solve3 is None or layer3_answer is None:
        raise RuntimeError(f"layer3 failed: {layer3_candidates}")
    output["layers"]["3"] = {
        "answer": layer3_answer,
        "key": solve3["key"],
        "candidates": layer3_candidates,
    }
    if args.stop_after_layer <= 3:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    layer4_data = solve3["nextLayer"]
    layer4_answer = str(crt(layer4_data["moduli"], layer4_data["remainders"]))
    _status, _headers, solve4 = client.request_json(
        DEFAULT_SOLVE_LAYER_PATH,
        method="POST",
        body={"sessionKey": session_key, "layer": 4, "answer": layer4_answer},
    )
    if not isinstance(solve4, dict) or not solve4.get("success"):
        raise RuntimeError(f"layer4 failed: {solve4}")
    output["layers"]["4"] = {"answer": layer4_answer, "key": solve4["key"]}
    if args.stop_after_layer <= 4:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    layer5_data = solve4["nextLayer"]
    layer5_answer = solve_layer5(layer5_data["ciphertext"], common_words)
    _status, _headers, solve5 = client.request_json(
        DEFAULT_SOLVE_LAYER_PATH,
        method="POST",
        body={"sessionKey": session_key, "layer": 5, "answer": layer5_answer},
    )
    if not isinstance(solve5, dict) or not solve5.get("success"):
        raise RuntimeError(
            f"layer5 failed: ciphertext={layer5_data['ciphertext']!r}, answer={layer5_answer!r}, payload={solve5!r}"
        )
    output["layers"]["5"] = {"answer": layer5_answer, "key": solve5["key"]}
    if args.stop_after_layer <= 5:
        output["nextLayer"] = solve5.get("nextLayer")
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    layer6_data = solve5["nextLayer"]
    nonce, digest = solve_pow(layer6_data["challenge"], layer6_data["difficulty"], limit=args.pow_limit)
    _status, _headers, solve6 = client.request_json(
        DEFAULT_SOLVE_LAYER_PATH,
        method="POST",
        body={"sessionKey": session_key, "layer": 6, "answer": str(nonce)},
    )
    output["layers"]["6"] = {"answer": str(nonce), "digest": digest, "rawResult": solve6}
    output["nextLayer"] = solve6.get("nextLayer") if isinstance(solve6, dict) else None
    if args.stop_after_layer <= 6:
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    if not isinstance(solve6, dict) or not solve6.get("success"):
        raise RuntimeError(f"layer6 failed: {solve6}")

    layer7_data = solve6["nextLayer"]
    layer7_answer = solve_layer7(layer7_data["collectedKeys"], layer7_data["salt"])
    _status, _headers, solve7 = client.request_json(
        DEFAULT_SOLVE_LAYER_PATH,
        method="POST",
        body={"sessionKey": session_key, "layer": 7, "answer": layer7_answer},
    )
    if not isinstance(solve7, dict) or not solve7.get("success"):
        raise RuntimeError(f"layer7 failed: {solve7}")
    output["layers"]["7"] = {"answer": layer7_answer, "rawResult": solve7}

    final_flag = str(solve7.get("flag") or solve7.get("key") or layer7_answer)
    level_submit = submit_level_answer(client, final_flag)
    output["levelSubmit"] = level_submit
    output["me"] = fetch_me(client)

    submit_payload = level_submit.get("submit")
    if isinstance(submit_payload, dict):
        redemption_code = submit_payload.get("redemptionCode")
        user = output["me"].get("user") if isinstance(output["me"], dict) else None
        if isinstance(user, dict) and user.get("gift"):
            output["reward"] = {
                "gift": user["gift"],
                "redemptionCode": user.get("redemptionCode"),
                "alreadyClaimed": True,
            }
        elif redemption_code:
            output["reward"] = redeem_reward(client, redemption_code)

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
