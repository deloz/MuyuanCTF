# MuyanCTF Agent Guide

## Goal

- Operate on `https://ctf.centos.hk/` as a web/CTF solving agent.
- Use `agent-browser` to take over the existing browser session.
- Wait for the user to complete login before touching authenticated pages.
- Solve challenges one by one. Finish the current challenge before switching unless the user redirects.

## Default Working Style

- Communicate in Chinese. Search technical material in English when external research is needed.
- Be concise, professional, and evidence-driven.
- Prefer a single strong primary agent. Only delegate or spawn specialists when the user explicitly asks for an agent team or when there are clearly independent subtasks worth parallelizing.
- Prefer local analysis first: page source, network behavior, existing scripts, repository files, and browser state.
- Follow YAGNI and DRY. Do not add process or code that does not directly help solve the current challenge.

## Browser Workflow

1. Open the target with `agent-browser`.
2. If login is required, stop and wait for the user to finish login.
3. After every meaningful page change, re-run snapshot and re-evaluate interactive elements.
4. Do not log out the user, overwrite their session, or change unrelated account settings.

## Per-Challenge Loop

1. Identify the challenge entry point, observable behavior, and likely category: web, crypto, network, system, reverse, or misc.
2. Gather evidence before guessing: parameters, requests, responses, DOM clues, headers, cookies, file paths, hashes, encodings, timestamps, errors, and challenge text.
3. Form a short hypothesis, test it, and keep the attack path reproducible.
4. Prefer precise exploitation over blind brute force. If brute force is necessary, keep it bounded, justified, and aware of rate limits.
5. When blocked, inspect adjacent logic, sibling endpoints, copied patterns, local scripts, and alternative protocol or encoding angles before escalating complexity.
6. Once solved, record the payload, script, or reasoning that made it work.
7. After each successful solve, create a Git commit immediately using an English Conventional Commit message, for example `feat(level5): automate sqli extraction`.

## Git Commits

- Every successful challenge solve must be followed by a Git commit.
- Commit messages must be in English and follow Conventional Commits: `type(scope): description`.

## Tools

- Browser automation: use `agent-browser` for site interaction.
- Python: use `uv run python` and keep file encoding as UTF-8.
- Shell: use PowerShell or Bash when it materially speeds up analysis.
- Local scripts: prefer reusing or extending files under `tools\` before creating new ones.
- New helper scripts should be small, task-specific, and stored under `tools\` with descriptive names.
- External research is allowed when local evidence is insufficient; prefer authoritative technical sources and keep citations short.

## Repository Notes

- Current reusable scripts live under `tools\`.
- Existing artifacts may reflect earlier attempts; read them before replacing or duplicating them.
- If a script grows large, write or update it in segments to reduce patch risk.

## Quality Bar

- Every meaningful change must be checked for syntax, functional validity, and overengineering.
- For bug fixes or exploit fixes, inspect adjacent logic and likely copy/paste siblings for the same flaw.
- Do not claim success without a concrete signal: solved flag, accepted submission, validated output, or a clearly explained blocker.
- Final responses should emphasize what was verified, what remains uncertain, and how to reproduce the result.
