# MuyanCTF

用于记录和复用 `https://ctf.centos.hk/` 的解题脚本与工作约定。

## 环境要求

- Python 3.12+（统一使用 UTF-8）
- `uv`
- `agent-browser`
- 已在浏览器中登录目标站点

如果 `agent-browser` 不在 `PATH` 中，可显式指定：

```powershell
$env:AGENT_BROWSER_BIN = "C:\path\to\agent-browser-win32-x64.exe"
```

## 使用方式

优先复用 `tools\` 下已有脚本，直接用 `uv` 运行：

```powershell
uv run python tools\level5_sqli.py --help
uv run python tools\level6_solver.py --help
```

这两个脚本当前都只依赖 Python 标准库。

## 目录说明

- `AGENTS.md`：仓库内协作与解题规则
- `tools\level5_sqli.py`：Level 5 SQL 注入辅助脚本
- `tools\level6_solver.py`：Level 6 时间锁题目辅助脚本

## 工作约定

- 中文沟通，英文检索技术资料
- 优先本地分析：页面源码、网络请求、浏览器状态、仓库脚本
- 新脚本保持小而专用，放在 `tools\` 下
- 解题结果必须可复现，并记录 payload、脚本或关键推理
