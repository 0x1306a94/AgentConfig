#!/usr/bin/env python3
"""通用读取拦截：Claude Code、Codex、Trae 的 PreToolUse，以及 Cursor 的读取和终端 hook。

规则文件默认是同目录 deny-read.rules，可用 DENY_READ_RULES 或 DENY_PATHS_RULES 覆盖。
每行一条 glob。不含 / 只匹配文件名；含 / 匹配规范化后的路径。
相对路径匹配任意目录下的同一段路径。
Claude Code、Codex 与 Trae 命中后 exit 2，原因写到 stderr。Cursor 命中后输出 permission deny。
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RULES_FILE = Path(
    os.environ.get("DENY_READ_RULES")
    or os.environ.get("DENY_PATHS_RULES")
    or (SCRIPT_DIR / "deny-read.rules")
)
SHELL_TOOLS = {"Bash", "PowerShell", "Shell", "RunCommand", "exec_command"}
CURSOR_EVENTS = {"beforeReadFile", "beforeTabFileRead", "beforeShellExecution", "preToolUse"}
PATH_FIELDS = ("file_path", "path", "notebook_path", "uri")
CASE_INSENSITIVE = sys.platform == "darwin" or os.name == "nt"
TOKEN_RE = re.compile(r"""'([^']*)'|"([^"]*)"|([^\s|&;<>()`]+)""")
QUOTED_RE = re.compile(r"""'([^']*)'|"([^"]*)\"""")
ADJACENT_QUOTE_RE = re.compile(r"""(['"])([^'"]+)\1(?=/)""")
PATH_RE = re.compile(r"""(?:~|/|\.\.?/)[^\s"'|&;<>()`]+""")


def fold(text: str) -> str:
    return text.casefold() if CASE_INSENSITIVE else text


def expand(text: str) -> str:
    """展开 $VAR / ${VAR} 与 ~/；未定义变量保持原样。"""
    if text == "~":
        text = str(Path.home())
    else:
        home = str(Path.home())
        text = text.replace("~/", home + "/").replace("~\\", home + "\\")
    return os.path.expandvars(text)


def find_project_root(session_directory: Path) -> Path:
    configured = os.environ.get("PROJECT_ROOT")
    if configured:
        return Path(expand(configured))
    for parent in [session_directory, *session_directory.parents]:
        if (parent / ".git").exists():
            return parent
    return session_directory


def load_rules() -> list[str]:
    try:
        text = RULES_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    rules = []
    for line in text.splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        rules.append(expand(rule).replace("\\", "/"))
    return rules


def session_directory_from(payload: dict) -> Path:
    raw = payload.get("cwd") or os.getcwd()
    try:
        return Path(expand(str(raw))).resolve(strict=False)
    except (OSError, ValueError):
        return Path.cwd()


def path_forms(text: str, session_directory: Path) -> list[str]:
    """返回词法路径和解析软链后的路径，两条都参与匹配。"""
    expanded = expand(text.strip()).replace("\\", "/")
    if expanded.startswith("file://"):
        expanded = expanded[len("file://") :]
    if not expanded or expanded.startswith("-"):
        return []
    path = Path(expanded)
    if not path.is_absolute():
        path = session_directory / path
    lexical = fold(os.path.normpath(path.as_posix()).replace("\\", "/"))
    try:
        resolved = fold(path.resolve(strict=False).as_posix())
    except (OSError, ValueError):
        resolved = lexical
    if resolved == lexical:
        return [resolved]
    return [resolved, lexical]


def suffixes(path: str) -> list[str]:
    parts = [part for part in path.split("/") if part]
    return ["/".join(parts[index:]) for index in range(len(parts))]


def matches(path: str, rule: str) -> bool:
    path = fold(path)
    rule = fold(rule)
    if "/" not in rule:
        return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], rule)
    patterns = [rule]
    if rule.endswith("/*"):
        patterns.append(rule[:-2])
    if rule.startswith("/"):
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    for suffix in suffixes(path):
        if any(fnmatch.fnmatchcase(suffix, pattern) for pattern in patterns):
            return True
    return False


def matching_rule(path: str, rules: list[str]) -> str | None:
    for rule in rules:
        if matches(path, rule):
            return rule
    return None


def matching_path_rule(path: str, rules: list[str]) -> str | None:
    for rule in rules:
        if "/" in rule and matches(path, rule):
            return rule
    return None


def name_is_denied(text: str, rules: list[str]) -> bool:
    name = fold(text.replace("\\", "/").rsplit("/", 1)[-1])
    return any("/" not in rule and fnmatch.fnmatchcase(name, fold(rule)) for rule in rules)


def is_directory(text: str, session_directory: Path) -> bool:
    try:
        return (session_directory / text).is_dir()
    except (OSError, ValueError):
        return False


def should_check(text: str, session_directory: Path, rules: list[str]) -> bool:
    if not text or text.startswith("-"):
        return False
    if name_is_denied(text, rules):
        return True
    normalized = text.replace("\\", "/")
    if normalized.startswith("~") or "/" in normalized:
        return True
    return is_directory(text, session_directory)


def quoted_pieces(text: str) -> list[str]:
    pieces = []
    for match in QUOTED_RE.finditer(text):
        piece = match.group(1) if match.group(1) is not None else match.group(2)
        if not piece:
            continue
        pieces.append(piece)
        pieces.extend(quoted_pieces(piece))
    return pieces


def command_candidates(command: str, session_directory: Path, rules: list[str]) -> list[str]:
    command = expand(command)
    while True:
        joined = ADJACENT_QUOTE_RE.sub(r"\2", command)
        if joined == command:
            break
        command = joined
    candidates = []
    for match in TOKEN_RE.finditer(command):
        token = next(group for group in match.groups() if group is not None)
        if token.startswith("-") and "=" in token:
            token = token.split("=", 1)[1]
        if should_check(token, session_directory, rules):
            candidates.append(token)
    for piece in quoted_pieces(command) + PATH_RE.findall(command):
        if should_check(piece, session_directory, rules):
            candidates.append(piece)
    return candidates


def target_texts(payload: dict, session_directory: Path, rules: list[str]) -> list[str]:
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return []
    tool_name = str(payload.get("tool_name") or "")
    if tool_name in SHELL_TOOLS:
        return command_candidates(str(tool_input.get("command") or ""), session_directory, rules)
    texts = []
    for key in PATH_FIELDS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            texts.append(value)
    extra_key = "pattern" if tool_name == "Glob" else "glob" if tool_name == "Grep" else ""
    extra = tool_input.get(extra_key) if extra_key else ""
    if isinstance(extra, str) and extra:
        texts.append(extra)
    return texts


def is_cursor(payload: dict) -> bool:
    if "cursor_version" in payload:
        return True
    return str(payload.get("hook_event_name") or "") in CURSOR_EVENTS


def is_shell(payload: dict) -> bool:
    if payload.get("hook_event_name") == "beforeShellExecution":
        return True
    return str(payload.get("tool_name") or "") in SHELL_TOOLS


def event_texts(payload: dict, session_directory: Path, rules: list[str]) -> list[str]:
    event = str(payload.get("hook_event_name") or "")
    if event in {"beforeReadFile", "beforeTabFileRead"}:
        texts = []
        file_path = payload.get("file_path")
        if isinstance(file_path, str) and file_path:
            texts.append(file_path)
        for item in payload.get("attachments") or []:
            if not isinstance(item, dict):
                continue
            attachment_path = item.get("file_path")
            if isinstance(attachment_path, str) and attachment_path:
                texts.append(attachment_path)
        return texts
    if event == "beforeShellExecution":
        command = payload.get("command")
        if not isinstance(command, str) or not command:
            return []
        return command_candidates(command, session_directory, rules)
    return target_texts(payload, session_directory, rules)


def finish(payload: dict, rule: str | None = None, path: str | None = None) -> int:
    message = f"已禁止读取敏感文件（命中规则 {rule}）：{path}"
    if not is_cursor(payload):
        if rule is None:
            return 0
        print(message, file=sys.stderr)
        return 2
    if rule is None:
        print(json.dumps({"permission": "allow"}))
        return 0
    body = {"permission": "deny", "user_message": message}
    event = str(payload.get("hook_event_name") or "")
    if event in {"beforeShellExecution", "preToolUse"}:
        body["agent_message"] = message
    print(json.dumps(body, ensure_ascii=False))
    return 0


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0
    if not isinstance(payload, dict):
        return 0

    session_directory = session_directory_from(payload)
    os.environ.setdefault("PROJECT_ROOT", str(find_project_root(session_directory)))
    rules = load_rules()
    if not rules:
        return finish(payload)

    if is_shell(payload):
        for form in path_forms(str(session_directory), session_directory):
            rule = matching_path_rule(form, rules)
            if rule:
                return finish(payload, rule, form)

    for text in event_texts(payload, session_directory, rules):
        for form in path_forms(text, session_directory):
            rule = matching_rule(form, rules)
            if rule:
                return finish(payload, rule, form)
    return finish(payload)


if __name__ == "__main__":
    sys.exit(main())
