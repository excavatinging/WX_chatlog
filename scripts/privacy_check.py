#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前隐私检查：只报告类别和位置，绝不回显匹配到的敏感值。"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import shutil

# 仅执行绝对 Git 路径，参数数组且不启用 shell。
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_TEXT_BYTES = 5 * 1024 * 1024

PATTERNS = (
    ("private_key", re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("cloud_api_key", re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("windows_user_path", re.compile(
        r"(?i)\b[A-Z]:[\\/]Users[\\/][^\\/\s\"']+"
    )),
    ("local_project_path", re.compile(
        r"(?i)\b[A-Z]:[\\/]Projects[\\/][^\r\n\"']+"
    )),
    ("unix_user_path", re.compile(
        r"(?i)(?:^|[\s\"'])/(?:home|Users)/[^/\s\"']+"
    )),
    ("wechat_id", re.compile(r"(?i)\bwxid_[A-Za-z0-9_-]{6,}\b")),
    ("phone_number", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")),
    ("long_hex_value", re.compile(r"(?i)(?<![A-F0-9])[A-F0-9]{64,}(?![A-F0-9])")),
    ("sensitive_assignment", re.compile(
        r"(?i)\b(?:password|passwd|passphrase|secret|token|api[_-]?key)\b"
        r"\s*[:=]\s*[\"'][^\"']{8,}[\"']"
    )),
)

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
ALLOWED_EMAIL_DOMAINS = {
    "example.com",
    "example.invalid",
    "users.noreply.github.com",
}
ALLOWED_EMAILS = {"noreply@github.com"}
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:secrets?|ctx_dumps?|exports?|contacts?|messages?)(?:/|$)"
    r"|(?:^|/)(?:passphrase\.txt|all_keys\.json|\.env(?:\..*)?)$"
    r"|\.(?:db|sqlite3?|dmp|dump|log|csv|pem|key|p12|pfx|kdbx|zip|7z|tar|gz)$"
)

try:
    _LOCAL_USERNAME = getpass.getuser().strip()
except (OSError, RuntimeError):
    _LOCAL_USERNAME = ""
LOCAL_USERNAME_RE = (
    re.compile(rf"(?i)\b{re.escape(_LOCAL_USERNAME)}\b")
    if len(_LOCAL_USERNAME) >= 3 else None
)


def _git(*args: str, text: bool = False) -> subprocess.CompletedProcess:
    executable = shutil.which("git")
    if not executable:
        raise RuntimeError("未找到 Git 可执行文件")
    resolved = Path(executable).resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise RuntimeError("拒绝执行仓库目录内的 Git 可执行文件")
    # executable 已解析且拒绝仓库内路径。
    return subprocess.run(  # nosec B603
        [str(resolved), "-C", str(ROOT), *args], check=False,
        capture_output=True, text=text
    )


def _scan_text(text: str, path: str, scope: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for category, pattern in PATTERNS:
            if pattern.search(line):
                findings.append({"scope": scope, "path": path,
                                 "line": line_no, "category": category})
        for match in EMAIL_RE.finditer(line):
            if (match.group(0).casefold() not in ALLOWED_EMAILS
                    and match.group(1).casefold() not in ALLOWED_EMAIL_DOMAINS):
                findings.append({"scope": scope, "path": path,
                                 "line": line_no, "category": "email"})
        if LOCAL_USERNAME_RE and LOCAL_USERNAME_RE.search(line):
            findings.append({"scope": scope, "path": path,
                             "line": line_no, "category": "local_username"})
    return findings


def _scan_path(path: str, scope: str) -> list[dict[str, object]]:
    if SENSITIVE_PATH_RE.search(path.replace("\\", "/")):
        return [{"scope": scope, "path": path, "line": 0,
                 "category": "sensitive_filename"}]
    return []


def _decode_text(data: bytes) -> str | None:
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_worktree() -> tuple[list[dict[str, object]], int]:
    result = _git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if result.returncode:
        raise RuntimeError("git ls-files 失败")
    paths = [item.decode("utf-8", errors="surrogateescape")
             for item in result.stdout.split(b"\x00") if item]
    findings: list[dict[str, object]] = []
    scanned = 0
    for rel in paths:
        if rel.startswith(".gstack/"):
            continue
        findings.extend(_scan_path(rel, "worktree"))
        path = ROOT / rel
        try:
            data = path.read_bytes()
        except OSError:
            findings.append({"scope": "worktree", "path": rel, "line": 0,
                             "category": "unreadable_file"})
            continue
        text = _decode_text(data)
        if text is None:
            findings.append({"scope": "worktree", "path": rel, "line": 0,
                             "category": "unscanned_binary_or_large"})
            continue
        scanned += 1
        findings.extend(_scan_text(text, rel, "worktree"))
    return findings, scanned


def scan_history() -> tuple[list[dict[str, object]], int]:
    objects = _git("rev-list", "--objects", "--all", text=True)
    if objects.returncode:
        raise RuntimeError("git rev-list 失败")
    findings: list[dict[str, object]] = []
    scanned = 0

    # 路径与 blob 内容分开枚举：name-only 覆盖曾出现过的每个历史路径，
    # rev-list 则让同一 blob 内容只扫描一次，避免按“提交×全树”指数式变慢。
    path_log = _git("log", "--all", "--format=", "--name-only", "-z")
    if path_log.returncode:
        raise RuntimeError("git 历史路径枚举失败")
    for raw_path in path_log.stdout.split(b"\x00"):
        raw_path = raw_path.strip(b"\r\n")
        if raw_path:
            path = raw_path.decode("utf-8", errors="surrogateescape")
            findings.extend(_scan_path(path, "history"))

    seen_blobs: set[str] = set()
    for line in objects.stdout.splitlines():
        oid, separator, path = line.partition(" ")
        if not separator or oid in seen_blobs:
            continue
        obj_type = _git("cat-file", "-t", oid, text=True)
        if obj_type.returncode or obj_type.stdout.strip() != "blob":
            continue
        seen_blobs.add(oid)
        blob = _git("cat-file", "blob", oid)
        if blob.returncode:
            findings.append({"scope": "history", "path": path, "line": 0,
                             "category": "unreadable_blob"})
            continue
        text = _decode_text(blob.stdout)
        if text is None:
            findings.append({"scope": "history", "path": path, "line": 0,
                             "category": "unscanned_binary_or_large"})
            continue
        scanned += 1
        findings.extend(_scan_text(text, path, "history"))

    log = _git(
        "log", "--all",
        "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x1e"
    )
    if log.returncode:
        raise RuntimeError("git log 失败")
    for record in (item.strip() for item in log.stdout.split(b"\x1e") if item.strip()):
        fields = [item.decode("utf-8", errors="replace").strip()
                  for item in record.split(b"\x00")]
        if len(fields) != 5:
            findings.append({"scope": "commit_metadata", "path": "unknown",
                             "line": 0, "category": "unparseable_metadata"})
            continue
        commit, author_name, author_email, committer_name, committer_email = fields
        for email in (author_email, committer_email):
            match = EMAIL_RE.fullmatch(email)
            if (match and email.casefold() not in ALLOWED_EMAILS
                    and match.group(1).casefold() not in ALLOWED_EMAIL_DOMAINS):
                findings.append({"scope": "commit_metadata", "path": commit[:12],
                                 "line": 0, "category": "email"})
        if LOCAL_USERNAME_RE and any(
                LOCAL_USERNAME_RE.search(name)
                for name in (author_name, committer_name)):
            findings.append({"scope": "commit_metadata", "path": commit[:12],
                             "line": 0, "category": "local_username"})
    return findings, scanned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-history", action="store_true",
                        help="只扫当前工作树（常规开发可用；发布前不要跳过历史）")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON")
    args = parser.parse_args()
    try:
        findings, worktree_count = scan_worktree()
        history_count = 0
        if not args.no_history:
            history_findings, history_count = scan_history()
            findings.extend(history_findings)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    # 同一 blob 可能在多个提交出现；发布门禁只需报告一次位置与类别。
    unique = []
    seen = set()
    for finding in findings:
        key = (finding["scope"], finding["path"], finding["line"], finding["category"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    report = {
        "ok": not unique,
        "worktree_text_files_scanned": worktree_count,
        "history_blobs_scanned": history_count,
        "findings": unique,
    }
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif unique:
        print(f"[FAIL] 隐私检查发现 {len(unique)} 项（敏感值已隐藏）")
        for finding in unique:
            where = f"{finding['path']}:{finding['line']}" if finding["line"] else finding["path"]
            print(f"  {finding['scope']} {where} [{finding['category']}]")
    else:
        print(f"[OK] 隐私检查通过：工作树 {worktree_count} 个文本文件，历史 {history_count} 个 blob")
    return 1 if unique else 0


if __name__ == "__main__":
    raise SystemExit(main())
