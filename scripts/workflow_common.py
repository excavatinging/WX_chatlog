#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工作流共享配置与只读环境探测。仓库内不保存任何机器特定路径。"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import glob
import os
import shutil
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BP_RVA = 0x3485D10
DEFAULT_EXPECTED_VERSION = "4.1.12.26"
DEFAULT_EXPECTED_FN_BYTES = bytes.fromhex("895104")


class WorkflowConfigError(RuntimeError):
    """环境未准备好或配置值不安全。"""


def _expand_path(value: str) -> Path:
    return Path(os.path.expandvars(value)).expanduser().resolve()


def require_windows_x64() -> None:
    if os.name != "nt":
        raise WorkflowConfigError("本工作流仅支持 Windows 10/11 x64")
    if struct.calcsize("P") != 8:
        raise WorkflowConfigError("必须使用 64 位 Python，32 位进程无法安全处理目标地址")


def require_env_file(name: str) -> Path:
    raw = os.environ.get(name, "").strip()
    if not raw:
        raise WorkflowConfigError(f"缺少环境变量 {name}；先运行 0_preflight.py")
    path = _expand_path(raw)
    if not path.is_file():
        raise WorkflowConfigError(f"{name} 指向的文件不存在")
    return path


def require_env_dir(name: str) -> Path:
    raw = os.environ.get(name, "").strip()
    if not raw:
        raise WorkflowConfigError(f"缺少环境变量 {name}；先运行 0_preflight.py")
    path = _expand_path(raw)
    if not path.is_dir():
        raise WorkflowConfigError(f"{name} 指向的目录不存在")
    return path


def resolve_weixin_paths() -> tuple[Path, Path]:
    exe = require_env_file("WX_EXE")
    if exe.name.casefold() != "weixin.exe":
        raise WorkflowConfigError("WX_EXE 必须指向 Weixin.exe")
    raw_dir = os.environ.get("WX_DIR", "").strip()
    workdir = _expand_path(raw_dir) if raw_dir else exe.parent
    if not workdir.is_dir():
        raise WorkflowConfigError("WX_DIR 指向的目录不存在")
    return exe, workdir


def resolve_weixin_dll(exe: Path | None = None, workdir: Path | None = None) -> Path:
    """定位要与断点资料核对的 Weixin.dll；多候选时拒绝自动选择。"""
    raw = os.environ.get("WX_DLL", "").strip()
    if raw:
        dll = _expand_path(raw)
        if not dll.is_file() or dll.name.casefold() != "weixin.dll":
            raise WorkflowConfigError("WX_DLL 必须指向存在的 Weixin.dll")
        return dll

    if exe is None or workdir is None:
        exe, workdir = resolve_weixin_paths()
    candidates = [
        path.resolve()
        for path in (workdir / "Weixin.dll", exe.parent / "Weixin.dll")
        if path.is_file()
    ]
    if not candidates:
        candidates.extend(
            path.resolve() for path in sorted(workdir.glob("*/Weixin.dll"))
            if path.is_file()
        )
    candidates = _dedupe_paths(candidates)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise WorkflowConfigError("未在确认的安装目录找到 Weixin.dll；请设置 WX_DLL")
    raise WorkflowConfigError("安装目录存在多个 Weixin.dll；请由用户确认后设置 WX_DLL")


def resolve_db_dir() -> Path:
    db_dir = require_env_dir("WX_DB_DIR")
    if db_dir.name.casefold() != "db_storage":
        raise WorkflowConfigError("WX_DB_DIR 必须指向账号目录下的 db_storage")
    return db_dir


def resolve_secrets_dir(*, create: bool = False) -> Path:
    raw = os.environ.get("WX_SECRETS_DIR", "").strip()
    default_dir = (PROJECT_ROOT / "secrets").resolve()
    path = _expand_path(raw) if raw else default_dir
    inside_project = path == PROJECT_ROOT or PROJECT_ROOT in path.parents
    inside_default = path == default_dir or default_dir in path.parents
    if inside_project and not inside_default:
        raise WorkflowConfigError(
            "WX_SECRETS_DIR 在仓库内时只能指向已忽略的 secrets 目录或其子目录"
        )
    if path.parent == path:
        raise WorkflowConfigError("WX_SECRETS_DIR 不能指向磁盘根目录")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_anchor_config() -> tuple[int, str, bytes]:
    raw_rva = os.environ.get("WX_BP_RVA", hex(DEFAULT_BP_RVA)).strip()
    try:
        rva = int(raw_rva, 0)
    except ValueError as exc:
        raise WorkflowConfigError("WX_BP_RVA 必须是十进制或 0x 开头的十六进制整数") from exc
    if not 0 < rva < 0x80000000:
        raise WorkflowConfigError("WX_BP_RVA 超出合理范围")

    version = os.environ.get("WX_EXPECTED_VERSION", DEFAULT_EXPECTED_VERSION).strip()
    parts = version.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        raise WorkflowConfigError("WX_EXPECTED_VERSION 必须是完整四段版本号，例如 4.1.12.26")

    raw_bytes = os.environ.get(
        "WX_EXPECTED_FN_BYTES", DEFAULT_EXPECTED_FN_BYTES.hex()
    ).replace(" ", "").strip()
    try:
        expected = bytes.fromhex(raw_bytes)
    except ValueError as exc:
        raise WorkflowConfigError("WX_EXPECTED_FN_BYTES 必须是偶数位十六进制字节串") from exc
    if not 3 <= len(expected) <= 32:
        raise WorkflowConfigError("WX_EXPECTED_FN_BYTES 长度必须为 3..32 字节")
    return rva, version, expected


def get_file_version(path: os.PathLike[str] | str) -> str:
    """读取 Windows FileVersion；失败返回空字符串。"""
    if os.name != "nt":
        return ""
    version = ctypes.WinDLL("version", use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wt.DWORD
    version.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
    version.GetFileVersionInfoW.restype = wt.BOOL
    version.VerQueryValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(wt.UINT)]
    version.VerQueryValueW.restype = wt.BOOL

    path_text = os.fspath(path)
    size = version.GetFileVersionInfoSizeW(path_text, None)
    if not size:
        return ""
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path_text, 0, size, data):
        return ""

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [("dwSignature", ctypes.c_uint32),
                    ("dwStrucVersion", ctypes.c_uint32),
                    ("dwFileVersionMS", ctypes.c_uint32),
                    ("dwFileVersionLS", ctypes.c_uint32),
                    ("dwProductVersionMS", ctypes.c_uint32),
                    ("dwProductVersionLS", ctypes.c_uint32)]

    ptr = ctypes.c_void_p()
    length = wt.UINT()
    if not version.VerQueryValueW(data, "\\", ctypes.byref(ptr), ctypes.byref(length)):
        return ""
    info = ctypes.cast(ptr, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    return (f"{info.dwFileVersionMS >> 16}.{info.dwFileVersionMS & 0xffff}."
            f"{info.dwFileVersionLS >> 16}.{info.dwFileVersionLS & 0xffff}")


def discover_weixin_exes() -> list[Path]:
    """只扫描有限的标准安装位置；结果仅供用户确认，不自动采用。"""
    candidates: list[Path] = []
    direct = shutil.which("Weixin.exe")
    if direct:
        candidates.append(Path(direct))
    roots = []
    for name in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        value = os.environ.get(name)
        if value:
            roots.append(Path(value))
    patterns = (
        ("Tencent", "Weixin", "Weixin.exe"),
        ("Tencent", "Weixin", "*", "Weixin.exe"),
        ("Programs", "Tencent", "Weixin", "Weixin.exe"),
        ("Programs", "Tencent", "Weixin", "*", "Weixin.exe"),
    )
    for root in roots:
        for parts in patterns:
            for match in glob.glob(os.fspath(root.joinpath(*parts))):
                path = Path(match)
                if path.is_file():
                    candidates.append(path.resolve())
    return _dedupe_paths(candidates)


def discover_db_dirs() -> list[Path]:
    """读取官方客户端配置中的数据根目录并枚举 db_storage；不读取数据库内容。"""
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        config_dir = Path(appdata) / "Tencent" / "xwechat" / "config"
        for ini_path in sorted(config_dir.glob("*.ini")):
            for encoding in ("utf-8-sig", "utf-16", "gbk"):
                try:
                    value = ini_path.read_text(encoding=encoding)[:4096].strip()
                except (OSError, UnicodeDecodeError):
                    continue
                if value and not any(ch in value for ch in "\r\n\x00"):
                    candidate = _expand_path(value)
                    if candidate.is_dir():
                        roots.append(candidate)
                break
    documents = Path.home() / "Documents"
    if documents.is_dir():
        roots.append(documents)

    matches: list[Path] = []
    for root in _dedupe_paths(roots):
        for pattern in ("xwechat_files/*/db_storage", "*/db_storage"):
            matches.extend(path.resolve() for path in root.glob(pattern) if path.is_dir())
    return _dedupe_paths(matches)


def count_encrypted_databases(db_dir: Path, page_size: int = 4096) -> tuple[int, int]:
    encrypted = plaintext = 0
    for path in sorted(db_dir.rglob("*.db")):
        try:
            with path.open("rb") as handle:
                page = handle.read(page_size)
        except OSError:
            continue
        if len(page) < page_size:
            continue
        if page.startswith(b"SQLite format 3\x00"):
            plaintext += 1
        else:
            encrypted += 1
    return encrypted, plaintext


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = os.path.normcase(os.fspath(path))
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result
