#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
① 断点捕获: 以调试器模式启动目标程序, 在 SQLCipher kdf_iter setter 设 INT3 断点,
   登录时每个数据库初始化都会命中, 转储 codec 上下文内存到 secrets/ctx_dumps/

原理: Windows 官方调试 API (CreateProcessW/WaitForDebugEvent), 单字节 0xCC 断点,
      不注入任何可执行代码到目标进程。

用法:
  1. 先运行 0_preflight.py，并用环境变量配置微信路径与版本锚点
  2. 完全退出当前微信
  3. 运行本脚本 → 微信以调试模式启动 → 在微信中登录
  4. 首次命中后自动收集数分钟, 无新命中自动退出 (微信不受影响继续运行)

输出: ctx_dumps/*.json  (含密钥上下文内存, 属敏感数据, 勿外传)
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import time

from win_dacl import secure_directory, secure_write_text
from workflow_common import (
    DEFAULT_BP_RVA,
    DEFAULT_EXPECTED_FN_BYTES,
    DEFAULT_EXPECTED_VERSION,
    WorkflowConfigError,
    get_file_version,
    require_windows_x64,
    resolve_anchor_config,
    resolve_secrets_dir,
    resolve_weixin_paths,
)

# ═══════════════════ CONFIG ═══════════════════
WEIXIN_EXE = ""
WEIXIN_DIR = ""
OUT_DIR = ""
# 已验证基线。换版本时用 find_kdf_anchor.py 生成环境变量，不修改仓库源码。
BP_RVA = DEFAULT_BP_RVA
EXPECTED_VERSION = DEFAULT_EXPECTED_VERSION
EXPECTED_FN_BYTES = DEFAULT_EXPECTED_FN_BYTES
# ═════════════════════════════════════════════

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

DEBUG_PROCESS = 0x1
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
PAGE_EXECUTE_READWRITE = 0x40
THREAD_CONTEXT_ACCESS = 0x0008 | 0x0010 | 0x0040
CONTEXT_FULL64 = 0x10000B


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", ctypes.c_uint32),
                ("ExceptionFlags", ctypes.c_uint32),
                ("ExceptionRecord", ctypes.c_void_p),
                ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", ctypes.c_uint32),
                ("ExceptionInformation", ctypes.c_uint64 * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", ctypes.c_uint32)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", wt.HANDLE),
                ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE),
                ("hProcess", wt.HANDLE),
                ("hThread", wt.HANDLE),
                ("lpBaseOfImage", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wt.DWORD),
                ("nDebugInfoSize", wt.DWORD),
                ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p),
                ("lpImageName", ctypes.c_void_p),
                ("fUnicode", wt.WORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE),
                ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wt.DWORD),
                ("nDebugInfoSize", wt.DWORD),
                ("lpImageName", ctypes.c_void_p),
                ("fUnicode", wt.WORD)]


class DEBUG_EVENT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                    ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                    ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                    ("LoadDll", LOAD_DLL_DEBUG_INFO),
                    ("raw", ctypes.c_byte * 160)]
    _fields_ = [("dwDebugEventCode", ctypes.c_uint32),
                ("dwProcessId", ctypes.c_uint32),
                ("dwThreadId", ctypes.c_uint32),
                ("u", _U)]


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]


class XMM_SAVE_AREA32(ctypes.Structure):
    """FXSAVE 格式 (winnt.h _XMM_SAVE_AREA32), 恰 512 字节"""
    _fields_ = [
        ("ControlWord", wt.WORD), ("StatusWord", wt.WORD),
        ("TagWord", ctypes.c_uint8), ("Reserved1", ctypes.c_uint8),
        ("ErrorOpcode", wt.WORD), ("ErrorOffset", wt.DWORD),
        ("ErrorSelector", wt.WORD),
        ("Reserved2", ctypes.c_uint8), ("Reserved3", ctypes.c_uint8),
        ("DataOffset", wt.DWORD), ("DataSelector", wt.DWORD),
        ("MxCsr", wt.DWORD), ("MxCsr_Mask", wt.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_uint8 * 96),
    ]


class CONTEXT(ctypes.Structure):
    """x64 CONTEXT 完整布局 (winnt.h)。GetThreadContext 要求实例 16 字节对齐。"""
    _align_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wt.DWORD), ("MxCsr", wt.DWORD),
        ("SegCs", wt.WORD), ("SegDs", wt.WORD), ("SegEs", wt.WORD),
        ("SegFs", wt.WORD), ("SegGs", wt.WORD), ("SegSs", wt.WORD),
        ("EFlags", wt.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", XMM_SAVE_AREA32),              # 512B, 填充至 16 对齐
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


# WinAPI 签名声明: 64 位下无 argtypes 时 Python int 会被当作 32 位 C int 传递,
# 64 位地址/句柄将被静默截断 — 这里显式声明防止此类错误
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenThread.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_size_t)]
kernel32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                      wt.DWORD, ctypes.POINTER(wt.DWORD)]
kernel32.VirtualProtectEx.restype = wt.BOOL
kernel32.FlushInstructionCache.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
kernel32.FlushInstructionCache.restype = wt.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]
kernel32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
kernel32.ContinueDebugEvent.restype = wt.BOOL
kernel32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wt.DWORD]
kernel32.DebugActiveProcessStop.restype = wt.BOOL


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


kernel32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wt.BOOL
kernel32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wt.BOOL


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD)] + [(n, ctypes.c_void_p) for n in
                ("lpReserved", "lpDesktop", "lpTitle")] + [
                (n, wt.DWORD) for n in ("dwX", "dwY", "dwXSize", "dwYSize",
                "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + [
                ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


kernel32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR,
                                    ctypes.c_void_p, ctypes.c_void_p,
                                    wt.BOOL, wt.DWORD, ctypes.c_void_p,
                                    wt.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                    ctypes.POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessW.restype = wt.BOOL


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return None


def write_mem(h, addr, data):
    buf = ctypes.create_string_buffer(data)
    w = ctypes.c_size_t()
    ok = kernel32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(w))
    return bool(ok and w.value == len(data))


def find_weixin_base(pid):
    """返回 (base, path) 或 (None, None)"""
    snap = kernel32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    if not snap or snap == ctypes.c_void_p(-1).value:   # NULL 或 INVALID_HANDLE_VALUE
        return None, None
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    base = path = None
    ok = kernel32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        if me.szModule.lower() == "weixin.dll":
            base = me.modBaseAddr
            path = me.szExePath
            break
        ok = kernel32.Module32NextW(snap, ctypes.byref(me))
    kernel32.CloseHandle(snap)
    return base, path


class BreakpointProfileMismatch(RuntimeError):
    pass


def _patch_byte(h, addr, value):
    """临时放宽页保护写 1 字节，随后立即恢复原保护。"""
    original = read_mem(h, addr, 1)
    if not original or len(original) != 1:
        return False
    old_prot = wt.DWORD()
    if not kernel32.VirtualProtectEx(h, ctypes.c_void_p(addr), 1,
                                     PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)):
        return False
    wrote = write_mem(h, addr, bytes([value]))
    flushed = bool(
        wrote and kernel32.FlushInstructionCache(h, ctypes.c_void_p(addr), 1)
    )
    ignored = wt.DWORD()
    restored = bool(kernel32.VirtualProtectEx(
        h, ctypes.c_void_p(addr), 1, old_prot.value, ctypes.byref(ignored)
    ))
    if wrote and flushed and restored:
        return True

    # 任何写后失败都回滚原字节，并再次尝试恢复原页保护，避免静默留下
    # INT3 或 RWX 页面。回滚也失败时，停止工作流并交给 cleanup 再尝试。
    rollback_old = wt.DWORD()
    rollback_ready = kernel32.VirtualProtectEx(
        h, ctypes.c_void_p(addr), 1, PAGE_EXECUTE_READWRITE,
        ctypes.byref(rollback_old)
    )
    rollback_wrote = bool(rollback_ready and write_mem(h, addr, original))
    rollback_flushed = bool(
        rollback_wrote
        and kernel32.FlushInstructionCache(h, ctypes.c_void_p(addr), 1)
    )
    rollback_ignored = wt.DWORD()
    rollback_restored = bool(
        rollback_ready
        and kernel32.VirtualProtectEx(
            h, ctypes.c_void_p(addr), 1, old_prot.value,
            ctypes.byref(rollback_ignored)
        )
    )
    if not (rollback_wrote and rollback_flushed and rollback_restored):
        raise RuntimeError("内存字节或页保护回滚失败，目标进程状态可能不完整")
    return False


def set_breakpoint(h, addr):
    """校验函数开头字节并设置 INT3；返回原首字节或 None。"""
    orig = read_mem(h, addr, len(EXPECTED_FN_BYTES))
    if not orig:
        return None
    if orig != EXPECTED_FN_BYTES:
        raise BreakpointProfileMismatch(
            f"断点位置字节 {orig.hex()} 与预期 {EXPECTED_FN_BYTES.hex()} 不一致")
    return orig[0] if _patch_byte(h, addr, 0xCC) else None


def clear_breakpoint(h, addr, orig_byte):
    """恢复断点原字节；页保护由 _patch_byte 自动复原。"""
    return _patch_byte(h, addr, orig_byte)


def dump_ctx_regions(hproc, ctx_ptr, max_regions=60):
    """转储 ctx 本体 (0x400) + 一层指针追踪"""
    regions = {}
    body = read_mem(hproc, ctx_ptr, 0x400)
    if body:
        regions[hex(ctx_ptr)] = body.hex()
        for off in range(0, len(body) - 8, 8):
            ptr = struct.unpack('<Q', body[off:off + 8])[0]
            if 0x10000 < ptr < 0x7FFFFFFFFFFF and hex(ptr) not in regions:
                d2 = read_mem(hproc, ptr, 0x400)
                if d2 and len(regions) < max_regions:
                    regions[hex(ptr)] = d2.hex()
    return regions


def get_thread_context(tid):
    handle = kernel32.OpenThread(THREAD_CONTEXT_ACCESS, False, tid)
    if not handle:
        raise RuntimeError(f"OpenThread 失败 err={ctypes.get_last_error()}")
    context = CONTEXT()
    if ctypes.addressof(context) % 16:
        kernel32.CloseHandle(handle)
        raise RuntimeError("CONTEXT 缓冲未按 16 字节对齐")
    context.ContextFlags = CONTEXT_FULL64
    if not kernel32.GetThreadContext(handle, ctypes.byref(context)):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise RuntimeError(f"GetThreadContext 失败 err={err}")
    return handle, context


def _recover_breakpoint_event(pid, tid, hproc, addr, orig_byte):
    """本工具断点处理失败时，恢复原指令并让线程从函数入口正常继续。"""
    if not clear_breakpoint(hproc, addr, orig_byte):
        raise RuntimeError("失败恢复期间无法还原断点字节")
    handle, context = get_thread_context(tid)
    try:
        context.Rip = addr
        context.EFlags &= ~0x100
        if not kernel32.SetThreadContext(handle, ctypes.byref(context)):
            raise RuntimeError(f"失败恢复期间 SetThreadContext err={ctypes.get_last_error()}")
    finally:
        kernel32.CloseHandle(handle)
    if not kernel32.ContinueDebugEvent(pid, tid, DBG_CONTINUE):
        raise RuntimeError(f"失败恢复期间 ContinueDebugEvent err={ctypes.get_last_error()}")


def _recover_single_step_event(pid, tid, hproc, addr, orig_byte):
    """重设断点失败时保留已执行结果，清除 TRAP 并停止继续设断。"""
    if not clear_breakpoint(hproc, addr, orig_byte):
        raise RuntimeError("单步失败恢复期间无法还原断点字节")
    handle, context = get_thread_context(tid)
    try:
        context.EFlags &= ~0x100
        if not kernel32.SetThreadContext(handle, ctypes.byref(context)):
            raise RuntimeError(f"单步失败恢复期间 SetThreadContext err={ctypes.get_last_error()}")
    finally:
        kernel32.CloseHandle(handle)
    if not kernel32.ContinueDebugEvent(pid, tid, DBG_CONTINUE):
        raise RuntimeError(f"单步失败恢复期间 ContinueDebugEvent err={ctypes.get_last_error()}")


def main():
    global WEIXIN_EXE, WEIXIN_DIR, OUT_DIR
    global BP_RVA, EXPECTED_VERSION, EXPECTED_FN_BYTES
    try:
        require_windows_x64()
        exe, workdir = resolve_weixin_paths()
        BP_RVA, EXPECTED_VERSION, EXPECTED_FN_BYTES = resolve_anchor_config()
        WEIXIN_EXE = os.fspath(exe)
        WEIXIN_DIR = os.fspath(workdir)
        secrets_dir = resolve_secrets_dir(create=True)
        secure_directory(secrets_dir)
        output_dir = secrets_dir / "ctx_dumps"
        secure_directory(output_dir)
        OUT_DIR = os.fspath(output_dir)
    except (WorkflowConfigError, RuntimeError) as exc:
        print(f"[!] 环境未准备好: {exc}")
        print("    先运行: python scripts/0_preflight.py")
        return 2

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{WEIXIN_EXE}"')

    print("[*] 以调试模式启动微信 (含全部子进程)...", flush=True)
    ok = kernel32.CreateProcessW(WEIXIN_EXE, cmd, None, None, False,
                                 DEBUG_PROCESS, None, WEIXIN_DIR,
                                 ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print(f"[!] CreateProcess 失败 err={ctypes.get_last_error()}")
        return 1
    main_pid = pi.dwProcessId
    kernel32.CloseHandle(pi.hThread)
    print(f"[✓] 微信已启动 PID={main_pid} — 请在微信窗口完成登录", flush=True)

    kernel32.DebugSetProcessKillOnExit(False)

    # 每进程状态
    procs = {main_pid: {"h": pi.hProcess, "armed": {}, "disabled": False,
                        "initial_breakpoint_seen": False}}
    exited = set()
    single_step_pending = {}
    ctx_files = []
    t0 = time.time()

    TOTAL = 900          # 总监听窗口 (秒)
    COLLECT_EXTRA = 240  # 首次命中后无新命中的收尾时间

    cleanup_ok = False
    try:
        _event_loop(procs, exited, single_step_pending, ctx_files,
                    main_pid, t0, TOTAL, COLLECT_EXTRA)
    finally:
        # 任何退出路径 (含 Ctrl+C) 都恢复断点并脱离调试
        cleanup_ok = cleanup(procs, exited)
    if not cleanup_ok:
        print("[!] 清理未完整成功；请不要继续使用该客户端进程，先由用户自行退出", flush=True)
        return 4
    print(f"[*] 结束: {len(ctx_files)} 个转储 → 敏感输出目录/ctx_dumps", flush=True)
    print("[*] 已脱离调试, 微信继续运行", flush=True)
    return 0 if ctx_files else 3


def _event_loop(procs, exited, single_step_pending, ctx_files,
                main_pid, t0, TOTAL, COLLECT_EXTRA):
    ev = DEBUG_EVENT()
    last_hb = 0.0
    last_hit = None
    poll_tick = 0

    while time.time() - t0 < TOTAL:
        if last_hit and time.time() - last_hit > COLLECT_EXTRA:
            break

        now = time.time()
        if now - last_hb > 15:
            last_hb = now
            armed = sum(len(p["armed"]) for p in procs.values() if isinstance(p["armed"], dict))
            print(f"[hb] {int(now - t0)}s 进程:{len(procs)} 断点:{armed} 捕获:{len(ctx_files)}", flush=True)

        # 轮询: Weixin.dll 加载后立即设断点 (每 400ms, 消除登录竞态)
        poll_tick += 1
        if poll_tick % 1 == 0:
            for pid, st in list(procs.items()):
                if pid in exited or st["armed"] or st.get("disabled"):
                    continue
                base, modpath = find_weixin_base(pid)
                if not base:
                    continue
                h = st["h"]
                if not h:
                    h = kernel32.OpenProcess(0x1F0FFF, False, pid)
                    if not h:
                        continue
                    st["h"] = h
                # 版本门禁: 只对验证过的微信版本设断 (防止错误地址写入)
                ver = get_file_version(modpath) if modpath else ""
                if not ver:
                    print(f"[!] PID {pid}: 无法读取 Weixin.dll 完整版本，安全门禁拒绝设断点", flush=True)
                    st["disabled"] = True
                    continue
                if ver != EXPECTED_VERSION:
                    print(f"[!] PID {pid}: Weixin.dll 版本 {ver} 未经验证 (预期 {EXPECTED_VERSION})，跳过", flush=True)
                    print("    请用 find_kdf_anchor.py 重新定位，并设置 WX_* 锚点环境变量", flush=True)
                    st["disabled"] = True
                    continue
                addr = base + BP_RVA
                try:
                    r = set_breakpoint(h, addr)
                except BreakpointProfileMismatch as exc:
                    print(f"[!] PID {pid}: 版本门禁拒绝设断点: {exc}", flush=True)
                    print("    请用 find_kdf_anchor.py 重新定位，并设置 WX_* 锚点环境变量", flush=True)
                    st["disabled"] = True
                    continue
                if r:
                    st["armed"][addr] = r
                    print(f"[✓] PID {pid}: 断点已设 (Weixin.dll {ver} @0x{base:x}+{BP_RVA:x})", flush=True)

        if not kernel32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue

        code = ev.dwDebugEventCode
        pid_ev, tid = ev.dwProcessId, ev.dwThreadId

        if code == EXIT_PROCESS_DEBUG_EVENT:
            exited.add(pid_ev)
            state = procs.get(pid_ev)
            if state and state.get("h"):
                kernel32.CloseHandle(state["h"])
                state["h"] = None
            alive = [p for p in procs if p not in exited]
            if not alive:
                print("[*] 全部进程已退出", flush=True)
                kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
                break
            if pid_ev == main_pid:
                # 微信4.x 为"启动器→真实进程"架构, 启动器退出是正常现象
                print(f"[*] 启动器退出, 继续监控真实进程 {alive}", flush=True)
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code == CREATE_PROCESS_DEBUG_EVENT:
            if pid_ev not in procs:
                procs[pid_ev] = {"h": None, "armed": {}, "disabled": False,
                                "initial_breakpoint_seen": False}
            state = procs[pid_ev]
            info = ev.u.CreateProcessInfo
            if not state["h"]:
                state["h"] = info.hProcess
            elif info.hProcess and info.hProcess != state["h"]:
                kernel32.CloseHandle(info.hProcess)
            if info.hThread:
                kernel32.CloseHandle(info.hThread)
            if info.hFile:
                kernel32.CloseHandle(info.hFile)
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code == CREATE_THREAD_DEBUG_EVENT:
            if pid_ev not in procs:
                procs[pid_ev] = {"h": None, "armed": {}, "disabled": False,
                                "initial_breakpoint_seen": False}
            if ev.u.CreateThread.hThread:
                kernel32.CloseHandle(ev.u.CreateThread.hThread)
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code == LOAD_DLL_DEBUG_EVENT:
            if ev.u.LoadDll.hFile:
                kernel32.CloseHandle(ev.u.LoadDll.hFile)
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code in (EXIT_THREAD_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
                    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT):
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code != EXCEPTION_DEBUG_EVENT:
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_EXCEPTION_NOT_HANDLED)
            continue

        exc_code = ev.u.Exception.ExceptionRecord.ExceptionCode
        exc_addr = ev.u.Exception.ExceptionRecord.ExceptionAddress or 0
        st = procs.get(pid_ev)

        # Windows 为每个新调试进程发送一次系统初始断点；必须由调试器消费。
        if (exc_code == EXCEPTION_BREAKPOINT and st
                and not st["initial_breakpoint_seen"]
                and exc_addr not in st["armed"]):
            st["initial_breakpoint_seen"] = True
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if exc_code == EXCEPTION_BREAKPOINT and st and st["armed"] and exc_addr in st["armed"]:
            last_hit = time.time()
            orig_byte = st["armed"][exc_addr]
            try:
                th, context = get_thread_context(tid)
                try:
                    rcx, rbx = context.Rcx, context.Rbx
                finally:
                    kernel32.CloseHandle(th)
                h = st["h"]
                print(f"[BP] pid={pid_ev} 捕获 #{len(ctx_files) + 1}", flush=True)
                regions = {}
                for ptr in (rcx, rbx):
                    if 0x10000 < ptr < 0x7FFFFFFFFFFF:
                        regions.update(dump_ctx_regions(h, ptr))
                fn = os.path.join(
                    OUT_DIR, f"ctx_p{pid_ev}_{int(time.time() * 1000)}.json"
                )
                payload = json.dumps(
                    {"pid": pid_ev, "rcx": rcx, "rbx": rbx,
                     "bp_addr": exc_addr, "regions": regions},
                    ensure_ascii=False, separators=(",", ":")
                )
                secure_write_text(fn, payload)
                # 恢复原字节 + 单步 + 重设断点
                if not clear_breakpoint(h, exc_addr, orig_byte):
                    raise RuntimeError("无法恢复断点原字节，已停止以避免目标进程状态不明")
                th, context = get_thread_context(tid)
                try:
                    context.Rip = exc_addr
                    context.EFlags |= 0x100  # TRAP
                    if not kernel32.SetThreadContext(th, ctypes.byref(context)):
                        raise RuntimeError(f"SetThreadContext 失败 err={ctypes.get_last_error()}")
                finally:
                    kernel32.CloseHandle(th)
                single_step_pending[(pid_ev, tid)] = exc_addr
                if not kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE):
                    raise RuntimeError(
                        f"ContinueDebugEvent 失败 err={ctypes.get_last_error()}"
                    )
            except (Exception, KeyboardInterrupt) as exc:
                single_step_pending.pop((pid_ev, tid), None)
                try:
                    _recover_breakpoint_event(pid_ev, tid, st["h"], exc_addr, orig_byte)
                except (RuntimeError, KeyboardInterrupt) as recovery_exc:
                    raise RuntimeError(
                        f"断点处理失败，且安全恢复失败: {recovery_exc}"
                    ) from exc
                raise
            ctx_files.append(fn)
            continue

        if exc_code == EXCEPTION_SINGLE_STEP and (pid_ev, tid) in single_step_pending:
            addr = single_step_pending[(pid_ev, tid)]
            st2 = procs.get(pid_ev)
            if st2 and st2["armed"] and addr in st2["armed"]:
                try:
                    th, context = get_thread_context(tid)
                    try:
                        context.EFlags &= ~0x100
                        if not kernel32.SetThreadContext(th, ctypes.byref(context)):
                            raise RuntimeError(
                                f"SetThreadContext 失败 err={ctypes.get_last_error()}"
                            )
                    finally:
                        kernel32.CloseHandle(th)
                    rearmed = set_breakpoint(st2["h"], addr)
                    if rearmed is None:
                        raise RuntimeError("单步后无法重新设置断点")
                    st2["armed"][addr] = rearmed
                    if not kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE):
                        raise RuntimeError(
                            f"ContinueDebugEvent 失败 err={ctypes.get_last_error()}"
                        )
                except (Exception, KeyboardInterrupt) as exc:
                    single_step_pending.pop((pid_ev, tid), None)
                    try:
                        _recover_single_step_event(
                            pid_ev, tid, st2["h"], addr, st2["armed"][addr]
                        )
                    except (RuntimeError, KeyboardInterrupt) as recovery_exc:
                        raise RuntimeError(
                            f"单步处理失败，且安全恢复失败: {recovery_exc}"
                        ) from exc
                    raise
            else:
                if not kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE):
                    raise RuntimeError(
                        f"ContinueDebugEvent 失败 err={ctypes.get_last_error()}"
                    )
            single_step_pending.pop((pid_ev, tid), None)
            continue

        # 非本工具的断点/单步异常 → 交回系统默认处理 (勿吞)
        kernel32.ContinueDebugEvent(pid_ev, tid, DBG_EXCEPTION_NOT_HANDLED)


def cleanup(procs, exited):
    """恢复所有断点字节与内存保护, 脱离调试。幂等, 可重复调用。"""
    failed_pids = set()
    for pid, st in procs.items():
        if pid in exited or not st.get("armed"):
            continue
        h = st.get("h")
        opened_here = False
        if not h:
            h = kernel32.OpenProcess(0x1F0FFF, False, pid)
            opened_here = bool(h)
        if h:
            for addr, orig_byte in list(st["armed"].items()):
                restored = False
                for _ in range(3):
                    try:
                        if clear_breakpoint(h, addr, orig_byte):
                            restored = True
                            break
                    except RuntimeError:
                        continue
                if restored:
                    st["armed"].pop(addr, None)
                else:
                    failed_pids.add(pid)
                    print(
                        f"[CRITICAL] PID {pid}: 断点字节三次恢复失败，目标进程状态未知",
                        flush=True,
                    )
            if opened_here:
                kernel32.CloseHandle(h)
        else:
            failed_pids.add(pid)
            print(f"[CRITICAL] PID {pid}: 无法打开进程以恢复断点", flush=True)
    kernel32.DebugSetProcessKillOnExit(False)
    for pid in procs:
        if pid not in exited and not kernel32.DebugActiveProcessStop(pid):
            print(
                f"[WARN] PID {pid}: 主动脱离调试失败，调试器退出时由系统释放",
                flush=True,
            )
    for st in procs.values():
        h = st.get("h")
        if h:
            kernel32.CloseHandle(h)
            st["h"] = None
    return not failed_pids


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[*] 中断 — 清理断点中...", flush=True)
        raise SystemExit(130)
    except RuntimeError as exc:
        print(f"[!] 工作流已停止: {exc}", flush=True)
        raise SystemExit(1)
