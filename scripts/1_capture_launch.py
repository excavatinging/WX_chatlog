#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
① 断点捕获: 以调试器模式启动微信, 在 SQLCipher kdf_iter setter 设 INT3 断点,
   登录时每个数据库初始化都会命中, 转储 codec 上下文内存到 ctx_dumps/

原理: Windows 官方调试 API (DebugActiveProcess/WaitForDebugEvent), 单字节 0xCC 断点,
      不注入任何可执行代码到目标进程。

用法:
  1. 配置下方 CONFIG (微信路径 / 数据库根目录)
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
import sys
import time

# ═══════════════════ CONFIG ═══════════════════
WEIXIN_EXE = os.environ.get("WX_EXE", r"C:\Program Files\Tencent\Weixin\Weixin.exe")
WEIXIN_DIR = os.environ.get("WX_DIR", r"C:\Program Files\Tencent\Weixin")
DB_DIR     = os.environ.get("WX_DB_DIR", r"D:\xwechat_files\<你的wxid目录>\db_storage")
OUT_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "secrets", "ctx_dumps")
# 断点 RVA (相对 Weixin.dll 基址)。4.1.12.26 实测值; 换版本用 find_kdf_anchor.py 重新定位
BP_RVA     = 0x3485D10
# 版本门禁: 断点地址只对经过验证的微信版本生效 (防止在错误地址写 0xCC)
# find_kdf_anchor.py 确认新版本后, 同时更新这里的预期函数开头字节
EXPECTED_VERSION_PREFIX = "4.1.12"
EXPECTED_FN_BYTES = bytes([0x89, 0x51, 0x04])   # mov [rcx+4],edx (4.1.12.26 @ BP_RVA)
# ═════════════════════════════════════════════

kernel32 = ctypes.windll.kernel32

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
THREAD_ALL = 0x1FFFFF
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


class DEBUG_EVENT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
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
version = ctypes.WinDLL("version")   # 版本信息 API 实际所在库 (kernel32 并不导出)

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
kernel32.FlushInstructionCache.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wt.DWORD]
kernel32.ContinueDebugEvent.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD]
kernel32.DebugSetProcessKillOnExit.argtypes = [wt.BOOL]
version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
version.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
version.VerQueryValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


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


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(read)):
        return buf.raw[:read.value]
    return None


def write_mem(h, addr, data):
    w = ctypes.c_size_t()
    return kernel32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(w))


def find_weixin_base(pid):
    """返回 (base, path) 或 (None, None)"""
    snap = kernel32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    if not snap or snap == 0xFFFFFFFFFFFFFFFF:   # NULL 或 INVALID_HANDLE_VALUE
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


def get_file_version(path):
    """从模块路径读 FileVersion (如 4.1.12.26); 失败返回 ''"""
    size = version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return ""
    data = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path, 0, size, data):
        return ""
    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [("dwSignature", ctypes.c_uint32), ("dwStrucVersion", ctypes.c_uint32),
                    ("dwFileVersionMS", ctypes.c_uint32), ("dwFileVersionLS", ctypes.c_uint32),
                    ("dwProductVersionMS", ctypes.c_uint32), ("dwProductVersionLS", ctypes.c_uint32)]
    p = ctypes.c_void_p()
    n = wt.UINT()
    if not version.VerQueryValueW(data, "\\", ctypes.byref(p), ctypes.byref(n)) or not p:
        return ""
    fi = ctypes.cast(p, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    return f"{fi.dwFileVersionMS >> 16}.{fi.dwFileVersionMS & 0xffff}.{fi.dwFileVersionLS >> 16}.{fi.dwFileVersionLS & 0xffff}"


def set_breakpoint(h, addr):
    """安全设断点: 校验函数开头字节 + 改保护 + 写 0xCC + 刷新指令缓存 + 记录原保护
    返回 (orig_byte, orig_prot) 或 None"""
    orig = read_mem(h, addr, len(EXPECTED_FN_BYTES))
    if not orig:
        return None
    if orig != EXPECTED_FN_BYTES:
        print(f"[!] 版本门禁: 0x{addr:x} 处字节 {orig.hex()} ≠ 预期 {EXPECTED_FN_BYTES.hex()}", flush=True)
        print("    微信版本与 BP_RVA 不匹配。请用 find_kdf_anchor.py 重新定位并更新 CONFIG", flush=True)
        return None
    old_prot = wt.DWORD()
    if not kernel32.VirtualProtectEx(h, ctypes.c_void_p(addr), 1,
                                     PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot)):
        return None
    if write_mem(h, addr, b'\xCC'):
        kernel32.FlushInstructionCache(h, ctypes.c_void_p(addr), 1)
        return (orig[0], old_prot.value)
    # 写失败则恢复保护
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(addr), 1, old_prot, ctypes.byref(wt.DWORD()))
    return None


def clear_breakpoint(h, addr, orig_byte, orig_prot):
    """完整清除断点: 恢复字节 + 恢复原保护 + 刷新指令缓存"""
    if write_mem(h, addr, bytes([orig_byte])):
        kernel32.FlushInstructionCache(h, ctypes.c_void_p(addr), 1)
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(addr), 1,
                              wt.DWORD(orig_prot), ctypes.byref(wt.DWORD()))


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


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{WEIXIN_EXE}"')

    print("[*] 以调试模式启动微信 (含全部子进程)...", flush=True)
    ok = kernel32.CreateProcessW(WEIXIN_EXE, cmd, None, None, False,
                                 DEBUG_PROCESS, None, WEIXIN_DIR,
                                 ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print(f"[!] CreateProcess 失败 err={ctypes.GetLastError()}")
        sys.exit(1)
    main_pid = pi.dwProcessId
    print(f"[✓] 微信已启动 PID={main_pid} — 请在微信窗口完成登录", flush=True)

    kernel32.DebugSetProcessKillOnExit(False)

    # 每进程状态
    procs = {main_pid: {"h": pi.hProcess, "armed": {}}}
    exited = set()
    single_step_pending = {}
    ctx_files = []
    t0 = time.time()

    TOTAL = 900          # 总监听窗口 (秒)
    COLLECT_EXTRA = 240  # 首次命中后无新命中的收尾时间

    try:
        _event_loop(procs, exited, single_step_pending, ctx_files,
                    main_pid, t0, TOTAL, COLLECT_EXTRA)
    finally:
        # 任何退出路径 (含 Ctrl+C) 都恢复断点并脱离调试
        cleanup(procs, exited, main_pid)
    print(f"[*] 结束: {len(ctx_files)} 个转储 → {OUT_DIR}", flush=True)
    print("[*] 已脱离调试, 微信继续运行", flush=True)


def _event_loop(procs, exited, single_step_pending, ctx_files,
                main_pid, t0, TOTAL, COLLECT_EXTRA):
    ctxbuf = CONTEXT()
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
                if pid in exited or st["armed"]:
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
                if ver and not ver.startswith(EXPECTED_VERSION_PREFIX):
                    print(f"[!] PID {pid}: Weixin.dll 版本 {ver} 未经验证 (预期 {EXPECTED_VERSION_PREFIX}.x), 跳过", flush=True)
                    print("    请用 find_kdf_anchor.py 重新定位 RVA 并更新 CONFIG", flush=True)
                    st["armed"] = None   # 标记不再尝试
                    continue
                addr = base + BP_RVA
                r = set_breakpoint(h, addr)
                if r:
                    orig_byte, orig_prot = r
                    st["armed"][addr] = (orig_byte, orig_prot)
                    print(f"[✓] PID {pid}: 断点已设 (Weixin.dll {ver} @0x{base:x}+{BP_RVA:x})", flush=True)

        if not kernel32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue

        code = ev.dwDebugEventCode
        pid_ev, tid = ev.dwProcessId, ev.dwThreadId

        if code == EXIT_PROCESS_DEBUG_EVENT:
            exited.add(pid_ev)
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
                procs[pid_ev] = {"h": None, "armed": {}}
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code in (CREATE_THREAD_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
                    LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
                    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT):
            if pid_ev not in procs:
                procs[pid_ev] = {"h": None, "armed": {}}
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if code != EXCEPTION_DEBUG_EVENT:
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_EXCEPTION_NOT_HANDLED)
            continue

        exc_code = ev.u.Exception.ExceptionRecord.ExceptionCode
        exc_addr = ev.u.Exception.ExceptionRecord.ExceptionAddress or 0
        st = procs.get(pid_ev)

        if exc_code == EXCEPTION_BREAKPOINT and st and st["armed"] and exc_addr in st["armed"]:
            last_hit = time.time()
            th = kernel32.OpenThread(THREAD_ALL, False, tid)
            ctxbuf.ContextFlags = CONTEXT_FULL64
            kernel32.GetThreadContext(th, ctypes.byref(ctxbuf))
            rcx, rbx = ctxbuf.Rcx, ctxbuf.Rbx
            kernel32.CloseHandle(th)
            h = st["h"]
            print(f"[BP] pid={pid_ev} rcx=0x{rcx:x} rbx=0x{rbx:x}", flush=True)
            regions = {}
            for ptr in (rcx, rbx):
                if 0x10000 < ptr < 0x7FFFFFFFFFFF:
                    regions.update(dump_ctx_regions(h, ptr))
            fn = os.path.join(OUT_DIR, f"ctx_p{pid_ev}_{int(time.time() * 1000)}.json")
            with open(fn, "w") as f:
                json.dump({"pid": pid_ev, "rcx": rcx, "rbx": rbx,
                           "bp_addr": exc_addr, "regions": regions}, f)
            try:
                os.chmod(fn, 0o600)
            except OSError:
                pass
            ctx_files.append(fn)
            # 恢复原字节(+保护) + 单步 + 重设断点
            orig_byte, orig_prot = st["armed"][exc_addr]
            clear_breakpoint(h, exc_addr, orig_byte, orig_prot)
            th = kernel32.OpenThread(THREAD_ALL, False, tid)
            kernel32.GetThreadContext(th, ctypes.byref(ctxbuf))
            ctxbuf.Rip = exc_addr
            ctxbuf.EFlags |= 0x100  # TRAP
            kernel32.SetThreadContext(th, ctypes.byref(ctxbuf))
            kernel32.CloseHandle(th)
            single_step_pending[(pid_ev, tid)] = exc_addr
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        if exc_code == EXCEPTION_SINGLE_STEP and (pid_ev, tid) in single_step_pending:
            addr = single_step_pending.pop((pid_ev, tid))
            st2 = procs.get(pid_ev)
            if st2 and st2["armed"] and addr in st2["armed"]:
                th = kernel32.OpenThread(THREAD_ALL, False, tid)
                kernel32.GetThreadContext(th, ctypes.byref(ctxbuf))
                ctxbuf.EFlags &= ~0x100
                kernel32.SetThreadContext(th, ctypes.byref(ctxbuf))
                kernel32.CloseHandle(th)
                write_mem(st2["h"], addr, b'\xCC')
                kernel32.FlushInstructionCache(st2["h"], ctypes.c_void_p(addr), 1)
            kernel32.ContinueDebugEvent(pid_ev, tid, DBG_CONTINUE)
            continue

        # 非本工具的断点/单步异常 → 交回系统默认处理 (勿吞)
        kernel32.ContinueDebugEvent(pid_ev, tid, DBG_EXCEPTION_NOT_HANDLED)


def cleanup(procs, exited, main_pid):
    """恢复所有断点字节与内存保护, 脱离调试。幂等, 可重复调用。"""
    for pid, st in procs.items():
        if pid in exited or not st.get("armed"):
            continue
        h = st.get("h")
        if not h:
            h = kernel32.OpenProcess(0x1F0FFF, False, pid)
        if h:
            for addr, (orig_byte, orig_prot) in list(st["armed"].items()):
                clear_breakpoint(h, addr, orig_byte, orig_prot)
            st["armed"] = {}
    kernel32.DebugSetProcessKillOnExit(False)
    try:
        kernel32.DebugActiveProcessStop(main_pid)
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] 中断 — 清理断点中...", flush=True)
        raise SystemExit(130)
