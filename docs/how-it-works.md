# 技术原理

## 微信 4.1.x 数据库加密体系

微信 4.x 将聊天记录存储为 SQLCipher 变体加密的 SQLite 数据库（`xwechat_files/<wxid>/db_storage/**/*.db`）：

```
salt     = db 文件前 16 字节（每个库随机生成）
enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, dklen=32)
mac_key  = PBKDF2-HMAC-SHA512(enc_key, salt ^ 0x3a, 2, dklen=32)

每页 (4096B): [salt(仅第1页前16B)][AES-256-CBC密文][iv(16)][HMAC-SHA512(64)]
页 HMAC 覆盖: 密文区 + 小端 u32 页号   ← 注意: 非标准 SQLCipher 的大端
```

密钥体系在 4.0 → 4.1.8+ 之间发生了关键变化：

| | 4.0.x | 4.1.8+ |
|---|---|---|
| 进程内存中的形态 | 派生后的 `enc_key`（以 `x'<hex>'` 等 hex 字符串形式常驻） | 仅 `passphrase`，且**即用即擦** |
| 静态内存扫描 | 可行（chatlog/wechat-cli 等的做法） | **全部失效** |
| 每库密钥 | 同一 passphrase 派生 | 同一 passphrase 派生（不变） |

这也是 2025 年末主流工具连环失效的根本原因——它们的提取器都在扫"已派生密钥的 hex 串形态"。

## 本项目方案：断点捕获 + 派生验证

### ① 断点捕获（1_capture_launch.py）

**锚点定位**：无符号表条件下，用 PBKDF2 迭代次数 `256000/0x3E800` 作为立即数锚点。在 183MB 的 `.text` 段中，该常量出现约百次，但"作为函数参数装载"（`mov edx, 0x3E800; call ...`）的调用点极少（实测仅 2 处）。被调函数即 SQLCipher 的 `kdf_iter` setter——每个数据库初始化的必经之路。

**断点机制**：全程使用 Windows 官方调试 API：
- `CreateProcessW(..., DEBUG_PROCESS, ...)` 以调试器身份启动微信（覆盖全部子进程）
- `VirtualProtectEx` + `WriteProcessMemory` 在函数入口写单字节 `0xCC`（INT3）
- `WaitForDebugEvent` 循环：命中 → 读 `CONTEXT` 寄存器（RCX = codec 上下文指针）→ `ReadProcessMemory` 转储上下文及一层指针追踪 → 恢复原字节 → 设 TRAP 标志单步 → 重设断点
- **不注入任何可执行代码**，断点字节退出前全部还原，微信进程无感

**工程细节**（都是实战踩坑）：
- 微信 4.x 是"启动器 → 真实进程"架构：启动器进程退出是正常现象，不能当作微信退出
- 调试事件常量：EXCEPTION=1, CREATE_THREAD=2, ..., EXIT_PROCESS=5（WinBase.h 定义，勿凭记忆写）
- 断点必须在登录**前**就位：数据库初始化只在登录时发生一次；轮询周期 400ms 保证 Weixin.dll 一加载即设断
- 实测一次登录命中 166 次（22 个库 × 多线程/多进程路径），转储约 4.5MB

### ② passphrase 提取（2_extract_passphrase.py）

对转储字节做 8 字节步进滑窗，每个 32B 窗口作为候选：

```
Way A (4.1+ 主路径): PBKDF2(候选, salt, 256000) → enc_key → mac_key → HMAC 验证
Way B (4.0 兼容):    候选本身即 enc_key → PBKDF2(候选, mac_salt, 2) → HMAC 验证
```

**算力问题**：Way A 每候选需 256000 轮 SHA512（约 1.2 秒），6.7 万候选朴素实现需 4 天。两个优化使其降到 45 分钟：
1. **单样本门控**——同一 passphrase 派生所有库，先用一个库的门控样本筛，命中即停（省 22 倍）
2. `imap_unordered` + chunksize 流水线，14 核打满

### ③ 密钥派生（3_derive_keys.py）

拿到 passphrase 后，对每个库用自己的 salt 派生 `enc_key`，逐库 HMAC 验证（应 100% 通过），输出 wechat-cli 格式的 `all_keys.json`。之后的查询/解密/导出交给 wechat-cli（其查询层兼容 4.1.12，仅密钥提取环节失效）。

## 为什么不直接 Hook 函数参数

理论上断在 `set_pass(ctx, key, len)` 上可直接读 RDX 拿到 passphrase（wx_key 系工具的 DLL 注入做法）。但静态分析无法可靠区分 setter 函数（代码模式相似者众多，实测某"3 参数 + 写 rcx 字段"候选并非登录路径）；而 `kdf_iter` setter 有 256000 这个不变常量做锚点，跨版本稳定。捕获 kdf 上下文后，passphrase 就存在其可达内存中（set_pass 先于 set_kdf_iter 调用），事后派生验证即可命中——虽然多花 45 分钟计算，但锚点可靠性高得多。

## 微信升级适配

只有 `BP_RVA`（kdf_iter setter 的 RVA）随版本变化。`find_kdf_anchor.py` 自动完成重新定位：
1. 解析 PE 节表，定位 `.text`
2. 搜索 `0x3E800` 立即数 → capstone 反演回溯找 `mov reg, 0x3E800; call target`
3. 过滤 call 目标中"开头写 [rcx+N] 且快速 ret"的 setter 特征

若微信未来改变迭代次数/哈希算法，`selftest_crypto.py` 的参数需同步调整（常数都集中在文件顶部）。

## 风险与边界

- 断点导致微信卡顿/崩溃的理论风险：INT3 + 单步循环是调试器标准行为，实测（含多次登录、长时间挂着）无异常；且 `DebugSetProcessKillOnExit(False)` 保证调试器退出不杀微信
- passphrase 可能随重新登录轮换：失效重跑三步即可（约 1 小时，其中 45 分钟无人值守）
- 本方案读取的是本机已登录账号自己的数据；适用性与合法性由使用者自负
