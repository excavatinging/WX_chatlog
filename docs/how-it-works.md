# 技术原理

## 微信 4.1.x 本地数据库加密体系

微信 4.x 将本地数据存储为 SQLCipher 变体加密的 SQLite 数据库（`xwechat_files/<account>/db_storage/**/*.db`）：

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
| 传统派生密钥字符串扫描 | 通常可行 | 部分构建中无法取得完整材料 |
| 每库密钥 | 同一 passphrase 派生 | 同一 passphrase 派生（不变） |

因此，依赖“已派生密钥 hex 串常驻”的提取器不能被当作 4.1.8+ 的稳定前提。具体行为仍以
客户端完整版本号和真实数据库验证为准。

## 本项目方案：断点捕获 + 派生验证

### ① 断点捕获（1_capture_launch.py）

> 提示：本节出现的路径/数值（如 PID、命中次数、转储量）为某次实测记录，仅作规模参考，不同环境会有差异。

**锚点定位**：无符号表条件下，用 PBKDF2 迭代次数 `256000/0x3E800` 作为立即数锚点。在 183MB 的 `.text` 段中，该常量出现约百次，但"作为函数参数装载"（`mov edx, 0x3E800; call ...`）的调用点极少（实测仅 2 处）。被调函数即 SQLCipher 的 `kdf_iter` setter——每个数据库初始化的必经之路。

**断点机制**：全程使用 Windows 官方调试 API：
- `CreateProcessW(..., DEBUG_PROCESS, ...)` 以调试器身份启动微信（覆盖全部子进程）
- `VirtualProtectEx` + `WriteProcessMemory` 在函数入口写单字节 `0xCC`（INT3）
- `WaitForDebugEvent` 循环：命中 → 读 `CONTEXT` 寄存器（RCX = codec 上下文指针）→ `ReadProcessMemory` 转储上下文及一层指针追踪 → 恢复原字节 → 设 TRAP 标志单步 → 重设断点
- 不注入 DLL 或可执行载荷；会临时写入一个 `INT3` 字节，并在命中、退出或异常清理时恢复
- 版本号与函数开头字节是双重门禁；无法读取完整版本或任一项不匹配时拒绝写入

**工程细节**（都是实战踩坑）：
- 微信 4.x 是"启动器 → 真实进程"架构：启动器进程退出是正常现象，不能当作微信退出
- 调试事件常量：EXCEPTION=1, CREATE_THREAD=2, ..., EXIT_PROCESS=5（WinBase.h 定义，勿凭记忆写）
- 断点必须在登录**前**就位：数据库初始化通常集中在登录阶段；400ms 轮询用于尽量缩短
  Weixin.dll 加载到设断之间的竞态窗口，但不能承诺未来版本零遗漏
- 实测一次登录命中 166 次（22 个库 × 多线程/多进程路径），转储约 4.5MB

### ② passphrase 提取（2_extract_passphrase.py）

对转储字节做可配置步进滑窗，每个 32B 窗口作为 passphrase 候选：

```
PBKDF2(候选, salt, 256000) → enc_key → mac_key → HMAC 验证
```

**算力问题**：每个候选需 256000 轮 SHA512，耗时取决于 CPU、转储量与步长。两个优化
显著降低默认运行时间：
1. **单样本门控**——同一 passphrase 派生所有库，先用一个库的门控样本筛，命中即停（省 22 倍）
2. `imap_unordered` + chunksize 流水线，默认最多使用 14 个逻辑 CPU，也可用
   `WX_WORKERS` 调整

门控命中后还会对收集到的全部加密数据库做确认；任何一个不匹配都不会写出 passphrase。
默认步长为 8，可用 `WX_SCAN_STEP=1` 做更慢但覆盖更密的重试。

### ③ 密钥派生（3_derive_keys.py）

拿到 passphrase 后，对每个库用自己的 salt 派生 `enc_key`，逐库 HMAC 验证。只有全部
可读加密数据库都通过时才原子写出 wechat-cli 格式的 `all_keys.json`；部分成功不会生成
看似可用但实际不完整的结果。

## 为什么不直接 Hook 函数参数

理论上断在密钥设置函数上可直接读寄存器拿到材料（DLL 注入类工具的做法）。但静态分析无法可靠区分 setter 函数（代码模式相似者众多，实测某"3 参数 + 写 rcx 字段"候选并非登录路径）；而 `kdf_iter` setter 有 256000 这个不变常量做锚点，跨版本稳定。捕获 kdf 上下文后，passphrase 就存在其可达内存中（密钥设置先于 kdf_iter 设置调用），事后派生验证即可命中——虽然多花几十分钟计算，但锚点可靠性高得多。

## 微信升级适配

`BP_RVA`、完整文件版本和预期函数字节共同组成版本资料。`find_kdf_anchor.py` 提供重新
定位候选：
1. 解析 PE 节表，定位 `.text`
2. 搜索 `0x3E800` 立即数 → capstone 反演回溯找 `mov reg, 0x3E800; call target`
3. 过滤 call 目标中"开头写 [rcx+N] 且快速 ret"的 setter 特征

定位器输出当前 shell 所需的 `WX_BP_RVA`、`WX_EXPECTED_VERSION` 和
`WX_EXPECTED_FN_BYTES`，不要求修改源码。候选评分仍需人工核对，随后必须做真实回归。
若微信未来改变迭代次数或哈希算法，需要重新研究，不能只更新 RVA。

## 风险与边界

- INT3 + 单步会暂停目标线程，仍存在卡顿或崩溃风险；脚本会恢复字节、关闭句柄并尝试
  从所有受调试进程脱离，页保护恢复失败会触发字节与权限回滚，
  `DebugSetProcessKillOnExit(False)` 用于避免调试器退出时终止客户端
- passphrase 或客户端版本变化后需要重跑，耗时不作固定承诺
- 内存转储、passphrase 与逐库密钥均属受限个人数据。Windows `chmod` 不会收紧 ACL，
  因此脚本使用当前用户专属 DACL、写后回读验证，并在保护失败时停止
- 本方案读取的是本机已登录账号自己的数据；适用性与合法性由使用者自负
