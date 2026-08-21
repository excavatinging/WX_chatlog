# WX-chatlog

> Windows 微信 4.1.8+ 本地数据访问研究工作流，面向个人数据自主与自有账号数据。

本仓库把环境发现、版本门禁、瞬态材料捕获、逐库派生验证和下游只读查询串成一条
可由 AI 编码助手执行、但由用户掌握授权与登录动作的工作流。机器路径和账号目录只
存在于当前终端的环境变量中，不写进源码或提交历史。

> 仅限访问你本人有权访问的本机账号数据。请遵守当地法律、软件许可协议和组织政策。

## 当前验证边界

- 已验证的客户端基线是 `4.1.12.26`，默认断点资料只允许这个**完整版本号**。
- `scripts/repo_check.py` 可验证编译、合成加密页、逐库输出格式、Windows DACL、
  Git 工作树和全部历史隐私扫描。
- 离线测试通过不代表新微信版本兼容。客户端升级后必须重新定位锚点并完成真实登录
  回归，不能只看自检结果。
- 主流程只支持 Windows 10/11 x64 与 64 位 Python 3.10 以上版本。

## 安全模型

工作流不注入 DLL 或可执行载荷，但会用 Windows 调试 API 临时把目标函数首字节改为
`INT3`，命中后恢复、单步，再重新设置断点。版本号和函数开头字节任何一项不匹配，
脚本都会拒绝写入目标进程。

所有敏感产物默认放在仓库下已忽略的 `secrets/`，也可用 `WX_SECRETS_DIR` 指向其他
本地目录。若自定义目录仍位于仓库内，只允许放在 `secrets/` 子树，避免误提交到其他
源码目录。敏感目录本身和其中的文件都会限制为当前用户；写文件时先保护空临时文件，
再写入、原子替换并复验。权限保护失败会终止，不会退回到 Windows 上无效的
`chmod 600`。

敏感产物包括：

- `ctx_dumps/*.json`：进程内存片段
- `passphrase.txt`：逐库派生材料
- `all_keys.json`：数据库密钥映射

不要同步、上传、截图或提交这些文件。用完后由用户自行决定保留或删除。

## 快速开始

### 1. 获取代码与环境

```powershell
git clone https://github.com/excavatinging/WX_chatlog.git
Set-Location WX_chatlog
python scripts\privacy_check.py
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts\repo_check.py
```

步骤 1 到 3 本身只使用 Python 标准库。`pycryptodome` 用于加密自检，`capstone` 只在
客户端升级、需要重新定位锚点时使用。

### 2. 只读探索并设置环境变量

先由用户确认安装位置和当前账号的数据目录。推荐从正在运行的 `Weixin.exe` 路径和
微信“设置 → 文件管理”确认，不要遍历无关目录，也不要把探测结果发到远端。

PowerShell：

```powershell
$env:WX_EXE = '<确认后的 Weixin.exe 完整路径>'
$env:WX_DB_DIR = '<确认后的 db_storage 完整路径>'
# 可选：$env:WX_DIR = '<启动工作目录>'
# 可选：安装目录有多个候选时，$env:WX_DLL = '<确认后的 Weixin.dll 完整路径>'
# 可选：$env:WX_SECRETS_DIR = '<敏感产物目录>'

python scripts\0_preflight.py
```

官方执行路径是 Windows PowerShell。WSL/Linux Python 不受支持；如果使用 Git Bash，
必须确保调用的是 64 位 Windows `python.exe`，并在同一个 shell 保留环境变量。

预检是只读操作：

- 退出码 `0`：环境与版本资料均就绪
- 退出码 `2`：仍需用户确认路径
- 退出码 `1`：平台、路径或版本资料无效
- AI 助手应使用 `python scripts/0_preflight.py --json`，只向用户报告状态与数量

仓库没有机器特定默认路径。未设置必需环境变量时，主脚本会停止并引导回预检。

### 3. 加密实现自检

```powershell
python scripts\selftest_crypto.py
```

退出码 `0` 只证明仓库算法的内部一致性，不证明某个新客户端版本已经适配。

### 4. 三步工作流

先由用户**完全退出微信**。AI 助手不得自动结束进程或代替用户登录。

```powershell
# ① 启动后由用户完成扫码登录；脚本收集结束后会脱离调试
python scripts\1_capture_launch.py

# ② 本地计算，默认最多使用 14 个逻辑 CPU
python scripts\2_extract_passphrase.py

# ③ 必须让所有可读加密数据库通过验证，才写 all_keys.json
python scripts\3_derive_keys.py
```

步骤 ② 可调参数：

- `WX_WORKERS`：并行进程数
- `WX_SCAN_STEP`：候选窗口步长，只允许 `1/2/4/8`，默认 `8`

若锚点已经确认但步骤 ② 无命中，可在同一终端设置 `WX_SCAN_STEP=1` 重试。候选数量和
耗时通常约增至 8 倍。

## 客户端升级适配

预检会直接核验 `Weixin.dll`，不会用 `Weixin.exe` 版本替代。若安装目录存在多个 DLL，
必须由用户确认并设置 `WX_DLL`。如果实际 DLL 版本与 `WX_EXPECTED_VERSION` 不同，不能
直接运行步骤 ①：

```powershell
python scripts\find_kdf_anchor.py '<Weixin.dll 完整路径>'
```

定位器会校验 PE32+ x64 文件结构，列出候选反汇编，并给出以下三个当前 shell 环境变量：

- `WX_BP_RVA`
- `WX_EXPECTED_VERSION`
- `WX_EXPECTED_FN_BYTES`

评分只是线索。最高分并列时必须人工核对调用关系；之后还要重新运行预检和真实回归。
无法读取完整 `FileVersion` 时，定位器会拒绝生成不完整版本资料。不需要、也不应为了
适配本机而修改仓库源码。

## 可选：接入 wechat-cli

`all_keys.json` 的路径键和 `enc_key/salt/size_mb` 结构与 wechat-cli 当前读取格式一致。
该兼容性已对照其固定提交
[`a378923`](https://github.com/huohuoer/wechat-cli/blob/a3789232d4f79bf0b30634d9dadbce71e4acd601/wechat_cli/keys/common.py#L128-L162)
及其[路径兼容逻辑](https://github.com/huohuoer/wechat-cli/blob/a3789232d4f79bf0b30634d9dadbce71e4acd601/wechat_cli/core/key_utils.py#L14-L33)。

```powershell
python -m pip install "wechat-cli @ git+https://github.com/huohuoer/wechat-cli.git@a3789232d4f79bf0b30634d9dadbce71e4acd601"

# 默认只校验并预演，不写用户目录
python scripts\4_configure_wechat_cli.py

# 用户确认后才写 ~/.wechat-cli/config.json 与 all_keys.json
python scripts\4_configure_wechat_cli.py --apply

wechat-cli sessions
```

步骤 ④ 会保留现有 `config.json` 的其他字段，只更新 `db_dir`，并对两个状态文件执行同样
的 Windows DACL 保护。查询内容仍是个人数据，AI 助手不得在回复或日志中复述。

## 给 AI 助手

仓库根目录的 [AGENTS.md](AGENTS.md) 是完整执行契约。核心顺序是：

1. 先跑离线发布门禁。
2. 只读探索，路径由用户确认。
3. 环境变量只留在当前 shell。
4. `0_preflight.py --json` 全绿后才继续。
5. 版本不同先停下适配。
6. 退出与登录动作交给用户。
7. 只报告计数、退出码和脱敏错误，不报告路径、账号名、联系人、密钥或查询内容。

## 发布前门禁

```powershell
python scripts\repo_check.py
```

它会运行：

- 全部 Python 文件编译
- 合成数据单元测试
- 普通模式及 `python -O` 加密自检
- Windows DACL 设置与回读验证
- 当前工作树和全部 Git 历史隐私扫描
- 对无法检查内容的二进制或超大文件直接阻断
- `git diff --check`

GitHub Actions 在 Windows 上用 Python `3.10`、`3.12`、`3.14` 重复执行该门禁。CI 不会
接触真实微信安装、数据库或账号数据；Python 3.12 任务还会执行 Bandit 静态检查与
`pip-audit` 依赖漏洞检查。

## 原理摘要

```text
salt     = db 文件前 16 字节
enc_key  = PBKDF2-HMAC-SHA512(passphrase, salt, 256000, 32)
mac_key  = PBKDF2-HMAC-SHA512(enc_key, salt XOR 0x3a, 2, 32)
页校验    = HMAC-SHA512(mac_key, page_data || LE(page_no))
```

传统的派生密钥字符串扫描在部分 4.1.8+ 构建中无法取得完整材料。本项目在 KDF 初始化
路径设置版本受控的断点，捕获其上下文，再离线派生并以数据库首页 HMAC 验证。技术细节
见 [docs/how-it-works.md](docs/how-it-works.md)。

## 文件说明

| 文件 | 作用 |
|---|---|
| `AGENTS.md` | AI 助手的授权、隐私和执行契约 |
| `scripts/0_preflight.py` | 只读环境发现与机器可读预检 |
| `scripts/1_capture_launch.py` | 版本受控的调试启动、断点与敏感转储 |
| `scripts/2_extract_passphrase.py` | 转储滑窗、PBKDF2 门控与全库确认 |
| `scripts/3_derive_keys.py` | 逐库派生并全量验证 `all_keys.json` |
| `scripts/4_configure_wechat_cli.py` | 预演或安装下游本地配置 |
| `scripts/find_kdf_anchor.py` | 新版本 KDF 锚点候选定位 |
| `scripts/win_dacl.py` | Windows 当前用户 DACL 与安全写入 |
| `scripts/privacy_check.py` | 工作树、历史和提交元数据隐私门禁 |
| `scripts/repo_check.py` | 一键发布前验证 |

## 已知限制

- 默认版本资料只覆盖 `4.1.12.26`。
- 步骤 ① 需要重新登录一次，只支持单账号主流程。
- 步骤 ② 可能运行较久，实际时间取决于转储量、CPU 和扫描步长。
- 调试器会短暂暂停线程，存在客户端卡顿或崩溃风险；脚本尽力恢复字节并脱离调试，
  但不能承诺对未来版本零影响。
- 下游项目会变化，使用前应重新核对其安装方式和文件格式。

## 参考

- [wechat-cli](https://github.com/huohuoer/wechat-cli)：本地下游查询工具链
- [chatlog](https://github.com/sjzar/chatlog)：历史加密参数与实现参考
- [连接微信与 AI](https://sikinzen.github.io/posts/howtoconnectwechatandai/)：版本差异研究线索

## License

[MIT](LICENSE)

## 免责声明

本项目仅供个人学习、研究与访问自有账号数据。使用者负责确认授权范围并遵守所在地
法律法规、软件许可协议和组织政策。作者不保证对未来版本持续兼容，也不对使用后果
承担责任。
