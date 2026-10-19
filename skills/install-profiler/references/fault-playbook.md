# 故障排查手册（症状 → 证据 → 机制 → 修复）

排查顺序固定为 **依赖 → 权限 → 状态**。先排除便宜的解释，再动贵的。
每一层都给出可执行的取证命令；没有证据之前不要给修复方案。

---

## 0. 三分钟取证包

```powershell
# 安装/卸载/修复的详细 MSI 日志（每次都值得留）
msiexec /i "<installer>" /l*v "$env:TEMP\install.log"

# 应用与系统事件（按时间倒序，关注来源与 Event ID）
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddDays(-3)} |
  Where-Object { $_.ProviderName -match '<厂商|产品名>' } |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message -First 50

# 服务真实配置（不是控制面板里看到的）
sc.exe qc <服务名>
sc.exe queryex <服务名>
Get-CimInstance Win32_Service -Filter "Name='<服务名>'" |
  Select-Object Name,State,StartMode,StartName,PathName,ExitCode,ProcessId

# 安装目录 ACL（权限类故障的关键证据）
icacls "<安装目录>"

# 注册表：卸载项 / 服务键 / 事件源
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "<产品名>"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<服务名>"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<Source名>"
```

---

## 1. 装不上（安装程序失败或回滚）

### 先看 MSI 错误码

`/l*v` 日志末尾搜 `Return value 3` 与 `Error 1603`，再向上找第一条真正的错误。

| 码 | 含义 | 典型机制 |
|---|---|---|
| 1602 | 用户取消 | 不是故障，或被 UAC/策略静默取消 |
| 1603 | 致命错误（万能码） | 必须从日志里找真正原因，见下 |
| 1618 | 另一个安装正在进行 | 全局 `_MSIExecute` 互斥体被占用；常有残留 msiexec |
| 1619 | 无法打开安装包 | 文件损坏/路径不可访问/被隔离 |
| 1625 | 被策略禁止 | AppLocker/WDAC/组策略禁用 Windows Installer |
| 1638 | 已有更高版本 | 产品升级规则（`Upgrade` 表）拒绝降级 |
| 1642 | 不允许升级 | 升级路径/语言/架构不匹配 |
| 1920 | 服务启动失败 | 服务账户无“登录为服务”权限、二进制缺失、依赖缺失 |
| 1935 | 程序集安装失败 | .NET/SxS 组件损坏或 VC 运行库缺失 |
| 2503 / 2502 | 安装服务无法启动 | `%windir%\Installer` 权限异常 / SYSTEM 无法访问临时目录 |
| 2755 | 缓存包失败 | 同上，`Installer` 缓存目录 ACL 问题 |
| 3010 | 需要重启 | 成功但需重启才生效 |

### 检查顺序

1. **磁盘与路径**：目标盘剩余空间；路径含特殊字符/超长路径；安装源在 U 盘/网络路径被断开。
2. **权限**：`%windir%\Installer`、`%TEMP%`、目标目录的 ACL；以管理员运行是否改变结果。
3. **策略**：`gpedit` 里 Windows Installer 的“禁止安装/关闭用户安装”；AppLocker/WDAC 规则；Defender ASR 规则（如“阻止来自 Office 宏的 Win32 API 调用”无关，但“阻止可执行文件运行”会拦安装器）。
4. **残留状态**：同 `UpgradeCode` 的旧版本残留（注册表有、文件没了）；`PendingFileRenameOperations`；MSI 缓存缺失。
5. **依赖**：VC++ 运行库（x86/x64 都要）、.NET 版本、驱动、数据库客户端。
6. **签名**：`Get-AuthenticodeSignature` 状态 `NotSigned` / `HashMismatch` → 可能被 SmartScreen 拦截或文件被篡改。

### 关键机制

- **MSI 是事务性的**：任一 `InstallExecuteSequence` 动作返回失败即整包回滚，所以“装了一半”通常不是 MSI 本体的行为，而是 EXE 引导器（Burn/InstallShield 前置步骤）失败。
- **MSI 缓存**：安装时原 `.msi` 会被复制到 `C:\Windows\Installer\<随机>.msi`。修复、卸载、更改功能都依赖这份缓存。清理工具删掉它 → 修复/卸载报 1619/1603，此时只能用原始安装包或官方清理工具。
- **1603 不是原因**：它只是“有动作失败了”。必须找到更早的那条 `Note: 1: 2262 2: ...` 或 `Error 1722/1723` 之类。

---

## 2. 装上了但起不来

### 按层排查

1. **进程是否真的启动**：任务管理器/`Get-Process`；是否闪退（WER 有记录）。
2. **服务类应用**：
   - `sc qc` 看 `BINARY_PATH_NAME` 是否存在；
   - `StartName` 账户是否有“作为服务登录”权限（`secpol.msc` → 本地策略 → 用户权限分配）；
   - 依赖服务是否运行（`sc enumdepend`）；
   - 服务启动后立刻停止：看事件日志 Service Control Manager（Event ID 7000/7001/7009/7011/7023/7031/7034），7009=超时，7031=意外终止。
3. **端口占用**：`Get-NetTCPConnection -LocalPort <port> -State Listen` → 若被别的进程占用，应用绑定失败。
4. **文件与 ACL**：安装目录、`%ProgramData%\<厂商>`、日志目录是否对该账户可写。
5. **依赖 DLL**：进程启动报 0xc0000135（缺 DLL）/0xc000007b（位数不匹配）→ 用 Process Monitor 过滤 `NAME NOT FOUND`，或 `dumpbin /dependents`。
6. **杀软/EDR 拦截**：Defender 保护历史、第三方 EDR 隔离区；文件被隔离后表现为“文件凭空消失”或“拒绝访问”。
7. **配置指向不存在路径**：从程序日志/事件日志里找它尝试打开的路径，验证存在性。

### 关键机制

- **服务启动失败几乎总是三件事之一**：二进制路径错误、账户权限不足、依赖未就绪。
- **WOW64 重定向**：32 位程序读写 `HKLM\SOFTWARE` 实际落到 `WOW6432Node`，排查注册表时必须两个位置都看。
- **UAC 虚拟化**：老程序写 `Program Files` 会被重定向到 `%LOCALAPPDATA%\VirtualStore`，配置“改了没生效”常见于此。

---

## 3. 运行中崩溃 / 报错

1. **WER 报告**：`%ProgramData%\Microsoft\Windows\WER\ReportArchive\` 下找 `AppCrash_<exe>_*`，里面有异常码与出错模块。
2. **应用日志**：安装画像里记录的日志路径；看错误前后几行，不要只看最后一行。
3. **事件日志**：Application 里该 Source 的 Event ID 与消息模板；Event ID 是定位代码分支的最短路径。
4. **崩溃模块**：失败模块名对应 DLL → 查版本冲突（同目录有旧版 DLL）、VC 运行库不匹配、SxS 清单损坏。
5. **权限相关**：只读文件、临时目录不可写、用户配置文件损坏（新建本地账户对比）。
6. **网络/许可**：代理、TLS 版本、证书过期、许可证服务器不可达——看应用日志里的 HTTP 状态码。

### 关键机制

- 事件日志的 **Source → EventMessageFile** 映射决定了消息能否渲染；`Event ID` 找不到描述说明 `EventMessageFile` 指向的 DLL 缺失/版本不对，这本身就是线索。
- 崩溃地址与模块名比错误对话框可靠得多；对话框文案常被本地化和泛化。

---

## 4. 升级 / 修复 / 卸载失败

| 现象 | 常见原因 | 验证 | 修复 |
|---|---|---|---|
| 修复报 1603/1619 | MSI 缓存被清理 | `Get-ChildItem C:\Windows\Installer\*.msi` 对照产品码 | 用原始安装包重新安装；或官方卸载工具 |
| 卸载卡在“请稍候” | 残留服务/进程占用文件 | `Get-Process`、`handle.exe`（需 Sysinternals） | 停服务→杀进程→重试；重启后重试 |
| 升级被拒（1638/1642） | 已装更高版本 / 语言架构不符 | `Upgrade` 表规则 + 已装产品属性 | 先卸旧版；或按厂商升级路径 |
| 卸载后残留 | `RemoveFile`/`RemoveRegistry` 未覆盖 | 对照 profile 里的这两张表 | 手工清理残余键/目录（先备份） |
| 重复条目 | 同一 UpgradeCode 多次安装 | 卸载项里按 ProductCode 去重 | 清理 ARP 残留条目（谨慎） |

### 关键机制

- 安装产品身份由 **ProductCode**（每次版本唯一）+ **UpgradeCode**（同族共享）决定；ARP 里出现两条通常意味着两个 ProductCode 共存。
- 卸载只按 MSI 记录的清单删文件，**运行时生成的文件不会被删**，这不是故障。

---

## 5. 配置不生效

1. 确认程序实际读取的路径：进程工作目录、`%ProgramData%` vs `%LOCALAPPDATA%` vs 安装目录下的默认配置。
2. 查配置优先级：命令行 > 用户配置 > 机器配置 > 内置默认。
3. 查虚拟化：`VirtualStore` 里是否有“影子配置”。
4. 查文件是否被策略/ACL 锁成只读；改完是否被服务启动时覆盖写回。
5. 32/64 位重定向：注册表与 `Program Files` 两套位置。

---

## 6. 修复后的验证（必须做）

- 同一症状的检查命令重跑一遍，输出对比（前后各留一份到 `evidence\`）。
- MSI 类：`msiexec /x` 或 `/i ... /f` 后再 `/l*v` 确认 `Return value 1`（成功）。
- 服务类：`sc query` 显示 `RUNNING` 且重启机器后仍能自启（验证启动类型真的生效）。
- 事件日志：修复时间点之后不再出现同一 Event ID。

---

## 7. 常见误判

- “重装就好了” —— 掩盖机制，问题会回来；重装前先留证据。
- “是杀毒软件的问题” —— 需要隔离区/保护历史证据，否则只是猜测。
- “注册表乱了” —— 除非有具体的键和值，否则不能作为结论。
- 把 MSI 的 `1603` 当根因 —— 它只是结果码。
- 用管理员权限“解决”权限问题 —— 掩盖了真实 ACL 缺陷，普通用户仍会复现。

---

## 8. 动态取证的读法（前后快照差分）

流程：`build-probe-plan` → `capture-snapshot -Label before` → **只复现一个动作** → `capture-snapshot -Label after` → `diff-snapshots`。

差分里每一条都是"假设"，不是结论。按下面的表去对照机制：

| 差分现象 | 可能机制 | 下一步 |
|---|---|---|
| 安装根下的文件**消失** | 自定义动作回滚、杀软隔离、清理工具误删 | 查 Defender 保护历史 / 隔离区；比对 MSI 缓存包是否完整 |
| 数据/日志目录**新增** `.log/.dat/.db` | 首次运行的正常状态写入 | 读新日志内容，时间对齐复现时刻 |
| 日志文件**停止增长** | 进程在写日志前就失败 | 查 WER、事件日志、进程是否存活 |
| `Services\<名>` 下值被**改/删** | 策略下发、更新程序、第三方"优化"工具 | 对比 `sc qc` 与实际注册表；查组策略来源 |
| 服务 `Running → Stopped` | 崩溃（7031）、依赖退出、账户权限、超时（7009） | 查 System 日志 7000/7001/7009/7031；看 `ExitCode` |
| 进程**出现后又消失** | 闪退 | 查 WER `AppCrash_*`、Event 1000 的出错模块 |
| 新 **WER 目录** | 确认崩溃 | 读 `Report.wer` 的异常码与出错模块名 |
| 端口绑定**消失/没出现** | 依赖服务未就绪、端口被占、绑定失败 | `Get-NetTCPConnection`、`netstat -ano` |
| 事件日志新增 **Error** | 真实错误路径 | 用 Event ID 回到代码分支；用 Source 定位组件 |
| 注册表值出现 `[PROPERTY]` 残留 | 安装时属性未解析 | 查 `Property` 表与 `SecureCustomProperties`/传递参数 |
| **diff 为空** | 观察面选错了 | 扩展 plan：把应用实际访问的路径/键加进来，或改用 Procmon |

### Procmon 的用法（仅限用户授权的虚拟机/测试机）

过滤条件由 `probe-plan.json` 的 `procmonFilters` 直接给出，核心是三类：

1. `Result is ACCESS DENIED` —— 权限类故障的唯一硬证据；
2. `Result is NAME NOT FOUND` —— 缺文件/缺 DLL/路径写错；
3. `Operation is Process Create` —— 谁拉起了谁（启动链、更新器）。

先设 `Path contains <安装目录>` 把噪音压下去，再逐条放行。Procmon 的日志要保存为 `.pml` 留在 `evidence/`，不要凭记忆描述。

### 结论的写法

每条结论必须能回答三个问题：

1. **证据**是什么（哪次快照、哪个 Event ID、哪个文件、哪个键）；
2. **机制**是什么（一句话解释为什么会出现这个现象）；
3. **反证**是什么（什么结果会推翻这个判断，怎么验证）。

答不出第三问的，写成"待验证假设"，不要写成根因。


---

## 9. 长时间运行后的性能问题（CPU 高 / 线程泄漏 / 内存涨 / 句柄泄漏）

单次快照看不出泄漏，必须**连续采样**。判据是"单调增长"，不是某个瞬间的数字。

### 9.1 先采样

```powershell
# 默认 12 次、每 5 秒一次；长跑问题建议 24 次 × 30 秒
watch-process.ps1 -Name '<进程名>' -Samples 24 -IntervalSeconds 30 -OutDir .\re\<case>\resource
```

输出 `resource-watch.md`：CPU%、线程数、句柄数、私有内存的时间序列，外加"线程增长是否单调"和"哪些线程在吃 CPU"。

判读：

| 曲线 | 结论 |
|---|---|
| 线程数单调上升、不回落到基线 | 线程泄漏（创建了不回收） |
| 句柄数单调上升 | 句柄/GDI/USER 泄漏（文件、窗口、画笔未释放） |
| 私有内存持续上升、GC 后不回落 | 内存泄漏或缓存无上限 |
| CPU 持续高但线程都在 Wait | 不是忙等，而是频繁唤醒（定时器过密/轮询/GC） |
| 单个线程 CPU delta 持续最高、状态 Running | 忙等/spin 或死循环 |
| 进程中途消失 | 崩溃；转第 3 节 |

> Chromium/CEF 类应用（如微信、企业微信、有道、B 站客户端）要**分进程统计**：
> `Get-Process | Where-Object { $_.Path -like '*<安装目录>*' } | Select Id,ProcessName,Threads,HandleCount`
> 主进程泄漏和 renderer 泄漏是两回事，混在一起会误判。

### 9.2 留证据再重启

重启会毁掉现场。顺序：**采样 → 抓转储 → 记时间点 → 才重启**。

```powershell
# 由任务管理器：详细信息 → 右键进程 → 创建转储文件
# 或用 Sysinternals procdump（需用户批准安装）
procdump -ma <PID> <输出目录>

# 事件日志里同时段的崩溃/挂起
Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddHours(-6);Id=1000,1001,1002} -MaxEvents 30
```

拿到 dump 后（授权范围内）：

```
!analyze -v          # 异常/挂起分析
!runaway 1           # 各线程 CPU 时间，直接指出吃 CPU 的线程
~*k                  # 所有线程调用栈
```

### 9.3 机制（常见根因）

| 现象 | 常见机制 |
|---|---|
| 线程泄漏 | 每次操作 `CreateThread`/`std::thread` 后未 join/detach；事件/定时器回调注册后未注销；线程池任务里再开线程；CEF/Chromium renderer 反复创建未回收 |
| CPU 高但吞吐低 | 忙等（spin）、轮询间隔过小、定时器风暴、锁竞争、GC 抖动 |
| 句柄泄漏 | 文件/注册表句柄未 Close；GDI 对象（HBRUSH/HDC）未 Delete；窗口句柄未销毁 |
| 内存涨 | 缓存/字典无上限、日志在内存里累积、图片/解码缓冲未释放 |

### 9.4 处置

| 优先级 | 动作 | 说明 |
|---|---|---|
| P0 | 抓 dump + 采样数据，报厂商 | 这类 bug 只能靠厂商修；没有 dump 的反馈基本无效 |
| P1 | 升级到最新版本 | 先确认问题版本与修复版本 |
| P2 | 计划任务定期重启 | 缓解手段，不是修复；重启前务必留证据 |
| P3 | 限制功能/插件 | 缩小触发面（如关闭某模块）以定位 |
| P4 | 观察指标告警 | 线程数/句柄数超过阈值时提前通知 |

**不要**把"定期重启"当成修复；也不要在没采样的情况下断言"内存泄漏"。