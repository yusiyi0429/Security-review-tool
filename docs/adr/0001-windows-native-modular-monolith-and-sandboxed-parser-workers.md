# ADR-0001：Windows 原生模块化单体与 AppContainer 解析工作进程

- 状态：Accepted（须通过 Windows 安全 spike）
- 日期：2026-07-20
- 决策者：产品方案基线；具名工程与安全负责人待指派
- 关联：REQ-001, REQ-008, REQ-012, REQ-015, REQ-019

## 背景

本工具面向内部人员，在资产发布前于 Windows 本机扫描最多约 10 GB/10 万文件的异构不可信内容。输入可能包含恶意归档、Office、PDF、JAR、二进制、Python、模型文件和 Docker/OCI 层。产品必须轻量、免管理员权限、无中心服务，且只有受限语义候选可以访问用户配置的内网 LLM。

主要驱动因素：

1. 不可信解析器漏洞不能直接获得用户文件、凭据、网络和历史数据库；
2. 单文件崩溃、超时或内存耗尽不能拖垮整个任务；
3. Windows GUI、DPAPI、NTFS ADS、AppContainer 和 Job Object 需要直接、稳定集成；
4. 用户需要解压即用，不安装服务、Docker、JRE、Python 或系统级运行时；
5. 第一版由小团队维护，不引入本地微服务的部署复杂度；
6. 本地完整敏感值可见和可导出，但普通日志不得含这些值。

## 决策

采用以下组合：

1. **.NET 10 LTS + C# + WPF** 构建 `win-x64` Windows 原生桌面客户端。
2. 交付 **自包含便携目录 ZIP**，不是字面意义的单一可执行文件；程序目录包含主进程、worker 和固定依赖。第一版不 trimming、不安装服务、不自动更新。
3. 业务实现为 **模块化单体**：Desktop、Application、Domain、Infrastructure、RulePack、ParserContracts 清晰分层；UI、数据库、HTTP 和解析库都位于 adapter 边界外。
4. 所有不可信格式解析在独立 `SecurityReview.Worker.exe` 中运行。worker 使用 **无网络 capability 的 AppContainer**，并受 **Windows Job Object** 的进程、内存、CPU 和生命周期限制。
5. 主进程打开资产只读句柄，使用 `DuplicateHandle` 授予 worker 单文件能力；worker 不获得扫描根目录路径访问权。IPC 使用带 ACL、随机名称、nonce 和协议版本的本地 Named Pipe。
6. 正式扫描若无法建立 AppContainer、ACL 或 Job 限制，则 **fail closed**，不退回普通用户权限解析。
7. 只有可信主进程可以访问规则、加密 SQLite、DPAPI credential 和内网 LLM。worker 永不持有 LLM 凭据或网络 capability。
8. 敏感历史采用 AES-256-GCM 字段级 envelope encryption，数据密钥由 DPAPI CurrentUser 保护。

目标系统必须是 Windows 11 x64，或同时受到微软和 .NET 10 支持的 Windows 10 Enterprise/IoT LTSC x64。实际终端版本是开发启动前的验证项。

## 为什么不用单文件发布

.NET 单文件发布与特定 OS/架构绑定，部分原生库可能需要提取，某些依赖路径假设也可能不兼容。本产品本来就需要独立 worker、安全依赖 manifest 和多个进程。便携目录 ZIP 更透明、更易校验和排障，也避免把“一个文件”误当成真正的安全或便携要求。

## 备选方案

### A. 所有解析器都在 WPF 主进程内

拒绝。实现简单，但恶意解析器利用、OOM、StackOverflow 或 native crash 会直接获得当前用户权限并终止应用，无法满足 REQ-008/AC-020。

### B. 普通低权限子进程，不使用 AppContainer

拒绝。普通同用户进程仍可枚举用户可访问文件、读取同用户数据并发起网络请求。Job Object 只限制资源，不构成文件和网络权限边界。

### C. Windows 服务负责扫描

拒绝。需要安装和通常需要管理员权限，扩大常驻攻击面和运维范围，不符合轻量便携、无服务的已确认约束。

### D. 整个应用使用 MSIX/UWP/WinUI AppContainer

不选第一版。它能提供整体容器化，但安装/签名/文件选择模型与“便携目录、任意本地待发布目录、无安装器”冲突。只隔离高风险 parser 能保留桌面文件选择和本地工作流，同时建立最重要边界。

### E. Electron/Tauri 前端 + 本地后台

不选。Electron 的包体和空闲内存不利于 300 MB 目标；Tauri 仍需要单独处理 Windows 原生隔离和后端生态。二者不能减少 parser sandbox、DPAPI、ADS、Job/handle broker 的工作，反而增加运行时和 IPC 面。

### F. Python 打包桌面应用

不选。Python 适合原型和规则实验，但本方案需要直接的 Windows token/AppContainer/Job/handle 集成、固定运行时供应链和低空闲内存；同时资产本身可能是恶意 Python，不能与产品运行时混淆。

### G. 本地 Docker/虚拟机扫描

拒绝。依赖 Docker Desktop/Hyper-V/管理员或大型环境，偏离免安装轻量工具；产品只需要静态读取导出的镜像。

### H. 中心扫描服务

拒绝第一版。会改变已确认的纯本地边界，新增上传、认证、租户隔离、中心存储与运维；不是当前需求的实现手段。

## 影响

### 正面

- 直接使用 Windows 的隔离、句柄和秘密保护能力；
- 主进程与单个解析器故障隔离，能够持续扫描并给出覆盖缺口；
- 用户无需安装 .NET、Python、Java、Docker 或数据库；
- 一个产品目录和一个本地数据目录，部署与支持面可控；
- 领域逻辑与第三方解析库隔离，便于按 corpus 替换和回归。

### 负面与成本

- AppContainer profile、pipe ACL、duplicated handle 和 Job Object 需要 P/Invoke 与真实 Windows 集成测试；Linux 开发环境不能证明这些行为；
- worker 可读第三方库和私有临时目录的 ACL/staging 较复杂；
- 主进程与 worker 间需要稳定、限长、可取消的协议和位置映射；
- 自包含应用不会自动获得机器全局 .NET runtime 的修补，发布方必须跟随 .NET 安全更新重新发布；
- WPF 绑定 Windows，未来跨平台需要重新评估界面和隔离模型；
- DPAPI CurrentUser 不抵抗同一用户恶意进程或管理员；本地历史也不具备不可抵赖性。

## 验证条件

实现功能前必须在每个目标 Windows build 上证明：

1. 无管理员权限可创建/复用/清理 AppContainer profile；
2. worker 无法访问 loopback、DNS、LAN 和 Internet；
3. worker 只能读取主进程复制的只读句柄，不能枚举扫描根或读取任意用户文件；
4. pipe 只允许当前用户和指定 AppContainer SID，伪造客户端和超长 frame 被拒绝；
5. worker 子进程、内存、超时和父进程退出由 Job Object 正确限制；
6. worker 崩溃/OOM/挂起只产生当前文件 gap，主应用和其他文件继续；
7. 发行目录中文件由 manifest hash 验证，worker staging 被篡改时禁止启动。

若第 1–5 项任一无法可靠实现，应暂停解析功能实现并重新提交 ADR；不能用普通子进程作为静默降级。

## 参考

- [.NET 10 Supported OS versions](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
- [WPF overview](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/overview/)
- [Single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)
- [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [.NET named pipes](https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-use-named-pipes-for-network-interprocess-communication)
