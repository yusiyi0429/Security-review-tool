# 技术方案走查与验证记录

| 属性 | 值 |
| --- | --- |
| 日期 | 2026-07-20 |
| 走查对象 | 项目资产安全信息审查工具 SRS 0.1 / ADR-0001 |
| 走查类型 | 设计期静态走查；尚非实现验收 |
| 结论 | **有条件通过，可进入实施计划；必须先完成 Windows 隔离 spike 和实施前置项** |

## 1. 走查结论

方案已把 PRD 的功能、异常、质量和安全要求收敛成一个可构建的 Windows 本地架构：WPF 可信协调器、无网络 AppContainer parser worker、Job Object 资源边界、只读 duplicated handle、版本化 Named Pipe、本地加密 SQLite、签名规则包、受限 OpenAI 兼容 LLM 和固定六 Sheet XLSX。

设计期检查通过：

- 19/19 PRD REQ 均有唯一主 SRS 功能需求；
- 60/60 AC 均在功能需求表中显式链接；
- 11/11 资产 ID、8/8 敏感类别 ID 均进入稳定策略注册表；
- 19 条功能需求、16 条可测 NFR、35 个验证用例 ID 完整；
- 正常流程、部分完成、失败、取消、恢复、缓存、导出和 LLM 回退均有行为定义；
- parser IPC、Manifest、RulePack、LLM、数据库、缓存和 XLSX 均有契约或字段约束；
- 关键架构选择及备选方案已记录在 ADR-0001。

尚未证明：AppContainer、Job Object、Named Pipe ACL、DuplicateHandle、ADS、DPAPI 和 WPF 性能在目标 Windows build 上的真实行为。当前工作区是 Linux 环境，且项目尚无实现代码，因此不能把设计检查表述成可运行产品验收。

## 2. 输入证据

| 输入 | 检查结果 |
| --- | --- |
| `敏感信息安全审查清单_1784536989321_0_jh4q.xlsx` | 实际 3 个可见 Sheet；Sheet1/Sheet2 有效，Sheet3 为空；Sheet2 是 Sheet1 敏感信息列的详细展开 |
| `docs/prd/prd-security-asset-content-review-tool.md` | 3 个业务目标、19 REQ、19 用户故事、60 AC；状态为可进入方案设计 |
| Repo-specific requirements baseline | 工作区不存在 `docs/requirements-standards-baseline.md`；本次以 PRD、全局工程约束和官方平台资料为基线 |
| 项目实现 | 尚无 solution、源代码、测试或构建配置；本次只创建设计交付物 |

走查时输入/产物摘要：

```text
af2107db02f87d5e05dc2b06a5060d6fdc79bb2a94314f98c3c6fa0b92072c4f  docs/prd/prd-security-asset-content-review-tool.md
fc95ba57096e438375f3457ceaa95010d59340b19d157a80ee892febe9cdaf17  docs/srs/srs-security-asset-content-review-tool.md
360bb66896db759e863f504fd23f6c164e5b499af2d67295cd0a0d998503656e  docs/adr/0001-windows-native-modular-monolith-and-sandboxed-parser-workers.md
```

这些摘要用于标识本次走查版本；后续修改文档时需重新生成。

## 3. 官方技术事实核对

| 事实 | 设计影响 | 证据 |
| --- | --- | --- |
| .NET 10 是 LTS，但自包含应用需要发布方重发才能获得随包运行时修补 | 选 .NET 10；发布流程必须跟随安全更新重建，不依赖终端全局运行时 | [.NET Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy) |
| .NET 10 的 Windows 支持矩阵不包含普通 Windows 10 22H2，只包含仍受支持的 Enterprise/IoT LTSC 等条目 | 将 PRD 的笼统 Windows 10 口径修正为官方仍支持版本，并增加终端版本盘点门 | [.NET 10 Supported OS](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md) |
| WPF 是 .NET 的 Windows 桌面 UI 框架 | 与 Windows-only、中文 GUI、系统缩放和便携需求匹配 | [WPF overview](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/overview/) |
| .NET 单文件发布与 OS/架构绑定，native library 和路径行为可能需要额外处理 | 采用自包含便携目录 ZIP，不强求单一 exe | [Single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview) |
| AppContainer 可通过 capability 限制文件和网络；没有网络 capability 时不应获得网络访问 | parser worker 使用无网络 AppContainer；必须在目标 Windows 实测 fail closed | [Implementing an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) |
| Job Object 能限制和统一管理进程树资源/生命周期 | worker crash/OOM/子进程和父进程退出边界使用 Job Object | [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) |
| Windows 可以跨进程复制内核 handle | 主进程以单文件只读 handle 授权 worker，避免授予根目录浏览权 | [DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) |
| .NET 提供本地 Named Pipe IPC，Windows DPAPI 可绑定当前用户保护数据 | IPC 和本地 secret 方案有平台原语支持 | [Named pipes](https://learn.microsoft.com/en-us/dotnet/standard/io/how-to-use-named-pipes-for-network-interprocess-communication), [DPAPI](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) |
| OCI 规范明确 manifest/config/layer descriptor 模型 | Docker archive 归一化到 OCI 模型并逐 layer 扫描可实现 | [OCI Image Format](https://github.com/opencontainers/image-spec) |
| JVM 规范定义 class 常量池结构 | 可实现边界检查的只读常量池 parser，无需完整反编译 | [JVM class format](https://docs.oracle.com/en/java/javase/26/docs/specs/jvms/jvms-4.html) |

## 4. 需求与验收追踪检查

### 4.1 机械检查

在工作区执行只读脚本，检查：

1. 功能需求表恰有 19 行；
2. 每一行同时含 SRS ID、上游 REQ、至少一个 AC 和至少一个 VT；
3. `REQ-001` 至 `REQ-019` 与 `SRS-F-001` 至 `SRS-F-019` 一一对应；
4. PRD 的每一个 `AC-001` 至 `AC-060` 都出现在功能需求表；
5. PRD 的每一个 `ASSET-*`、`SENS-*` 都出现在 SRS；
6. SRS 中 19 个功能 ID、16 个 NFR ID、35 个 VT ID 唯一存在；
7. Markdown code fence 数量为偶数。

结果：

```text
functional_rows=19 trace_rows=19 ac_links=60 asset_ids=11 category_ids=8 nfr=16 vt=35 code_fences=balanced
exit_code=0
```

### 4.2 语义抽查

| 代表链路 | 走查结果 |
| --- | --- |
| BRD-OBJ-002 → REQ-001 → AC-001 → SRS-F-001 → VT-001/002 | 免管理员、便携、Windows GUI 与启动目标一致；平台版本口径已修正 |
| BRD-OBJ-003 → REQ-008 → AC-018..021 → SRS-F-008 → VT-011..014 | 禁止执行、恶意归档、worker 故障和加密文件均形成安全边界/覆盖缺口 |
| BRD-OBJ-001/003 → REQ-012 → AC-032..035 → SRS-F-012 → VT-018..020 | 最小发送、提示注入、异常输出和不可用回退都有确定行为 |
| BRD-OBJ-003 → REQ-016 → AC-048..050 → SRS-F-016 → VT-026/027 | 六 Sheet、完整值、每位置一行和公式/外链防护均进入契约 |
| BRD-OBJ-002/003 → REQ-019 → AC-058..060 → SRS-F-019 → VT-033..035 | 默认无遥测、唯一 LLM 网络目标与脱敏诊断均可抓包/语料验证 |

未发现孤立 REQ、孤立 AC 或没有验证入口的 SRS 功能需求。

## 5. 架构适配性走查

| 驱动因素 | 方案响应 | 结论 |
| --- | --- | --- |
| 轻量 Windows 客户端 | WPF + 自包含目录，无服务/安装器/额外 runtime | 满足；包体需实现期测量 |
| 任意不可信格式 | parser 独立进程、AppContainer、Job、只读 handle、限长 IPC | 设计充分；真实 Windows spike 是硬门 |
| 只扫描定位 | Domain 不含修复/发布 API；预览只读 | 满足 |
| 内网 LLM | 可信主进程唯一 HTTP adapter，候选级最小输入 | 满足；端点参数待提供 |
| 完整敏感值可见/导出 | UI 按需解密；XLSX 完整值；日志保持脱敏 | 满足已接受业务决策 |
| 无中心服务 | SQLite/DPAPI/本地规则和历史 | 满足；不宣称不可篡改/跨电脑共享 |
| 低漏报和无静默跳过 | coverage ledger、Partial 状态、detector 失败也产生 gap | 满足 |
| Docker 历史层 | OCI 归一化、每层独立扫描、whiteout 不删除早期证据 | 满足静态扫描目标 |

## 6. 契约完整性走查

| 契约 | 已定义内容 | 后续机器可读交付 |
| --- | --- | --- |
| Manifest | 文件名、schema 示例、路径/ID/证据验证 | JSON Schema + valid/invalid fixtures |
| Parser IPC | frame、大小、版本、nonce、sequence、取消、`ParseJob`/`ContentChunk` | JSON Schema/DTO + pipe contract tests |
| Coverage | 终结覆盖状态、标准 reason code、字段 | enum/schema + corpus reconciliation |
| RulePack | 固定目录、manifest、hash、ECDSA、导入事务、只增不减 | JSON Schemas + builder/validator golden packages |
| Detection | 顺序、算法类别、正则限制、占位符和合并键 | detector interfaces + rule corpus |
| LLM | HTTPS exact-origin、无重定向/隐式代理、请求最小化、response schema、重试/熔断/缓存 | mock server contract suite |
| Persistence | 实体、加密 payload、AAD/HMAC、迁移、保留 | migrations + crypto/tamper tests |
| Cache/diff | 三阶段键和差异状态 | invalidation matrix |
| XLSX | 固定 Sheet、文本 cell、关系 allowlist、原子写入 | workbook schema/security validator |

设计未冻结第三方 YAML reader 的具体包版本，这是有意的实施前供应链决策；其能力边界已经冻结为禁用对象实例化、深度/alias/size 受限并通过恶意语料。

## 7. 安全走查要点

### 7.1 关键不变量

1. parser 无网络、无 credential、无历史库、无扫描根目录浏览权；
2. 没有 AppContainer 安全边界时不运行正式解析；
3. 资产不执行，外部关系不解析，归档链接不跟随；
4. 任何失败不转换为“未发现风险”，而转换为 coverage gap；
5. 确定性完整秘密不发送 LLM，LLM 不能删除候选或创建豁免；
6. 完整值只进入加密历史、受控 UI 和用户明确导出的 XLSX，不进入普通日志；
7. 规则和缓存的任何关键指纹变化都会重跑受影响阶段。

### 7.2 需要动态证明的攻击假设

- AppContainer 是否在目标企业 Windows 策略下确实拒绝 loopback、DNS、LAN 和 Internet；
- duplicated handle 是否是 worker 唯一输入能力，worker staging ACL 是否没有扩大访问；
- pipe DACL、nonce 和 frame validator 是否能拒绝同用户伪造/超长/乱序输入；
- worker 能否通过子进程、文件链接、归档路径或 native library 逃离 Job/AppContainer；
- regex、YAML、Open XML、PDF、JVM、PE/ELF 和 OCI adapter 对 fuzz/crash/OOM 样本的行为；
- HTTP capture 中是否只有允许字段，并确认自动重定向和隐式系统代理确实关闭；
- XLSX package 是否完全不存在 formula、macro、external link、DDE 和 clickable hyperlink；
- DB、keyring、cache、日志、dump 和 temp 是否包含 canary 明文。

## 8. 性能与可靠性走查

16 条 NFR 均给出了目标和测量方法。实现阶段仍需建立固定参考机，否则 5 秒、300 MB、1.5 GB、30 分钟只能做趋势监测。

30 分钟目标只覆盖本地阶段，不含 LLM 延迟；任务限制与性能存在明确关系：展开超过 50 GB、归档超过 10 万 entry、深度超过 5 或单条目超过 4 GB 会记录 gap，而不是用无限资源追求表面完整。此取舍与 PRD 的“明确覆盖边界”一致。

断电/崩溃后的可信行为不是继续伪装原任务：启动恢复会清理孤立资源，把非终态任务标为 Interrupted，并保留已经事务提交的证据。导出失败不改变扫描状态，也不留下半成品。

## 9. 已接受取舍

- 使用 Windows 原生栈，换取直接隔离集成；不追求跨平台；
- 使用便携目录而非单 exe，换取 worker、native dependency 和发行 manifest 的透明性；
- 本地敏感数据字段级加密，但不对抗当前用户/管理员，不作为不可抵赖审计；
- LLM 提供语义辅助，任何异常保留人工候选，接受误报而不静默漏报；
- 不 OCR、不完整反编译/反汇编、不反序列化危险模型格式，以 coverage gap 明示边界；
- 第一版没有自动更新，自包含 runtime 的安全补丁由内部再发布流程承担。

## 10. 实施前置项与 Owner

| 前置项 | 建议 Owner | 是否阻塞 |
| --- | --- | --- |
| 盘点 Windows 11/Windows 10 edition/build，与 .NET 10 支持矩阵对齐 | 客户端负责人 / IT | 阻塞正式平台承诺 |
| AppContainer + handle + pipe + Job + no-network spike | 安全工程负责人 | 阻塞 parser 功能实现 |
| 提供 LLM Base URL、认证、模型、限流、并发和证书要求 | 内网 LLM 服务 Owner | 阻塞语义联调，不阻塞本地闭环 |
| 规则 ECDSA 私钥保管、双人发布和公钥轮换 | 安全规则负责人 | 阻塞规则包正式发布 |
| YAML reader 和全部 NuGet 版本/许可证/SBOM 审批 | 客户端 + 安全工程 | 阻塞相应 parser 发布 |
| 合成/脱敏格式语料、恶意样本和语义标注集 | 质量 + 安全规则 | 阻塞验收与发布 |
| 企业 Authenticode 证书 | 构建发布负责人 | 建议阻塞广泛分发；试点可用摘要替代并显式说明 |

具名人员和日期尚未提供，因此当前状态是“可进入实施计划”，不是“可直接发布”。

## 11. 后续建议

下一份交付物应是按依赖顺序拆分的实现计划。第一个可执行切片只做：solution 骨架、状态机/coverage contract、Windows sandbox spike、一个 text parser、一个 deterministic detector 和一个加密任务记录。其成功标准不是漂亮 UI，而是能在无管理员 Windows 上证明 worker 无网络、只读单句柄、崩溃隔离，并把失败准确记录为 coverage gap。

完成该 spike 后再扩展 Office/PDF/JAR/Docker 等解析器，可以尽早验证整个产品最难且最影响安全性的假设。

## 12. 变更记录

| 日期 | 变更 |
| --- | --- |
| 2026-07-20 | 创建方案走查，记录静态追踪结果、官方事实、风险和实施前置项。 |
