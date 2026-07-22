# Security Asset Content Review Tool

> 敏感信息资产内容审查工具 V1

A portable Windows desktop client that statically scans release assets, locates sensitive information, records every coverage gap, optionally asks a configured OpenAI-compatible LLM to review semantic candidates, and exports a fixed six-sheet XLSX report.

## 系统要求

- **Windows 11 x64（受支持版本）**
- 无管理员权限要求（AppContainer 沙箱在标准用户下运行）
- 无需 .NET Runtime / Docker / Java / Python / Office 预装

## 快速开始

1. 下载 `SecurityReviewTool-<version>-win-x64-setup.exe`
2. 验证 SHA-256 和 Authenticode 签名
3. 双击安装；安装完成后可直接启动
4. 选择扫描根目录、导入规则包、开始扫描

安装器按当前用户安装到 `%LOCALAPPDATA%\Programs\SecurityReviewTool`，无需管理员权限。
如需免安装使用，仍可下载 ZIP 便携版并解压运行。

详细说明见 [`docs/operations/quick-start.md`](docs/operations/quick-start.md)

## 架构概览

```
┌────────────────────────────────────────────┐
│  WPF Desktop（协调器）                       │
│  ┌──────────┐ ┌──────┐ ┌──────────────────┐ │
│  │ 清单引擎  │ │ 策略  │ │ 检测 / LLM / 审查│ │
│  └──────────┘ └──────┘ └──────────────────┘ │
│  ┌─────────────────────────────────────────┐ │
│  │  加密持久化（SQLite + DPAPI + AES-GCM）  │ │
│  └─────────────────────────────────────────┘ │
└──────────────────┬─────────────────────────┘
                   │ 命名管道（IPC）
┌──────────────────▼─────────────────────────┐
│  AppContainer Worker（无网络 / 只读句柄）     │
│  ┌──────────────────────────────────────┐   │
│  │  格式解析器（文本/结构化/Office/PDF/   │   │
│  │  JVM/PE/ELF/Docker/OCI/模型）        │   │
│  └──────────────────────────────────────┘   │
│  Job Object：内存/进程限制、崩溃隔离          │
└─────────────────────────────────────────────┘
```

## 核心功能

| 功能 | 说明 |
|------|------|
| **静态解析** | 30+ 文件格式支持（文本/CSV/JSON/XML/YAML/Office/PDF/JVM/PE/ELF/Docker/OCI/Safetensors/GGUF/ONNX） |
| **敏感检测** | 8 类基线（网络地址/凭据/私钥/受限实体/占位符/许可/合规/语义），ECDSA 签名规则包 |
| **沙箱隔离** | AppContainer 零网络能力、嵌套 Job Object、只读句柄、无降级回退 |
| **LLM 审查** | 云 API HTTPS / 受限内网 HTTP、≤16 KiB 最小化候选、注入检测、严格响应解析 |
| **加密存储** | DPAPI CurrentUser + AES-256-GCM + HMAC、零明文泄露 |
| **六 Sheet XLSX** | 扫描摘要/敏感发现/合规发现/未覆盖/文件清单/复核记录 |
| **审查/异常/差异** | 追加式审查、精确过期异常、重扫差异对比 |

## 项目结构

```
src/
  SecurityReview.Domain/         领域模型
  SecurityReview.Application/    用例/端口
  SecurityReview.ParserContracts/ IPC 协议
  SecurityReview.Parsers/         格式解析器
  SecurityReview.RulePack/        规则包/检测
  SecurityReview.Infrastructure/  Windows/加密/持久化/LLM
  SecurityReview.Worker/          AppContainer 解析进程
  SecurityReview.Desktop/         WPF 桌面
tools/                            规则包构建器/语料工具
tests/                            单元/契约/集成/安全/性能测试
docs/                             文档/ADR/PRD/SRS/运维
```

## 构建

```powershell
# 环境需求：.NET SDK 10.0.302、PowerShell 7
dotnet restore SecurityReviewTool.sln --locked-mode -r win-x64
dotnet build SecurityReviewTool.sln -c Release
dotnet test SecurityReviewTool.sln -c Release

# 试点发布：生成便携 ZIP 和单文件安装器
pwsh ./build/package.ps1 -Version 1.0.3 -AllowUnsignedPilot
pwsh ./build/package-installer.ps1 -Version 1.0.3 -AllowUnsignedPilot
```

## 发布流程

参见 [`docs/operations/release-process.md`](docs/operations/release-process.md)

## 许可

内部安全工具 - 未经授权不得分发。
