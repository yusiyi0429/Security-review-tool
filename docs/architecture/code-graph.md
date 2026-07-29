# Code Graph

> 此文件由 `build/update-code-graph.ps1` 生成；请勿手工修改。

本图覆盖 `src/` 与 `tools/` 中的项目。箭头 `A --> B` 表示项目 A 直接引用项目 B；测试项目未纳入，以保持运行时代码的依赖关系清晰。

更新：`pwsh ./build/update-code-graph.ps1`。验证生成文件没有过期：`pwsh ./build/update-code-graph.ps1 -Check`。

```mermaid
flowchart LR
  subgraph source["应用与核心组件（src）"]
    P0["SecurityReview.Application<br/>100 C# files"]
    P1["SecurityReview.Desktop<br/>39 C# files"]
    P2["SecurityReview.Domain<br/>50 C# files"]
    P3["SecurityReview.Infrastructure<br/>85 C# files"]
    P4["SecurityReview.ParserContracts<br/>11 C# files"]
    P5["SecurityReview.Parsers<br/>60 C# files"]
    P6["SecurityReview.RulePack<br/>29 C# files"]
    P7["SecurityReview.Worker<br/>7 C# files"]
  end
  subgraph tool["开发工具（tools）"]
    P8["SecurityReview.CorpusTool<br/>8 C# files"]
    P9["SecurityReview.RulePackBuilder<br/>8 C# files"]
  end
  P0 --> P2
  P0 --> P4
  P0 --> P5
  P0 --> P6
  P1 --> P0
  P1 --> P2
  P1 --> P3
  P3 --> P0
  P3 --> P2
  P3 --> P4
  P3 --> P6
  P4 --> P2
  P5 --> P2
  P5 --> P4
  P6 --> P2
  P6 --> P4
  P7 --> P2
  P7 --> P4
  P7 --> P5
  P8 --> P0
  P8 --> P2
  P8 --> P4
  P8 --> P5
  P8 --> P6
  P9 --> P2
  P9 --> P6
  class P0,P1,P2,P3,P4,P5,P6,P7 sourceNode
  class P8,P9 toolNode
  classDef sourceNode fill:#dbeafe,stroke:#2563eb,color:#172554
  classDef toolNode fill:#dcfce7,stroke:#16a34a,color:#14532d
```

## 项目清单

| 项目 | 路径 | C# 文件 | 直接依赖 |
| --- | --- | ---: | --- |
| SecurityReview.Application | `src/SecurityReview.Application/SecurityReview.Application.csproj` | 100 | SecurityReview.Domain, SecurityReview.ParserContracts, SecurityReview.Parsers, SecurityReview.RulePack |
| SecurityReview.Desktop | `src/SecurityReview.Desktop/SecurityReview.Desktop.csproj` | 39 | SecurityReview.Application, SecurityReview.Domain, SecurityReview.Infrastructure |
| SecurityReview.Domain | `src/SecurityReview.Domain/SecurityReview.Domain.csproj` | 50 | — |
| SecurityReview.Infrastructure | `src/SecurityReview.Infrastructure/SecurityReview.Infrastructure.csproj` | 85 | SecurityReview.Application, SecurityReview.Domain, SecurityReview.ParserContracts, SecurityReview.RulePack |
| SecurityReview.ParserContracts | `src/SecurityReview.ParserContracts/SecurityReview.ParserContracts.csproj` | 11 | SecurityReview.Domain |
| SecurityReview.Parsers | `src/SecurityReview.Parsers/SecurityReview.Parsers.csproj` | 60 | SecurityReview.Domain, SecurityReview.ParserContracts |
| SecurityReview.RulePack | `src/SecurityReview.RulePack/SecurityReview.RulePack.csproj` | 29 | SecurityReview.Domain, SecurityReview.ParserContracts |
| SecurityReview.Worker | `src/SecurityReview.Worker/SecurityReview.Worker.csproj` | 7 | SecurityReview.Domain, SecurityReview.ParserContracts, SecurityReview.Parsers |
| SecurityReview.CorpusTool | `tools/SecurityReview.CorpusTool/SecurityReview.CorpusTool.csproj` | 8 | SecurityReview.Application, SecurityReview.Domain, SecurityReview.ParserContracts, SecurityReview.Parsers, SecurityReview.RulePack |
| SecurityReview.RulePackBuilder | `tools/SecurityReview.RulePackBuilder/SecurityReview.RulePackBuilder.csproj` | 8 | SecurityReview.Domain, SecurityReview.RulePack |
