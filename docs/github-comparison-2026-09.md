# GitHub 同类项目对比（2026-09-08）

本次检索使用 GitHub 官方 API 读取仓库元数据和 README。Star 数和推送时间是检索当天的快照，不是质量证明。

## 选取的项目

| 项目 | 定位与 README 中的能力 | 与本项目的关系 |
|---|---|---|
| [GH05TCREW/pentestagent](https://github.com/GH05TCREW/pentestagent) | MIT，Python；多 Agent 编排、MCP、Docker/Kali runtime、浏览器工具、RAG、任务状态和报告 | 最直接的参考范本；你的 MVP 是它的轻量、确定性子集 |
| [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | MIT，Python；CTF/渗透测试多阶段流水线，支持 Claude/Codex 等后端、会话保存、多模型配置和交互模式 | 真实 LLM 驱动和持久会话比当前 MVP 完整 |
| [s0ld13rr/pentestcode](https://github.com/s0ld13rr/pentestcode) | MIT，TypeScript；13 个专职 Agent、结构化 engagement state、18 个工具、解析器、AD/Kerberos、后渗透和会话恢复 | 角色专业化、工具深度和长期状态明显领先 |
| [SHAdd0WTAka/Zen-Ai-Pentest](https://github.com/SHAdd0WTAka/Zen-Ai-Pentest) | MIT，Python；72+ 安全工具、11-Agent 编排、8 个 MCP Server、Docker 隔离、风险引擎和多模型投票 | 工具覆盖、沙箱、误报控制和 MCP 产品化程度更高 |
| [KHenryAegis/VulnBot](https://github.com/KHenryAegis/VulnBot) | MIT，Python；多 Agent 协作和 RAG，面向自动化渗透测试 | 证明课程题目方向有成熟先例；维护时间较旧，需谨慎复用 |
| [aielte-research/HackSynth](https://github.com/aielte-research/HackSynth) | AGPL-3.0，Python；Planner + Summarizer，并提供 PicoCTF/OverTheWire 共约 200 个挑战的评测集 | 重点是研究和 benchmark，不是完整生产平台；你的 MVP 缺少它的可重复评测集 |
| [pensar-x/argus-validation-benchmarks](https://github.com/pensar-x/argus-validation-benchmarks) | Apache-2.0；71 个 Docker 化渗透 benchmark、10 个威胁建模 benchmark、固定漏洞和 flag/ground truth | 可直接借鉴靶场清单、manifest 和评分方式 |
| [OWASP/Agent-Security-Regression-Harness](https://github.com/OWASP/Agent-Security-Regression-Harness) | Apache-2.0；场景文件、trace、工具调用拒绝、目标完整性等安全回归断言 | 不是自动渗透工具，但最适合补你的 Harness 测试层 |

## 你的 MVP 已经具备的能力

- Recon、Vuln、Exploit、Report 四个清晰角色。
- Orchestrator 负责计划、执行、状态记录、失败重试和报告。
- 结构化 facts、findings、events 和 exploit results。
- 本地知识库检索，可关联 CWE、证据和修复建议。
- 目标白名单、动作白名单、固定诊断命令和无 shell 执行。
- CLI、Dashboard/API、JSON/Markdown 报告。
- 1000 次并发模拟运行和 50 次 API 并发测试已通过。

## 与同类项目相比的主要缺口

按课程交付优先级排序：

1. **没有真实 LLM 决策层。** 当前 Agent 是确定性规则，尚未接入 OpenAI-compatible、DeepSeek、Kimi、Anthropic 或本地模型，也没有真正的 tool-calling、上下文压缩和模型失败回退。
2. **没有真实安全工具适配器。** 当前 `DemoLabAdapter` 在进程内返回固定响应；没有 nmap、HTTP 深度枚举、目录发现、漏洞扫描、代码审计、AD/LDAP、凭据验证等可替换适配器。
3. **Exploit 只是模拟。** 当前不会在沙箱中验证漏洞、获取权限、读取 flag 或保存可复核的 PoC 输出。课程第二题要求的真实利用链因此尚未完成。
4. **没有课程要求的三类靶场。** 尚未接入 Windows 域环境、指定的 ExploitGym `v8:sbxbrk/398773898`、另一个 ExploitGym 靶场和复杂网络靶场。这是能否宣称“满足题目测试要求”的最大差距。
5. **多 Agent 目前是串行四步，不是并行任务树。** 角色名和边界已经有了，但没有独立上下文、依赖图、并发 Worker、任务领取/租约或真正的动态重规划。`pentestcode`、`pentestagent` 和 Zen-Ai-Pentest 在这方面更完整。
6. **状态与任务管理仍有限。** 当前已有带 schema 的 checkpoint 和 `--resume`，Dashboard 也支持后台任务及状态轮询；但没有持久化任务队列、取消、锁租约和跨机器恢复。
7. **工具权限模型仍是演示级。** 有 allowlist，但没有按 Agent 细分的工具权限、资源配额、网络 egress 控制、容器/VM 隔离、密钥注入策略和人工审批点。
8. **缺少真实 benchmark 和基线。** 目前只有 4 个单元测试和模拟压力测试，没有固定 ground truth、成功率、误报率、覆盖率、耗时、token/cost、工具调用数，也没有与单 Agent 基线对照。
9. **报告证据还不够接近渗透报告。** Demo 仍以模拟验证为主；local-web 已保存真实响应摘要、正负差分、复现结果和 SHA-256 哈希，但仍缺截图、风险接受记录和整改复测结果。
10. **工程集成较少。** 尚无 MCP server、Webhook、身份认证、并发任务持久队列、Docker Compose 靶场编排、CI 安全回归或前端结果筛选。

## 我建议的补齐顺序

第一阶段先做课程“可验收”闭环：加入 `LabAdapter` 抽象和 Docker 化本地靶场，至少准备一个 Web 靶场与一个可复现的权限/flag 目标；工具执行统一经过 scope、timeout、输出上限和审计记录。这样可以把当前固定 Demo 替换为真实但授权的测试环境。

第二阶段接入一个 OpenAI-compatible 模型，并保留确定性策略作为离线 fallback。把 Orchestrator 改成持久化任务树：每个 Agent 有独立输入/输出、工具权限和 checkpoint，支持失败后的替代步骤和恢复。

第三阶段补 benchmark：优先借鉴 Argus 的 manifest/ground truth 形式和 OWASP Harness 的 trace/assertion 形式，建立“发现正确、范围不越界、拒绝危险工具、报告证据完整”四类指标，再和当前四 Agent 版本、单 Agent 版本做对比。

最后再扩展 Windows/AD、ExploitGym 和复杂网络环境。它们需要单独的授权、网络隔离和环境复现文档，不能用模拟结果替代。

## 结论

你的项目现在更像“安全边界清楚的多 Agent 编排原型”，不是“可对真实目标自主执行的渗透平台”。这并不说明架构方向错了：课程要求的 Harness 骨架已经覆盖了，但要追上 GitHub 上成熟项目，最需要投入的是靶场适配与可重复评测，而不是继续增加 Agent 数量。

复用代码时应逐仓库核对许可证：PentestAgent、PentestGPT、PentestCode、Zen-Ai-Pentest、VulnBot 为 MIT；HackSynth 为 AGPL-3.0；Argus 和 OWASP 回归 Harness 为 Apache-2.0。当前 MVP 没有复制这些仓库的源代码。

