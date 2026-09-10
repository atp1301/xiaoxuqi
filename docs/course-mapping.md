# 课程要求与 MVP 范围

来源：`2026网络空间安全课程设计-new(1).pdf`，第 3–4 页第 2 题；通用交付要求在第 6–7 页。

## 已实现目标

本项目是第 2 题“面向完整攻击链智能构建的多 Agent 分工协作 Harness 系统设计与实现”的可运行原型。Harness 在这里指统一管理 Agent、状态、工具和执行边界的运行框架。

| 课程能力 | MVP 的验证方式 | 后续扩展 |
|---|---|---|
| 多 Agent 分工协作 | Operator 协调者 + 侦察/代码审计/环境复现/漏洞分析/验证/横向移动/报告，通过共享状态传递信息 | 模型驱动的动态角色生成 |
| Plan-and-Execute 与 ReAct | 任务树计划；每步记录 Thought → Action → Observation，Operator 综合后分配下一步 | 接入模型决策与动态任务拆分 |
| 状态化任务与共享进度 | 任务树节点、依赖、working/episodic memory、checkpoint；Dashboard `/api/runs/{id}/progress` | 并发 worker 与跨机器恢复 |
| 失败恢复 | 工具失败有界重试，失败记录进入 checkpoint 和最终报告 | 环境快照回滚和替代策略 |
| 知识增强 | 本地四类 RAG：CVE/CWE、ATT&CK TTP、Payload 模板、成功案例（含 out/*.md） | 真实向量库与外部情报源 |
| 最小权限与工具边界 | `TOOL_REGISTRY` + `PolicyEngine.require_action`；stub 工具不可执行 | 独立容器/虚拟机运行环境 |
| ??????? | Demo + local-web SQLi differential + complex-web discover/verify/identity/flag | GOAD and ExploitGym official scorer |

## Remaining hard tests

Demo and the single-process local-web lab do not replace Windows domain or ExploitGym official scorer runs. The complex Web/network requirement is covered by `lab/complex_web`.

1. Windows 域环境：域控与多个域内节点。
2. ExploitGym 两个中等复杂靶场，包括课程指定 `v8:sbxbrk/398773898`。
3. Complex Web/network lab: implemented as self-built `lab/complex_web` (edge-gateway / app-api / internal-admin). Evidence: `lab/complex_web/manifest.json` and `out-complex-web/`.

GOAD and ExploitGym still need an isolated authorized host. The complex-web chain is a local training lab with a ground-truth flag; it is not a claim of compromise against an external host.

## 课程最终交付清单

课程要求的完整提交包还包括：任务分工、技术原理、概要设计、详细设计、测试分析、安装使用文档、源代码、PPT 和截屏录像。本 MVP 提供源代码、安装使用、架构说明、测试与演示脚本；PPT、录像和真实靶场测试数据需要在最终阶段补齐。

建议演示时明确标注“模拟靶场 / 确定性策略”，避免将原型结果当作真实渗透效果。

