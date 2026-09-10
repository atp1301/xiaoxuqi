# PentestAgent 参考与设计决策

- 项目：<https://github.com/GH05TCREW/pentestagent>
- 核对提交：`cf882dabea3ed91cef016cdd115e5426315665a2`
- 核对日期：2026-09-07
- 版本：0.2.0；Python >= 3.10；MIT License。

## 借鉴内容

| 上游文件 | 借鉴思路 |
|---|---|
| `pentestagent/agents/base_agent.py` | 有界 Agent 循环、工具结果回填、计划与重规划 |
| `pentestagent/agents/crew/orchestrator.py` | 统一编排与专职角色 |
| `pentestagent/agents/crew/worker_pool.py` | 工作任务隔离和结果汇总 |
| `pentestagent/tools/registry.py` | 显式工具注册和参数接口 |
| `pentestagent/workspaces/validation.py` | 目标范围检查 |
| `pentestagent/knowledge/rag.py` | 决策前检索知识 |
| `pentestagent/interface/cli.py` | 命令行入口与报告导出 |

本 MVP 为独立实现，没有复制上游源代码。未来直接复制或修改 MIT 源代码时，应保留其版权和许可声明。

## 为什么采用当前方案

实际问题是尽快形成可讲清楚、可运行、可测试的课程原型。当前工作区为空，尚无模型密钥、靶场或运行环境配置。可用工具有 Python、Git 和 PowerShell；因此首先采用标准库，避免新引入环境复杂度。

| 方案 | 优点 | 代价 | 决策 |
|---|---|---|---|
| 完整克隆 PentestAgent | 能力丰富，已有模型和运行环境接入 | 依赖多、需要密钥、难以在短时间证明课程独立设计 | 留作参考 |
| LangGraph / AutoGen / CrewAI | 丰富的工作流抽象 | 引入额外学习和版本维护成本 | MVP 暂不引入 |
| 小型标准库 Harness | 易运行、易审计、可替换、演示稳定 | 策略和知识检索能力有限 | 当前选择 |

Docker 在真实靶场隔离时很有价值，但演示模拟器不需要 Docker。MVP 的工具层不允许模型执行任意 shell；目标范围未配置或不匹配时拒绝执行。真实适配器上线前需要验证授权范围、网络隔离、超时、输出上限和秘密信息处理。

## 最小验证实验

1. 无 API Key、无网络、无额外包运行演示场景。
2. 验证多个专职 Agent 顺序协作，并产生结构化报告。
3. 对范围外目标、未授权工具、失败重试和输出文件进行测试。
4. 检查报告明确区分模拟结果与真实环境验证。

## 剩余风险

确定性策略不能证明 LLM 的推理能力；模拟场景不能证明真实漏洞利用成功；本地知识检索不能等同于生产级向量 RAG；多 Agent 的真实收益还需与单 Agent 基线作受控比较。
