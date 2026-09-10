# 测试分析报告

日期：2026-09-10  
范围：Harness MVP 的功能链、范围策略、适配器、模型客户端、checkpoint 与报告输出。

## 测试方法

项目不依赖第三方测试框架，使用 Python 标准库 `unittest`。测试分为确定性 Demo 链路、本地 HTTP 训练服务链路、策略拒绝、模型客户端解析、靶场只读检查、失败重试和 checkpoint 恢复。checkpoint 使用临时目录，避免污染项目输出。

## 功能测试表

| 编号 | 场景 | 预期 | 结果/证据 |
|---|---|---|---|
| T-01 | `Orchestrator().run()` Demo | 完成运行，产生 3 条训练发现，写 JSON/Markdown | 已验证：历史 `out/*.json`；单元测试 `test_demo_run_produces_findings_and_reports` |
| T-02 | `local-web` 本地服务 | 五路侦察、基于真实响应的 SQLi 发现、baseline/正向/负向差分验证和完整报告 | 已验证：`test_local_http_adapter_runs_full_chain_against_local_lab`（服务在测试线程内启动；1 条 `http-lab` 发现，状态 `verified`） |
| T-03 | 越界目标和任意 Shell | `PolicyViolation`，不执行请求/命令 | 已验证：`test_policy_blocks_out_of_scope_and_shell` |
| T-04 | 目标解析 | 接受白名单 loopback 地址和端口 | 已验证：`test_target_parser_accepts_allowed_forms` |
| T-05 | 失败恢复 | 瞬时侦察异常最多重试两次并记录事件 | 已验证：`test_react_retries_a_transient_agent_failure` |
| T-06 | LLM 客户端 | 解析 OpenAI-compatible JSON，Key 不进入 repr/报告 | 已验证：`test_openai_compatible_client_parses_json_advisory`、`test_llm_config_is_optional_and_key_is_not_serialized` |
| T-07 | 靶场就绪检查 | 只读检查 Docker、local-web、GOAD、ExploitGym、Vulhub | 已验证：`test_lab_readiness_check_is_read_only_and_explicit` |
| T-08 | checkpoint 写入/恢复 | 原子 JSON、schema v1、同一 run_id，成功步骤跳过；失败步骤可在修复后继续 | 已验证：`tests/test_checkpoint.py`；checkpoint 含 `schema_version`、`next_step_index`、`step_statuses`、`state`，并拒绝错误 schema |
| T-09 | Dashboard 后台任务 | POST 快速返回任务状态，GET 轮询进度并读取报告，拒绝越界输出目录 | 已验证：`tests/test_dashboard.py` 3 项 |
| T-10 | ExploitGym 适配器 | 只读检查 checkout、任务清单和指定任务 ID，不启动环境 | 已验证：`tests/test_exploitgym_adapter.py` 5 项；状态仍为 `external-benchmark-pending` |
| T-11 | Exploit 验证异常 | local-web 验证抛错时 Agent 返回 `failed`，并写入 `exploit_results.status=failed` | 已验证：`test_exploit_validation_exception_marks_agent_failed` |

## 可复现实测命令

```powershell
python -m unittest discover -s tests -v
python -m compileall -q harness_mvp lab tests
python -m harness_mvp --scenario demo --target demo.local --output out
python -m harness_mvp --check-labs
```

当前源码测试结果：27 项测试全部通过；编译检查通过；Demo 输出 `completed`、3 条模拟训练发现；local-web 输出 1 条基于真实响应的 SQLi 发现并完成 `verified` 验证；修复版 local-web 输出 0 条发现；`--check-labs` 只读返回环境状态。实际环境中 Docker Server 已检测到，local-web 未启动时显示 `not_ready`，GOAD/ExploitGym/Vulhub 未配置时显示 `not_configured`。这些状态不代表外部靶场验收。

## Checkpoint 验证

成功运行会在输出目录创建 `.checkpoints/<run_id>.json`。文件使用同目录临时文件和 `os.replace` 原子替换，记录 `schema_version=1`、固定计划、每步状态和尝试次数、下一步索引以及完整 `RunState`。使用下列命令可恢复同一运行：

```powershell
python -m harness_mvp --resume out\.checkpoints\<run_id>.json --output out
```

恢复会沿用 checkpoint 中的 target/scenario/run_id，跳过失败步骤之前已经成功的步骤；从第一个未完成步骤开始重新建立其依赖结果，并为本次恢复提供新的有界重试预算。历史错误、事件和尝试记录保留在状态中。最终 JSON/Markdown 报告包含 `agent_results`、`checkpoint` 和 `test_evidence` 字段。

## 课程要求映射

| 课程证据 | 当前测试/产物 | 结论 |
|---|---|---|
| 多 Agent 分工与编排 | T-01/T-02 的四步 Agent 结果和事件时间线 | MVP 已具备 |
| 状态共享和失败恢复 | T-05、T-08 的 facts、events、checkpoint | MVP 已具备有限恢复 |
| 最小权限与边界 | T-03 及 `PolicyEngine` | MVP 已具备演示级控制 |
| 报告可追溯 | JSON/Markdown、agent_results、checkpoint | MVP 已具备 |
| 三类真实靶场验收 | `--check-labs` 与 `lab/catalog.json` | 尚未完成，不能宣称通过 |

## 截图与外部环境证据

本报告不虚构截图或外部靶场结果。当前交付未附截图文件，答辩材料可在执行命令后补充以下占位：

- `[截图占位 1：CLI Demo 成功输出与 out-course-upgrade/<run_id>.md]`
- `[截图占位 2：Dashboard /api/runs/<id> 的后台进度、发现卡片和报告链接]`
- `[截图占位 3：local-web 易受攻击版与 --fixed 修复版的对照结果]`
- `[外部靶场证据占位：GOAD、ExploitGym 两任务、复杂 Web 环境的 manifest/scorer/清理记录]`


