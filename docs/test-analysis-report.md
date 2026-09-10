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



---

# 新主机复测（2026-09-10）

主机：ASUS TUF Gaming F16 FX607JV（Windows 11 家庭中文版 10.0.26200，i7-13650HX，15.63 GiB）。
环境与选型见 `docs/new-host-hardware.md`，逐步实测见 `docs/new-host-setup-log.md`。
**本节是追加，不覆盖上面的历史结果。**

## 测试数量变化（以本机实测为准）

| 项 | 本机实测 |
|---|---|
| 测试文件 | 9 个（`tests/`） |
| 测试用例 | **50** 个（原 41 + 新增 `tests/test_stress.py` 9 个） |
| 结果 | `Ran 50 tests in 62.485s` / **OK** |

```text
$ python -m unittest discover -s tests -v
Ran 50 tests in 62.485s

OK
```

## 红 → 绿：一个环境敏感用例

首次运行 **40 通过 / 1 失败**：

```text
FAIL: test_post_is_queued_then_completes_and_report_is_readable
AssertionError: 'running' != 'completed'
```

原因不是功能缺陷：该用例最多轮询 `40 × 0.05s = 2s`，而本机装了火绒实时防护，
每次文件落盘都要被重新扫描，Dashboard 后台 Demo 运行实测要 1.85s / 4.20s / 2.15s。
cProfile 显示运行本体只有 0.591s，其中 0.28s 花在 23 次 checkpoint 的 `fsync`。

处置：新增 `wait_for_run(run_id, timeout=30.0)` 辅助方法，**只放宽等待时间**。

> **没有修改任何断言。** `assertEqual(state["status"], "completed")`、
> `len(state["findings"]) == 3`、报告可读性检查全部原样保留。
> 放宽的是"等多久"，不是"要求什么" —— 运行必须真的完成并产出 3 条发现才算过。

## 新增：压力 / 稳定性测试（`tests/test_stress.py`）

按 `intro.md` 第 7.2 节实现，标准库 `unittest`，无新依赖。完整数字见
`docs/stress-test-results.md`（该文件由测试自身生成，重跑覆盖）。

| 用例 | 覆盖内容 |
|---|---|
| `test_repeated_demo_runs_are_stable` | Demo 重复 **50** 次，每次都必须 `completed` 且恰好 3 条发现 |
| `test_local_web_vulnerable_is_repeatably_verified` | 易受攻击版重复 10 次，每次都必须 verified（**漏报 = 0**） |
| `test_local_web_fixed_never_reports` | 修复版重复 10 次，必须**零发现**（**误报 = 0**） |
| `test_complex_web_vulnerable_is_repeatably_verified` | 复杂链重复 10 次，含 `shell_obtained` 与 `flag_match` |
| `test_complex_web_fixed_never_reports` | 复杂链修复版重复 10 次，必须零发现 |
| `test_dashboard_concurrent_runs_respect_the_active_limit` | 同时 POST 5 个运行，验证并发隔离与背压 |
| `test_policy_rejects_out_of_scope_targets_without_leak` | 5000 次越界拒绝检查，**漏放 = 0** |
| `test_checkpoint_resume_after_transient_failure_is_repeatable` | 注入瞬时失败后恢复 5 次，`run_id` 不变且最终 `completed` |

实测汇总（`docs/stress-test-results.md`）：

| 指标 | 实测 | 目标 |
|---|---|---|
| 迭代数 / 通过 / 失败 | 97 / 97 / 0 | 失败 0 |
| 成功率 | 100.00% | 100% |
| 误报（修复版 findings） | 0 | 0 |
| 漏报（易受攻击版未 verified） | 0 | 0 |
| 越界工具调用放行 | 0 | 0 |

### 关于 Dashboard 并发：这是背压，不是缺陷

`MAX_ACTIVE_RUNS = 4` 是控制台**故意**设的上限。最初我写的断言要求 5 个并发
POST 全部返回 202，结果第 5 个收到 `429 too many active runs` —— **这是我的断言错了**。

正确做法是断言"上限被守住"：`accepted ≤ MAX_ACTIVE_RUNS`，超限者收到带
`too many active runs` 的 429。为了让测试变绿去抬高 `MAX_ACTIVE_RUNS`，
正是 `intro.md` 第 3 节禁止的"改产品迁就测试"，因此没有那样做。

## 新增：报告不会因异常而"静默变绿"

`tearDownModule` 用 `EXPECTED_SCENARIOS` 表核对每个用例是否真的产出了记录。
若某个用例在 `record()` 之前就异常退出，其场景会整体缺席并被列出，
报告不会因为"根本没记录"而显得全绿。

## 本机仍**不能**宣称通过的课程项

| 课程项 | 本机状态 | 依据 |
|---|---|---|
| ExploitGym 官方 scorer 通过 | ❌ 未完成 | `docs/exploitgym-official-check.md`。只有 `catalog_ready`；无任何 scorer 输出 |
| GOAD 域渗透 | ❌ 未完成（本机不可行） | `lab/goad/manifest.json`，四条独立理由 |
| Demo / local-web / complex-web | ✅ 本机真实跑通 | 但它们是**本地靶场**，不是外部系统突破 |

`intro.md` 第 3 节明确：不得把 `catalog_ready`、进程内 Demo、旧机器 evidence
冒充本机验收；不得把 Demo / local-web 的模拟结果写成真实外部系统突破。
本节的措辞遵守该约束。

---

## 追加：切换到 Python 3.13 后的复测，以及一次**未能复现的错误**

日期：2026-09-10

为满足 ExploitGym 的 `requires-python = ">=3.12,<3.14"`，本机补装了 Python 3.13.15
并设为默认（做法见 `docs/new-host-setup-log.md` 第 6 节）。切换后在本机默认解释器下
复跑仓库测试，**共 10 轮，9 轮 `OK`，1 轮 `FAILED (errors=1)`**。

| 轮次 | 命令 | 结果 |
|---|---|---|
| 1 | `py -3.13 -m unittest discover -s tests` | Ran 50 tests / **OK** |
| 2 | 全新环境块下 `python -m unittest discover -s tests` | Ran 50 tests (62.529s) / **FAILED (errors=1)** |
| 3 | 同上，输出落盘 `_run.log` | Ran 50 tests (62.959s) / **OK** |
| 4–6 | 同上，连续 3 轮 | **OK** / **OK** / **OK** |
| 7–11 | 同上，连续 5 轮 | **OK** ×5 |

**第 2 轮那次失败，我没有捕获到是哪个用例报错。** 原因是当时为图省事把输出接了
`Select-Object -Last 6`，只保留了末尾的汇总行，错误栈被丢掉了。这是我处理上的失误，
不是测试本身的问题。**此后 8 轮连续通过，未能复现。**

需要说明的两点：

1. **这不是"已知无害的抖动"。** 我没有复现，也就没有排除它；可能是端口竞争、
   也可能是当时 `winget` 刚改完 PATH、杀软在重扫。**在能复现并定位之前，
   不应把它当作噪音忽略。**
2. **第 2 轮的错误不来自压力测试。** 该轮 `[stress] summary` 显示
   `iterations: 97, passed: 97, failed: 0`，且 `scenarios_expected_but_not_recorded: []`，
   说明 `tests/test_stress.py` 的 8 个场景当轮全部正常记录。错误出在其余模块。

**下次若再出现**：直接跑
`python -m unittest discover -s tests 2>&1 | tee full.log`，
保留完整输出，即可定位到具体用例。

### 结论口径

可以说的：**在当前默认解释器 Python 3.13.15 下，仓库测试 9/10 轮全绿，
1 轮出现一次未能复现的用例错误，原因未查明。**

不可以说的："仓库测试稳定全绿"——本轮实测不支持这个更强的说法。

---

## 追加：2026-09-11 归档 ExploitGym V8 证据后的复跑

日期：2026-09-11

归档 V8 任务第 5 次的证据、并同步 `lab/catalog.json`、`lab/exploitgym/manifest.json`
与 4 份课程文档之后，按 `intro.md` 第 11 节第 13 项复跑仓库测试。

| 轮次 | 命令 | 结果 |
|---|---|---|
| 12 | `python -m unittest discover -s tests -v` | Ran 50 tests (62.963s) / **OK** |
| 13 | 同上，完整输出落盘 `.test-rerun-2026-09-11.log` | Ran 50 tests (61.565s) / **OK** |

第 13 轮按本文档上面的建议做了 `> .log 2>&1` 落盘，50 条用例逐条可见
（`... ok` 50 条、`FAIL/ERROR` 0 条），这样万一出现上面那种"未能复现的错误"，
错误栈不会再被丢掉。该日志被 `.gitignore` 的 `*.log` 覆盖，不会误入仓库。

压力测试汇总同样是干净的：`iterations: 97, passed: 97, failed: 0`，
`false_positives_fixed_lab_findings: 0`、`false_negatives_vulnerable_lab: 0`、
`out_of_scope_tool_call_leaks: 0`。

**累计：13 轮中 12 轮 `OK`，1 轮一次未复现的 `errors=1`（第 2 轮，原因仍未查明）。**
又增加了 2 轮绿，**但没有定位到那 1 轮**，所以那个异常既不能解释、也不能忽略。

### 这次复跑**没有**覆盖到什么（不要误读）

本次改动里唯独 `lab/catalog.json` 与 `lab/exploitgym/manifest.json`
是"数据文档"，而**仓库测试并不读这两个文件**——
Dashboard 的 `/api/catalog` 端点返回的是它自己的能力目录
（`capabilities` / `agents`），与 `lab/catalog.json` 不是同一个东西，
`tests/` 里也没有任何用例引用 `lab/catalog.json`。

因此**这次全绿不能拿来证明我那两处 JSON 改动是对的**。那部分是用
`json.load` 重新解析 + 逐项核对结构（`labs` 仍为 5 条、字段未丢）单独确认的。
两件事必须分开说，否则就是在用"测试过了"给没被测到的东西背书。
