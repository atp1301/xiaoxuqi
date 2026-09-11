# Harness MVP

> 新机器接手（空白电脑上的 Claude Code / 编码 Agent）：先完整阅读仓库根目录 [intro.md](intro.md)，再动手。那是给新主机的系统任务书，包含 Docker、ExploitGym、GOAD、单元测试和压力测试的逐步指令。不要跳过其中的安全边界。

这是一个面向课程演示的安全多 Agent pentest harness。它把一次运行拆成 Operator 协调者 + 7 个专职 Agent（侦察、代码审计、环境复现、漏洞分析、验证、横向移动、报告）。Orchestrator 显式承担“接收汇报 → 综合 → 分配任务”，按任务树执行，并把每步包成 Thought → Action → Observation。

## 快速运行

需要 Python 3.10 或更高版本，不需要安装第三方包：

```powershell
python -m harness_mvp --scenario demo --target demo.local --output out
```

命令会在 `out/` 生成 `<run_id>.json` 和 `<run_id>.md`。演示靶场由 `DemoLabAdapter` 在进程内返回固定响应，因此不会向互联网发送探测请求。示例会发现 SQL 注入、反射型 XSS 和缺少授权三个训练用问题，Exploit Agent 只生成“模拟验证”记录，不发送攻击载荷。

## Dashboard/API

```powershell
python -m harness_mvp --serve --port 8765
```

打开 `http://127.0.0.1:8765/` 进入网页控制台。页面会展示系统能力、Operator 与七角色、安全边界，并支持启动 Demo/local-web/complex-web、检查靶场就绪、检索知识库、只读检查 ExploitGym。

接口包括：

* `GET /api/catalog`：能力与边界说明
* `GET /api/labs`：只读靶场就绪检查
* `GET /api/knowledge?q=&limit=`：知识库检索
* `GET /api/exploitgym?task_id=`：ExploitGym 只读检查
* `GET /api/runs`：运行列表
* `POST /api/runs`：JSON body 可传 `target`、`scenario`、`output`
* `GET /api/runs/{id}`：完整运行状态
* `GET /api/runs/{id}/progress`：任务树与共享进度
* `GET /api/runs/{id}/report`：Markdown 报告
* `GET /api/tools`：工具库与权限/stub 状态
## 真实本地靶场适配

MVP 还提供 `local-web` 适配器。它只访问白名单中的本机地址，记录响应摘要，并继续使用同一套 Agent、范围策略和报告链路：

```powershell
docker compose -f lab/docker-compose.yml up -d --build
python -m harness_mvp --scenario local-web --target http://127.0.0.1:18088 --output out-local
docker compose -f lab/docker-compose.yml down -v
```

Docker 引擎不可用时，可直接运行 `python lab/app.py --port 18088`，然后使用同样的 Harness 命令。该训练服务只在 loopback 提供虚构课程数据，不包含宿主文件读取或任意攻击载荷接口。

当前 `local-web` 训练服务使用内存 SQLite 保存虚构课程记录。`/search` 存在故意设置的 GET 型 SQL 注入，Harness 使用 baseline 与两组固定课程测试输入做正负差分验证，不接受用户自定义载荷、不读取宿主文件；成功时报告会记录 `source=http-lab`、响应摘要和 SHA-256 哈希，并将验证状态标为 `verified`。这是真实本地训练服务验证，不代表对外部系统进行测试。

## Complex Web multi-node lab

Course B uses a self-built Vulhub-style compose lab (`lab/complex_web`) with three nodes: `edge-gateway`, `app-api`, and `internal-admin`. This replaces Demo-only evidence for the complex Web/network requirement. It is an authorized loopback training environment, not a public CVE exploit pack.

```powershell
python -m lab.complex_web
python -m harness_mvp --scenario complex-web --target http://127.0.0.1:18089 --output out-complex-web
```

Docker alternative:

```powershell
docker compose -f lab/complex_web/docker-compose.yml up -d --build
python -m harness_mvp --scenario complex-web --target http://127.0.0.1:18089 --output out-complex-web
docker compose -f lab/complex_web/docker-compose.yml down -v
```

The recorded chain is discover -> SQLi differential -> constrained in-lab identity (`uid=65532`) -> ground-truth flag. The adapter still sends only fixed GET probes and stores original URLs, bodies, and SHA-256 hashes. Manifest: `lab/complex_web/manifest.json`.


运行完成后，输出目录还会生成 `.checkpoints/<run_id>.json`。checkpoint 使用原子替换写入，记录每步状态和重试次数；可用以下命令从断点恢复：

```powershell
python -m harness_mvp --resume out\.checkpoints\<run_id>.json --output out
```

检查课程环境就绪状态（只读，不启动环境、不执行 payload）：

```powershell
python -m harness_mvp --check-labs
```

通过 `GOAD_ROOT`、`EXPLOITGYM_ROOT`、`VULHUB_ROOT` 指向各自的本地 checkout 后，检查器会继续验证关键文件是否存在。

## 可选的 LLM 配置

三种模式：`deterministic` 全程不调用模型；`auto` 在没有配置凭据时等同 `deterministic`，配置了才参与；`llm` 要求凭据，缺失会被**同步拒绝**而不是静默降级。控制台右上角的"决策模式"下拉框与 CLI 的 `--mode` 是同一个开关。

**模型只解读证据，不制造证据。** 每轮最多两次调用，都在确定性探测**之后**：

| 调用点 | 模型做什么 | 模型碰不到什么 |
|---|---|---|
| `vuln` | 对已测出的 finding 定级（`severity`）并写风险叙述 | 不能新增/删除 finding，不能设置 `exploitable`，不能改 `verified` 结论 |
| `report` | 写整体风险、执行摘要、优先处置、局限性 | 同上；报告会固定标注该节为"解读而非证据" |

实测差分（真实 HTTP 探测 + 真实 SHA-256）锁定了 `confidence` 的区间，模型只能在该区间内定位：验证通过 `[0.90, 0.99]`，验证失败 `[0.30, 0.40]`，无实测 `[0.40, 0.70]`。已验证的漏洞不允许被降级到 `high` 以下；模型想要的数值会作为 `model_confidence_position` 存入报告以备审计。

模型返回的文本只保留 `finding_id`/`severity`/`confidence`/`narrative` 四个键，其余一律丢弃并记入 `rejected`，因此模型在结构上无法注入 finding。审计只保存响应与输入的 SHA-256，不落原文。

Key 可以放在项目根目录的 `.env`（已 gitignore）里，也可以放在进程环境里；**进程环境始终优先**，`.env` 只在 `cli.main()` 里加载，`unittest` 不会读到开发者凭据。

PowerShell 示例（Key 只存在于当前进程环境，不会写入报告）：

```powershell
$env:HARNESS_LLM_API_KEY = "sk-..."
$env:HARNESS_LLM_BASE_URL = "https://api.openai.com/v1"
$env:HARNESS_LLM_MODEL = "gpt-4o-mini"
python -m harness_mvp --mode llm --scenario demo --target demo.local --output out-llm
```

DeepSeek、Kimi 或本地 OpenAI-compatible 服务只需要改 `HARNESS_LLM_BASE_URL` 和 `HARNESS_LLM_MODEL`。对于你提供的 Kapibala/New API 钱包，使用：

```powershell
$env:HARNESS_LLM_API_KEY = "你的钱包 API Key"
$env:HARNESS_LLM_BASE_URL = "https://kapibala.asia/v1"
$env:HARNESS_LLM_MODEL = "钱包页面中显示的模型名"
$env:HARNESS_LLM_TIMEOUT = "180"   # 推理模型实测单次 61.5s，60 会超时
python -m harness_mvp --mode llm --scenario demo --target demo.local --output out-kapibala
```

不要把 Key 写进源码、Git、命令历史或报告。模型调用失败（超时、连不上、返回垃圾）**不会**让评估失败：运行照常 `completed`，报告里写明"已回退确定性定级"。

## ReAct 记录的诚实性

`_THOUGHTS` 里每个步骤的样板文字是**确定性文案，不是模型推理**——这一点在源码注释、报告和这里都明确标注。唯一例外是 `exploit` 步引用的模型风险判读，它是 `vuln` 步那次调用的产物，没有额外开销。

## 安全边界

默认目标白名单只有 `demo.local`、`localhost` 和 `127.0.0.1`。所有工具调用先经过 `PolicyEngine`；HTTP 工具只发有超时的 GET，命令工具只接受 `python --version` 这一条固定诊断命令，始终使用 `shell=False`。生产或真实授权测试前应增加独立审批、认证、速率限制、审计存储和更严格的网络隔离。

## 课程要求映射

* 多 Agent：`agents.py` 中的 Recon/CodeAudit/EnvRepro/Vuln/Exploit/PostExploit/Report；`Orchestrator` 为协调智能体 Operator。
* 状态感知：短期记忆 `working_memory`（`facts` 别名）+ `episodic_memory`，以及 findings/events。
* 规划执行：任务树 `parent_id`/`depends_on`，ReAct 三段事件，失败有限重试。
* 失败恢复：每个步骤最多两次尝试，并把错误写入状态、checkpoint 和报告；可用 `--resume` 从断点继续。
* 知识库/RAG：`KnowledgeBase.search()` 覆盖 CVE/CWE、ATT&CK TTP、Payload 模板、成功案例四类，标准库 TF-IDF/余弦相似度。
* 工具库：`TOOL_REGISTRY` 注册已实现工具与 nmap/目录枚举/命令执行等沙箱 stub；`PolicyEngine.require_action` 按 registry 做最小权限检查。
* 报告：同时输出 JSON（机器可读）和 Markdown（答辩可读）。

## 测试

```powershell
python -m unittest discover -s tests -v
```

