# Harness MVP

这是一个面向课程演示的安全多 Agent pentest harness。它把一次运行拆成 Recon、Vuln、Exploit 和 Report 四个职责清晰的 Agent，由 Orchestrator 负责规划、执行、记录状态并在失败时有限重试。

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

打开 `http://127.0.0.1:8765/` 进入网页控制台。页面会展示系统能力、四步 Agent、安全边界，并支持启动 Demo/local-web、检查靶场就绪、检索知识库、只读检查 ExploitGym。

接口包括：

* `GET /api/catalog`：能力与边界说明
* `GET /api/labs`：只读靶场就绪检查
* `GET /api/knowledge?q=&limit=`：知识库检索
* `GET /api/exploitgym?task_id=`：ExploitGym 只读检查
* `GET /api/runs`：运行列表
* `POST /api/runs`：JSON body 可传 `target`、`scenario`、`output`
* `GET /api/runs/{id}`：完整运行状态
* `GET /api/runs/{id}/report`：Markdown 报告
## 真实本地靶场适配

MVP 还提供 `local-web` 适配器。它只访问白名单中的本机地址，记录响应摘要，并继续使用同一套 Agent、范围策略和报告链路：

```powershell
docker compose -f lab/docker-compose.yml up -d --build
python -m harness_mvp --scenario local-web --target http://127.0.0.1:18088 --output out-local
docker compose -f lab/docker-compose.yml down -v
```

Docker 引擎不可用时，可直接运行 `python lab/app.py --port 18088`，然后使用同样的 Harness 命令。该训练服务只在 loopback 提供虚构课程数据，不包含宿主文件读取或任意攻击载荷接口。

当前 `local-web` 训练服务使用内存 SQLite 保存虚构课程记录。`/search` 存在故意设置的 GET 型 SQL 注入，Harness 使用 baseline 与两组固定课程测试输入做正负差分验证，不接受用户自定义载荷、不读取宿主文件；成功时报告会记录 `source=http-lab`、响应摘要和 SHA-256 哈希，并将验证状态标为 `verified`。这是真实本地训练服务验证，不代表对外部系统进行测试。

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

默认的 `auto` 模式不需要 Key，适合离线演示；配置 Key 后，`auto` 会让模型对已观测证据给出受限分析建议，确定性规则仍负责产生可复核发现。`llm` 模式要求 Key，且只允许 OpenAI-compatible 的 JSON 分析接口。

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
$env:HARNESS_LLM_TIMEOUT = "60"
python -m harness_mvp --mode llm --scenario demo --target demo.local --output out-kapibala
```

不要把 Key 写进源码、Git、命令历史或报告。没有配置 Key 时，`auto` 会安全地回到确定性策略。

## 安全边界

默认目标白名单只有 `demo.local`、`localhost` 和 `127.0.0.1`。所有工具调用先经过 `PolicyEngine`；HTTP 工具只发有超时的 GET，命令工具只接受 `python --version` 这一条固定诊断命令，始终使用 `shell=False`。生产或真实授权测试前应增加独立审批、认证、速率限制、审计存储和更严格的网络隔离。

## 课程要求映射

* 多 Agent：`agents.py` 中的 Recon/Vuln/Exploit/Report。
* 状态感知：`RunState.facts`、`findings`、`exploit_results`、`events`。
* 规划执行：`Orchestrator.plan()` 与执行循环。
* 失败恢复：每个步骤最多两次尝试，并把错误写入状态、checkpoint 和报告；可用 `--resume` 从断点继续。
* 知识库/RAG：`KnowledgeBase.search()` 使用 12 条本地 CWE 教学条目和标准库 TF-IDF/余弦相似度，为发现关联 CWE/修复建议。
* 报告：同时输出 JSON（机器可读）和 Markdown（答辩可读）。

## 测试

```powershell
python -m unittest discover -s tests -v
```

