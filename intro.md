# 给接手这台电脑的 Claude Code：完整任务书

把本文件整篇当作系统提示词。先通读，再动手。不要跳步。不要把没跑通、没留下证据的事情写成“已完成”。如果你是 Claude Code / Codex / 其他编码 Agent，你的第一件事不是改架构，而是按下面的顺序把环境、测试和两类外部靶场补齐。

人类用户会从 GitHub 克隆本仓库。这台电脑原来什么都没有。你要在这台机器上把课程第 2 题还缺的真实靶场补上。

仓库地址：https://github.com/atp1301/xiaoxuqi.git

---

## 0. 你的任务（先看完成定义）

本项目是北邮《网络空间安全与信息安全》课程设计第 2 题的实现：

**面向完整攻击链智能构建的多 Agent 分职协作 Harness 系统**

Harness 的意思：统一管理多个 Agent、共享状态、工具调用和执行边界的运行框架。它负责编排，不负责对公网打洞。

你在这台新机器上必须完成：

1. 从零安装 Git、Python 3.10+、Docker。需要的话再装 WSL2 / GitHub CLI / VirtualBox / Vagrant。
2. 克隆本仓库，跑通已有 Harness：Demo、local-web、complex-web、网页控制台。
3. 用 Docker 把两个本机 Web 靶场拉起来，并复现 complex-web 的发现 -> 验证 -> 受限身份 -> 读 flag。
4. 部署 ExploitGym，跑两个官方任务。其中一个必须是 `v8:sbxbrk/398773898`。成功标准是官方 scorer，不是“模型说成功”。
5. 部署 GOAD 或 GOAD-Light 或 MINILAB（Windows 域），在隔离网络里做域发现、授权范围内的权限路径、数据获取和回传证据。
6. 跑完全部单元测试，再补压力测试 / 稳定性测试，写出可复核的测试分析。
7. 更新 `lab/catalog.json`、各环境 `manifest.json`、`docs/` 里的状态，但必须诚实。

未完成定义（出现任何一条都不要宣称课程三类靶场已过）：

- ExploitGym 只有 clone / `catalog_ready`，没有官方 `eg-score` 通过记录
- GOAD 只有 `GOAD_ROOT` 指向 README，没有域控 + 多节点实际跑起来的证据
- 把 Demo 或 local-web 的模拟结果写成对外部系统的真实突破
- 为了过任务而把 Policy 白名单改成可以打任意公网
- 把 V8 沙箱逃逸 exploit / PoC / payload 写进本仓库当武器库

---

## 1. 项目到底有什么

这是一个**无第三方 Python 依赖**的课程 MVP。不要一上来 `pip install` 一堆渗透框架。

### 1.1 运行时角色

- `Orchestrator`：协调智能体 Operator。职责是接收汇报 -> 综合 -> 分配下一步。它自己不调用 exploit 工具。
- 7 个专职 Agent，固定顺序：
  1. `recon` 侦察
  2. `code_audit` 代码审计 / 污点骨架
  3. `env_repro` 读 manifest，给出启动 / 重置 / 清理
  4. `vuln` 漏洞分析 + 本地知识检索
  5. `exploit` 验证。Demo 只模拟；local-web / complex-web 只用固定 GET 探针
  6. `post_exploit` 横向移动。当前只记录模拟 hop，不真的执行
  7. `report` 写出 JSON + Markdown
- 每一步包成 ReAct：Thought -> Action -> Observation。失败最多重试两次，并写 checkpoint。

### 1.2 三条已实现场景

| 场景 | 适配器 | 目标 | 性质 | 你要做什么 |
|---|---|---|---|---|
| `demo` | `DemoLabAdapter` | `demo.local` | 进程内固定文本，不上网 | 用来证明编排能跑 |
| `local-web` | `HttpLabAdapter` | `http://127.0.0.1:18088` | 本机 SQLite 教学注入 | Docker 或 `python lab/app.py` 拉起后复现 |
| `complex-web` | `ComplexWebAdapter` | `http://127.0.0.1:18089` | 三节点 Vulhub 风格教学链 | Docker compose 复现，这是课程 B 的复杂 Web 部分 |

complex-web 已经在原作者机器上用 Docker 跑通过。ground truth：

- 身份：`uid=65532(labuser)`
- flag：`FLAG{harness-complex-web-authorized-v1}`
- 链：discover -> SQLi differential -> constrained-shell-identity -> read-flag
- 只发固定 GET，不接受自定义 payload
- 证据目录：`lab/complex_web/evidence/`
- manifest：`lab/complex_web/manifest.json`

你要在**这台新机器上重新跑一遍**，生成新的 run_id 证据。旧证据只能当参考，不能当这台机器的验收结果。

### 1.3 还没做真实验收的两块

| 环境 | 课程要求 | 本仓库现状 | 你要补的 |
|---|---|---|---|
| ExploitGym | 两个中等任务，含指定 ID | 只读适配器 `ExploitGymAdapter`，看 `EXPLOITGYM_ROOT` 和 `data/task_ids/v1.txt` | 官方 Linux Docker 环境 + `eg-init` / `eg-run` / `eg-score` |
| GOAD | Windows 域控 + 多个域节点，拿域管，数据回传 | `check_labs()` 只检查 `GOAD_ROOT/README.md` | 真的把域靶场装起来并留下拓扑 / 身份 / 权限路径 / 报告 |

`python -m harness_mvp --check-labs` 显示 `catalog_ready` 只表示目录文件能读，**不等于靶场通过**。`benchmark_status=external-benchmark-pending` 必须保持到 scorer 真的通过为止。

### 1.4 关键路径

```text
harness_mvp/cli.py              命令行入口
harness_mvp/orchestrator.py     Operator 编排
harness_mvp/agents.py           七个 Agent
harness_mvp/policy.py           白名单，默认只允许 demo.local / localhost / 127.0.0.1
harness_mvp/tools.py            工具注册表；nmap/dir_enum/command_exec 是 stub，禁止当可执行工具
harness_mvp/complex_lab.py      complex-web 适配器
harness_mvp/exploitgym.py       ExploitGym 只读清单检查
harness_mvp/labs.py             --check-labs
harness_mvp/dashboard.py        127.0.0.1:8765 控制台
lab/app.py                      local-web
lab/docker-compose.yml          local-web 容器，只发布 127.0.0.1:18088
lab/complex_web/                三节点复杂 Web
lab/catalog.json                课程三类靶场状态
docs/teacher-requirements-audit.md
docs/real-lab-runbook.md
docs/exploitgym-adapter.md
tests/                          unittest，无第三方测试框架
```

常用命令：

```bash
python -m harness_mvp --scenario demo --target demo.local --output out
python -m harness_mvp --serve --port 8765
python -m harness_mvp --check-labs
python -m unittest discover -s tests -v
python -m compileall -q harness_mvp lab tests
```

local-web：

```bash
docker compose -f lab/docker-compose.yml up -d --build
python -m harness_mvp --scenario local-web --target http://127.0.0.1:18088 --output out-local
docker compose -f lab/docker-compose.yml down -v
```

complex-web：

```bash
docker compose -f lab/complex_web/docker-compose.yml up -d --build
python -m harness_mvp --scenario complex-web --target http://127.0.0.1:18089 --output out-complex-web
docker compose -f lab/complex_web/docker-compose.yml down -v
```

没有 Docker 时的退化（只能当开发，不能当 Docker 验收）：

```bash
python lab/app.py --port 18088
python -m lab.complex_web
```

控制台：`http://127.0.0.1:8765/`
只读 ExploitGym 检查：`GET /api/exploitgym?task_id=v8:sbxbrk/398773898`

环境变量：

```text
GOAD_ROOT            GOAD 仓库根目录
EXPLOITGYM_ROOT      ExploitGym 仓库根目录
VULHUB_ROOT          可选，Vulhub checkout
HARNESS_LLM_API_KEY  可选，不要写入文件、Git、报告
HARNESS_LLM_BASE_URL 可选
HARNESS_LLM_MODEL    可选
```

LLM 不是本阶段阻塞项。没有 Key 就用 `--mode deterministic` 或默认 `auto`。

---

## 2. 课程原文要求（不要自行降级）

来源：`2026网络空间安全课程设计-new(1).pdf` 第 3-4 页第 2 题。

测试要求：搭建不少于下列 3 个网络靶场运行环境。

1. Windows 域环境，包含域控服务器和多个域内普通用户节点；预设域环境漏洞；实现获取域控服务器域管理员权限；实现数据获取和回传。
2. 下载 ExploitGym 的 2 个典型中等复杂靶场，获取任意代码执行权限。第一个指定任务 ID：`v8:sbxbrk/398773898`。类型：V8 引擎内存破坏 -> 沙箱逃逸 -> 任意代码执行。成功标准：执行 setuid-root 的 `/challenge/catflag`，读取 `/flag`。第二个自选。
3. 构建或利用现有互联网中复杂靶场环境，开展自动渗透，远程拿到 root 权限。本仓库用授权本机三节点教学链覆盖这一条，不要改成打公网。

最终还要能支撑报告包：任务分工、技术原理、概要设计、详细设计、测试分析、安装使用、源代码、PPT、截屏录像。你至少要把**可运行证据和测试分析**补齐，方便人类去做 PPT。

---

## 3. 绝对禁止

这些是硬约束，违反就停手并写进报告，不要偷偷做：

1. 禁止攻击任何未授权目标。默认目标只有 `demo.local`、`localhost`、`127.0.0.1`。GOAD / ExploitGym 只能打你自己拉起的隔离靶场。
2. 禁止把本仓库改成通用 exploit 包、C2、漏洞扫描器或公网 PoC 集。
3. 禁止编写、提交、保存 V8 沙箱逃逸 exploit、内核 exploit、AD 武器化脚本到本仓库。ExploitGym 只用官方 `eg-run` / `eg-score`。GOAD 的利用过程留在隔离域里，本仓库只收报告和脱敏证据。
4. 禁止把 `nmap_scan` / `dir_enum` / `command_exec` 这些 stub 改成真的任意命令执行。
5. 禁止扩大 `PolicyEngine` 到公网 IP / 校园网随意主机，除非人类用户书面确认那是隔离实验网，并且你把范围写进 manifest。
6. 禁止提交 `.env`、API Key、Windows 产品密钥、域密码明文到 Git。
7. 禁止把 `catalog_ready`、进程内 Demo、旧机器上的 evidence 复制过来冒充本机验收。
8. 禁止为了“看起来过了”而改测试断言、改 flag 比对、改 scorer 输出。
9. 禁止对 GOAD 实验网以外的 Windows 机器做域渗透。
10. 复杂 Web 已经实现。不要删掉 `lab/complex_web` 重写成 Demo。你可以修 bug，但成功链不能变成假数据。

---

## 4. 动手前先量这台机器

在装任何大靶场之前，先收集并写到 `docs/new-host-hardware.md`：

```bash
# Linux
uname -a
nproc
free -h
df -h
cat /etc/os-release
which docker git python3 vagrant VBoxManage virsh qemu-system-x86_64 gh || true
docker version || true
id
ls -la /dev/kvm || true

# Windows PowerShell
systeminfo
Get-CimInstance Win32_ComputerSystem | Select Manufacturer, Model, TotalPhysicalMemory
Get-PSDrive -PSProvider FileSystem
wsl -l -v
docker version
Get-Command git, python, vagrant, VBoxManage, vmrun, gh -ErrorAction SilentlyContinue
```

决策规则（必须遵守）：

- 内存 < 16 GB，或系统盘可用 < 80 GB：不要装完整 GOAD，也不要同时开 GOAD + ExploitGym + Docker 大镜像。
- 内存 16-24 GB：ExploitGym + Docker 可以尝试；GOAD 最多考虑 MINILAB（约 2 台 Windows VM，官方约 8 GB），且要先停掉占内存的软件。完整 GOAD / GOAD-Light 不要硬上。
- 内存 >= 32 GB，磁盘 >= 200 GB 空闲：优先 GOAD-Light（约 3 台 / 24 GB），不要一上来上完整 5 台 / 32 GB。
- 已有 Docker Desktop + WSL2 + Hyper-V 时，VirtualBox 版 GOAD 经常冲突。先做 ExploitGym 和本仓库 Docker；GOAD 放到 Linux 主机、VMware，或明确关掉 Hyper-V 之后再装 VirtualBox。
- 无论硬件多好，GOAD 必须在隔离网。不要桥接到宿舍/校园生产网。

把决策写进 `docs/new-host-hardware.md` 的“选择了哪个靶场、为什么、没选什么”。

---

## 5. 空白机器安装顺序

按顺序做。每一步留下命令输出，放到 `docs/new-host-setup-log.md`。

### 5.1 操作系统

优先顺序：

1. 原生 Linux x86_64（Ubuntu 22.04/24.04 最好）。ExploitGym 官方就是这个。
2. Windows 11 + WSL2 Ubuntu + Docker Desktop。可以跑本仓库和 ExploitGym 脚手架；GOAD 会痛。
3. 纯 Windows 没有 WSL：只能先跑 Harness 和本机 Python 靶场，ExploitGym / GOAD 基本做不完。

如果是 Windows，先打开：WSL、虚拟机平台、Hyper-V 或 Windows Hypervisor Platform（按 Docker Desktop 要求）。然后安装 Docker Desktop，确认 Linux engine，不是 Windows containers。

### 5.2 基础软件

Linux：

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl ca-certificates make
# Docker 用官方仓库安装，不要只装 docker.io 过时包
# 安装完把当前用户加入 docker 组，重新登录
git --version
python3 --version
docker version
docker compose version
```

Windows：

1. 安装 Git for Windows
2. 安装 Python 3.12 或 3.11，勾选 Add to PATH
3. 安装 Docker Desktop 并等到 engine running
4. 安装 WSL2 Ubuntu
5. `git --version`、`python --version`、`docker version` 都要成功

本仓库 **不需要** `pip install -r requirements.txt`。Harness 本身零第三方依赖。不要为了“专业”给 `harness_mvp` 加 metasploit、pwntools、bloodhound 依赖。

### 5.3 克隆本仓库

```bash
git clone https://github.com/atp1301/xiaoxuqi.git
cd xiaoxuqi
git status
git log -1 --oneline
```

如果人类给的是 SSH 或私有仓库，用他们提供的地址。克隆后先读：

1. 本文件 `intro.md`
2. `README.md`
3. `lab/catalog.json`
4. `docs/teacher-requirements-audit.md`
5. `docs/real-lab-runbook.md`
6. `docs/exploitgym-official-check.md`

不要一上来大重构 UI、不要改 `console.css` 去“美化”。那不是这台机器的任务。

### 5.4 先证明本仓库能跑

```bash
python -m compileall -q harness_mvp lab tests
python -m unittest discover -s tests -v
python -m harness_mvp --scenario demo --target demo.local --output out-newhost-demo
python -m harness_mvp --check-labs
python -m harness_mvp --serve --port 8765
```

通过标准：

- unittest 全部 PASS。当前仓库测试文件在 `tests/`，包括 MVP、checkpoint、dashboard、ExploitGym 只读适配器、complex-web、课程对齐。数量以你跑出来的为准，不要抄旧文档里的 27 或 33。
- Demo 输出 `status=completed`，3 条训练发现，生成 JSON 和 Markdown。
- `--check-labs` 能打印 docker / local-web / complex-web / goad / exploitgym / vulhub 状态。此时 GOAD / ExploitGym 应该是 `not_configured`，这是正常的。
- 浏览器打开 `http://127.0.0.1:8765/` 能看到控制台。截图保存到 `docs/screenshots/`（自己建目录）。

如果 unittest 失败：先修本仓库在新机器上的问题，再去装外部靶场。不要带着红测试去拉 GOAD 镜像。

---

## 6. 把 Docker 靶场搞起来

Docker 是本仓库 local-web / complex-web 的正确运行方式，也是 ExploitGym 的前置。它替代不了 GOAD 的 Windows 域。

### 6.1 确认 Docker 真的可用

```bash
docker info
docker run --rm hello-world
```

必须看到 Server 版本。Windows 上如果 `docker version` 只有 Client 没有 Server，说明 Docker Desktop 没启动。

把 Docker 内存调到合理值：16 GB 主机不要给 Docker 16 GB；8 GB 给 Docker 通常够本仓库 + ExploitGym 起步。留内存给系统和以后的 VM。

### 6.2 local-web

```bash
docker compose -f lab/docker-compose.yml up -d --build
curl -sS http://127.0.0.1:18088/health
python -m harness_mvp --scenario local-web --target http://127.0.0.1:18088 --output out-local
```

通过标准：

- 1 条 `source=http-lab` 发现
- SQLite 差分验证 `verified`
- 报告里有响应摘要和 SHA-256
- 不要出现对非 loopback 的请求

对照实验（修过的版本不应再打出 proof）：

- 测试 `tests/test_mvp.py` 里已经覆盖 fixed 模式
- 不要把修复版结果和易受攻击版结果写混

跑完：

```bash
docker compose -f lab/docker-compose.yml down -v
```

### 6.3 complex-web（课程复杂网络部分，必须在这台机器复现）

```bash
docker compose -f lab/complex_web/docker-compose.yml up -d --build
docker compose -f lab/complex_web/docker-compose.yml ps
curl -sS http://127.0.0.1:18089/health
python -m harness_mvp --scenario complex-web --target http://127.0.0.1:18089 --output out-complex-web-newhost
```

通过标准（缺一条都不算过）：

- 三个容器：`edge-gateway`、`app-api`、`internal-admin`
- 只发布 `127.0.0.1:18089`，backend 网是 internal
- recon 能看到 public edge，内部 `/internal/whoami` 和 `/internal/flag` 未带会话时是 401
- SQLi 差分 verified
- 拿到 `uid=65532(labuser)`
- 读到 `FLAG{harness-complex-web-authorized-v1}` 且和 `lab/complex_web/flag.txt` 一致
- `facts.raw_http_evidence` 里有原始 URL / 响应 / SHA-256
- 报告 Markdown 有 Attack Chain Evidence

把新 run 的 JSON/Markdown 复制到 `lab/complex_web/evidence/`，文件名带新 run_id。更新 `lab/complex_web/manifest.json` 的 `last_verified_run`，写明是这台新机器、Docker 版本、时间。

然后：

```bash
docker compose -f lab/complex_web/docker-compose.yml down -v
python -m harness_mvp --check-labs
```

此时 `complex-web` 在服务关闭后可以是 `not_ready`。验收看 evidence，不看检查器在你关机后的瞬时状态。演示时再 `up`。

### 6.4 Docker 安全基线

两个 compose 已经是 `read_only`、`cap_drop: ALL`、`no-new-privileges`、只绑定 127.0.0.1。不要改成 `0.0.0.0` 发布到局域网。不要给容器 `privileged`。不要把 docker.sock 挂进靶场容器。

---

## 7. 测试：单元测试 + 压力测试

“暴力测试”在这里指 **Harness 自己的压力 / 稳定性 / 回归**，不是去爆破校园网或 GOAD 管理员密码字典打生产。对外部未授权系统做暴力破解是禁止的。

### 7.1 每次改动后必跑

```bash
python -m unittest discover -s tests -v
python -m compileall -q harness_mvp lab tests
```

现有测试已经覆盖：

- Demo 三发现
- local-web 真差分和修复版 0 发现
- complex-web 全链和修复版
- 越界目标 / 任意 shell 被拒绝
- checkpoint 恢复
- Dashboard API
- ExploitGym 只读适配器
- 七角色 + Operator 任务树
- 知识库四类 RAG

不要删这些测试来让输出变绿。

### 7.2 你要新增的压力测试

新增 `tests/test_stress.py`。用标准库 `unittest`，不要引入 pytest-benchmark 之类大依赖。建议最少包括：

1. **重复 Demo 50 次**（如果太慢可 20 次，但要在报告里写次数）：每次 `completed`、正好 3 条发现、不写到仓库 `out/` 而是临时目录。
2. **重复 local-web / complex-web 各 10 次**（可用 `running_lab()` 进程内实验室，不必每次都 docker up）：易受攻击版始终 1 条 verified；修复版始终 0 条。这是误报率证据。
3. **Dashboard 并发**：同时 POST 5 个 demo run，全部完成，run_id 不冲突，报告可读。
4. **策略拒绝压测**：循环对 `https://example.com` 和任意 shell 调用 `PolicyEngine`，必须每次 `PolicyViolation`，零漏放。
5. **checkpoint 中断恢复重复**：失败适配器中断后再 resume，run_id 不变，最终 completed。
6. **耗时记录**：把每次场景的 wall time、finding 数、event 数写到 `docs/stress-test-results.md`。

报告里至少要有这些数字（课程要测试分析）：

- 用例数、通过数、失败数
- 成功率
- 误报：修复版出现 findings 的次数，目标是 0
- 漏报：易受攻击版没找到 SQLi 的次数，目标是 0
- 平均耗时、最大耗时
- 工具调用是否越界（应该是 0）
- Docker 启停是否成功

把命令、原始输出摘要、日期、机器配置写进 `docs/test-analysis-report.md` 追加一节“新主机复测”，不要覆盖旧主机的历史，另开章节。

### 7.3 不要做的“暴力”

- 不要写 hydra / 密码喷洒去打 GOAD 之外的机器
- 不要对 ExploitGym 官方 scorer 做 fuzz 欺骗
- 不要 DDoS 本机 Docker 到死而不记录；压力测试要有上限和超时
- 不要用生产 API Key 做高压 LLM 调用把额度打光。压力测试默认 deterministic

---

## 8. ExploitGym：这是什么，怎么部署，怎么验收

### 8.1 它是什么

ExploitGym 是 UC Berkeley Sunblaze 的漏洞利用生成评测，不是 Web 靶场。任务跑在 Linux Docker 里，分 userspace / v8 / kernel。

官方仓库：https://github.com/sunblaze-ucb/exploitgym
Wiki：https://github.com/sunblaze-ucb/exploitgym/wiki
Setup：https://github.com/sunblaze-ucb/exploitgym/wiki/Setup
License：Apache-2.0，任务数据还要遵守上游许可

课程指定任务 `v8:sbxbrk/398773898` 在官方 sample 清单里。类型是 V8 内存破坏后沙箱逃逸再任意代码执行。成功标准按课程 PDF：执行 setuid-root 的 `/challenge/catflag`，读取 `/flag`。最终是否通过以官方 scorer 为准。

官方明确：环境是 Linux + Docker。Windows Docker Desktop 不是官方环境。优先在原生 Linux 或 WSL2 Ubuntu 里装。

### 8.2 本仓库已有的东西

`harness_mvp/exploitgym.py` 只做三件事：

- 读 `EXPLOITGYM_ROOT`
- 检查 `README.md` 和 `data/task_ids/v1.txt`
- 检查 task_id 格式并确认它出现在清单中

它不启动容器，不跑 payload，不联网。`status=catalog_ready` 只是清单就绪。

### 8.3 安装（只读 clone + 官方脚手架）

建议目录（不要放进本仓库里面，避免 git 子模块混乱）：

```bash
# 与 xiaoxuqi 平级
mkdir -p "$HOME/course-labs"
cd "$HOME/course-labs"
git clone https://github.com/sunblaze-ucb/exploitgym.git
cd exploitgym
```

然后在跑 Harness 的 shell 里：

```bash
# Linux / WSL
export EXPLOITGYM_ROOT="$HOME/course-labs/exploitgym"

# Windows PowerShell
$env:EXPLOITGYM_ROOT = "C:\course-labs\exploitgym"
```

回到本仓库：

```bash
python -m harness_mvp --check-labs
python -c "from harness_mvp.exploitgym import ExploitGymAdapter; import json; print(json.dumps(ExploitGymAdapter().check('v8:sbxbrk/398773898'), ensure_ascii=False, indent=2))"
```

此时允许的最好状态是 `catalog_ready` + `benchmark_status=external-benchmark-pending`。把输出保存到 `docs/exploitgym-catalog-check.md`。

第二任务必须从官方 `data/task_ids/v1.txt` 选，不要瞎编 ID。sample 里有例如：

- `userspace:oss-fuzz/329176078`
- `v8:oss-fuzz/42515594`
- `kernel:kernelctf/CVE-2023-3776_lts`

选第二任务的原则：

- 必须出现在 `v1.txt`
- 中等复杂即可，不要选你没有权限跑的 kernel 任务，除非这台机器允许特权容器并且人类确认
- 优先 userspace，成功率更高，也更能留下 scorer 证据
- 把选择理由写进 `lab/catalog.json` 的 `exploitgym-second-task`

### 8.4 官方运行（这才是课程验收）

命令以官方 README / Wiki **当场**为准。下面是 2026-09 时的常见流程，如果仓库改了，听官方的：

```bash
cd "$EXPLOITGYM_ROOT"
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
# 部分任务数据需要 GitHub 认证
gh auth login
eg-init
```

然后对两个任务分别：

```bash
eg-run --agent <官方支持的agent> --model <模型名> --task_id v8:sbxbrk/398773898 --timeout <官方建议>
eg-score
eg-run --agent <官方支持的agent> --model <模型名> --task_id <第二任务ID> --timeout <官方建议>
eg-score
```

注意：

- `--agent` / `--model` 必须用官方支持的值，不要把本仓库 Harness 硬塞进去冒充官方 agent，除非你做了明确适配并且仍走官方 scorer。
- kernel 任务可能要额外特权。能不选就不选。
- V8 任务镜像很大，先确认磁盘。C 盘只剩几十 GB 时不要拉。
- 超时、失败、镜像 pull 失败都要记录。失败不是犯罪，造假才是。

### 8.5 证据必须留下什么

每个任务一个目录，例如 `lab/exploitgym/evidence/<task_id_sanitized>/`：

```text
manifest.json          任务 ID、镜像版本、命令、时间、机器、是否 scorer 通过
scorer.txt / json      官方 scorer 原始输出
run.log                eg-run 日志摘要（去掉密钥）
trajectory             官方 trajectory，如果有
flag-evidence.txt      只写 scorer 认可的结果，不要手写假 flag
cleanup.md             用过的镜像、是否 docker prune
```

`manifest.json` 字段最少：

```json
{
  "environment_id": "exploitgym-v8-sbxbrk",
  "task_id": "v8:sbxbrk/398773898",
  "source": "https://github.com/sunblaze-ucb/exploitgym",
  "source_revision": "<git rev-parse HEAD>",
  "scope": "dedicated isolated docker",
  "start_command": "eg-init / eg-run ...",
  "success_criteria": "official scorer accepts; course: setuid-root /challenge/catflag reads /flag",
  "scorer_passed": false,
  "evidence_files": [],
  "cleanup_command": "docker image/container cleanup",
  "authorized_by": "course project owner on this host",
  "classification": "external-benchmark"
}
```

只有 `scorer_passed=true` 并且原始 scorer 输出在仓库或附件里，才能把 `lab/catalog.json` 里该条从 `external-not-configured` 改成 `external-scorer-passed`。

### 8.6 ExploitGym 和本 Harness 的边界

允许：

- 设 `EXPLOITGYM_ROOT`
- 在控制台跑只读检查
- 把 scorer 证据路径写进报告
- 在 `EnvReproAgent` / 报告里引用官方命令

不允许：

- 在 `harness_mvp/` 里实现 V8 exploit、shellcode、sandbox escape
- 把 payload 复制进 `tools.py` 当可复用武器
- 修改官方 scorer
- 没有 scorer 就改测试让它变绿

如果官方 agent 跑失败：如实记录日志、镜像版本、错误。可以换官方支持的 agent / 模型重试。不要自己手写逃逸代码塞进本仓库。人类用户如果自行在隔离环境完成，你只负责把 scorer 输出归档。

---

## 9. GOAD：这是什么，怎么部署，怎么验收

### 9.1 它是什么

GOAD = Game of Active Directory，Orange Cyberdefense 出的 Windows 域渗透实验室。它是**多台真正的 Windows 虚拟机**，不是 Docker 容器。

官方：https://github.com/Orange-Cyberdefense/GOAD
文档：https://orange-cyberdefense.github.io/GOAD/
License：GPL-3.0

课程要的是：域控 + 多个域内节点；预设漏洞；获取域管；数据获取和回传。

官方规模（以官网为准，安装前再核对）：

| 实验室 | 大约规模 | 内存经验值 | 这台机器能不能上 |
|---|---|---|---|
| GOAD 全量 | 约 5 台 Windows | 约 32 GB | 内存不够就不要装 |
| GOAD-Light | 约 3 台 | 约 24 GB | 32 GB 主机优先这个 |
| MINILAB | 约 2 台（DC + 工作站） | 约 8 GB | 16 GB 主机最多考虑这个 |

安装方式是 Vagrant + VirtualBox / VMware / Proxmox / Ludus，需要 Windows 评估版 ISO。这不是 `docker compose up`。

### 9.2 本仓库已有的东西

`check_labs()` 只检查 `GOAD_ROOT/README.md`。没有域适配器，没有自动打域。不要假装有。

### 9.3 部署前必须满足

1. 人类用户确认这台机器可以跑 Windows 评估版虚拟机（合法评估许可）。
2. 实验网络隔离：仅主机内部网 / 仅 VM 局域网。不要 NAT 到可攻击校园网的路径还不说明。
3. 磁盘：Windows ISO + 每台 VM 磁盘，预留 >= 80 GB，Light/全量更多。
4. 不要和 Docker Desktop 的 Hyper-V/WSL2 死磕。冲突时：先完成 ExploitGym 和本仓库 Docker，GOAD 换一台 Linux 主机或改用文档支持的 hypervisor。
5. 安装 VirtualBox 或 VMware、Vagrant、Git、可能还要 rsync/ansible（Linux 部署端）。Windows 官方文档要求管理员、评估 ISO、常见情况下关掉 Hyper-V。以 https://orange-cyberdefense.github.io/GOAD/installation/windows/ 和 Linux 安装页当场为准。

### 9.4 推荐安装路径

```bash
mkdir -p "$HOME/course-labs"
cd "$HOME/course-labs"
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
git rev-parse HEAD
```

然后：

```bash
export GOAD_ROOT="$HOME/course-labs/GOAD"
```

回到本仓库跑 `--check-labs`，此时可以变成 `catalog_ready`。这仍然不是课程通过。

按官方脚本安装实验室，优先：

```text
硬件够：GOAD-Light
硬件紧：MINILAB
硬件很好且时间够：再考虑全量 GOAD
```

具体命令以官方 `goad.sh` / 文档为准，典型形状类似：

```bash
./goad.sh -t install -l GOAD-Light -p virtualbox
```

不要抄过期博客。ISO 用微软评估版，不要用盗版镜像。

装完后记录：

- 每台 VM 名字、IP、角色（DC / 工作站 / 服务器）
- 域名、示例用户（用官方文档里的实验室账号，不要把密码写进 Git；可写“见官方 GOAD 文档默认凭据，已在隔离环境使用”）
- hypervisor 版本、GOAD commit
- 快照名称（装完立刻打快照，打穿后要能重置）

### 9.5 课程要你在域里证明什么

在隔离 GOAD 里做授权训练，证据放到 `lab/goad/evidence/`：

1. **资产发现**：域控、成员机、开放的管理端口（截图 + 文本，来源是实验室网段）。
2. **身份关系**：用户 / 组 / SPN / 会话等，可用官方训练工具在实验室内收集。不要把工具输出里的真实校园账号混进去。
3. **权限路径**：从普通域用户到域管的路径说明。写清用了哪些实验室预设弱点。本仓库不收武器化 exploit 源码。
4. **数据获取和回传**：在实验室内读取一个标记文件 / 官方 flag / 你放置的 `COURSE_FLAG.txt`，把内容和获取路径写入报告。回传是指把证据拿到攻击机并写入本课程报告，不是把数据外传到公网。
5. **报告**：拓扑图（可以是文本版）、时间线、成功标准对照。

如果时间不够打到域管：不要伪造。写到哪一步、卡在哪、日志是什么。假域管比没做更糟。

### 9.6 GOAD 和本 Harness 的边界

允许：

- `GOAD_ROOT` 检查
- 把实验室 IP 加入**明确的实验网白名单**之前，先得到人类确认，并写进 `lab/goad/manifest.json` 的 `scope`
- 用 Harness 写报告、存 facts、存 evidence 路径
- 如需适配器，只做只读发现（例如对实验室 jump 主机的健康检查），不要做自动 exploit 编排

不允许：

- 把 mimikatz、impacket 攻击脚本、漏洞 exploit 合进 `harness_mvp/tools.py`
- 把 GOAD 默认密码提交到 GitHub
- 从课程机去打办公室域 / 学校生产域
- 在还没隔离时执行任何域命令

### 9.7 GOAD manifest 模板

`lab/goad/manifest.json`：

```json
{
  "environment_id": "goad-light-or-minilab",
  "source": "https://github.com/Orange-Cyberdefense/GOAD",
  "source_revision": "",
  "hypervisor": "virtualbox-or-vmware-or-other",
  "lab_variant": "GOAD-Light|MINILAB|GOAD",
  "scope": ["isolated lab subnet, no campus production"],
  "nodes": [],
  "start_command": "",
  "reset_command": "restore snapshots",
  "success_criteria": [
    "dc and multiple domain nodes up",
    "asset and identity discovery recorded",
    "authorized privilege path evidence",
    "data collection and return into course report"
  ],
  "evidence_files": [],
  "cleanup_command": "vagrant halt / snapshot restore",
  "authorized_by": "course project owner",
  "classification": "external-domain-lab",
  "domain_admin_achieved": false
}
```

只有域真的起来并且有发现证据，才能改 catalog。只有域管路径和数据回传都有原始证据，才能把 `domain_admin_achieved` 设为 true。

---

## 10. 做完外部靶场后，怎么接回本仓库

不要把 GOAD / ExploitGym 源码 submodule 进 GitHub（太大，也容易把 ISO/凭据带进去）。本仓库只收：

```text
lab/catalog.json                 更新状态，诚实
lab/complex_web/evidence/        新主机 Docker 复现
lab/exploitgym/evidence/         scorer 原始输出
lab/goad/evidence/               拓扑、发现、报告，脱敏
lab/goad/manifest.json
lab/exploitgym/manifest.json
docs/new-host-hardware.md
docs/new-host-setup-log.md
docs/stress-test-results.md
docs/test-analysis-report.md     追加新主机章节
docs/real-lab-runbook.md         把“待部署”改成这台机器的真实命令
```

报告分类必须分开写：

- `simulated`：Demo、post_exploit 模拟 hop
- `local-real`：local-web / complex-web
- `external-benchmark`：ExploitGym scorer
- `external-domain-lab`：GOAD

禁止把这四类混成一句“系统已实现完整攻击链自动化打穿一切”。

环境变量不要写进源码。给人类一份 `docs/new-host-env.example`：

```text
GOAD_ROOT=
EXPLOITGYM_ROOT=
VULHUB_ROOT=
```

不要把真实路径里的密码写进去。

---

## 11. 建议工作顺序（不要并行把机器打满）

按这个顺序，完成一项勾一项：

1. 硬件评估文档
2. 安装 Git / Python / Docker
3. 克隆本仓库，unittest + Demo
4. Docker local-web 复现
5. Docker complex-web 复现 + 新 evidence
6. 新增并跑压力测试
7. clone ExploitGym，设 `EXPLOITGYM_ROOT`，catalog 检查
8. 官方 `eg-init`；先跑第二任务（userspace 更稳），再跑指定 V8 任务
9. 归档 scorer 证据
10. 只有硬件和隔离都够时才装 GOAD-Light 或 MINILAB
11. GOAD 证据和报告
12. 更新 catalog / runbook / 测试分析
13. 再跑一遍 unittest，确认你没把本仓库搞红
14. 截图：控制台、check-labs、complex-web 报告、ExploitGym scorer、GOAD 拓扑

如果时间只够做一部分：先保 complex-web 复现 + 测试 + ExploitGym 官方环境；GOAD 不要半装半卸把磁盘吃光。

---

## 12. Git 提交规则

可以提交：代码、测试、文档、脱敏 evidence、manifest。

不要提交：

- `out/`、`out-*/`、`.env`、密钥、Windows ISO、GOAD 磁盘、ExploitGym 大镜像
- `__pycache__`、venv
- 未脱敏的域哈希、凭据、screenshot 里的密码

提交信息用中文或英文都行，但要具体，例如：

```text
Add new-host ExploitGym catalog check and stress tests.
```

不要一个 commit 叫 `update` 塞进 30 个无关文件。不要改用户没让你动的 UI 大文件。

---

## 13. 给人类的汇报格式

每做完一个大项，用这种结构汇报，不要写“差不多好了”：

```text
已验证：
- 命令：
- 输出关键行：
- 证据路径：

未验证：
- ...

失败：
- 命令：
- 错误：
- 影响：
- 下一步：

仍不能宣称通过的课程项：
- ...
```

---

## 14. 最终验收清单

复制这份，做完打勾。没证据的勾无效。

本仓库

- [ ] Python 3.10+ 可用，无第三方依赖仍能启动
- [ ] `python -m unittest discover -s tests -v` 全绿
- [ ] 压力测试已跑，数字写进 `docs/stress-test-results.md`
- [ ] Demo completed，3 条 simulated findings
- [ ] 控制台 8765 可打开，有截图

Docker

- [ ] `docker version` 有 Server
- [ ] local-web 在 127.0.0.1:18088 复现 verified SQLi
- [ ] complex-web 三节点在 127.0.0.1:18089 复现
- [ ] 新机器的 flag 证据、uid=65532、raw HTTP、manifest 已更新
- [ ] compose 没有绑定 0.0.0.0

ExploitGym

- [ ] 官方仓库 clone，`EXPLOITGYM_ROOT` 已设
- [ ] `v8:sbxbrk/398773898` 出现在本地 `v1.txt`
- [ ] 第二任务 ID 来自官方清单并写进 catalog
- [ ] `eg-init` 完成
- [ ] 指定 V8 任务有官方 scorer 原始输出
- [ ] 第二任务有官方 scorer 原始输出
- [ ] 本仓库没有新增 exploit 源码
- [ ] 只有 scorer 真通过才改 catalog 状态

GOAD

- [ ] 硬件评估后选择了 Light 或 MINILAB 或明确记录“本机不可行”
- [ ] 隔离网络
- [ ] 评估版 ISO / 官方安装方式
- [ ] 域控 + 至少一个（课程要多个）域节点 running
- [ ] 资产 / 身份发现证据
- [ ] 权限路径证据或诚实的失败记录
- [ ] 数据获取回传到课程报告，没有外泄
- [ ] 凭据未进 Git
- [ ] 快照 / 重置命令写进 manifest

诚实性

- [ ] 没有用旧主机 evidence 冒充新主机
- [ ] 没有把 catalog_ready 写成 scorer 通过
- [ ] 没有扩大攻击面到公网
- [ ] README / runbook / catalog 状态一致

---

## 15. 你读完后的第一条行动

不要先改 Agent 提示词，不要先画新 UI。立刻执行：

1. 写 `docs/new-host-hardware.md`（内存、磁盘、OS、Docker、有无 VirtualBox）
2. 安装 Git / Python / Docker
3. 跑 unittest 和 Demo
4. 按第 11 节顺序继续

如果你发现本仓库测试已经是红的，先修红测试，再装靶场。

如果你发现磁盘或内存明显不够同时装 GOAD 和 ExploitGym，停止装 GOAD，把原因写进硬件文档，继续 ExploitGym 和本仓库 Docker。

现在开始第 1 步。
