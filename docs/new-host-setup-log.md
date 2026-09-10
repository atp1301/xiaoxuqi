# 新主机环境搭建与首次跑通记录

日期：2026-09-10
主机：ASUS TUF Gaming F16 FX607JV（Windows 11 家庭中文版 10.0.26200，i7-13650HX，15.63 GiB）
硬件评估见 `docs/new-host-hardware.md`。

本文件按 `intro.md` 第 5 节的顺序记录每一步的**实际命令与关键输出**。

---

## 1. 环境盘点（安装前）

这台机器不是空白机器，基础工具已经就绪，未重复安装：

```text
git --version      -> git version 2.52.0.windows.1
python --version   -> Python 3.14.4
docker version     -> Client 29.7.2 / Server 29.7.2 (Docker Desktop 4.90.0)
wsl -l -v          -> Ubuntu (Stopped), docker-desktop (Stopped)
```

结论：Git / Python 3.10+ / Docker 均已满足 `intro.md` 第 5.1–5.2 节要求，跳过安装。
未安装且**本机不需要**：Vagrant、VirtualBox、VMware、gh（GOAD 已判定不可行，见硬件文档第 5 节）。

Python 版本注意：盘点时本机为 **3.14.4**，高于课程要求的 3.10+。仓库零第三方依赖，实测可直接运行。
（该版本后来不足以跑 ExploitGym，见下面第 6 节，已补装 3.13。）

## 6. 补装 Python 3.13 与 uv（为了 ExploitGym 的 `requires-python`）

ExploitGym 的 `pyproject.toml` 声明 `requires-python = ">=3.12,<3.14"`，
而盘点时宿主与 WSL 都只有 **3.14.4**，超出上界；两处也都没有 `uv`。
本次补装，**采用并行安装而非替换**：仓库已归档的全部证据（压力报告、
complex-web 的 `cf386e367e8b`）都产自 3.14.4，替换默认解释器会让基线失去可复现性。

```text
# 1) 宿主：winget 并行装 3.13.15
$ winget install --id Python.Python.3.13 --exact --scope user ...
已成功安装
$ py -0p
 -V:3.14          ...\Python314\python.exe
 -V:3.13          ...\Python313\python.exe      <- 新增
 -V:3.10          ...\Python310\python.exe

# 2) 先在 3.13 上验证仓库，确认无回归，再切换默认
$ py -3.13 -m unittest discover -s tests
Ran 50 tests in 64.033s
OK

# 3) 设默认：用户级 PY_PYTHON=3.13（安装器已把 Python313 写到 PATH 之前）
$ python -VV     -> Python 3.13.15
$ py -V          -> Python 3.13.15

# 4) uv：宿主
$ winget install --id astral-sh.uv --exact ...
$ uv --version   -> uv 0.12.12

# 5) uv：WSL（官方独立安装脚本；Ubuntu 26.04 自带 python3 无 pip）
$ wsl ... curl -LsSf https://astral.sh/uv/install.sh | sh
$ wsl ... uv --version -> uv 0.12.12        # ~/.local/bin 已在登录 PATH 上

# 6) WSL：uv 托管的独立 CPython 3.13.15，不动 /usr/bin/python3
$ wsl ... uv python install 3.13
Installed Python 3.13.15 in 2.89s
$ wsl ... python3.13 -VV -> Python 3.13.15
```

**验证（决定性）** —— 让 `uv` 在官方仓库里按 `requires-python` 自行解析：

```text
$ cd /mnt/f/course-labs/exploitgym && uv python find      # WSL
/home/zjr/.local/share/uv/python/cpython-3.13-linux-x86_64-gnu/bin/python3.13

$ uv python find                                          # Windows 宿主
C:\Users\35148\AppData\Local\Programs\Python\Python313\python.exe
```

两处都在 `[3.12,3.14)` 区间内，ExploitGym 的 Python 版本阻塞消除。

**刻意没做的两件事：**

1. **WSL 的 `/usr/bin/python3` 保持 3.14.4 未动。** 覆盖 Ubuntu 的系统 `python3`
   会影响 apt 等系统组件；3.13 只以 `python3.13` 形式存在，用 `uv` 调度即可。
2. **没删 Windows 安装器写进 PATH 的 `Python313\Lib` 与 `Python313\libs`。**
   这两条是无用项（目录不该上 PATH），但清理需改机器级 PATH，风险大于收益；
   它们不改变 `python` 的解析结果。

**仍然阻塞的**：ExploitGym 官方评测还缺服务商 API Key，见
`docs/exploitgym-official-check.md` 第 2.4 节。本次只解除了环境层面（Python + uv）的阻塞。

## 2. 阻塞事件：火绒把仓库源文件当病毒隔离（已解决）

### 现象

`python -m unittest discover -s tests -v` 首次运行 **7 个测试全部 error**：

```text
ModuleNotFoundError: No module named 'harness_mvp.knowledge'
```

`git status` 显示 `harness_mvp/knowledge.py` 被删除，但 `git log` 里该文件确实存在。

### 定位过程

| 实验 | 结果 |
|---|---|
| `git checkout -- harness_mvp/knowledge.py` 恢复 | 文件回来，16292 字节 |
| `python -c "print(1)"` 后再看 | 文件**还在** |
| `python -c "open('harness_mvp/knowledge.py').read()"` | `OSError: [Errno 9] Bad file descriptor`，随后文件**消失** |
| 同内容复制为 `zz_copy.py`（同目录） | 同样被删 |
| 同内容复制到 `%TEMP%\zz_outside.py` | 同样被删 |
| 读取 `harness_mvp/tools.py`（内容不同） | 正常，不受影响 |

结论：**按内容触发的隔离，与文件名、所在目录无关**。100% 可复现。

### 物证

```text
C:\ProgramData\Huorong\Sysdiag\Quarantine\45C101C7116D8DC56715C25A0DA7E0FAC06BCE52
  创建时间: Sep 10 15:03   ← 正是文件消失的时刻
  大小:     16308 字节
  同目录其余条目创建时间均为 Apr 18 2025
```

哈希比对（决定性证据）：

```text
knowledge.py (工作区 CRLF 形态) 的 SHA-1 = 45c101c7116d8dc56715c25a0da7e0fac06bce52
火绒隔离区条目文件名                    = 45C101C7116D8DC56715C25A0DA7E0FAC06BCE52
```

**完全一致。** 工作区文件 16292 字节 + 16 字节隔离容器头 = 16308 字节，也吻合。

### 排除其他嫌疑

- Windows Defender：`AntivirusEnabled=False`、`AMServiceEnabled=False`、无特征库 —— 已禁用，不是它。
- McAfee：`SecurityCenter2` 有注册项，但**无进程、无服务、无安装目录** —— 卸载残留，不是它。
- 火绒 `HipsDaemon` / `HipsTray`（`C:\Program Files\Huorong\Sysdiag`）确认在运行。

### 处置

`knowledge.py` 内含 Log4j / JNDI / CVE 教学词条，触发火绒启发式规则，属**误报**。

由人类用户将 `E:\Desktop\xxq\xiaoxuqi` 加入**火绒「信任区」**。验证：

```text
python -c "open('harness_mvp/knowledge.py',encoding='utf-8').read()"
-> READ OK - len= 16060     文件存活
```

**未丢失任何数据**：全程可用 `git checkout` 从 git 对象库恢复。

> 后续影响：这台机器上所有 Python 文件 I/O 都会先过火绒过滤驱动，实测使 Demo 运行从 ~0.6s 拉长到 0.7–2.0s，并偶发更高（见第 4 节与 `stress-test-results.md`）。

## 3. 测试基线（红 → 绿）

修好隔离问题后：

```bash
python -m compileall -q harness_mvp lab tests     # 退出码 0
python -m unittest discover -s tests -v
```

第一次结果：**41 个测试，40 通过，1 失败**。

```text
FAIL: test_post_is_queued_then_completes_and_report_is_readable (test_dashboard.DashboardTests)
AssertionError: 'running' != 'completed'
```

### 这是环境速度问题，不是功能缺陷

- 该测试最多轮询 `40 × 0.05s = 2 秒`；本机上一次 Dashboard 后台 Demo 运行实测耗时 **1.85s / 4.20s / 2.15s**（三次），稳定超过 2 秒预算。
- 把轮询上限放宽后，运行**确实到达 `completed` 且 findings=3**：

```text
trial 0: status=completed findings=3 elapsed=1.85s
trial 1: status=completed findings=3 elapsed=4.20s
trial 2: status=completed findings=3 elapsed=2.15s
```

- cProfile 显示运行本体仅 **0.591 秒**，其中 0.28s 花在 23 次 checkpoint 的 `fsync` 上。进程启动 ~90ms。多出来的时间来自火绒对每次文件落盘的重新扫描。

### 改动（只放宽等待，不动断言）

`tests/test_dashboard.py` 新增 `wait_for_run(run_id, timeout=30.0)` 辅助方法，两个轮询型用例改用它。

**没有修改任何断言。** `assertEqual(state["status"], "completed")`、`len(state["findings"]) == 3`、报告可读性检查全部原样保留 —— 放宽的只是"等多久"，不是"要求什么"。这不是为了让输出变绿而放水：运行必须真的完成且产出 3 条发现，测试才会通过。

改动后：

```text
Ran 41 tests in 72.496s
OK
```

另注：完整套件偶发一次 `ConnectionAbortedError: [WinError 10053]`（HTTP 连接被宿主软件中止），重跑不复现。疑与火绒网络过滤驱动（`bin/hrndis`）有关，已记录为已知偶发项，不掩盖。

## 4. Demo 与 check-labs

```bash
python -m harness_mvp --scenario demo --target demo.local --output out-newhost-demo
```

```json
{
  "run_id": "d8cd9c7dcbfd",
  "status": "completed",
  "findings": 3,
  "reports": {
    "json": "out-newhost-demo\\d8cd9c7dcbfd.json",
    "markdown": "out-newhost-demo\\d8cd9c7dcbfd.md"
  }
}
```

符合 `intro.md` 第 5.4 节通过标准：`status=completed`、3 条发现、JSON + Markdown 都生成。

```bash
python -m harness_mvp --check-labs
```

```text
docker         ready            server 29.7.2
local-web      not_ready        <urlopen error timed out>
complex-web    not_ready        <urlopen error timed out>
goad           not_configured   GOAD_ROOT is not set
exploitgym     not_configured   EXPLOITGYM_ROOT is not set
vulhub         not_configured   VULHUB_ROOT is not set
```

`goad` / `exploitgym` / `vulhub` 此时为 `not_configured`，与 `intro.md` 第 5.4 节预期一致。
`local-web` / `complex-web` 的 `not_ready` 是因为容器尚未启动，下一步处理。

## 5. Docker 引擎

首次 `--check-labs` 时 Docker Desktop 的 Linux 引擎未运行：

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

启动 Docker Desktop 后：

```text
docker info --format 'Server={{.ServerVersion}} Mem={{.MemTotal}} NCPU={{.NCPU}} OS={{.OperatingSystem}}'
Server=29.7.2 Mem=8125480960 NCPU=20 OS=Docker Desktop
```

```text
docker run --rm hello-world
Hello from Docker!
This message shows that your installation appears to be working correctly.
```

Server 端确认可用（不只是装了 Client）。

注意这里记录的是 `NCPU=20`。**该值后来成了事故伏笔** —— 见第 7 节。

---

## 7. 事故：WSL2 内存上限把整个 VM 卡死（已解决）

**日期**：2026-09-10
**触发**：ExploitGym 官方 `scripts/setup/setup_data.sh` 编译 Node 22.21.0。

### 现象

构建启动约 20 分钟后，一切与 WSL 相关的操作同时失效：

```text
$ wsl.exe -d Ubuntu -- echo hi
wsl: 检测到 localhost 代理配置，但未镜像 WSL。NAT 模式下的 WSL 不支持 localhost 代理。
由于连接方在一段时间后没有正确答复或连接的主机没有反应，连接尝试失败。
错误代码: Wsl/Service/0x8007274c
```

- `wsl.exe -e bash -lc ...`、`-e /bin/sh -c ...`、直接 `-e /bin/echo` **三种调用全部同样超时**
- Windows 侧 `docker ps` / `docker info` **也超时**
- 但 `wsl --status` 与 `wsl --list --running` **正常应答**，Ubuntu 显示为"运行中"

> **教训**：`--list --running` 说"运行中"**不等于**该发行版可用。
> 判断可用性要看能不能真正 spawn 出进程，不是看状态页。

### 定位

```text
宿主 vmmemWSL = 7,792,784 K  ≈ 7.43 GiB
宿主总内存    = 15.63 GiB
```

**7.43 ≈ 15.63 的一半** —— 命中 WSL2 的默认上限（物理内存的 50%）。
连续采样 6 次，该值稳定在 7,79x,xxx K **几乎完全不动**：
不再增长也不再回落，正是"A 卡在天花板上"的特征（对比第 7 节末尾修复后
的健康读数，是 5.1 → 6.5 GB 来回波动的）。

同时宿主空闲内存掉到 **1.07 GiB**。

脚本里写死的是 `make -j"$(nproc)"`。事故当时容器内 `nproc` 为 **20**
（见第 5 节），即 20 路并行编译 V8 + ICU，每个编译单元约 1–2 GB —— 需求量
远超 7.8 GiB 上限，于是内核反复回收页面，VM 失去响应。

### 排除项

- **不是代理问题。** 那条 `localhost 代理` 警告只是警告：v2rayN 设置了 WinINET
  系统代理（`ProxyEnable=1`, `ProxyServer=127.0.0.1:10808`），WSL2 检测到但
  NAT 模式无法镜像它。实测 `HTTP_PROXY` / `HTTPS_PROXY` 在 User/Machine/Process
  三个作用域**都未设置**，也没有 `.wslconfig` 代理段。且 `wsl --status`
  在同样的代理设置下能正常应答。**这条警告会与健康会话共存，不要追它。**
- **不是构建脚本 hang。** `data/runtime/node/` 始终为空，且 VM 内存平线，
  说明是资源耗尽而非逻辑死锁。

### 处置

`wsl --shutdown`（**这会一并杀掉 Docker Desktop 的引擎发行版**）后写入
`C:\Users\35148\.wslconfig`：

```ini
[wsl2]
memory=10GB
swap=8GB
processors=6

[experimental]
autoMemoryReclaim=gradual
```

**`processors=6` 才是真正的限流杠杆。** 因为脚本写死 `make -j"$(nproc)"`，
在容器上打 `--cpus` 只约束 cgroup 配额，容器内 `nproc` 仍会读到满额；
只有压低 VM 可见的 CPU 数，`nproc` 才会跟着变小，`make -j` 才真的被限住。

### 恢复后的验证

```text
$ wsl -d Ubuntu -e /bin/sh -c 'nproc; ...'
nproc     = 6
MemTotal  = 10185332 kB      # ≈ 9.7 GiB
SwapTotal = 8388608 kB       # 8 GiB
```

构建重启后 **VM 内部**读数：

```text
               total        used        free      shared  buff/cache   available
Mem:            9946        1034        5198          54        3967        8912
Swap:           8192           0        8192
```

**可用 8.9 GiB，swap 使用 0** —— 绰绰有余，事故未重演。
`setup_data.sh` 对已存在的 gdb/nc/socat 正确输出 `(already exists, skipping)`，
所以重跑不必重新编译这三个，只重做 Node 一步。

### 两个附带的坑

1. **`wsl --shutdown` 之后 Ubuntu 里的 `docker` 命令会消失**，报
   `The command 'docker' could not be found in this WSL 2 distro` ——
   Docker Desktop 还没重新注入 WSL 集成。用 `docker desktop start` 拉起引擎
   （提示 `Docker Desktop is already running`，但 15 秒后 server 就回来了），
   镜像与 `data/runtime/` 下的既有产物**都不会丢**。
2. **Git Bash 会改写传给 `wsl.exe` 的绝对路径**：`-e /bin/sh` 被转成
   `C:/Program Files/Git/usr/bin/sh`，报 `execvpe(...) failed: No such file or directory`。
   调用前 `export MSYS_NO_PATHCONV=1` 即可。

### 处置结果：构建跑完

重启后重跑，`setup_data.sh` 约 4800 s 后**正常结束**，产物齐全：

```text
gdb          17.1
Node.js      v22.21.0   （alpine:3.20 内 --fully-static 静态构建）
codex-cli    0.120.0
gemini-cli   0.37.2
claude-code  2.1.119    （见下方"第三处偏离"）
```

随后 `bash scripts/setup/validate.sh` 报 **All 7 checks passed**
（gdb / nc / node / claude-code / codex / gemini-cli / socat）。

> 计数小坑：想数编译产物文件数时不能从 WSL 的 shell 去数 `/tmp` ——
> 真正的编译发生在 `docker run --rm alpine:3.20` **容器内**，
> 容器的 `/tmp` 和 WSL 的 `/tmp` 不是同一个。要看得 `docker exec` 进容器。

### 第三处偏离：`claude-code` 的 postinstall 连环失败（有意为之，如实记录）

`codex-cli` 与 `gemini-cli` 安装顺利，`claude-code@2.1.119` 失败，
原因是**上游脚本自带的两个缺陷连环**，不是本机环境问题：

1. `npm error code 127 / sh: 1: node: not found` —— 安装脚本把刚构建好的 node 放在
   `bin/` 下，却**没有把该目录加入 npm 生命周期脚本的 PATH**。
2. 补上 PATH 后仍失败：`install.cjs` 从 **node 二进制**（musl 静态构建）推断 libc，
   索要 `...-linux-x64-musl`；而 npm 从**宿主 libc**（glibc）解析 `optionalDependencies`，
   装的是 `...-linux-x64`；手动补装 musl 包被 npm 直接拒绝
   `EBADPLATFORM ... wanted {"libc":"musl"} (current: {"libc":"glibc"})`。
   两边永远谈不拢。用 `--libc=musl` 骗过去也不行，装出来的二进制要
   `/lib/ld-musl-x86_64.so.1`，glibc 宿主上不存在。

**处置**：装 **glibc 版**，把它的 245230208 字节原生二进制覆盖到那个 500 字节的报错存根
`bin/claude.exe` 上；脚本在失败点之前就中止了、没生成 `claude-code.sh`，
故按其自身 `write_launcher` 模板（`bin_name=claude`）逐字重建。

**选 glibc 的判据**：真正的运行环境是 cybergym 任务容器，不是本机 ——
容器是 Ubuntu 16.04.7 / glibc 2.23，glibc 版两处都能跑，musl 版两处都跑不起来。
实测确认容器内 `node v22.21.0` / `codex-cli 0.120.0` / `claude 2.1.119` /
`gemini 0.37.2` **四个都可执行**。

**边界**：这是**对官方脚本的一次有意偏离**，只影响 `--agent claude_code` 是否可选，
**不改变评分逻辑**；`--agent codex` 未作任何修补。完整分析见
`docs/exploitgym-official-check.md` 第 2.7 节。
