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
