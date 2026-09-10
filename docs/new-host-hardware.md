# 新主机硬件评估与靶场选型

日期：2026-09-10
用途：北邮《网络空间安全与信息安全》课程设计第 2 题 —— 在这台机器上补齐真实靶场。
依据：`intro.md` 第 4 节（动手前先量这台机器）。

本文件只记录**实测**结果。所有命令都在本机执行，输出为当场粘贴。

---

## 1. 基本配置

| 项目 | 实测值 |
|---|---|
| 机型 | ASUSTeK COMPUTER INC. ASUS TUF Gaming F16 FX607JV_FX607JV |
| 操作系统 | Microsoft Windows 11 家庭中文版，10.0.26200，64 位 |
| CPU | 13th Gen Intel(R) Core(TM) i7-13650HX，14 核 / 20 逻辑处理器 |
| 内存 | 16,780,480,512 字节 = **15.63 GiB** |
| Shell | Git Bash (MINGW64_NT-10.0-26200)，MSYS 3.6.5 |

原始输出：

```text
TotalPhysicalMemory : 16780480512
NumberOfCores       : 14
NumberOfLogicalProcessors : 20
Version             : 10.0.26200
```

## 2. 磁盘

```text
Name UsedGB FreeGB
C     327.7   72.3
D     290.6  133.6
E      59.3   40.7
F     452.1  479.1
```

| 盘 | 空闲 | 说明 |
|---|---|---|
| C: | 72.3 GB | 系统盘。Docker Desktop 的 WSL2 虚拟磁盘默认落在这里 |
| D: | 133.6 GB | — |
| E: | 40.7 GB | **本仓库所在盘**（`E:\Desktop\xxq\xiaoxuqi`） |
| F: | **479.1 GB** | 空闲最多，外部靶场检出与镜像数据放这里 |

## 3. 已安装工具（实测）

| 工具 | 状态 |
|---|---|
| Git | 2.52.0.windows.1 ✅ |
| Python（默认） | **3.13.15**（`...\Programs\Python\Python313`）✅ 见下 |
| Python（并存） | 3.14.4（`...\Python314`）、3.10.11（`...\Python310`）✅ |
| uv | 0.12.12 ✅（winget `astral-sh.uv`） |
| Docker Desktop | 4.90.0 (238679)，Client 29.7.2 ✅ |
| Docker Engine | 29.7.2，**Linux/amd64**，`docker info` 可连 ✅ |
| Docker 分配资源 | MemTotal 8,125,480,960 字节（8.1 GB）、NCPU 20 |
| WSL2 | Ubuntu（Stopped）、docker-desktop（Stopped）✅ 已装 |
| Vagrant | ❌ 未安装 |
| VirtualBox | ❌ 未安装（`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` 不存在） |
| VMware Workstation | ❌ 未安装（`vmrun.exe` 不存在） |
| GitHub CLI (gh) | ❌ 未安装 |

`docker run --rm hello-world` 成功（拉取 `library/hello-world` 并打印 "Hello from Docker!"），说明 Server 端真的可用，不只是 Client 装了。

## 4. 本机安全软件（重要，见 `new-host-setup-log.md` 第 2 节）

| 产品 | 状态 |
|---|---|
| 火绒安全软件 (Huorong) 6.0.11.2 | **正在运行**（`C:\Program Files\Huorong\Sysdiag`，`HipsDaemon` / `HipsTray`），实时防护开启 |
| Windows Defender | 已禁用（`AntivirusEnabled=False`、`AMServiceEnabled=False`） |
| McAfee | 仅注册表残留（SecurityCenter2 有条目，但无进程、无服务、无安装目录） |

火绒会按**内容**对文件做启发式隔离，曾把本仓库的 `harness_mvp/knowledge.py` 误判隔离（详见 setup log）。已由人类用户把仓库目录加入火绒信任区后解决。

## 5. 选型决策（依据 `intro.md` 第 4 节规则）

`intro.md` 第 4 节的判定规则：

- 内存 < 16 GB，或系统盘可用 < 80 GB → 不装完整 GOAD
- 内存 16–24 GB → ExploitGym + Docker 可尝试；GOAD 最多考虑 MINILAB，且完整 GOAD / GOAD-Light 不要硬上
- 内存 ≥ 32 GB 且磁盘 ≥ 200 GB 空闲 → 才优先 GOAD-Light
- 已有 Docker Desktop + WSL2 + Hyper-V 时，VirtualBox 版 GOAD 经常冲突 → 先做 ExploitGym 和本仓库 Docker

本机：内存 **15.63 GiB（落在 16–24 GB 区间的下沿）**，C 盘空闲 **72.3 GB（< 80 GB）**，**未安装任何 hypervisor**，且 Docker Desktop + WSL2 正在使用 Hyper-V 平台。

### 结论表

| 靶场 | 本机可行性 | 决定 |
|---|---|---|
| 本仓库 Demo / local-web / complex-web（Docker） | ✅ 可行 | **做**。Docker Server 实测可用，两个 compose 只发布 127.0.0.1 |
| ExploitGym（官方 Linux Docker） | ✅ 可行 | **做**。Docker 是官方环境要求，本机引擎为 linux/amd64 |
| GOAD 全量（约 5 台 Windows / 约 32 GB） | ❌ 不可行 | **不做**。内存不足，且无 hypervisor |
| GOAD-Light（约 3 台 / 约 24 GB） | ❌ 不可行 | **不做**。内存不足，且 `intro.md` 明确要求 32 GB 主机才优先考虑 |
| MINILAB（约 2 台，DC + 工作站 / 约 8 GB） | ❌ 本机不可行 | **不做**，原因见下 |

### 为什么不做 GOAD（任何规格）

三条独立理由，任意一条都足以否决：

1. **没有 hypervisor。** GOAD 是 Vagrant + VirtualBox/VMware 驱动的**真 Windows 虚拟机**，不是容器。本机 VirtualBox 与 VMware 均未安装。
2. **装了也会冲突。** Docker Desktop 正在占用 Hyper-V / WSL2 平台。`intro.md` 第 4 节明确指出：已有 Docker Desktop + WSL2 + Hyper-V 时 VirtualBox 版 GOAD 经常冲突，应当"先做 ExploitGym 和本仓库 Docker"。
3. **内存不够。** 本机总共 15.63 GiB，其中 8.1 GB 已经分给 Docker。MINILAB 官方经验值约 8 GB 是**给 VM 的**，叠加宿主系统与 Docker 后必然换页。同时开 GOAD + ExploitGym + Docker 大镜像正是 `intro.md` 禁止的组合。

按 `intro.md` 第 15 节："如果你发现磁盘或内存明显不够同时装 GOAD 和 ExploitGym，停止装 GOAD，把原因写进硬件文档，继续 ExploitGym 和本仓库 Docker。"

**本机对 GOAD 的处置：不安装，如实记录为"本机不可行"。** `lab/catalog.json` 中 GOAD 条目的状态保持 `external-not-configured`，不得因为"写了 manifest"或"clone 了仓库"而升级。`lab/goad/manifest.json` 会写明 `domain_admin_achieved: false` 与不可行原因。

> GOAD 要完成，需要一台独立 Linux 主机（或一台能独占 Hyper-V 的机器）按官方 `goad.sh` 部署。这台笔记本不是合适的载体。

### 磁盘规划

`intro.md` 建议把外部靶场 clone 到与仓库平级的位置。本机 C 盘仅剩 72.3 GB，而 ExploitGym 的 V8 任务镜像很大（`intro.md` 第 8.4 节明确警告"C 盘只剩几十 GB 时不要拉"）。

因此**外部靶场检出放在 F 盘**（空闲 479.1 GB），而不是默认的 `$HOME`（在 C 盘）：

```text
F:\course-labs\exploitgym
```

`EXPLOITGYM_ROOT` 指向该目录。Docker 镜像本身仍由 Docker Desktop 管理（落在其 WSL2 虚拟磁盘），拉取前会先确认 C 盘余量。

## 6. 复现本文件的命令

```bash
# 内存 / CPU / 机型
powershell.exe -NoProfile -Command "Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,TotalPhysicalMemory"

# 磁盘
powershell.exe -NoProfile -Command "Get-PSDrive -PSProvider FileSystem | Select Name,@{n='FreeGB';e={[math]::Round(\$_.Free/1GB,1)}}"

# Docker
docker version
docker info --format '{{.MemTotal}} {{.NCPU}} {{.OperatingSystem}}'

# hypervisor 有无
which vagrant VBoxManage vmrun gh
```
