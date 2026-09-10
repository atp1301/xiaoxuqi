# 证据截图目录

日期：2026-09-10 / 主机：ASUS TUF Gaming F16 FX607JV

## 重要说明：本目录里是**文本抓取**，不是图片截图

生成这些文件的是命令行 agent，**没有能力**截取浏览器或终端窗口的图片。
与其放 `[截图占位]` 或伪造 PNG，这里放的是**真实命令输出的原样文本抓取**，
命名后缀统一为 `.txt`，避免被误认成图片证据。

需要真正的图片时，请人类用户在本机执行对应命令后自行截屏。

## 本目录内容

| 文件 | 内容 | 来源命令 |
|---|---|---|
| `01-check-labs.txt` | 两个本地靶场**未启动**时的就绪检查（`not_ready` / `not_configured`） | `python -m harness_mvp --check-labs` |
| `02-check-labs-ready.txt` | 两个靶场**已启动**时的就绪检查（`ready` / `catalog_ready`） | 同上，前置 `docker compose up -d --build` |
| `03-console.txt` | Web 控制台：提交运行、轮询到 `completed`、读取报告 | `python -m harness_mvp --serve --port 8765` + HTTP 调用 |
| `04-complex-web-report.txt` | complex-web 全链：差分、SHA-256、`uid=65532(labuser)`、flag | `python -m harness_mvp --scenario complex-web` |

## 明确**没有**的两项（以及原因）

| 缺的东西 | 原因 |
|---|---|
| ExploitGym 官方 scorer 截图 | **本机没有跑出任何 scorer 输出**。阻塞原因见 `docs/exploitgym-official-check.md`：官方要求 Python `>=3.12,<3.14`（本机宿主与 WSL 均为 3.14.4）、缺 `uv`、缺服务商 API Key。**没有的东西不画。** |
| GOAD 域拓扑截图 | **本机未部署 GOAD**（无 hypervisor、Docker 已占 Hyper-V/WSL2、内存与磁盘不足）。见 `lab/goad/manifest.json`。 |

这两项属于 `intro.md` 第 3 节定义的"不算做完"，本仓库如实保持为未通过状态。

## 复核方式

```bash
# 01 / 02
EXPLOITGYM_ROOT=F:/course-labs/exploitgym python -m harness_mvp --check-labs

# 03（另开一个终端执行）
python -m harness_mvp --serve --port 8765
#   浏览器打开 http://127.0.0.1:8765

# 04（需要先启动靶场）
docker compose -f lab/complex_web/docker-compose.yml up -d --build
python -m harness_mvp --scenario complex-web --target http://127.0.0.1:18089 --output out-complex-web-newhost
docker compose -f lab/complex_web/docker-compose.yml down -v
```
