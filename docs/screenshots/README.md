# 证据截图目录

建立：2026-09-10 · 更新：2026-09-11 · 主机：ASUS TUF Gaming F16 FX607JV

本目录现在有**两组**文件：2026-09-11 补上的真实 `.png` 图片，以及 2026-09-10
建立的 `.txt` 文本抓取。**两组都保留**，`.txt` 不是废料，理由见下。

## 一、图片截图（`.png`，2026-09-11）

| 文件 | 尺寸 | 内容 |
|---|---|---|
| `01-console.png` | 1440×1150 | Web 控制台首页，运行中的真实页面：运行 `af947d4d333f`、7 步任务树全部「完成」、发现 `F-001`（HIGH / CWE-89 / 99%） |
| `02-check-labs.png` | 1100×1260 | `--check-labs`：六个靶场状态，含 `exploitgym: catalog_ready` |
| `03-complex-web-report.png` | 1100×2680 | complex-web 运行报告全文（含 `uid=65532(labuser)`、`Flag match: True`、SHA-256、任务树、Agent Results） |
| `04-exploitgym-scorer.png` | 1100×1190 | ExploitGym 官方 scorer 原始输出 + 本次 `run.log` 时间窗（`total_score=0.000`） |

### 这批图是**渲染**出来的，不是照相机拍的 —— 说明白

三张里有一张是真正的**页面捕获**，另三张是**把真实输出渲染成 HTML 后截图**。
区别写在这里，免得被当成同一种东西：

| 文件 | 性质 |
|---|---|
| `01-console.png` | **真实捕获**：无头 Chrome 打开正在运行的 `http://127.0.0.1:8765/` |
| `02` / `03` / `04` | **真实输出的渲染**：内容来自命令输出、API 返回的报告、归档的原始文件，包成 HTML 再截图 |

渲染脚本 `make-pages.py`（同目录）只实现标题/列表/代码块等必要语法，
**不改写内容**；每个页面页眉都写明来源命令或 URL 与渲染时间戳，
所以任何一张都能对着源文件复核。`03` 用了 `zoom:0.8` 才让整篇进画面 ——
这是排版缩放，不是内容删减。

## 二、文本抓取（`.txt`，2026-09-10）—— 保留

| 文件 | 内容 | 来源命令 |
|---|---|---|
| `01-check-labs.txt` | 两个本地靶场**未启动**时的就绪检查（`not_ready` / `not_configured`） | `python -m harness_mvp --check-labs` |
| `02-check-labs-ready.txt` | 两个靶场**已启动**时的就绪检查（`ready` / `catalog_ready`） | 同上，前置 `docker compose up -d --build` |
| `03-console.txt` | Web 控制台：提交运行、轮询到 `completed`、读取报告 | `python -m harness_mvp --serve --port 8765` + HTTP 调用 |
| `04-complex-web-report.txt` | complex-web 全链：差分、SHA-256、`uid=65532(labuser)`、flag | `python -m harness_mvp --scenario complex-web` |

## 作废一条旧说明

本文件先前写着：

> 生成这些文件的是命令行 agent，**没有能力**截取浏览器或终端窗口的图片。

**这个前提是错的，2026-09-11 推翻。** 本机装有 Chrome，用
`--headless=new --screenshot` 可以正常出图。我先做了一次最小验证（确认能写出
一个非空的 PNG）再批量截，所以补上了上面那批图。

`.txt` 一律保留不删：它们是当时真实命令输出的抓取，记录的是 **2026-09-10 的另一次
运行**（例如 `01-check-labs.txt` 是靶场未启动、`02-check-labs-ready.txt` 是已启动），
与 `.png` 记录的那次不是同一时刻，有独立价值。

## 明确仍然**没有**的一项

| 缺的东西 | 原因 |
|---|---|
| GOAD 域拓扑截图 | **本机未部署 GOAD**（无 hypervisor、Docker 已占 Hyper-V/WSL2、内存与磁盘不足）。见 `lab/goad/manifest.json`。**没有的东西不画。** |

原表里的另一项「ExploitGym 官方 scorer 截图」已由 `04-exploitgym-scorer.png` 补上
——注意那是**得 0 分**的输出，不是通过证据，别读反了。

GOAD 这一项属于 `intro.md` 第 3 节定义的"不算做完"，仓库如实保持为未通过状态。

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

# 重新生成 02 / 03 / 04 三张图（先在仓库根目录备好 _work 下的输入，见脚本 docstring）
python docs/screenshots/make-pages.py
chrome --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
       --force-device-scale-factor=1 --window-size=1100,1260 \
       --screenshot="<绝对路径>\02-check-labs.png" file:///<绝对路径>/_work/check-labs.html
```

`_work/` 是中间目录，不提交，用完即删。
