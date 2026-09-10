# 按课程要求的 GitHub 项目审计

审计日期：2026-09-08

课程依据：`2026网络空间安全课程设计-new(1).pdf` 第 3–4 页第 2 题。老师要求的是“面向完整攻击链智能构建的多 Agent 分工协作 Harness 系统”，并明确要求三类靶场测试。这里的 Harness 指统一管理 Agent、状态、工具和执行边界的运行框架。

## 老师要求拆解

| 要求 | 必须出现的证据 | 可参考 GitHub 项目 | 当前 MVP |
|---|---|---|---|
| 侦察、漏洞利用/验证、后渗透等职责分工 | 每个角色有独立输入、输出、权限和可审计结果 | [pentestagent](https://github.com/GH05TCREW/pentestagent)、[pentestcode](https://github.com/s0ld13rr/pentestcode)、[Zen-Ai-Pentest](https://github.com/SHAdd0WTAka/Zen-Ai-Pentest) | 已有 Recon/Vuln/Exploit/Report 四角色；后渗透、代码审计、环境调试角色尚未接入 |
| Plan-and-Execute + ReAct | 有任务计划；每次工具观察都更新状态并决定下一步 | [pentestagent](https://github.com/GH05TCREW/pentestagent)、[PentestGPT](https://github.com/GreyDGL/PentestGPT) | 已有固定计划、事件和有限重试；还不是模型驱动的动态重规划 |
| 状态化任务树与共享进度 | 任务节点、依赖、历史动作、发现、检查点可恢复 | [pentestcode](https://github.com/s0ld13rr/pentestcode)、[pentestagent](https://github.com/GH05TCREW/pentestagent) | 有 facts/findings/events，并已增加带 schema 的 checkpoint，可在进程重启后恢复；尚无并发任务树 |
| 失败恢复 | 失败日志、替代步骤、重试上限、恢复后的继续执行证据 | [pentestagent](https://github.com/GH05TCREW/pentestagent) | 有每步最多两次重试和失败记录；没有靶场快照/替代工具策略 |
| 知识增强 | CVE、TTP、Payload、成功案例检索记录 | [pentestagent](https://github.com/GH05TCREW/pentestagent)、[VulnBot](https://github.com/KHenryAegis/VulnBot) | 有本地轻量检索和 CWE 关联；没有向量库和真实数据集 |
| 沙箱验证 | 工具在隔离环境执行，保存可复核的验证结果 | [pentestagent](https://github.com/GH05TCREW/pentestagent)、[Zen-Ai-Pentest](https://github.com/SHAdd0WTAka/Zen-Ai-Pentest) | local-web 已有受限 SQLite 半真实验证；仍没有课程要求的 GOAD/ExploitGym Docker/VM 沙箱 |
| Windows 域靶场 | 域控 + 多个域内节点；能展示权限获取、数据获取和回传 | [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | 未搭建，不能宣称达标 |
| ExploitGym 两个靶场 | 下载并运行两个任务；其中包括指定 ID；以任务成功标准验收 | [ExploitGym](https://github.com/sunblaze-ucb/exploitgym) | 未下载、未运行、未验证；不能宣称达标 |
| 指定 ExploitGym 任务 | `v8:sbxbrk/398773898`，成功标准是按课程说明取得目标结果 | [ExploitGym sample task list](https://raw.githubusercontent.com/sunblaze-ucb/exploitgym/main/data/task_ids/sample.txt) | 已核对官方 sample 列表包含该 ID，但本项目没有执行它 |
| 复杂网络靶场 | 在自建或已有复杂环境中完成自动渗透并保留证据 | [Vulhub](https://github.com/vulhub/vulhub)、[Argus Benchmarks](https://github.com/pensar-x/argus-validation-benchmarks) | 未接入真实靶场，不能宣称达标 |
| 测试分析与可重复性 | ground truth、成功率、误报率、耗时、工具调用和复测结果 | [Argus Validation Benchmarks](https://github.com/pensar-x/argus-validation-benchmarks)、[OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness)、[HackSynth](https://github.com/aielte-research/HackSynth) | 只有 Demo 单测和压力测试，缺少真实靶场指标 |

## 最贴合老师要求的组合

不是把某个仓库整体复制过来，而是组合三个层次：

```text
你的 Harness（编排、状态、权限、报告）
  + GOAD（Windows 域环境）
  + ExploitGym（V8/userspace/kernel 两个任务）
  + Vulhub 或 Argus（复杂 Web/网络环境）
  + OWASP/Argus 风格的 trace、ground truth 和评分
```

这套组合和老师的原文一一对应。`GOAD` 是 GPL-3.0；`ExploitGym` 是 Apache-2.0，但其任务数据还要遵守上游数据许可；`Vulhub` 是 MIT；`Argus` 和 OWASP Harness 是 Apache-2.0。接入时要保留许可并单独核对数据许可。

## 当前项目的真实结论

当前项目符合老师要求中的“设计与原型”部分：角色边界、编排、状态记录、失败重试、知识关联、报告和安全范围控制已经能演示。

当前项目不符合老师要求中的“完整测试验收”部分：三类真实靶场都未接入，Exploit 阶段仅在本地训练服务完成半真实验证；外部靶场尚未验收，checkpoint 恢复已实现，也没有真实 benchmark 结果。因此 PPT 或报告中应写成“已完成 Harness MVP，真实靶场适配与验收进行中”，不要写成“已完成老师要求的三类环境测试”。

## 补齐验收的最短路径

1. 先用 Vulhub 建一个可重置的本地 Web 靶场，将 `DemoLabAdapter` 替换为 `LabAdapter`，记录原始请求/响应和复现步骤。
2. 在独立主机或虚拟化环境部署 GOAD-Light/MINILAB，先只证明资产发现、身份关系和授权范围内的验证记录；不要把域环境暴露到公网。
3. 按 ExploitGym 官方 setup 文档运行两个任务：指定 `v8:sbxbrk/398773898` 加一个第二任务。只使用官方 scorer/flag 作为成功判据，不把“模型说成功”当作证据。
4. 为三个环境各写一份 manifest：目标、版本、启动命令、重置命令、成功标准、证据文件和清理命令。
5. 用 Argus/OWASP 风格输出每次运行的 trace 和评分：是否越界、是否调用禁止工具、是否达到 ground truth、耗时、失败原因和报告完整度。

## 环境可行性提醒

GOAD 需要多台 Windows VM 和合法的评估授权；ExploitGym 官方安装说明要求 Docker，并建议在专用 Linux 主机运行，部分任务还涉及 GDB、静态 Node 和内核能力；Vulhub 对本地演示最容易，但单个漏洞环境不能自动证明“复杂网络靶场”已完成。三者都应在隔离、授权的实验网络中运行。

