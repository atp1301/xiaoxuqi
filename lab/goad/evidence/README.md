# GOAD 域实验证据目录（当前为空）

日期：2026-09-10

## 这里现在是空的，因为本机没有部署 GOAD

`intro.md` 第 10 节要求本仓库收 `lab/goad/evidence/`：**拓扑、发现、报告，脱敏**。
一项都没有，因为这台机器上**不存在**该实验环境。

判定为「本机不可行」，四条独立理由（任意一条即足以否决），
完整论证见 `lab/goad/manifest.json` 与 `docs/new-host-hardware.md` 第 5 节：

| 理由 | 实测 |
|---|---|
| 没有 hypervisor | VirtualBox / VMware / Vagrant 全部未安装 |
| 装了也会冲突 | Docker Desktop 正占用 Hyper-V / WSL2 平台 |
| 内存不够 | 15.63 GiB 总量，其中 8.1 GB 已分给 Docker |
| 磁盘低于门槛 | C 盘空闲 72.3 GB < `intro.md` 第 4 节的 80 GB 底线 |

`intro.md` 第 15 节的原话是：磁盘或内存明显不够同时装 GOAD 和 ExploitGym 时，
**停止装 GOAD，把原因写进硬件文档**，继续 ExploitGym 与本仓库 Docker。
本仓库遵守了这一条。

## 不要往这里放什么

- **不要放伪造的拓扑图或"域管已拿下"的记录。** 没有域，就没有域管。
- **不要放未脱敏的域哈希、凭据、密码。** 第 3 节第 6 条与第 12 节都禁止。
  截图里带密码同样不行。
- **不要放 AD 武器化脚本。** 第 3 节第 3 条明确禁止把 AD 武器化脚本提交进本仓库。

`domain_admin_achieved` 在 `lab/goad/manifest.json` 中保持 `false`。
只有域真的起来、且有权限路径与数据回传的**原始证据**，才允许改成 `true`
（第 9.7 节）。

## 真要在别的机器上做，需要什么

1. 一台独立 Linux 主机（或能独占 Hyper-V 的机器），按官方 `goad.sh` 部署。
2. GOAD-Light 建议 ≥32 GB 内存；MINILAB 约 24 GB 起（含宿主开销）。
3. 域控 + 至少一个（课程要求多个）已入域节点处于 running 状态，且网络隔离。
4. 完成后回传：拓扑、资产/身份发现、权限路径证据或诚实的失败记录，
   **脱敏后**再放进本目录。
