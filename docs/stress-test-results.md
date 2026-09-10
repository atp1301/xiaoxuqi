# Harness 压力 / 稳定性测试结果

> 本文件由 `tests/test_stress.py` 在 `HARNESS_STRESS_WRITE_DOC=1` 时生成，
> 数字来自真实运行，不是手写。重新运行会覆盖本文件。

## 运行参数

| 项 | 值 |
|---|---|
| Demo 重复次数 | 50 |
| 每个 Web 场景重复次数 | 10 |
| Dashboard 并发数 | 5 |
| 策略拒绝压测迭代数 | 200 |
| checkpoint 恢复重复次数 | 5 |

## 总体

| 指标 | 值 | 目标 |
|---|---|---|
| 迭代数 | 97 | — |
| 通过 | 97 | — |
| 失败 | 0 | 0 |
| 成功率 | 100.00% | 100% |
| 最大单次耗时 | 0.9017s | — |
| 误报（修复版 findings 数） | 0 | 0 |
| 漏报（易受攻击版未 verified 次数） | 0 | 0 |
| 越界工具调用放行次数 | 0 | 0 |
| 策略拒绝实际检查次数 | 5000 | — |
| 应有记录却缺席的场景 | 无 | 无 |
| unittest 结论 | Ran 9 tests in 42.123s / OK | OK |

## 分场景耗时

| 场景 | 迭代 | 通过 | 失败 | 平均耗时 | 最小 | 最大 |
|---|---|---|---|---|---|---|
| checkpoint-resume | 5 | 5 | 0 | 0.1270s | 0.1256s | 0.1285s |
| complex-web-fixed | 10 | 10 | 0 | 0.4951s | 0.4583s | 0.5404s |
| complex-web-vulnerable | 10 | 10 | 0 | 0.8206s | 0.7355s | 0.9017s |
| dashboard-concurrent | 1 | 1 | 0 | 0.4488s | 0.4488s | 0.4488s |
| demo | 50 | 50 | 0 | 0.0826s | 0.0773s | 0.0903s |
| local-web-fixed | 10 | 10 | 0 | 0.1745s | 0.1158s | 0.2199s |
| local-web-vulnerable | 10 | 10 | 0 | 0.2208s | 0.1931s | 0.2660s |
| policy-soak | 1 | 1 | 0 | 0.0100s | 0.0100s | 0.0100s |

## 说明

- 全部目标都在 `PolicyEngine` 白名单内（`demo.local` / `localhost` / `127.0.0.1`），
  没有对任何非授权主机发起请求。
- Web 场景用进程内靶场（`lab.app.Handler` / `lab.complex_web.running_lab`），
  不依赖 Docker，因此本表不含 `docker compose up/down` 的耗时；
  那部分来自 compose 实测，见文末「Docker 启停实测」一节（源文件 `docs/stress-docker-evidence.md`）。
- 压力测试默认 `--mode deterministic` 语义（未配置 `HARNESS_LLM_API_KEY`），
  不会消耗任何真实模型额度。

## Docker 启停实测（本机）

日期：2026-09-10 / 主机：ASUS TUF Gaming F16 FX607JV
引擎：Docker Desktop 4.90.0 (Engine 29.7.2, linux/amd64)；端口只发布到 127.0.0.1。
计时用 bash 纳秒整数运算（本机无 `bc`）。就绪探测带重试，避免把"还没起来"误记成失败。

```text
engine=29.7.2 os=Docker Desktop mem=8125480960

=== local-web | lab/docker-compose.yml ===
$ docker compose -f lab/docker-compose.yml down -v
$ docker compose -f lab/docker-compose.yml up -d --build
up   exit=0 wall=1279 ms
ready after 1 polls (130 ms), GET / -> HTTP 200
running containers: training-web 
down exit=0 wall=3866 ms

=== complex-web | lab/complex_web/docker-compose.yml ===
$ docker compose -f lab/complex_web/docker-compose.yml down -v
$ docker compose -f lab/complex_web/docker-compose.yml up -d --build
up   exit=0 wall=2082 ms
ready after 2 polls (770 ms), GET / -> HTTP 200
running containers: app-api edge-gateway internal-admin 
down exit=0 wall=7344 ms

```
