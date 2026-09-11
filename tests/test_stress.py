"""Harness 压力 / 稳定性 / 回归测试（对应 intro.md 第 7.2 节）。

这里测的是 **Harness 自己**：重复运行是否稳定、并发是否安全、策略门是否零漏放、
checkpoint 能否恢复。它不会去"爆破"任何外部系统 —— 全部目标都落在
PolicyEngine 的 loopback 白名单内（demo.local / localhost / 127.0.0.1）。

计数可用环境变量调整，默认值即 intro.md 建议值：

    HARNESS_STRESS_DEMO_RUNS       重复 Demo 次数（默认 50）
    HARNESS_STRESS_WEB_RUNS        每个 Web 场景重复次数（默认 10）
    HARNESS_STRESS_CONCURRENT      并发 Dashboard 运行数（默认 5）
    HARNESS_STRESS_POLICY          策略拒绝压测迭代数（默认 200）
    HARNESS_STRESS_CHECKPOINT      中断恢复重复次数（默认 5）

设置 ``HARNESS_STRESS_WRITE_DOC=1`` 时，tearDownModule 会把统计写入
``docs/stress-test-results.md``；否则只把 JSON 摘要打到 stdout，让普通
``unittest discover`` 保持无副作用。所有运行产物都写临时目录，绝不碰仓库 ``out/``。
"""
from __future__ import annotations

import json
import os
import statistics
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from harness_mvp.complex_lab import ComplexWebAdapter
from harness_mvp.dashboard import MAX_ACTIVE_RUNS, DashboardHandler
from harness_mvp.models import RunStatus
from harness_mvp.orchestrator import Orchestrator
from harness_mvp.policy import PolicyEngine, PolicyViolation
from harness_mvp.tools import DemoLabAdapter, HttpLabAdapter, SafeCommandRunner
from lab.app import Handler
from lab.complex_web.server import running_lab

DEMO_RUNS = int(os.getenv("HARNESS_STRESS_DEMO_RUNS", "50"))
WEB_RUNS = int(os.getenv("HARNESS_STRESS_WEB_RUNS", "10"))
CONCURRENT_RUNS = int(os.getenv("HARNESS_STRESS_CONCURRENT", "5"))
POLICY_ITERATIONS = int(os.getenv("HARNESS_STRESS_POLICY", "200"))
CHECKPOINT_ITERATIONS = int(os.getenv("HARNESS_STRESS_CHECKPOINT", "5"))

# 每条记录 = 一次可判定成败的迭代，报告的成功率由它算出。
METRICS: list[dict[str, object]] = []

# 每个用例应当产出哪些场景的记录。若某个用例在 record() 之前就异常退出，
# 它对应的场景会整体缺席 —— tearDownModule 靠这张表把这种"静默失败"揪出来，
# 否则报告会因为"根本没记录"而显得全绿。
EXPECTED_SCENARIOS = {
    "test_repeated_demo_runs_are_stable": {"demo"},
    "test_local_web_vulnerable_is_repeatably_verified": {"local-web-vulnerable"},
    "test_local_web_fixed_never_reports": {"local-web-fixed"},
    "test_complex_web_vulnerable_is_repeatably_verified": {"complex-web-vulnerable"},
    "test_complex_web_fixed_never_reports": {"complex-web-fixed"},
    "test_dashboard_concurrent_runs_respect_the_active_limit": {"dashboard-concurrent"},
    "test_policy_rejects_out_of_scope_targets_without_leak": {"policy-soak"},
    "test_checkpoint_resume_after_transient_failure_is_repeatable": {"checkpoint-resume"},
}


def record(scenario: str, wall_s: float, findings: int, events: int, passed: bool, note: str = "") -> None:
    METRICS.append({
        "scenario": scenario, "wall_s": round(wall_s, 4), "findings": findings,
        "events": events, "passed": passed, "note": note,
    })


@contextmanager
def local_lab(fixed: bool = False):
    """在进程内起一个 local-web 靶场（等价于 lab/app.py，但不用 Docker）。"""
    previous = Handler.fixed
    Handler.fixed = fixed
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        Handler.fixed = previous
        server.shutdown()
        server.server_close()


class FlakyAdapter:
    """第一次探测抛错、之后委托给真实适配器。用来制造一次可恢复的中断。"""

    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.failures = 0

    def probe(self, target, path="/"):
        if self.failures == 0:
            self.failures += 1
            raise RuntimeError("stress: injected transient lab failure")
        return self.delegate.probe(target, path)


class StressTests(unittest.TestCase):
    # ---------- 1. 重复 Demo ----------

    def test_repeated_demo_runs_are_stable(self):
        for _ in range(DEMO_RUNS):
            with tempfile.TemporaryDirectory() as directory:
                started = time.perf_counter()
                state = Orchestrator(mode="deterministic").run(output_dir=directory)
                wall = time.perf_counter() - started
                ok = (state.status == RunStatus.COMPLETED
                      and len(state.findings) == 3
                      and Path(state.report_paths["json"]).exists()
                      and Path(state.report_paths["markdown"]).exists())
                record("demo", wall, len(state.findings), len(state.events), ok)
                self.assertEqual(state.status, RunStatus.COMPLETED)
                self.assertEqual(len(state.findings), 3)
                # 产物必须落在临时目录，绝不能污染仓库 out/
                self.assertTrue(Path(state.report_paths["json"]).is_relative_to(directory))

    # ---------- 2. local-web：易受攻击版必须命中，修复版必须零误报 ----------

    def test_local_web_vulnerable_is_repeatably_verified(self):
        with local_lab(fixed=False) as target:
            for _ in range(WEB_RUNS):
                with tempfile.TemporaryDirectory() as directory:
                    started = time.perf_counter()
                    state = Orchestrator(mode="deterministic", adapter=HttpLabAdapter()).run(target, "local-web", directory)
                    wall = time.perf_counter() - started
                    validation = state.findings[0].metadata["validation"] if state.findings else {}
                    # agents.py 把 differential 的键平铺进 validation，不是嵌套的。
                    ok = (state.status == RunStatus.COMPLETED and len(state.findings) == 1
                          and validation.get("status") == "verified"
                          and validation.get("verified") is True)
                    record("local-web-vulnerable", wall, len(state.findings), len(state.events), ok)
                    self.assertEqual(len(state.findings), 1, "漏报：易受攻击版没找到 SQLi")
                    self.assertEqual(validation.get("status"), "verified")
                    self.assertTrue(validation["verified"])

    def test_local_web_fixed_never_reports(self):
        with local_lab(fixed=True) as target:
            for _ in range(WEB_RUNS):
                with tempfile.TemporaryDirectory() as directory:
                    started = time.perf_counter()
                    state = Orchestrator(mode="deterministic", adapter=HttpLabAdapter()).run(target, "local-web", directory)
                    wall = time.perf_counter() - started
                    record("local-web-fixed", wall, len(state.findings), len(state.events), not state.findings)
                    self.assertEqual(state.findings, [], "误报：修复版仍报出 finding")

    # ---------- 3. complex-web：同上，含完整攻击链 ----------

    def test_complex_web_vulnerable_is_repeatably_verified(self):
        for _ in range(WEB_RUNS):
            with running_lab() as lab, tempfile.TemporaryDirectory() as directory:
                started = time.perf_counter()
                state = Orchestrator(mode="deterministic", adapter=ComplexWebAdapter()).run(lab.gateway_url, "complex-web", directory)
                wall = time.perf_counter() - started
                chain = state.exploit_results[0] if state.exploit_results else {}
                ok = (state.status == RunStatus.COMPLETED and len(state.findings) == 1
                      and chain.get("flag_match") is True)
                record("complex-web-vulnerable", wall, len(state.findings), len(state.events), ok)
                self.assertEqual(len(state.findings), 1, "漏报：复杂链没找到 SQLi")
                self.assertTrue(state.facts["complex_sqli_differential"]["verified"])
                self.assertTrue(chain.get("shell_obtained"))
                self.assertTrue(chain.get("flag_match"))

    def test_complex_web_fixed_never_reports(self):
        for _ in range(WEB_RUNS):
            with running_lab(fixed=True) as lab, tempfile.TemporaryDirectory() as directory:
                started = time.perf_counter()
                state = Orchestrator(mode="deterministic", adapter=ComplexWebAdapter()).run(lab.gateway_url, "complex-web", directory)
                wall = time.perf_counter() - started
                record("complex-web-fixed", wall, len(state.findings), len(state.events), not state.findings)
                self.assertEqual(state.findings, [], "误报：修复版仍报出 finding")

    # ---------- 4. Dashboard 并发 ----------

    def test_dashboard_concurrent_runs_respect_the_active_limit(self):
        """同时 POST CONCURRENT_RUNS 个运行，验证并发隔离与背压。

        控制台自身的 ``MAX_ACTIVE_RUNS`` 是**故意**设的上限，不是缺陷 ——
        所以这里断言"上限被守住"，而不是"5 个都必须收下"。为了让测试变绿去抬高
        这个上限，正是 intro.md 第 3 节禁止的"改产品迁就测试"。
        """
        findings_seen = 0
        detail = ""
        passed = False
        tmp = tempfile.TemporaryDirectory()
        previous_runs, previous_root = DashboardHandler.runs, DashboardHandler.output_root
        DashboardHandler.runs = {}
        DashboardHandler.output_root = Path(tmp.name).resolve()
        server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_port}"
        started = time.perf_counter()
        try:
            def post_run(results, index, barrier):
                barrier.wait()  # 让所有请求尽量同时发出，制造真正的并发
                body = json.dumps({"target": "demo.local", "scenario": "demo",
                                   "output": f"out{index}"}).encode()
                request = Request(base + "/api/runs", data=body,
                                  headers={"Content-Type": "application/json"}, method="POST")
                try:
                    with urlopen(request, timeout=60) as response:
                        results[index] = {"code": response.status, "body": json.loads(response.read().decode())}
                except HTTPError as exc:
                    payload = exc.read().decode()
                    exc.close()
                    results[index] = {"code": exc.code, "body": json.loads(payload)}

            results: dict[int, dict] = {}
            barrier = threading.Barrier(CONCURRENT_RUNS)
            threads = [threading.Thread(target=post_run, args=(results, i, barrier))
                       for i in range(CONCURRENT_RUNS)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=180)

            self.assertEqual(len(results), CONCURRENT_RUNS, "有并发请求没拿到响应")
            accepted = [results[i]["body"]["run_id"] for i in range(CONCURRENT_RUNS)
                        if results[i]["code"] == 202]
            rejected = [i for i in range(CONCURRENT_RUNS) if results[i]["code"] == 429]

            self.assertEqual(len(accepted) + len(rejected), CONCURRENT_RUNS,
                             f"出现了 202/429 之外的响应：{ {i: results[i]['code'] for i in results} }")
            self.assertLessEqual(len(accepted), MAX_ACTIVE_RUNS, "并发上限被突破")
            if CONCURRENT_RUNS > MAX_ACTIVE_RUNS:
                self.assertGreaterEqual(len(rejected), 1, "超出上限却没有背压，429 没触发")
            for index in rejected:
                self.assertIn("too many active runs", results[index]["body"]["error"])
            self.assertEqual(len(set(accepted)), len(accepted), "并发下 run_id 出现冲突")

            deadline, states = time.monotonic() + 180, {}
            while time.monotonic() < deadline:
                states = {rid: json.loads(urlopen(f"{base}/api/runs/{rid}", timeout=15).read().decode())
                          for rid in accepted}
                if all(item["status"] in {"completed", "failed"} for item in states.values()):
                    break
                time.sleep(0.05)

            for rid in accepted:
                state = states[rid]
                self.assertEqual(state["status"], "completed", f"{rid} 未完成")
                self.assertEqual(len(state["findings"]), 3)
                report = urlopen(f"{base}/api/runs/{rid}/report", timeout=30).read().decode()
                self.assertIn("Harness MVP Security Assessment", report)
                findings_seen += len(state["findings"])

            passed = True
            detail = f"submitted={CONCURRENT_RUNS} accepted={len(accepted)} rejected={len(rejected)}"
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            record("dashboard-concurrent", time.perf_counter() - started,
                   findings_seen, CONCURRENT_RUNS, passed, detail)
            server.shutdown()
            server.server_close()
            DashboardHandler.runs, DashboardHandler.output_root = previous_runs, previous_root
            tmp.cleanup()

    # ---------- 5. 策略拒绝零漏放 ----------

    def test_policy_rejects_out_of_scope_targets_without_leak(self):
        hostile_targets = [
            "https://example.com", "http://example.com/", "https://www.google.com",
            "http://8.8.8.8", "https://1.1.1.1", "http://192.168.1.1", "http://10.0.0.1",
            "http://172.16.5.5", "https://evil.example.org", "http://attacker.invalid",
            "https://127.0.0.1.evil.com", "http://localhost.evil.com", "https://0.0.0.0",
        ]
        hostile_commands = [
            ["bash", "-c", "id"], ["sh", "-c", "id"], ["cmd", "/c", "whoami"],
            ["powershell", "-Command", "Get-Process"], ["curl", "http://example.com"],
            ["nmap", "-sV", "127.0.0.1"], ["nc", "-e", "/bin/sh", "10.0.0.1", "4444"],
            ["python", "-c", "import os; os.system('id')"], ["python", "-m", "http.server"],
        ]
        engine = PolicyEngine()
        runner = SafeCommandRunner(engine)  # run() 先过 require_command，可验证端到端拦截
        leaks = 0
        iterations = 0
        started = time.perf_counter()
        for _ in range(POLICY_ITERATIONS):
            for target in hostile_targets:
                iterations += 1
                try:
                    engine.require_target(target)
                    leaks += 1  # 放行了就是漏放
                except PolicyViolation:
                    pass
            for command in hostile_commands:
                iterations += 1
                try:
                    runner.run(command)  # 未拦住就会真的执行，所以这里必须抛
                    leaks += 1
                except PolicyViolation:
                    pass
            # 三个 stub 工具必须始终不可执行
            for action in ("nmap_scan", "dir_enum", "command_exec"):
                iterations += 1
                try:
                    engine.require_action(action, "127.0.0.1")
                    leaks += 1
                except PolicyViolation:
                    pass
        wall = time.perf_counter() - started
        record("policy-soak", wall, 0, iterations, leaks == 0, f"iterations={iterations} leaks={leaks}")
        self.assertEqual(leaks, 0, f"策略漏放 {leaks} 次（应为 0）")

    def test_policy_still_allows_the_authorized_lab(self):
        # 拒绝压测不能把白名单本身压坏：授权目标必须仍然放行。
        engine = PolicyEngine()
        for target in ("demo.local", "http://127.0.0.1:18089", "http://localhost:18088"):
            self.assertTrue(engine.check_target(target).allowed, f"{target} 应被放行")

    # ---------- 6. checkpoint 中断恢复 ----------

    def test_checkpoint_resume_after_transient_failure_is_repeatable(self):
        for _ in range(CHECKPOINT_ITERATIONS):
            with tempfile.TemporaryDirectory() as directory:
                policy = PolicyEngine()
                flaky = FlakyAdapter(DemoLabAdapter(policy))
                started = time.perf_counter()
                first = Orchestrator(mode="deterministic", policy=policy, adapter=flaky).run(output_dir=directory)
                interrupted_wall = time.perf_counter() - started
                self.assertEqual(flaky.failures, 1, "注入的瞬时失败没有被触发")
                self.assertTrue(any(event.message == "agent failed; retrying" for event in first.events),
                                "重试没有被记录")

                checkpoint = Path(first.checkpoint_path)
                self.assertTrue(checkpoint.exists(), "中断后没有留下 checkpoint")

                started = time.perf_counter()
                resumed = Orchestrator(mode="deterministic").run(resume_from=checkpoint, output_dir=directory)
                resumed_wall = time.perf_counter() - started

                ok = (resumed.run_id == first.run_id and resumed.status == RunStatus.COMPLETED
                      and len(resumed.findings) == 3)
                record("checkpoint-resume", interrupted_wall + resumed_wall,
                       len(resumed.findings), len(resumed.events), ok,
                       f"interrupted={interrupted_wall:.2f}s resumed={resumed_wall:.2f}s")
                self.assertEqual(resumed.run_id, first.run_id, "恢复后 run_id 变了")
                self.assertEqual(resumed.status, RunStatus.COMPLETED, "恢复后没有 completed")
                self.assertEqual(len(resumed.findings), 3)
                self.assertTrue(any("restored from checkpoint" in event.message for event in resumed.events))


# ---------- 统计与报告 ----------

def _summary() -> dict[str, object]:
    by_scenario: dict[str, list[dict[str, object]]] = {}
    for item in METRICS:
        by_scenario.setdefault(str(item["scenario"]), []).append(item)

    scenarios = {}
    for name, items in sorted(by_scenario.items()):
        walls = [float(i["wall_s"]) for i in items]
        scenarios[name] = {
            "iterations": len(items),
            "passed": sum(1 for i in items if i["passed"]),
            "failed": sum(1 for i in items if not i["passed"]),
            "avg_s": round(statistics.fmean(walls), 4) if walls else 0.0,
            "max_s": round(max(walls), 4) if walls else 0.0,
            "min_s": round(min(walls), 4) if walls else 0.0,
            "findings_total": sum(int(i["findings"]) for i in items),
        }

    total = len(METRICS)
    passed = sum(1 for i in METRICS if i["passed"])
    max_s = max((float(i["wall_s"]) for i in METRICS), default=0.0)

    # 误报 = 修复版出现 findings 的次数；漏报 = 易受攻击版没出现 verified finding 的次数
    false_positives = sum(
        int(i["findings"]) for i in METRICS
        if str(i["scenario"]).endswith("-fixed")
    )
    false_negatives = sum(
        1 for i in METRICS
        if str(i["scenario"]) in {"local-web-vulnerable", "complex-web-vulnerable"} and not i["passed"]
    )
    leaks = sum(
        1 for i in METRICS if str(i["scenario"]) == "policy-soak" and not i["passed"]
    )

    recorded = set(by_scenario)
    expected = {name for group in EXPECTED_SCENARIOS.values() for name in group}
    missing = sorted(expected - recorded)
    # policy-soak 一条记录代表一整轮压测，真正的拒绝检查次数存在 events 里。
    policy_checks = sum(int(i["events"]) for i in METRICS if str(i["scenario"]) == "policy-soak")

    return {
        "scenarios_expected_but_not_recorded": missing,
        "policy_checks_performed": policy_checks,
        "counts": {
            "demo_runs": DEMO_RUNS, "web_runs": WEB_RUNS, "concurrent_runs": CONCURRENT_RUNS,
            "policy_iterations": POLICY_ITERATIONS, "checkpoint_iterations": CHECKPOINT_ITERATIONS,
        },
        "totals": {
            "iterations": total, "passed": passed, "failed": total - passed,
            "success_rate": round(passed / total, 4) if total else 0.0,
            "max_wall_s": round(max_s, 4),
        },
        "scenarios": scenarios,
        "false_positives_fixed_lab_findings": false_positives,
        "false_negatives_vulnerable_lab": false_negatives,
        "out_of_scope_tool_call_leaks": leaks,
    }


def _render_markdown(summary: dict[str, object]) -> str:
    counts = summary["counts"]
    totals = summary["totals"]
    missing = summary["scenarios_expected_but_not_recorded"]
    lines = [
        "# Harness 压力 / 稳定性测试结果",
        "",
        "> 本文件由 `tests/test_stress.py` 在 `HARNESS_STRESS_WRITE_DOC=1` 时生成，",
        "> 数字来自真实运行，不是手写。重新运行会覆盖本文件。",
        "",
        "## 运行参数",
        "",
        "| 项 | 值 |",
        "|---|---|",
        f"| Demo 重复次数 | {counts['demo_runs']} |",
        f"| 每个 Web 场景重复次数 | {counts['web_runs']} |",
        f"| Dashboard 并发数 | {counts['concurrent_runs']} |",
        f"| 策略拒绝压测迭代数 | {counts['policy_iterations']} |",
        f"| checkpoint 恢复重复次数 | {counts['checkpoint_iterations']} |",
        "",
        "## 总体",
        "",
        "| 指标 | 值 | 目标 |",
        "|---|---|---|",
        f"| 迭代数 | {totals['iterations']} | — |",
        f"| 通过 | {totals['passed']} | — |",
        f"| 失败 | {totals['failed']} | 0 |",
        f"| 成功率 | {totals['success_rate']:.2%} | 100% |",
        f"| 最大单次耗时 | {totals['max_wall_s']:.4f}s | — |",
        f"| 误报（修复版 findings 数） | {summary['false_positives_fixed_lab_findings']} | 0 |",
        f"| 漏报（易受攻击版未 verified 次数） | {summary['false_negatives_vulnerable_lab']} | 0 |",
        f"| 越界工具调用放行次数 | {summary['out_of_scope_tool_call_leaks']} | 0 |",
        f"| 策略拒绝实际检查次数 | {summary['policy_checks_performed']} | — |",
        f"| 应有记录却缺席的场景 | {missing or '无'} | 无 |",
        f"| unittest 结论 | {summary.get('unittest_verdict') or '（见运行日志）'} | OK |",
        "",
        "## 分场景耗时",
        "",
        "| 场景 | 迭代 | 通过 | 失败 | 平均耗时 | 最小 | 最大 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, stats in summary["scenarios"].items():
        lines.append(
            f"| {name} | {stats['iterations']} | {stats['passed']} | {stats['failed']} | "
            f"{stats['avg_s']:.4f}s | {stats['min_s']:.4f}s | {stats['max_s']:.4f}s |"
        )
    lines += [
        "",
        "## 说明",
        "",
        "- 全部目标都在 `PolicyEngine` 白名单内（`demo.local` / `localhost` / `127.0.0.1`），",
        "  没有对任何非授权主机发起请求。",
        "- Web 场景用进程内靶场（`lab.app.Handler` / `lab.complex_web.running_lab`），",
        "  不依赖 Docker，因此本表不含 `docker compose up/down` 的耗时；",
        "  那部分来自 compose 实测，见文末「Docker 启停实测」一节（源文件 `docs/stress-docker-evidence.md`）。",
        "- 压力测试默认 `--mode deterministic` 语义（未配置 `HARNESS_LLM_API_KEY`），",
        "  不会消耗任何真实模型额度。",
        "",
    ]
    return "\n".join(lines)


DOCKER_EVIDENCE = Path("docs/stress-docker-evidence.md")


def _write_doc(target: str, verdict: str = "") -> None:
    summary = _summary()
    if verdict:
        summary["unittest_verdict"] = verdict
    body = _render_markdown(summary)
    # Docker 启停耗时来自 compose 实测（本套件不碰 Docker），以伴生文件形式并入，
    # 这样重新生成报告不会把它抹掉。
    if DOCKER_EVIDENCE.exists():
        body += "\n" + DOCKER_EVIDENCE.read_text(encoding="utf-8").rstrip() + "\n"
    path = Path("docs/stress-test-results.md") if target == "1" else Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    print(f"\n[stress] wrote {path}")


def tearDownModule():
    # 注意：这里**不写文件**。普通 `unittest discover` 必须保持无副作用，
    # 否则跑一次单元测试就会改动 docs/。要生成报告请用 __main__ 入口。
    print("[stress] summary " + json.dumps(_summary(), ensure_ascii=False))


if __name__ == "__main__":
    import io
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    stream = io.StringIO()
    started = time.perf_counter()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    elapsed = time.perf_counter() - started
    sys.stdout.write(stream.getvalue())

    verdict = (f"Ran {result.testsRun} tests in {elapsed:.3f}s / "
               f"{'OK' if result.wasSuccessful() else 'FAILED'}")
    print(f"[stress] verdict {verdict}")

    doc_target = os.getenv("HARNESS_STRESS_WRITE_DOC")
    if doc_target or "--write-doc" in sys.argv:
        _write_doc(doc_target or "1", verdict)

    raise SystemExit(0 if result.wasSuccessful() else 1)
