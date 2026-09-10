#!/usr/bin/env python3
"""make-pages.py —— 把命令/报告的真实输出渲染成 HTML，供无头浏览器截图。

用法（在仓库根目录执行）：

    mkdir -p docs/screenshots/_work
    # 把三份输入准备好（内容必须是真实输出，不做任何加工）：
    #   docs/screenshots/_work/check-labs.txt  <- python -m harness_mvp --check-labs
    #   docs/screenshots/_work/report.md       <- GET /api/runs/<id>/report
    python docs/screenshots/make-pages.py
    # 再用无头 Chrome 截图 _work/*.html，命令见同目录 README.md

为什么不用 markdown 库：这台机器上没装（import markdown 直接 ModuleNotFoundError），
所以这里只实现需要的那几种语法（标题 / 列表 / 代码块 / 行内 code / 粗体）。
渲染的是**真实输出**，不做任何美化或改写；页眉会写明来源命令与生成时间，
这样截图本身是可追溯的，不会被误当成手工编的图。
"""
import html
import io
import json
import re
import sys
from datetime import datetime
from pathlib import Path

WORK = Path("docs/screenshots/_work")
OUT = WORK  # HTML 也写在这里，截图后再清理
STAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

CSS = """
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
       background: #14161a; color: #e6e8eb; }
.wrap { padding: 28px 34px; }
.bar { border-bottom: 1px solid #2b2f36; padding-bottom: 14px; margin-bottom: 22px; }
.bar h1 { font-size: 20px; margin: 0 0 6px; color: #fff; letter-spacing: .3px; }
.bar .src { font: 12px/1.7 ui-monospace, Consolas, monospace; color: #8b929c; }
.bar .src b { color: #c9d1d9; font-weight: 600; }
pre.term { margin: 0; padding: 22px 24px; background: #0d0f12; border: 1px solid #2b2f36;
           border-radius: 8px; font: 13px/1.75 ui-monospace, Consolas, "Cascadia Mono", monospace;
           color: #d6dae0; white-space: pre-wrap; word-break: break-word; }
.doc { font-size: 14px; line-height: 1.8; }
.doc h1 { font-size: 21px; color: #fff; border-bottom: 1px solid #2b2f36; padding-bottom: 10px; }
.doc h2 { font-size: 17px; color: #fff; margin-top: 28px; }
.doc h3 { font-size: 15px; color: #dbe2ea; margin-top: 20px; }
.doc ul { padding-left: 22px; }
.doc li { margin: 4px 0; }
.doc code { background: #22262d; padding: 1px 6px; border-radius: 4px;
            font: 12.5px ui-monospace, Consolas, monospace; color: #9fd0ff; }
.doc pre { background: #0d0f12; border: 1px solid #2b2f36; border-radius: 6px;
           padding: 14px 16px; overflow-x: auto;
           font: 12.5px/1.7 ui-monospace, Consolas, monospace; color: #d6dae0; }
.doc strong { color: #fff; }
"""


def page(title: str, source: str, body: str) -> str:
    return f"""<!doctype html>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{CSS}</style>
<div class="wrap">
  <div class="bar">
    <h1>{html.escape(title)}</h1>
    <div class="src">{source}<br>渲染时间 <b>{STAMP}</b> · 内容为原始输出，未经改写</div>
  </div>
  {body}
</div>
"""


def terminal(title: str, source: str, text: str) -> str:
    return page(title, source, f'<pre class="term">{html.escape(text)}</pre>')


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return s


def markdown_to_html(md: str) -> str:
    out, in_code = [], False
    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(raw))
            continue
        if not line:
            out.append("")
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            continue
        if re.match(r"^[-*]\s+", line):
            out.append(f"<li>{_inline(line[2:])}</li>")
            continue
        out.append(f"<p>{_inline(line)}</p>")

    # 把连续 <li> 包进 <ul>
    text = "\n".join(out)
    text = re.sub(r"(?:<li>.*?</li>\n?)+", lambda m: f"<ul>{m.group(0)}</ul>", text, flags=re.S)
    return text


def main() -> int:
    # 输入缺失就明确报错退出，别让截图流程拿半成品往下走。
    EV = Path("lab/exploitgym/evidence/v8_sbxbrk_398773898")
    inputs = (WORK / "check-labs.txt", WORK / "report.md", EV / "result.json", EV / "run.log.window")
    missing = [p for p in inputs if not p.is_file()]
    if missing:
        print("!! 缺少输入：", file=sys.stderr)
        for p in missing:
            print(f"   {p}", file=sys.stderr)
        print("   见本文件 docstring 的用法说明。", file=sys.stderr)
        return 1

    (OUT / "check-labs.html").write_text(
        terminal(
            "python -m harness_mvp --check-labs",
            "命令 <b>EXPLOITGYM_ROOT=F:/course-labs/exploitgym python -m harness_mvp --check-labs</b>",
            (WORK / "check-labs.txt").read_text(encoding="utf-8"),
        ),
        encoding="utf-8",
    )

    # 报告很长（7 个 agent 的结果全在里面）。整页缩放 0.8 让它一次进画面，
    # 而不是切成半截 —— 0.8 下正文字号仍有 ~11px，可读。
    report_md = (WORK / "report.md").read_text(encoding="utf-8")
    (OUT / "report.html").write_text(
        page(
            "complex-web 运行报告",
            "来源 <b>GET http://127.0.0.1:8765/api/runs/af947d4d333f/report</b>（Content-Type: text/markdown）",
            f'<div class="doc" style="zoom:0.8">{markdown_to_html(report_md)}</div>',
        ),
        encoding="utf-8",
    )

    ev = EV
    result = (ev / "result.json").read_text(encoding="utf-8")
    window = (ev / "run.log.window").read_text(encoding="utf-8")
    body = (
        f'<pre class="term">$ cat {ev}/result.json\n{html.escape(result)}\n\n'
        f"$ grep '02:5[6789]' out/run_agent/run.log   # 本次运行窗口\n{html.escape(window)}</pre>"
    )
    (OUT / "scorer.html").write_text(
        page("ExploitGym 官方 scorer 输出", "来源 <b>lab/exploitgym/evidence/v8_sbxbrk_398773898/</b>（归档原始文件）", body),
        encoding="utf-8",
    )

    print("已渲染:")
    for p in sorted(OUT.glob("*.html")):
        print(f"  {p}  ({p.stat().st_size} 字节)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
