"""Render before/after coverage comparison as a sticky PR comment body.

Reads artifacts downloaded by the calling workflow:
  stats/baseline/meta.json, project.summary.json, corpus.json, harness/*.summary.json
  stats/current/ ... (same layout)

Writes the markdown body to stdout.
"""

import datetime
import json
import os
import pathlib
import sys

MARKER = "<!-- fuzz-coverage-report -->"

FOOTER_GENERIC = (
    "<sub>Per-harness data from `report_target/&lt;fuzzer&gt;/linux/summary.json`. "
    "Full HTML reports in the workflow artifacts.</sub>"
)
FOOTER_UPSTREAM = (
    "<sub>Same harness config applied to both sides "
    "(baseline = base source + PR harness). " + FOOTER_GENERIC[5:]
)


def _load_json(path: pathlib.Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def _load_variant(base: pathlib.Path) -> dict:
    harness: dict = {}
    hd = base / "harness"
    if hd.is_dir():
        for f in sorted(hd.glob("*.summary.json")):
            data = _load_json(f)
            if data is not None:
                harness[f.name.removesuffix(".summary.json")] = data
    return {
        "meta": _load_json(base / "meta.json"),
        "project": _load_json(base / "project.summary.json"),
        "corpus": _load_json(base / "corpus.json") or {},
        "harness": harness,
    }


def _totals(summary):
    if not summary:
        return None
    t = summary["data"][0]["totals"]
    return {
        "lines": (t["lines"]["covered"], t["lines"]["count"], t["lines"]["percent"]),
        "branches": (
            t["branches"]["covered"],
            t["branches"]["count"],
            t["branches"]["percent"],
        ),
        "functions": (
            t["functions"]["covered"],
            t["functions"]["count"],
            t["functions"]["percent"],
        ),
    }


def _fmt_cov(tot, key):
    if not tot:
        return "—"
    cov, n, pct = tot[key]
    return f"{pct:.1f}% ({cov}/{n})"


def _fmt_delta(b, a, key):
    if not b and not a:
        return "—"
    if not b:
        return "**new**"
    if not a:
        return "**removed**"
    d = a[key][2] - b[key][2]
    sign = "+" if d >= 0 else ""
    return f"**{sign}{d:.1f} pp**"


def render(
    stats_root: pathlib.Path,
    run_url: str,
    fuzz_seconds: str,
    now_utc: str,
    footer: str,
) -> str:
    b = _load_variant(stats_root / "baseline")
    c = _load_variant(stats_root / "current")

    b_meta = b["meta"] or {}
    c_meta = c["meta"] or {}
    b_sha_full = b_meta.get("sha") or ""
    c_sha_full = c_meta.get("sha") or ""
    b_sha = b_sha_full[:7] if b_sha_full else "unknown"
    c_sha = c_sha_full[:7] if c_sha_full else "unknown"
    project = c_meta.get("project") or b_meta.get("project") or "?"
    b_has = bool(b_meta.get("has_project"))
    c_has = bool(c_meta.get("has_project"))

    out = [MARKER, "", "## Fuzzing Coverage Report", ""]

    tested = f"**Tested:** project `{project}` · base `{b_sha}`"
    if not b_has:
        tested += " _(no baseline — project not present at base or baseline build failed)_"
    tested += f" → head `{c_sha}`"
    if not c_has:
        tested += " _(current measurement failed)_"
    tested += (
        f" · {fuzz_seconds}s total fuzz budget"
        f" · updated {now_utc}"
        f" · [workflow run]({run_url})"
    )
    out += [tested, ""]

    bt = _totals(b["project"])
    ct = _totals(c["project"])
    if bt or ct:
        out += [
            "| Metric | Before | After | Delta |",
            "|---|---|---|---|",
            f"| Line coverage | {_fmt_cov(bt, 'lines')} | {_fmt_cov(ct, 'lines')} | {_fmt_delta(bt, ct, 'lines')} |",
            f"| Branch coverage | {_fmt_cov(bt, 'branches')} | {_fmt_cov(ct, 'branches')} | {_fmt_delta(bt, ct, 'branches')} |",
            f"| Function coverage | {_fmt_cov(bt, 'functions')} | {_fmt_cov(ct, 'functions')} | {_fmt_delta(bt, ct, 'functions')} |",
            "",
        ]

    all_h = sorted(
        set(b["harness"].keys())
        | set(c["harness"].keys())
        | set(b["corpus"].keys())
        | set(c["corpus"].keys())
    )
    if all_h:
        out += [
            "### Per-harness",
            "",
            "| Harness | Lines before | Lines after | Δ | Corpus (b→a) |",
            "|---|---|---|---|---|",
        ]
        for h in all_h:
            bh = _totals(b["harness"].get(h))
            ch = _totals(c["harness"].get(h))
            bc = b["corpus"].get(h)
            cc = c["corpus"].get(h)
            bc_s = str(bc) if bc is not None else "—"
            cc_s = str(cc) if cc is not None else "—"
            out.append(
                f"| `{h}` | {_fmt_cov(bh, 'lines')} | {_fmt_cov(ch, 'lines')} | "
                f"{_fmt_delta(bh, ch, 'lines')} | {bc_s} → {cc_s} |"
            )
        out.append("")

    if not (bt or ct or all_h):
        out += [
            "_No coverage data collected. Check the workflow run for build errors._",
            "",
        ]

    out.append(footer)
    return "\n".join(out)


def main():
    stats_root = pathlib.Path(os.environ.get("STATS_ROOT", "stats"))
    run_url = os.environ["RUN_URL"]
    fuzz_seconds = os.environ.get("FUZZ_SECONDS", "300")
    footer_kind = os.environ.get("FOOTER", "generic")
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer = FOOTER_UPSTREAM if footer_kind == "upstream" else FOOTER_GENERIC
    sys.stdout.write(render(stats_root, run_url, fuzz_seconds, now_utc, footer))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
