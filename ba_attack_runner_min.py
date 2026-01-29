import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SID_RE = re.compile(r"\[\d+:(\d+):\d+\]")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def trunc(s, limit: int = 4000) -> str:
    if s is None:
        s = ""
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    else:
        s = str(s)

    return s if len(s) <= limit else s[:limit] + f"\n... (truncated {len(s)-limit} chars)"



def run_shell(cmd: str, timeout: int) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = (e.stderr or "") + "\n[timeout]"
        return 124, out, err


def fastlog_cursor(path: Path) -> tuple[int, int]:
    st = path.stat()
    return (st.st_ino, st.st_size)


def read_fastlog_delta(path: Path, cur: tuple[int, int]) -> tuple[str, tuple[int, int]]:
    """Returns (new_text, new_cursor). Handles log rotation by inode change."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return "", cur

    inode, size = st.st_ino, st.st_size
    old_inode, old_off = cur

    start = old_off if inode == old_inode else 0
    if size < start:
        start = 0

    if size == start:
        return "", (inode, size)

    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(start)
        txt = f.read()

    return txt, (inode, size)


def parse_sid_counts(text: str) -> dict[int, int]:
    counts: dict[int, int] = {}
    for line in text.splitlines():
        m = SID_RE.search(line)
        if not m:
            continue
        sid = int(m.group(1))
        counts[sid] = counts.get(sid, 0) + 1
    return counts


def as_sid_list(x) -> list[int]:
    if x is None:
        return []
    if isinstance(x, int):
        return [x]
    if isinstance(x, str):
        x = x.strip()
        return [int(x)] if x.isdigit() else []
    if isinstance(x, list):
        out = []
        for v in x:
            try:
                out.append(int(v))
            except Exception:
                pass
        return out
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", help="JSON file with attacks")
    ap.add_argument("--fastlog", default=None, help="Override fast.log path")
    ap.add_argument("--outdir", default=None, help="Output directory (default: ./attack_runs/<timestamp>)")
    ap.add_argument("--timeout", type=int, default=20, help="Default command timeout (seconds)")
    ap.add_argument("--max-log-wait", type=float, default=15.0, help="Max seconds to wait for fast.log to update")
    ap.add_argument("--poll", type=float, default=1.0, help="Polling interval for fast.log updates")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    if isinstance(cfg, list):
        attacks = cfg
        fastlog = args.fastlog or "/var/log/suricata/fast.log"
    else:
        attacks = cfg.get("attacks", [])
        fastlog = args.fastlog or cfg.get("fastlog") or (cfg.get("suricata", {}) or {}).get("fast_log") or "/var/log/suricata/fast.log"

    if not isinstance(attacks, list):
        print("Config error: attacks must be a list", file=sys.stderr)
        return 2

    outdir = Path(args.outdir) if args.outdir else Path("attack_runs") / datetime.now().strftime("%Y%m%d_%H%M%S")
    mkdir(outdir)

    runlog = outdir / "run.log"
    report_path = outdir / "run_report.json"

    def log(line=""):
        print(line)
        with runlog.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    fastlog_path = Path(fastlog)
    log(f"BA Attack Runner started: {now()}")
    log(f"Config: {cfg_path.resolve()}")
    log(f"Fastlog: {fastlog_path}")
    log(f"Outdir: {outdir.resolve()}")

    if fastlog_path.exists():
        cur = fastlog_cursor(fastlog_path)
    else:
        log(f"[WARN] fast.log not found at {fastlog_path}. Rule checks will be empty.")
        cur = (0, 0)

    results = []
    total_counts: dict[int, int] = {}

    enabled = [a for a in attacks if a.get("enabled", True)]
    log(f"Enabled attacks: {len(enabled)}/{len(attacks)}")

    for i, a in enumerate(enabled, 1):
        aid = a.get("id", f"attack-{i}")
        name = a.get("name", "")
        cmd = a.get("command", "")
        timeout = int(a.get("timeout", args.timeout))
        post_wait = float(a.get("post_wait", 2))
        expected = as_sid_list(a.get("expected_rulesid"))

        log("=" * 90)
        log(f"[{i}/{len(enabled)}] {aid} - {name}")
        log(f"Command: {cmd}")

        t0 = time.time()
        rc, out, err = run_shell(cmd, timeout=timeout)
        runtime = time.time() - t0

        if post_wait > 0:
            log(f"Post-wait: {post_wait:.1f}s")
            time.sleep(post_wait)

        frag = ""
        new_cur = cur
        if fastlog_path.exists():
            waited = 0.0
            while waited <= args.max_log_wait:
                chunk, new_cur = read_fastlog_delta(fastlog_path, new_cur)
                if chunk:
                    frag += chunk
                    break
                time.sleep(args.poll)
                waited += args.poll

        cur = new_cur
        counts = parse_sid_counts(frag)

        for sid, c in counts.items():
            total_counts[sid] = total_counts.get(sid, 0) + c

        missing = [sid for sid in expected if counts.get(sid, 0) == 0]
        passed = (len(missing) == 0)

        log(f"rc={rc} runtime={runtime:.2f}s attack_check={'PASS' if passed else 'FAIL'}")
        if expected:
            log(f"Expected SIDs: {expected}")
        log(f"Observed SIDs: {sorted(counts.keys()) if counts else '(none)'}")
        if missing:
            log(f"Missing SIDs: {missing}")

        results.append({
            "id": aid,
            "name": name,
            "command": cmd,
            "timeout": timeout,
            "post_wait": post_wait,
            "expected_rulesid": expected,
            "returncode": rc,
            "runtime_s": runtime,
            "stdout": trunc(out),
            "stderr": trunc(err),
            "observed_counts": counts,
            "pass": passed,
            "missing": missing,
        })

    fails = [r for r in results if not r["pass"]]
    summary = {
        "started_at": now(),
        "fastlog": str(fastlog_path),
        "attacks_total": len(attacks),
        "attacks_enabled": len(enabled),
        "attacks_pass": len(results) - len(fails),
        "attacks_fail": len(fails),
        "total_sid_counts": {str(k): v for k, v in sorted(total_counts.items())},
    }

    report = {
        "summary": summary,
        "attacks": results,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    log("=" * 90)
    log("SUMMARY")
    log(f"PASS={summary['attacks_pass']} FAIL={summary['attacks_fail']}")
    log(f"Artifacts: {runlog} , {report_path}")

    return 0 if not fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
