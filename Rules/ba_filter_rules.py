from __future__ import annotations

import gzip
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set, Tuple


IOT_PORTS_STRONG = {
    1883, 8883,
    5683, 5684,
    554, 8554,
    23,
    1900,
    5353,
    67, 68,
    53,
    123,
    7547,
    49000,
    3702,
}


IOT_PORTS_WEAK = {
    80, 443, 8080, 8443, 8888,  
    8899,                       
    22,                         
}



IOT_KEYWORDS = {
    "camera", "ipcam", "webcam", "nvr", "rtsp", "onvif",
    "router", "gateway", "modem", "firmware", "embedded",
    "iot", "smart home", "smarthome", "upnp", "ssdp", "mdns",
    "coap", "mqtt", "mosquitto",
    "mirai", "gafgyt", "botnet",
    "tr-064", "tr-069", "cwmp",
}


VENDOR_STACK_HINTS = {
    "hikvision", "dahua", "reolink", "axis",
    "tp-link", "tplink", "tenda", "totolink", "netgear", "d-link", "dlink",
    "xiaomi", "aqara", "sonoff", "shelly", "tuya",
    "mediatek", "busybox", "dropbear",
    "live555", "gpon",
}


RULE_ACTIONS = ("alert", "drop", "reject", "pass", "log")


_HEADER_RE = re.compile(
    r"^\s*(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src>.+?)\s+(?P<src_port>\S+)\s+"
    r"(?P<dir><-|->|<>|<->)\s+(?P<dst>.+?)\s+(?P<dst_port>\S+)\s*\(",
    re.DOTALL
)


SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)


def usage_exit() -> None:
    print("Usage: python3 filter_rules_min.py <input_dir> <output_rules_file>", file=sys.stderr)
    sys.exit(2)


def discover_rule_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for r, _, names in os.walk(root):
        for n in names:
            if n.endswith(".rules") or n.endswith(".rules.gz"):
                files.append(Path(r) / n)
    return sorted(files)


def open_text(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def is_rule_start(line: str) -> bool:
    s = line.lstrip()
    if not s or s.startswith("#"):
        return False
    return s.startswith(RULE_ACTIONS) and "(" in s


def rule_complete(chunks: List[str]) -> bool:
    text = "".join(chunks)
    depth = 0
    in_q = False
    esc = False
    saw_open = False
    for ch in text:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_q = not in_q
            continue
        if in_q:
            continue
        if ch == "(":
            depth += 1
            saw_open = True
        elif ch == ")":
            depth = max(0, depth - 1)
    return saw_open and depth == 0


def iter_rule_blocks(path: Path) -> Iterator[Tuple[str, str]]:
    pending_comments: List[str] = []
    rule_lines: List[str] = []
    in_rule = False

    with open_text(path) as f:
        for ln in f:
            s = ln.strip()

            if not in_rule:
                if not s:
                    pending_comments.append(ln)
                    continue
                if ln.lstrip().startswith("#"):
                    pending_comments.append(ln)
                    continue
                if is_rule_start(ln):
                    in_rule = True
                    rule_lines = [ln]
                    continue
                pending_comments = []
                continue

            rule_lines.append(ln)
            if rule_complete(rule_lines):
                rule_text = "".join(rule_lines)
                raw_block = "".join(pending_comments) + rule_text
                yield raw_block, rule_text
                pending_comments = []
                rule_lines = []
                in_rule = False


def extract_ports(expr: str) -> Set[int]:
    nums = set(int(x) for x in re.findall(r"\b(\d{1,5})\b", expr))
    return {n for n in nums if 0 < n < 65536}


def normalize(*parts: Optional[str]) -> str:
    return " ".join(p for p in parts if p).lower()


def classify(rule_text: str) -> bool:
    m = _HEADER_RE.match(rule_text)
    src_port = m.group("src_port") if m else ""
    dst_port = m.group("dst_port") if m else ""

    ports = set()
    ports |= extract_ports(src_port)
    ports |= extract_ports(dst_port)

    hay = normalize(rule_text)

    score = 0
    signals = 0

    strong_hits = any(p in IOT_PORTS_STRONG for p in ports)
    weak_hits = any(p in IOT_PORTS_WEAK for p in ports)

    if strong_hits:
        score += 3
        signals += 1
    elif weak_hits:
        score += 1
        signals += 1

    proto_hits = 0
    for k in ("mqtt", "coap", "rtsp", "ssdp", "upnp", "tr-069", "tr-064", "cwmp", "mdns"):
        if k in hay:
            proto_hits += 1
    if proto_hits:
        score += 2
        signals += 1

    kw_hits = sum(1 for k in IOT_KEYWORDS if k in hay)
    if kw_hits:
        score += 2
        signals += 1
        if "mirai" in hay or "botnet" in hay or "gafgyt" in hay:
            score += 2  # boost for IoT botnet relevance

    vendor_hits = sum(1 for k in VENDOR_STACK_HINTS if k in hay)
    if vendor_hits:
        score += 2
        signals += 1

    return (signals >= 2 and score >= 3) or (score >= 6)


def extract_sid(rule_text: str) -> Optional[int]:
    m = SID_RE.search(rule_text)
    return int(m.group(1)) if m else None


def main() -> int:
    if len(sys.argv) != 3:
        usage_exit()

    inp = Path(sys.argv[1]).expanduser()
    out = Path(sys.argv[2]).expanduser()

    if not inp.exists() or not inp.is_dir():
        print(f"Input directory not found: {inp}", file=sys.stderr)
        return 2

    files = discover_rule_files(inp)
    if not files:
        print(f"No .rules/.rules.gz files found in: {inp}", file=sys.stderr)
        return 2

    out.parent.mkdir(parents=True, exist_ok=True)

    seen_sids: Set[int] = set()
    total_rules = 0
    kept_rules = 0
    deduped = 0

    with out.open("w", encoding="utf-8") as out_f:
        out_f.write("# Smart-Home relevant rules (filtered)\n")
        out_f.write(f"# Input: {inp}\n")
        out_f.write("\n")

        for fpath in files:
            for raw_block, rule_text in iter_rule_blocks(fpath):
                total_rules += 1

                if not classify(rule_text):
                    continue

                sid = extract_sid(rule_text)
                if sid is not None:
                    if sid in seen_sids:
                        deduped += 1
                        continue
                    seen_sids.add(sid)

                kept_rules += 1
                out_f.write(f"# source: {fpath}\n")
                out_f.write(raw_block.rstrip("\n") + "\n\n")

    print(f"files={len(files)} total_rules={total_rules} kept={kept_rules} deduped={deduped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
