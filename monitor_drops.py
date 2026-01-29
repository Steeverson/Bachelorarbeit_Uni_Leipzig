#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata EVE Drop Monitor (Python, no deps)
- folgt /var/log/suricata/eve.json (auch nach Logrotate)
- zeigt Delta je Stats-Event + berechnete Drops/s
- farbige Ausgabe mit Schwellwerten
"""

import argparse
import io
import json
import os
import sys
import time
from typing import Tuple

DEFAULT_EVE = "/var/log/suricata/eve.json"

ANSI_RED = "\033[0;31m"
ANSI_YEL = "\033[0;33m"
ANSI_GRN = "\033[0;32m"
ANSI_CLR = "\033[0m"

def colorize(s: str, color: str, enable: bool) -> str:
    return f"{color}{s}{ANSI_CLR}" if enable else s

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Monitor Suricata drops from eve.json (stats events).")
    p.add_argument("path", nargs="?", default=DEFAULT_EVE, help=f"Pfad zur eve.json (default: {DEFAULT_EVE})")
    p.add_argument("--warn", type=int, default=100, help="Warn-Schwelle für kernel_drops pro Intervall (Delta)")
    p.add_argument("--crit", type=int, default=500, help="Kritische Schwelle für kernel_drops pro Intervall (Delta)")
    p.add_argument("--from-start", action="store_true", help="Nicht ans Dateiende springen, sondern ab Anfang lesen")
    p.add_argument("--no-color", action="store_true", help="Farben deaktivieren")
    p.add_argument("--quiet", action="store_true", help="Kopfzeile nicht drucken")
    return p.parse_args()

def open_follow(path: str, from_start: bool) -> Tuple[io.TextIOBase, os.stat_result]:
    f = open(path, "r", encoding="utf-8", errors="replace")
    st = os.stat(path)
    if not from_start:
        f.seek(0, io.SEEK_END)
    return f, st

def rotated(old_stat: os.stat_result, path: str, f: io.TextIOBase) -> bool:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return True
    # inode oder device-Wechsel => rotiert/neu
    if st.st_ino != old_stat.st_ino or st.st_dev != old_stat.st_dev:
        return True
    # Datei wurde abgeschnitten
    try:
        if f.tell() > st.st_size:
            return True
    except Exception:
        return True
    return False

def iter_lines(path: str, from_start: bool):
    f, st = open_follow(path, from_start)
    buffer_sleep = 0.25
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        # kein neuer Inhalt
        time.sleep(buffer_sleep)
        if rotated(st, path, f):
            try:
                f.close()
            except Exception:
                pass
            # warten bis neue Datei erscheint
            for _ in range(40):  # bis ~10s
                try:
                    f, st = open_follow(path, True)
                    break
                except FileNotFoundError:
                    time.sleep(0.25)
            else:
                # weiterhin nicht vorhanden -> nochmal probieren
                continue

def extract_stats(obj: dict) -> Tuple[int, int, int]:
    """
    Gibt (kernel_drops, kernel_packets, decoder_drop) zurück.
    Fehlende Felder werden als 0 interpretiert.
    """
    s = obj.get("stats") or {}
    capture = s.get("capture") or {}
    decoder = s.get("decoder") or {}
    kd = int(capture.get("kernel_drops") or 0)
    kp = int(capture.get("kernel_packets") or 0)
    dd = int(decoder.get("drop") or 0)
    return kd, kp, dd

def main():
    args = parse_args()
    use_color = (not args.no_color) and sys.stdout.isatty()

    # Vorab prüfen
    if not os.path.exists(args.path) or not os.access(args.path, os.R_OK):
        print(colorize(f"Kann Datei nicht lesen: {args.path}", ANSI_RED, use_color), file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(colorize(f"Suricata Drop-Monitor — Datei: {args.path}", ANSI_GRN, use_color))
        print(f"Warn: {colorize(str(args.warn), ANSI_YEL, use_color)}   "
              f"Kritisch: {colorize(str(args.crit), ANSI_RED, use_color)}")
        print("Strg+C zum Beenden.")
        print("\n{:<19} {:<10} {:<10} {:<10} {:<14}".format("Zeit", "ΔDrops", "Drops/s", "ΔPackets", "decoder_drop"))

    prev_kd = prev_kp = prev_dd = 0
    have_prev = False
    prev_ts = time.time()

    try:
        for line in iter_lines(args.path, from_start=args.from_start):
            # schneller Filter: nur Zeilen mit "stats"
            if '"stats"' not in line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # nur Stats-Events verarbeiten
            if "stats" not in obj:
                continue

            kd, kp, dd = extract_stats(obj)
            now = time.time()

            if not have_prev:
                prev_kd, prev_kp, prev_dd, prev_ts = kd, kp, dd, now
                have_prev = True
                continue

            elapsed = max(1e-6, now - prev_ts)
            kd_delta = max(0, kd - prev_kd)
            kp_delta = max(0, kp - prev_kp)
            dd_delta = max(0, dd - prev_dd)
            kd_rate = kd_delta / elapsed

            # Farbe nach Schwellwert
            if kd_delta >= args.crit:
                col = ANSI_RED
            elif kd_delta >= args.warn:
                col = ANSI_YEL
            else:
                col = ANSI_GRN

            print("{:<19} {}{:<10}{} {:<10.1f} {:<10} {:<14}".format(
                time.strftime("%H:%M:%S"),
                col if use_color else "",
                kd_delta,
                ANSI_CLR if use_color else "",
                kd_rate,
                kp_delta,
                dd_delta
            ))
            sys.stdout.flush()

            prev_kd, prev_kp, prev_dd, prev_ts = kd, kp, dd, now

    except KeyboardInterrupt:
        print("\nBeendet.")

if __name__ == "__main__":
    main()
