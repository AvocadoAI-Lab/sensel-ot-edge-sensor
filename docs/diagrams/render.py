#!/usr/bin/env python3
"""Render the documentation flow diagrams to PNG (matplotlib, headless).

    python3 docs/diagrams/render.py

Diagram labels are intentionally English so they render without a CJK font.
Colour key: blue = existing, green = hardened/new, amber = evidence/storage,
grey = external.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402
from pathlib import Path  # noqa: E402

OUT = Path(__file__).resolve().parent
BLUE, GREEN, AMBER, GREY = "#cfe8ff", "#c8e6c9", "#ffe0b2", "#e0e0e0"


def _box(ax, x, y, w, h, text, fc=BLUE, fs=9, bold=False):
    ax.add_patch(
        FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=2.0",
                       lw=1.3, ec="#37474f", fc=fc)
    )
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", color="#102027")


def _arrow(ax, p1, p2, text="", fs=7, ls="-"):
    ax.add_patch(
        FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=13, lw=1.4,
                        color="#455a64", linestyle=ls, shrinkA=3, shrinkB=3)
    )
    if text:
        ax.text((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2 + 1.4, text, ha="center",
                va="bottom", fontsize=fs, color="#455a64")


def architecture():
    fig, ax = plt.subplots(figsize=(16, 8))
    ax.set_xlim(0, 164)
    ax.set_ylim(0, 92)
    ax.axis("off")
    ax.text(82, 88, "SenseL OT Edge Sensor — dual-path architecture",
            ha="center", fontsize=13, fontweight="bold")
    ax.text(82, 82, "(green = hardened components)", ha="center", fontsize=9, color="#2e7d32")

    _box(ax, 4, 38, 24, 16, "OT devices\nRelay / IED / PLC", GREY, 9, True)
    # active (telemetry) lane
    _box(ax, 40, 64, 28, 13, "EdgeX\ndevice-mqtt / modbus", BLUE, 8)
    _box(ax, 78, 64, 20, 13, "Core Data", BLUE, 8)
    # passive (security) lane — the focus of this repo
    _box(ax, 40, 12, 28, 18, "Packet Sensor\ncapture -> L2-L7 -> detect", GREEN, 8, True)
    _box(ax, 78, 15, 20, 13, "security-events\n.jsonl", AMBER, 8)
    # shared right side
    _box(ax, 106, 38, 26, 16, "SenseL Edge Agent\nbuffer + retry", BLUE, 8, True)
    _box(ax, 140, 40, 20, 13, "SenseL\nPlatform", GREY, 9, True)

    _arrow(ax, (28, 49), (40, 70), "telemetry")
    _arrow(ax, (28, 43), (40, 21), "SPAN/TAP (read-only)")
    _arrow(ax, (68, 70), (78, 70))
    _arrow(ax, (98, 70), (118, 54))
    _arrow(ax, (68, 21), (78, 21))
    _arrow(ax, (98, 21), (118, 38))
    _arrow(ax, (132, 46), (140, 46), "MQTT / HTTP")
    _arrow(ax, (54, 30), (54, 64), "Local MQTT\nfeature summary", ls="--")

    ax.text(82, 4,
            "hardened: ARP/OT-003 · MMS BER parse · OT-013 wrap · OT-015/017 · pcap-on-disk evidence · tailer rotation",
            ha="center", fontsize=7.5, color="#2e7d32")
    fig.savefig(OUT / "architecture.png", dpi=130, bbox_inches="tight")
    plt.close(fig)


def detection_pipeline():
    fig, ax = plt.subplots(figsize=(11, 14))
    ax.set_xlim(0, 124)
    ax.set_ylim(0, 200)
    ax.axis("off")
    ax.text(62, 195, "Packet Sensor — per-packet detection pipeline",
            ha="center", fontsize=13, fontweight="bold")
    ax.text(62, 189, "(green = hardened / corrected)", ha="center", fontsize=9, color="#2e7d32")

    nodes = [
        ("Packet in  (scapy sniff)", BLUE),
        ("PCAP ring buffer  (+ rolling on-disk pcap)", AMBER),
        ("L2 Ethernet  parse_ethernet", BLUE),
        ("ARP -> evaluate_arp -> OT-003 (ip<->mac flip)", GREEN),
        ("L3 IP / L4 transport", BLUE),
        ("inventory.observe", BLUE),
        ("MVP rules: OT-001 / 002 / 004 / 005 / 006 / 010", BLUE),
        ("Modbus TCP -> OT-007", BLUE),
        ("GOOSE: OT-011 / OT-012 / OT-013 (wrap-safe)", GREEN),
        ("MMS (real BER): OT-014 / OT-016 / OT-018", GREEN),
        ("SecurityEvent -> .jsonl (+ evidence_ref / pcap_file)", AMBER),
    ]
    top, gap, h, w, x = 178, 15, 9, 92, 6
    ys = [top - i * gap for i in range(len(nodes))]
    for (t, c), y in zip(nodes, ys):
        _box(ax, x, y, w, h, t, c, 8)
    for i in range(len(nodes) - 1):
        _arrow(ax, (x + w / 2, ys[i]), (x + w / 2, ys[i + 1] + h))

    # periodic (window) branch
    _box(ax, x + w + 2, top - 3 * gap, 22, 14, "feature window\ntimer (60s)", GREY, 7, True)
    _box(ax, x + w + 2, top - 6.4 * gap, 22, 18, "OT-008 rate\nOT-009 offline\nOT-017 silence", GREEN, 7)
    _arrow(ax, (x + w + 13, top - 3 * gap), (x + w + 13, top - 6.4 * gap + 18))
    fig.savefig(OUT / "detection-pipeline.png", dpi=130, bbox_inches="tight")
    plt.close(fig)


def main():
    architecture()
    detection_pipeline()
    print("wrote architecture.png, detection-pipeline.png")


if __name__ == "__main__":
    main()
