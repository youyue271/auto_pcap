from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from TrafficAnalyzer.parsers.packet_parser import PacketParser


@dataclass(frozen=True)
class TsharkStage:
    name: str
    display_filter: str | None
    fields: list[str]


MINIMAL_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]

PROTOCOL_STAGES = [
    TsharkStage(
        name="HTTP",
        display_filter="http",
        fields=[
            "frame.number",
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.user_agent",
            "http.content_type",
            "http.response.code",
            "http.file_data",
        ],
    ),
    TsharkStage(
        name="DNS",
        display_filter="dns",
        fields=[
            "frame.number",
            "dns.qry.name",
            "dns.qry.type",
            "dns.resp.name",
            "dns.flags.rcode",
            "dns.a",
        ],
    ),
    TsharkStage(
        name="TLS",
        display_filter="tls",
        fields=[
            "frame.number",
            "tls.handshake.extensions_server_name",
            "tls.record.version",
            "tls.handshake.ciphersuite",
        ],
    ),
    TsharkStage(
        name="Modbus",
        display_filter="mbtcp or modbus",
        fields=[
            "frame.number",
            "mbtcp.trans_id",
            "mbtcp.unit_id",
            "modbus.func_code",
            "modbus.reference_num",
        ],
    ),
]


def run_tshark_fields(pcap_path: str, display_filter: str | None, fields: list[str]) -> float:
    cmd = [
        "tshark",
        "-r",
        pcap_path,
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    for field in fields:
        cmd.extend(["-e", field])

    started = time.perf_counter()
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.perf_counter() - started


def run_full_pyshark(pcap_path: str) -> tuple[float, int]:
    parser = PacketParser(mode="pyshark")
    started = time.perf_counter()
    count = 0
    for _ in parser.parse_file(pcap_path):
        count += 1
    return time.perf_counter() - started, count


def run_lazy_pipeline(pcap_path: str, workers: int) -> dict:
    stage1 = run_tshark_fields(pcap_path, None, MINIMAL_FIELDS)
    stage2_inputs = [(stage.name, stage.display_filter, stage.fields) for stage in PROTOCOL_STAGES]

    def _stage_runner(item: tuple[str, str | None, list[str]]) -> tuple[str, float]:
        name, display_filter, fields = item
        return name, run_tshark_fields(pcap_path, display_filter, fields)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        stage2 = dict(executor.map(_stage_runner, stage2_inputs))

    total = stage1 + (max(stage2.values()) if stage2 else 0.0)
    return {
        "stage1": stage1,
        "stage2": stage2,
        "total": total,
    }


def run_benchmark_for_pcap(pcap_path: str, workers: int) -> dict:
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    size_mb = path.stat().st_size / (1024 * 1024)
    full_seconds, packet_count = run_full_pyshark(str(path))
    lazy = run_lazy_pipeline(str(path), workers=workers)
    speedup = full_seconds / lazy["total"] if lazy["total"] > 0 else 0.0
    return {
        "path": str(path),
        "name": path.name,
        "size_mb": round(size_mb, 2),
        "full_seconds": full_seconds,
        "packet_count": packet_count,
        "lazy": lazy,
        "speedup": speedup,
    }


def _print_result(result: dict) -> None:
    print(f"\n== {result['name']} ({result['size_mb']:.2f} MB) ==")
    print(f"full_parse      : {result['full_seconds']:.2f}s  packets={result['packet_count']}")
    lazy = result["lazy"]
    print(f"lazy_stage1     : {lazy['stage1']:.2f}s")
    for name, seconds in lazy["stage2"].items():
        print(f"lazy_stage2_{name:<6}: {seconds:.2f}s")
    print(f"lazy_total      : {lazy['total']:.2f}s")
    if result["speedup"] > 0:
        print(f"speedup         : {result['speedup']:.1f}x")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark full parse vs lazy field loading")
    parser.add_argument(
        "pcaps",
        nargs="*",
        default=["tests/Modbus.pcap", "tests/file.pcapng", "tests/MMS.pcap"],
        help="PCAP files to benchmark",
    )
    parser.add_argument("--workers", type=int, default=min(os.cpu_count() or 2, 4))
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    for pcap in args.pcaps:
        path = Path(pcap)
        if not path.exists():
            print(f"[skip] {pcap} not found")
            continue
        result = run_benchmark_for_pcap(str(path), workers=args.workers)
        _print_result(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
