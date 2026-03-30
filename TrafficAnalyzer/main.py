from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict

from TrafficAnalyzer.benchmarks.lazy_parse import main as benchmark_main
from TrafficAnalyzer.pipeline import build_default_pipeline_service
from TrafficAnalyzer.runtime import format_runtime_report, runtime_report_dict, validate_runtime


def _print_runtime_validation(result) -> bool:
    for message in result.warnings:
        print(f"警告: {message}")
    if result.ok:
        return True

    for message in result.errors:
        print(f"错误: {message}")
    return False


def cmd_analyze(args) -> int:
    if not os.path.exists(args.pcap_path):
        print(f"错误: 文件 {args.pcap_path} 未找到。")
        return 1
    if not _print_runtime_validation(validate_runtime("analyze")):
        return 1

    service = build_default_pipeline_service()
    try:
        report = service.analyze_file(args.pcap_path, max_packets=args.max_packets)
    except Exception as exc:
        print(f"分析失败: {exc}")
        return 1

    if args.json:
        print(json.dumps(asdict(report), ensure_ascii=False, indent=2))
        return 0

    print("分析完成")
    print(f"- 文件: {args.pcap_path}")
    print(f"- 包数量: {report.packet_count}")
    print(f"- 协议事件: {report.stats.get('protocol_event_count', 0)}")
    print(f"- 告警数量: {report.stats.get('alert_count', 0)}")
    if report.stats.get("protocol_distribution"):
        print(f"- 协议分布: {report.stats['protocol_distribution']}")
    if report.alerts:
        print("告警详情:")
        for alert in report.alerts:
            print(
                f"  [{alert.severity}] {alert.name} "
                f"(rule={alert.rule_id}, confidence={alert.confidence})"
            )
    return 0


def cmd_web(args) -> int:
    validation = validate_runtime("web")
    if not _print_runtime_validation(validation):
        return 1

    import uvicorn

    uvicorn.run(
        "TrafficAnalyzer.web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def cmd_benchmark(args) -> int:
    if not _print_runtime_validation(validate_runtime("benchmark")):
        return 1

    benchmark_args: list[str] = []
    if args.workers is not None:
        benchmark_args.extend(["--workers", str(args.workers)])
    benchmark_args.extend(args.pcaps)
    return benchmark_main(benchmark_args)


def cmd_doctor(args) -> int:
    report = runtime_report_dict()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_runtime_report(report))
    return 0 if report["healthy"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TrafficAnalyzer: 全流程流量分析框架")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="分析一个 pcap 文件")
    analyze_parser.add_argument("pcap_path", help="PCAP 文件路径")
    analyze_parser.add_argument("--max-packets", type=int, default=None, help="仅分析前 N 个包")
    analyze_parser.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    analyze_parser.set_defaults(func=cmd_analyze)

    web_parser = subparsers.add_parser("web", help="启动 Web UI")
    web_parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    web_parser.add_argument("--port", type=int, default=8000, help="监听端口")
    web_parser.add_argument("--reload", action="store_true", help="开发模式自动重载")
    web_parser.set_defaults(func=cmd_web)

    benchmark_parser = subparsers.add_parser("benchmark", help="对比全量解析与懒加载解析性能")
    benchmark_parser.add_argument("pcaps", nargs="*", default=[], help="PCAP 文件路径")
    benchmark_parser.add_argument("--workers", type=int, default=None, help="并行 worker 数")
    benchmark_parser.set_defaults(func=cmd_benchmark)

    doctor_parser = subparsers.add_parser("doctor", help="检查运行环境与依赖状态")
    doctor_parser.add_argument("--json", action="store_true", help="以 JSON 输出检查结果")
    doctor_parser.set_defaults(func=cmd_doctor)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
