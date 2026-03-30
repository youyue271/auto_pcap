from __future__ import annotations

from dataclasses import dataclass
from importlib.util import find_spec
import shutil
from typing import Any

from TrafficAnalyzer.config import WIRESHARK_FAST_PATH_COMMAND, WIRESHARK_SPLIT_COMMANDS


@dataclass(frozen=True)
class RuntimeValidation:
    ok: bool
    errors: list[str]
    warnings: list[str]


def collect_runtime_snapshot() -> dict[str, dict[str, bool]]:
    commands = {
        WIRESHARK_FAST_PATH_COMMAND: shutil.which(WIRESHARK_FAST_PATH_COMMAND) is not None,
        WIRESHARK_SPLIT_COMMANDS[0]: shutil.which(WIRESHARK_SPLIT_COMMANDS[0]) is not None,
        WIRESHARK_SPLIT_COMMANDS[1]: shutil.which(WIRESHARK_SPLIT_COMMANDS[1]) is not None,
    }
    modules = {
        "pyshark": find_spec("pyshark") is not None,
        "uvicorn": find_spec("uvicorn") is not None,
        "fastapi": find_spec("fastapi") is not None,
        "jinja2": find_spec("jinja2") is not None,
        "multipart": find_spec("multipart") is not None,
    }
    return {
        "commands": commands,
        "modules": modules,
    }


def validate_runtime(target: str, snapshot: dict[str, dict[str, bool]] | None = None) -> RuntimeValidation:
    snapshot = snapshot or collect_runtime_snapshot()
    commands = snapshot["commands"]
    modules = snapshot["modules"]

    has_tshark = commands[WIRESHARK_FAST_PATH_COMMAND]
    has_pyshark = modules["pyshark"]
    errors: list[str] = []
    warnings: list[str] = []

    if target in {"analyze", "web"}:
        if not has_tshark and not has_pyshark:
            errors.append(
                "缺少 `tshark` 和 `pyshark`，无法解析 PCAP。请安装 Wireshark CLI 或执行 `pip install pyshark`。"
            )
        elif not has_tshark:
            warnings.append("未检测到 `tshark`，将回退到 `pyshark`，性能会明显下降。")

    if target == "web":
        if not modules["uvicorn"]:
            errors.append("未安装 `uvicorn`。请执行: pip install uvicorn")
        if not modules["fastapi"]:
            errors.append("未安装 `fastapi`。请执行: pip install fastapi")
        if not modules["jinja2"]:
            errors.append("未安装 `jinja2`。请执行: pip install jinja2")
        if not modules["multipart"]:
            errors.append("未安装 `python-multipart`。请执行: pip install python-multipart")
        for command_name in WIRESHARK_SPLIT_COMMANDS:
            if not commands[command_name]:
                warnings.append(f"未检测到 `{command_name}`，大文件分片并行解析将不可用。")

    if target == "benchmark":
        if not has_tshark:
            errors.append("`benchmark` 需要 `tshark`。请先安装 Wireshark CLI。")
        if not has_pyshark:
            errors.append("`benchmark` 需要 `pyshark`。请执行: pip install pyshark")

    return RuntimeValidation(ok=not errors, errors=errors, warnings=warnings)


def runtime_report_dict(snapshot: dict[str, dict[str, bool]] | None = None) -> dict[str, Any]:
    snapshot = snapshot or collect_runtime_snapshot()
    features = {
        "analyze": validate_runtime("analyze", snapshot=snapshot),
        "web": validate_runtime("web", snapshot=snapshot),
        "benchmark": validate_runtime("benchmark", snapshot=snapshot),
    }
    return {
        "healthy": features["analyze"].ok,
        "snapshot": snapshot,
        "features": {
            name: {
                "ok": result.ok,
                "errors": result.errors,
                "warnings": result.warnings,
            }
            for name, result in features.items()
        },
    }


def format_runtime_report(report: dict[str, Any]) -> str:
    lines = ["TrafficAnalyzer Runtime Doctor"]

    commands = report.get("snapshot", {}).get("commands", {})
    modules = report.get("snapshot", {}).get("modules", {})
    lines.append("Commands:")
    for name in sorted(commands):
        status = "OK" if commands[name] else "MISSING"
        lines.append(f"  - {name}: {status}")

    lines.append("Python Modules:")
    for name in sorted(modules):
        status = "OK" if modules[name] else "MISSING"
        lines.append(f"  - {name}: {status}")

    lines.append("Features:")
    for name, details in report.get("features", {}).items():
        status = "OK" if details.get("ok") else "ERROR"
        lines.append(f"  - {name}: {status}")
        for message in details.get("errors", []):
            lines.append(f"    error: {message}")
        for message in details.get("warnings", []):
            lines.append(f"    warn: {message}")

    return "\n".join(lines)
