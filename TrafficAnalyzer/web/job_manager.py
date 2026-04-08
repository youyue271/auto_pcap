from __future__ import annotations

import atexit
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from multiprocessing import Process
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from threading import RLock, Thread
import time
import traceback
from typing import Callable, Dict, Iterator, Optional
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
import re

from TrafficAnalyzer.attacks.webshell_parsers.godzilla import GodzillaParser
from TrafficAnalyzer.config import LARGE_PCAP_THRESHOLD, PARALLEL_PARSE_MAX_WORKERS
from TrafficAnalyzer.core.loader import PcapLoader
from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.parsers.packet_parser import PacketParser
from TrafficAnalyzer.pipeline import build_default_pipeline_service
from TrafficAnalyzer.utils.tls_keylog import normalize_local_input_path, resolve_tls_keylog_text

PROJECT_STORAGE_ROOT = Path(__file__).resolve().parents[2] / "data" / "projects"

BASIC_PROTOCOL_LAYER_HINTS: dict[str, set[str]] = {
    "HTTP": {"http"},
    "DNS": {"dns"},
    "TLS": {"tls", "ssl"},
    "Modbus": {"mbtcp", "modbus"},
    "USB": {"usb", "usbhid"},
}

BASIC_PROTOCOL_PORT_HINTS: dict[str, set[int]] = {
    "HTTP": {80, 8000, 8008, 8080, 8081, 8888},
    "DNS": {53},
    "TLS": {443, 8443},
    "Modbus": {502},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _basic_protocol_hits(packet: PacketRecord) -> set[str]:
    layers = {str(layer or "").strip().lower() for layer in (packet.layers or []) if str(layer or "").strip()}
    ports = {
        int(port)
        for port in (packet.src_port, packet.dst_port)
        if isinstance(port, int) and port > 0
    }
    hits: set[str] = set()
    for name, layer_hints in BASIC_PROTOCOL_LAYER_HINTS.items():
        if layers & layer_hints:
            hits.add(name)
            continue
        port_hints = BASIC_PROTOCOL_PORT_HINTS.get(name) or set()
        if ports & port_hints:
            hits.add(name)
    return hits


def _update_basic_protocol_counter(counter: Counter[str], packet: PacketRecord) -> None:
    for name in _basic_protocol_hits(packet):
        counter[name] += 1


def _merge_basic_protocol_counter(counter: Counter[str], values: dict | None) -> None:
    for name, value in (values or {}).items():
        try:
            amount = int(value)
        except (TypeError, ValueError):
            continue
        if amount > 0:
            counter[str(name)] += amount


def _normalize_basic_protocol_counter(counter: Counter[str]) -> dict[str, int]:
    return {
        str(name): int(count)
        for name, count in counter.most_common()
        if int(count) > 0
    }


def _init_packet_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                idx INTEGER PRIMARY KEY,
                packet_json TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _stream_packets_from_db(db_path: str, fetch_size: int) -> Iterator[PacketRecord]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT packet_json FROM packets ORDER BY idx")
        while True:
            rows = cur.fetchmany(fetch_size)
            if not rows:
                break
            for (packet_json,) in rows:
                payload = json.loads(packet_json)
                yield PacketRecord(**payload)
    finally:
        conn.close()


def _stream_packet_json_chunks_from_db(db_path: str, fetch_size: int) -> Iterator[list[str]]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT packet_json FROM packets ORDER BY idx")
        while True:
            rows = cur.fetchmany(fetch_size)
            if not rows:
                break
            yield [packet_json for (packet_json,) in rows]
    finally:
        conn.close()


def _write_json_atomic(path: str, payload: dict) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False)
    os.replace(tmp_path, path)


def _read_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _project_capture_path(project_dir: Path, filename: str, fallback_path: str = "") -> Path:
    suffix = Path(filename).suffix or Path(fallback_path).suffix or ".pcap"
    return project_dir / f"source{suffix}"


def _packet_record_to_dict(record: PacketRecord) -> dict:
    return dict(record.__dict__)


def _packet_record_to_json(record: PacketRecord) -> str:
    return json.dumps(_packet_record_to_dict(record), ensure_ascii=False, separators=(",", ":"))


def _module_progress_payload(processed: int, total: int | None) -> dict:
    percent = None
    if total and total > 0:
        percent = round((processed / total) * 100, 2)
    return {
        "processed": processed,
        "total": total,
        "percent": percent,
        "updated_at": _now_iso(),
    }


def _write_module_progress(path: str, *, processed: int, total: int | None) -> None:
    _write_json_atomic(path, _module_progress_payload(processed=processed, total=total))


def _read_module_progress(path: str | None) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    try:
        payload = _read_json_file(path)
    except Exception:
        return None
    processed = int(payload.get("processed", 0) or 0)
    total_raw = payload.get("total")
    total = int(total_raw) if isinstance(total_raw, (int, float)) else None
    percent_raw = payload.get("percent")
    percent = float(percent_raw) if isinstance(percent_raw, (int, float)) else None
    updated_at = payload.get("updated_at")
    return {
        "processed": processed,
        "total": total,
        "percent": percent,
        "updated_at": updated_at,
    }


def _elapsed_ms(started_at: str | None, finished_at: str | None = None) -> int | None:
    started_text = str(started_at or "").strip()
    if not started_text:
        return None
    try:
        started_dt = datetime.fromisoformat(started_text)
    except ValueError:
        return None

    finished_text = str(finished_at or "").strip()
    if finished_text:
        try:
            finished_dt = datetime.fromisoformat(finished_text)
        except ValueError:
            finished_dt = datetime.now(timezone.utc)
    else:
        finished_dt = datetime.now(timezone.utc)
    return max(0, int((finished_dt - started_dt).total_seconds() * 1000))


def _progress_packet_stream(
    packets: Iterator[PacketRecord],
    *,
    total_packets: int | None,
    progress_callback: Callable[[int], None] | None,
    progress_interval: int = 1000,
) -> Iterator[PacketRecord]:
    if progress_callback is None:
        yield from packets
        return

    processed = 0
    last_reported = 0
    last_report_at = time.monotonic()
    for packet in packets:
        processed += 1
        now = time.monotonic()
        should_report = (
            (processed - last_reported) >= progress_interval
            or (total_packets is not None and processed >= total_packets)
            or (now - last_report_at) >= 1.0
        )
        if should_report:
            progress_callback(processed)
            last_reported = processed
            last_report_at = now
        yield packet

    if processed != last_reported:
        progress_callback(processed)


def _parse_packet_chunk(
    pcap_path: str,
    progress_callback: Callable[[int], None] | None = None,
    progress_interval: int = 1000,
    output_path: str | None = None,
    tls_keylog_text: str | None = None,
) -> dict:
    parser = PacketParser(tls_keylog_text=tls_keylog_text)
    records: list[dict] = []
    packet_count = 0
    basic_protocol_counter: Counter[str] = Counter()
    pending_progress = 0
    last_progress_at = time.monotonic()
    writer = None

    try:
        if output_path:
            writer = open(output_path, "w", encoding="utf-8")

        for record in parser.parse_file(pcap_path):
            packet_count += 1
            _update_basic_protocol_counter(basic_protocol_counter, record)
            if writer is not None:
                writer.write(_packet_record_to_json(record))
                writer.write("\n")
            else:
                records.append(_packet_record_to_dict(record))
            pending_progress += 1

            should_report = pending_progress >= progress_interval or (time.monotonic() - last_progress_at) >= 1.0
            if progress_callback and should_report:
                progress_callback(pending_progress)
                pending_progress = 0
                last_progress_at = time.monotonic()
    except Exception:
        if output_path:
            try:
                os.remove(output_path)
            except OSError:
                pass
        raise
    finally:
        if writer is not None:
            writer.close()

    if progress_callback and pending_progress:
        progress_callback(pending_progress)

    result = {
        "pcap_path": pcap_path,
        "packet_count": packet_count,
        "basic_protocol_distribution": _normalize_basic_protocol_counter(basic_protocol_counter),
    }
    if output_path:
        result["output_path"] = output_path
    else:
        result["records"] = records
    return result


def _analyze_chunk_map(task: tuple[str, str, str, list[str]]) -> dict:
    module_type, module_name, source, packet_rows = task
    service = build_default_pipeline_service()
    packets = (PacketRecord(**json.loads(item)) for item in packet_rows)

    if module_type == "protocol":
        report = service.analyze_packets(
            packets,
            source=source,
            enabled_protocols=[module_name],
            enabled_attacks=[],
        )
        detail = report.stats.get("detailed_views", {}).get(module_name, {})
        return {
            "summary": {
                "packet_count": report.packet_count,
                "protocol_event_count": report.stats.get("protocol_event_count", 0),
                "alert_count": report.stats.get("alert_count", 0),
            },
            "detail": detail,
            "debug": report.stats.get("debug", {}),
        }

    report = service.analyze_packets(
        packets,
        source=source,
        enabled_protocols=None,
        enabled_attacks=[module_name],
    )
    detail = report.stats.get("attack_detailed_views", {}).get(module_name, {})
    return {
        "summary": {
            "packet_count": report.packet_count,
            "protocol_event_count": report.stats.get("protocol_event_count", 0),
            "alert_count": report.stats.get("alert_count", 0),
        },
        "detail": detail,
        "alerts": [asdict(alert) for alert in report.alerts],
        "debug": report.stats.get("debug", {}),
    }


def _merge_debug(target: dict, debug: dict) -> None:
    target["chunks"] += 1
    stage_ms = debug.get("stage_ms", {})
    for key, value in stage_ms.items():
        if isinstance(value, (int, float)):
            target["stage_ms"][key] = round(target["stage_ms"].get(key, 0.0) + float(value), 2)

    target["error_count"] += int(debug.get("error_count", 0) or 0)
    errors = debug.get("errors", [])
    for item in errors:
        if len(target["errors"]) >= 30:
            break
        target["errors"].append(item)

    comp_out = debug.get("component_outputs", {})
    p_counts = comp_out.get("protocol_event_count_by_parser", {})
    a_counts = comp_out.get("alert_count_by_detector", {})
    for key, value in p_counts.items():
        target["protocol_event_count_by_parser"][key] += int(value)
    for key, value in a_counts.items():
        target["alert_count_by_detector"][key] += int(value)


def _finalize_debug(target: dict) -> dict:
    return {
        "mode": "mapreduce",
        "chunk_count": target["chunks"],
        "stage_ms": target["stage_ms"],
        "error_count": target["error_count"],
        "errors": target["errors"],
        "component_outputs": {
            "protocol_event_count_by_parser": dict(target["protocol_event_count_by_parser"]),
            "alert_count_by_detector": dict(target["alert_count_by_detector"]),
        },
    }


def _merge_protocol_detail(target: dict, top_counters: dict[str, Counter[str]], partial: dict) -> None:
    for key, value in partial.items():
        if key.startswith("top_") and isinstance(value, list):
            counter = top_counters.setdefault(key, Counter())
            for item in value:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    continue
                counter[str(item[0])] += int(item[1])
            continue

        if isinstance(value, list):
            acc = target.setdefault(key, [])
            limit = 300 if key in {"requests", "queries", "sessions", "operations", "records"} else 500
            remain = limit - len(acc)
            if remain > 0:
                acc.extend(value[:remain])
            continue

        if isinstance(value, (int, float)):
            target[key] = target.get(key, 0) + value
            continue

        target[key] = value


def _run_mapreduce_worker(
    *,
    db_path: str,
    module_type: str,
    module_name: str,
    source: str,
    fetch_size: int,
    progress_callback: Callable[[int], None] | None = None,
) -> dict:
    worker_count = max(1, min((os.cpu_count() or 2), 4))
    summary = {"packet_count": 0, "protocol_event_count": 0, "alert_count": 0}
    debug_acc = {
        "chunks": 0,
        "stage_ms": {},
        "error_count": 0,
        "errors": [],
        "protocol_event_count_by_parser": Counter(),
        "alert_count_by_detector": Counter(),
    }

    tasks = (
        (module_type, module_name, source, chunk)
        for chunk in _stream_packet_json_chunks_from_db(db_path=db_path, fetch_size=fetch_size)
    )

    if module_type == "protocol":
        detail: dict = {}
        top_counters: dict[str, Counter[str]] = {}
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            for partial in executor.map(_analyze_chunk_map, tasks):
                part_summary = partial.get("summary", {})
                summary["packet_count"] += int(part_summary.get("packet_count", 0))
                summary["protocol_event_count"] += int(part_summary.get("protocol_event_count", 0))
                summary["alert_count"] += int(part_summary.get("alert_count", 0))
                if progress_callback is not None:
                    progress_callback(summary["packet_count"])
                _merge_protocol_detail(detail, top_counters, partial.get("detail", {}))
                _merge_debug(debug_acc, partial.get("debug", {}))

        for key, counter in top_counters.items():
            if module_name == "HTTP" and key in {"top_hosts", "top_paths"}:
                limit = 200
            else:
                limit = 20 if key == "top_func_codes" else 30
            detail[key] = counter.most_common(limit)

        return {
            "module": {"type": module_type, "name": module_name},
            "summary": summary,
            "detail": detail,
            "debug": _finalize_debug(debug_acc),
        }

    alerts: list[dict] = []
    detail = {}
    top_counters: dict[str, Counter[str]] = {}
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        for partial in executor.map(_analyze_chunk_map, tasks):
            part_summary = partial.get("summary", {})
            summary["packet_count"] += int(part_summary.get("packet_count", 0))
            summary["protocol_event_count"] += int(part_summary.get("protocol_event_count", 0))
            summary["alert_count"] += int(part_summary.get("alert_count", 0))
            if progress_callback is not None:
                progress_callback(summary["packet_count"])
            _merge_protocol_detail(detail, top_counters, partial.get("detail", {}))
            alerts.extend(partial.get("alerts", []))
            _merge_debug(debug_acc, partial.get("debug", {}))

    for key, counter in top_counters.items():
        limit = 20 if key in {"top_rules", "top_families", "top_variants", "top_func_codes"} else 30
        detail[key] = counter.most_common(limit)

    return {
        "module": {"type": module_type, "name": module_name},
        "summary": summary,
        "detail": detail,
        "alerts": alerts,
        "debug": _finalize_debug(debug_acc),
    }


def _module_worker(
    *,
    db_path: str,
    module_type: str,
    module_name: str,
    source: str,
    result_path: str,
    fetch_size: int,
    progress_path: str | None = None,
    total_packets: int | None = None,
) -> None:
    try:
        progress_callback = None
        if progress_path:
            _write_module_progress(progress_path, processed=0, total=total_packets)

            def progress_callback(processed: int) -> None:
                _write_module_progress(progress_path, processed=processed, total=total_packets)

        map_reducible_protocols = {"DNS", "TLS", "Modbus"}
        map_reducible_attacks = set()
        enable_mapreduce = (module_type == "protocol" and module_name in map_reducible_protocols) or (
            module_type == "attack" and module_name in map_reducible_attacks
        )

        if enable_mapreduce:
            result = _run_mapreduce_worker(
                db_path=db_path,
                module_type=module_type,
                module_name=module_name,
                source=source,
                fetch_size=fetch_size,
                progress_callback=progress_callback,
            )
            _write_json_atomic(result_path, {"ok": True, "result": result})
            return

        service = build_default_pipeline_service()
        packet_stream = _progress_packet_stream(
            _stream_packets_from_db(db_path=db_path, fetch_size=fetch_size),
            total_packets=total_packets,
            progress_callback=progress_callback,
        )

        if module_type == "protocol":
            report = service.analyze_packets(
                packet_stream,
                source=source,
                enabled_protocols=[module_name],
                enabled_attacks=[],
            )
            detail = report.stats.get("detailed_views", {}).get(module_name, {})
            result = {
                "module": {"type": module_type, "name": module_name},
                "summary": {
                    "packet_count": report.packet_count,
                    "protocol_event_count": report.stats.get("protocol_event_count", 0),
                    "alert_count": report.stats.get("alert_count", 0),
                },
                "detail": detail,
                "debug": report.stats.get("debug", {}),
            }
        else:
            report = service.analyze_packets(
                packet_stream,
                source=source,
                enabled_protocols=None,
                enabled_attacks=[module_name],
            )
            detail = report.stats.get("attack_detailed_views", {}).get(module_name, {})
            result = {
                "module": {"type": module_type, "name": module_name},
                "summary": {
                    "packet_count": report.packet_count,
                    "protocol_event_count": report.stats.get("protocol_event_count", 0),
                    "alert_count": report.stats.get("alert_count", 0),
                },
                "detail": detail,
                "alerts": [asdict(alert) for alert in report.alerts],
                "debug": report.stats.get("debug", {}),
            }

        _write_json_atomic(result_path, {"ok": True, "result": result})
    except Exception as exc:
        _write_json_atomic(
            result_path,
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(limit=20),
            },
        )


@dataclass
class ModuleExecution:
    module_type: str
    module_name: str
    status: str = "pending"  # pending | running | completed | stopped | error
    created_at: str = field(default_factory=_now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[dict] = None
    stop_requested: bool = False
    run_id: int = 0
    process: Optional[Process] = field(default=None, repr=False)
    watcher: Optional[Thread] = field(default=None, repr=False)
    result_path: Optional[str] = field(default=None, repr=False)
    progress_path: Optional[str] = field(default=None, repr=False)

    @property
    def key(self) -> str:
        return f"{self.module_type}:{self.module_name}"


@dataclass
class TLSDecryptExecution:
    task_id: str = ""
    key_hash: str = ""
    status: str = "idle"  # idle | running | completed | error
    stage: str = "idle"
    message: str = ""
    keylog_source: Optional[dict] = None
    created_at: str = field(default_factory=_now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    updated_at: Optional[str] = None
    progress: dict = field(default_factory=lambda: _module_progress_payload(processed=0, total=None))
    result: Optional[dict] = None
    error: Optional[str] = None


@dataclass
class AnalysisJob:
    job_id: str
    filename: str
    temp_path: str
    db_path: str
    max_packets: Optional[int]
    project_id: str = ""
    project_dir: str = ""
    metadata_path: str = ""
    source_size_bytes: Optional[int] = None
    tls_keylog_text: Optional[str] = field(default=None, repr=False)
    managed_temp: bool = True
    status: str = "queued"  # queued | parsing | parsed | error
    created_at: str = field(default_factory=_now_iso)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    packet_count: int = 0
    source_packet_count: Optional[int] = None
    source_packet_count_estimated: bool = False
    target_packet_count: Optional[int] = None
    progress_updated_at: Optional[str] = None
    parse_error: Optional[str] = None
    parse_mode: str = "sequential"
    basic_protocol_distribution: Dict[str, int] = field(default_factory=dict)
    revision: int = 0
    modules: Dict[str, ModuleExecution] = field(default_factory=dict)
    tls_decrypt: Optional[TLSDecryptExecution] = field(default=None, repr=False)
    parse_thread: Optional[Thread] = field(default=None, repr=False)
    lock: RLock = field(default_factory=RLock, repr=False)

    def __post_init__(self) -> None:
        if not self.project_id:
            self.project_id = self.job_id

    def bump_revision(self) -> None:
        self.revision += 1


class JobManager:
    def __init__(
        self,
        db_flush_size: int = 500,
        module_db_fetch_size: int = 2000,
        parallel_parse_threshold_bytes: int = LARGE_PCAP_THRESHOLD,
        parallel_parse_max_workers: int = PARALLEL_PARSE_MAX_WORKERS,
        split_target_mb: float = 64.0,
        storage_root: str | None = None,
    ):
        self.jobs: Dict[str, AnalysisJob] = {}
        self.lock = RLock()
        self.pipeline_service = build_default_pipeline_service()
        self.module_catalog = self.pipeline_service.list_modules()
        self.protocol_names = {item["name"] for item in self.module_catalog["protocols"]}
        self.attack_names = {item["name"] for item in self.module_catalog["attacks"]}
        self.db_flush_size = db_flush_size
        self.module_db_fetch_size = module_db_fetch_size
        self.parallel_parse_threshold_bytes = parallel_parse_threshold_bytes
        self.parallel_parse_max_workers = max(1, int(parallel_parse_max_workers))
        self.split_target_mb = split_target_mb
        self.storage_root = Path(storage_root) if storage_root else PROJECT_STORAGE_ROOT
        self._shutdown_done = False
        self._load_persisted_jobs()
        atexit.register(self.shutdown)

    def list_modules(self) -> dict:
        return self.module_catalog

    def list_projects(self) -> list[dict]:
        with self.lock:
            projects = list(self.jobs.values())

        items = [self._project_snapshot(job) for job in projects]
        items.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
        return items

    def load_project(self, project_id: str) -> dict:
        job = self._get_job(project_id)
        return {
            "ok": True,
            "project": self._project_snapshot(job),
            "job": self.job_status(job.job_id)["job"],
            "results": self.job_results(job.job_id),
        }

    def delete_project(self, project_id: str) -> dict:
        job = self._get_job(project_id)

        with job.lock:
            pending_modules = sum(1 for module in job.modules.values() if module.status == "pending")
            running_modules = sum(1 for module in job.modules.values() if module.status == "running")
            delete_block_reason = self._project_delete_block_reason(
                status=job.status,
                pending_module_count=pending_modules,
                running_module_count=running_modules,
            )
            if delete_block_reason:
                raise HTTPError(f"项目当前不可删除: {delete_block_reason}")
            project_dir = job.project_dir

        with self.lock:
            self.jobs.pop(job.job_id, None)

        if project_dir:
            shutil.rmtree(project_dir, ignore_errors=True)
        return {"deleted": True, "project_id": job.project_id, "job_id": job.job_id}

    def cleanup_projects(
        self,
        *,
        project_ids: list[str] | None = None,
        keep_recent: int | None = None,
    ) -> dict:
        if keep_recent is not None:
            try:
                keep_recent = int(keep_recent)
            except (TypeError, ValueError) as exc:
                raise HTTPError("keep_recent 必须是整数") from exc
        normalized_ids: list[str] = []
        if project_ids:
            seen: set[str] = set()
            for item in project_ids:
                project_id = str(item or "").strip()
                if not project_id or project_id in seen:
                    continue
                seen.add(project_id)
                normalized_ids.append(project_id)

        if keep_recent is not None and keep_recent < 0:
            raise HTTPError("keep_recent 不能小于 0")
        if not normalized_ids and keep_recent is None:
            raise HTTPError("缺少清理目标")

        if normalized_ids:
            target_ids = normalized_ids
        else:
            projects = self.list_projects()
            target_ids = [item["project_id"] for item in projects[keep_recent:]]

        deleted: list[dict] = []
        skipped: list[dict] = []
        for project_id in target_ids:
            try:
                deleted.append(self.delete_project(project_id))
            except HTTPError as exc:
                skipped.append({"project_id": project_id, "reason": str(exc)})

        return {
            "requested_count": len(target_ids),
            "deleted_count": len(deleted),
            "skipped_count": len(skipped),
            "deleted": deleted,
            "skipped": skipped,
            "keep_recent": keep_recent,
        }

    def _load_persisted_jobs(self) -> None:
        if not self.storage_root.exists():
            return

        for meta_path in sorted(self.storage_root.glob("*/meta.json")):
            try:
                payload = _read_json_file(str(meta_path))
                job = self._job_from_meta(payload, meta_path=meta_path)
            except Exception:
                continue
            self.jobs[job.job_id] = job

    def _job_from_meta(self, payload: dict, meta_path: Path) -> AnalysisJob:
        project_dir = meta_path.parent
        db_path = project_dir / "packets.sqlite3"
        if not db_path.exists():
            raise FileNotFoundError(f"项目数据库不存在: {db_path}")

        raw_status = str(payload.get("status") or "error")
        status = raw_status if raw_status in {"queued", "parsing", "parsed", "error"} else "error"
        parse_error = payload.get("parse_error")
        if status in {"queued", "parsing"}:
            status = "error"
            parse_error = parse_error or "服务重启前任务未完成，已标记为异常恢复。"

        job = AnalysisJob(
            job_id=str(payload.get("job_id") or payload.get("project_id") or project_dir.name),
            project_id=str(payload.get("project_id") or payload.get("job_id") or project_dir.name),
            filename=str(payload.get("filename") or project_dir.name),
            temp_path=str(
                payload.get("temp_path")
                or payload.get("capture_path")
                or _project_capture_path(project_dir, str(payload.get("filename") or project_dir.name))
            ),
            db_path=str(db_path),
            max_packets=payload.get("max_packets"),
            project_dir=str(project_dir),
            metadata_path=str(meta_path),
            source_size_bytes=payload.get("source_size_bytes"),
            managed_temp=False,
            status=status,
            created_at=payload.get("created_at") or _now_iso(),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            packet_count=int(payload.get("packet_count", 0) or 0),
            source_packet_count=payload.get("source_packet_count"),
            source_packet_count_estimated=bool(payload.get("source_packet_count_estimated", False)),
            target_packet_count=payload.get("target_packet_count"),
            progress_updated_at=payload.get("progress_updated_at"),
            parse_error=parse_error,
            parse_mode=str(payload.get("parse_mode") or "sequential"),
            basic_protocol_distribution={
                str(name): int(value)
                for name, value in (payload.get("basic_protocol_distribution") or {}).items()
                if isinstance(value, (int, float))
            },
        )

        modules_payload = payload.get("modules") or {}
        for key, item in modules_payload.items():
            module = ModuleExecution(
                module_type=str(item.get("module_type") or "protocol"),
                module_name=str(item.get("module_name") or key),
                status=str(item.get("status") or "pending"),
                created_at=item.get("created_at") or _now_iso(),
                started_at=item.get("started_at"),
                finished_at=item.get("finished_at"),
                error=item.get("error"),
            )
            if module.status in {"running", "pending"}:
                module.status = "stopped"

            result_file = item.get("result_file")
            if result_file:
                result_path = project_dir / result_file
                if result_path.exists():
                    try:
                        module.result = _read_json_file(str(result_path))
                    except Exception:
                        module.result = None
            job.modules[module.key] = module

        return job

    def _project_snapshot(self, job: AnalysisJob) -> dict:
        with job.lock:
            modules = list(job.modules.values())
            running_module_count = sum(1 for module in modules if module.status == "running")
            pending_module_count = sum(1 for module in modules if module.status == "pending")
            completed_module_count = sum(1 for module in modules if module.status == "completed")
            error_module_count = sum(1 for module in modules if module.status == "error")
            stopped_module_count = sum(1 for module in modules if module.status == "stopped")
            delete_block_reason = self._project_delete_block_reason(
                status=job.status,
                pending_module_count=pending_module_count,
                running_module_count=running_module_count,
            )
            latest_completed_modules = [
                {
                    "type": module.module_type,
                    "name": module.module_name,
                    "finished_at": module.finished_at,
                }
                for module in sorted(
                    [item for item in modules if item.status == "completed"],
                    key=lambda item: item.finished_at or item.started_at or item.created_at or "",
                    reverse=True,
                )[:3]
            ]
            recent_errors: list[dict] = []
            if job.parse_error:
                recent_errors.append(
                    {
                        "scope": "parse",
                        "name": "base_parse",
                        "message": job.parse_error,
                        "at": job.finished_at or job.progress_updated_at,
                    }
                )
            recent_errors.extend(
                {
                    "scope": "module",
                    "name": module.module_name,
                    "message": module.error,
                    "at": module.finished_at or module.started_at or module.created_at,
                }
                for module in sorted(
                    [item for item in modules if item.error],
                    key=lambda item: item.finished_at or item.started_at or item.created_at or "",
                    reverse=True,
                )[:3]
            )
            return {
                "project_id": job.project_id,
                "job_id": job.job_id,
                "filename": job.filename,
                "status": job.status,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
                "updated_at": job.progress_updated_at or job.finished_at or job.created_at,
                "packet_count": job.packet_count,
                "source_packet_count": job.source_packet_count,
                "target_packet_count": job.target_packet_count,
                "source_size_bytes": job.source_size_bytes,
                "parse_mode": job.parse_mode,
                "parse_error": job.parse_error,
                "module_count": len(modules),
                "active_module_count": len(modules) - stopped_module_count,
                "running_module_count": running_module_count,
                "pending_module_count": pending_module_count,
                "completed_module_count": completed_module_count,
                "error_module_count": error_module_count,
                "stopped_module_count": stopped_module_count,
                "latest_completed_modules": latest_completed_modules,
                "recent_errors": recent_errors[:3],
                "can_delete": delete_block_reason is None,
                "delete_block_reason": delete_block_reason,
            }

    def _module_result_filename(self, module: ModuleExecution) -> str:
        safe_name = module.module_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        return f"{module.module_type}__{safe_name}.json"

    def _persist_job(self, job: AnalysisJob) -> None:
        project_dir = Path(job.project_dir) if job.project_dir else None
        metadata_path = Path(job.metadata_path) if job.metadata_path else None
        if not project_dir or not metadata_path:
            return

        project_dir.mkdir(parents=True, exist_ok=True)
        module_dir = project_dir / "module_results"
        module_dir.mkdir(parents=True, exist_ok=True)

        stale_files = {path.name for path in module_dir.glob("*.json")}
        modules_payload: dict[str, dict] = {}

        with job.lock:
            for key, module in job.modules.items():
                result_file = None
                if module.result is not None:
                    result_file = self._module_result_filename(module)
                    _write_json_atomic(str(module_dir / result_file), module.result)
                    stale_files.discard(result_file)

                modules_payload[key] = {
                    "module_type": module.module_type,
                    "module_name": module.module_name,
                    "status": module.status,
                    "created_at": module.created_at,
                    "started_at": module.started_at,
                    "finished_at": module.finished_at,
                    "error": module.error,
                    "result_file": f"module_results/{result_file}" if result_file else None,
                }

            payload = {
                "project_id": job.project_id,
                "job_id": job.job_id,
                "filename": job.filename,
                "temp_path": job.temp_path,
                "capture_path": job.temp_path,
                "status": job.status,
                "created_at": job.created_at,
                "started_at": job.started_at,
                "finished_at": job.finished_at,
                "progress_updated_at": job.progress_updated_at,
                "packet_count": job.packet_count,
                "source_packet_count": job.source_packet_count,
                "source_packet_count_estimated": job.source_packet_count_estimated,
                "target_packet_count": job.target_packet_count,
                "source_size_bytes": job.source_size_bytes,
                "max_packets": job.max_packets,
                "parse_error": job.parse_error,
                "parse_mode": job.parse_mode,
                "basic_protocol_distribution": job.basic_protocol_distribution,
                "modules": modules_payload,
            }

        for filename in stale_files:
            self._safe_remove_file(str(module_dir / filename))
        _write_json_atomic(str(metadata_path), payload)

    def create_job(
        self,
        filename: str,
        temp_path: str,
        max_packets: Optional[int],
        source_size_bytes: Optional[int] = None,
        tls_keylog_text: str | None = None,
        tls_keylog_file_name: str | None = None,
        tls_keylog_file_bytes: bytes | None = None,
        managed_temp: bool = True,
    ) -> str:
        normalized_tls_keylog = None
        if (tls_keylog_text and str(tls_keylog_text).strip()) or tls_keylog_file_bytes:
            normalized_tls_keylog, _ = resolve_tls_keylog_text(
                key_text=tls_keylog_text,
                key_file_name=tls_keylog_file_name,
                key_file_bytes=tls_keylog_file_bytes,
            )
            if not normalized_tls_keylog:
                raise HTTPError("TLS keylog 内容无效，未解析到可用密钥行")

        job_id = uuid4().hex
        project_dir = self.storage_root / job_id
        project_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(project_dir / "packets.sqlite3")
        _init_packet_db(db_path)
        capture_path = _project_capture_path(project_dir, filename, temp_path)
        shutil.move(temp_path, capture_path)

        job = AnalysisJob(
            job_id=job_id,
            project_id=job_id,
            filename=filename,
            temp_path=str(capture_path),
            db_path=db_path,
            max_packets=max_packets,
            project_dir=str(project_dir),
            metadata_path=str(project_dir / "meta.json"),
            source_size_bytes=source_size_bytes,
            tls_keylog_text=normalized_tls_keylog,
            managed_temp=managed_temp,
        )
        parse_thread = Thread(target=self._run_base_parse, args=(job_id,), daemon=True, name=f"parse-{job_id[:6]}")
        job.parse_thread = parse_thread

        with self.lock:
            self.jobs[job_id] = job

        self._persist_job(job)
        parse_thread.start()
        return job_id

    def add_module(self, job_id: str, module_type: str, module_name: str) -> dict:
        job = self._get_job(job_id)
        self._validate_module(module_type, module_name)
        key = f"{module_type}:{module_name}"

        with job.lock:
            existing = job.modules.get(key)
            if existing and existing.status in {"pending", "running", "completed"} and not existing.stop_requested:
                return self._module_snapshot(existing)

            module = ModuleExecution(module_type=module_type, module_name=module_name)
            job.modules[key] = module
            job.bump_revision()
            should_start = job.status == "parsed"

        if should_start:
            self._submit_module(job_id, key)
        else:
            self._persist_job(job)
        return self._module_snapshot(module)

    def restart_module(self, job_id: str, module_type: str, module_name: str) -> dict:
        job = self._get_job(job_id)
        self._validate_module(module_type, module_name)
        key = f"{module_type}:{module_name}"

        with job.lock:
            if job.status != "parsed":
                raise HTTPError("基础解析尚未完成，无法重新执行模块")
            module = job.modules.get(key)
            if not module:
                raise HTTPError(f"模块不存在: {key}")
            if module.status in {"pending", "running"}:
                raise HTTPError(f"模块仍在运行中，无法重新执行: {key}")

            module.stop_requested = False
            module.status = "pending"
            module.started_at = None
            module.finished_at = None
            module.error = None
            module.result = None
            module.process = None
            module.watcher = None
            module.result_path = None
            module.progress_path = None
            job.bump_revision()

        self._submit_module(job.job_id, key)
        return self._module_snapshot(module)

    def remove_module(self, job_id: str, module_type: str, module_name: str) -> dict:
        job = self._get_job(job_id)
        key = f"{module_type}:{module_name}"

        process: Optional[Process] = None
        result_path: Optional[str] = None
        progress_path: Optional[str] = None
        removed_snapshot: Optional[dict] = None
        with job.lock:
            module = job.modules.get(key)
            if not module:
                return {"removed": False, "reason": "module_not_found"}
            removed_snapshot = self._module_snapshot(module)
            module.stop_requested = True
            process = module.process
            result_path = module.result_path
            progress_path = module.progress_path
            job.modules.pop(key, None)
            job.bump_revision()

        self._terminate_process(process)
        self._safe_remove_file(result_path)
        self._safe_remove_file(progress_path)
        self._persist_job(job)
        return {"removed": True, "module": removed_snapshot or {"module_type": module_type, "module_name": module_name, "status": "removed"}}

    def job_status(self, job_id: str) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            modules = [self._module_snapshot(m) for m in job.modules.values()]
            tls_decrypt = self._tls_decrypt_snapshot(job.tls_decrypt)
            running_modules = sum(1 for m in modules if m["status"] == "running")
            pending_modules = sum(1 for m in modules if m["status"] == "pending")
            completed_modules = sum(1 for m in modules if m["status"] == "completed")
            error_modules = sum(1 for m in modules if m["status"] == "error")
            active_modules = sum(1 for m in modules if m["status"] != "stopped")
            protocol_events = 0
            alerts = 0
            progress_percent = None
            delete_block_reason = self._project_delete_block_reason(
                status=job.status,
                pending_module_count=pending_modules,
                running_module_count=running_modules,
            )
            recommended_protocol_modules = self._recommend_protocol_modules(job.basic_protocol_distribution)
            if job.target_packet_count:
                progress_percent = round((job.packet_count / job.target_packet_count) * 100, 2)
            for module in job.modules.values():
                if module.status == "stopped":
                    continue
                if module.result:
                    summary = module.result.get("summary", {})
                    protocol_events += int(summary.get("protocol_event_count", 0))
                    alerts += int(summary.get("alert_count", 0))
            return {
                "ok": True,
                "job": {
                    "job_id": job.job_id,
                    "project_id": job.project_id,
                    "filename": job.filename,
                    "status": job.status,
                    "created_at": job.created_at,
                    "started_at": job.started_at,
                    "finished_at": job.finished_at,
                    "packet_count": job.packet_count,
                    "source_packet_count": job.source_packet_count,
                    "source_packet_count_estimated": job.source_packet_count_estimated,
                    "target_packet_count": job.target_packet_count,
                    "progress_updated_at": job.progress_updated_at,
                    "source_size_bytes": job.source_size_bytes,
                    "max_packets": job.max_packets,
                    "parse_error": job.parse_error,
                    "parse_mode": job.parse_mode,
                    "revision": job.revision,
                    "can_delete": delete_block_reason is None,
                    "delete_block_reason": delete_block_reason,
                    "progress": {
                        "parsed": job.packet_count,
                        "total": job.target_packet_count,
                        "percent": progress_percent,
                        "updated_at": job.progress_updated_at,
                    },
                    "overview": {
                        "packet_count": job.packet_count,
                        "target_packet_count": job.target_packet_count,
                        "progress_percent": progress_percent,
                        "basic_protocol_distribution": job.basic_protocol_distribution,
                        "recommended_protocol_modules": recommended_protocol_modules,
                        "active_modules": active_modules,
                        "running_modules": running_modules,
                        "pending_modules": pending_modules,
                        "completed_modules": completed_modules,
                        "error_modules": error_modules,
                        "protocol_event_count": protocol_events,
                        "alert_count": alerts,
                    },
                    "modules": modules,
                    "tls_decrypt": tls_decrypt,
                },
            }

    def _recommend_protocol_modules(self, distribution: dict[str, int]) -> list[dict]:
        protocol_catalog = {
            str(item.get("name") or ""): item
            for item in self.module_catalog.get("protocols", [])
        }
        rows: list[dict] = []
        for name, count in sorted((distribution or {}).items(), key=lambda item: (-int(item[1]), str(item[0]))):
            item = protocol_catalog.get(str(name))
            if not item:
                continue
            rows.append(
                {
                    "type": "protocol",
                    "name": str(name),
                    "count": int(count),
                    "description": str(item.get("description") or ""),
                }
            )
        return rows

    def job_results(self, job_id: str) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            modules = []
            for module in job.modules.values():
                item = self._module_snapshot(module)
                if module.result is not None:
                    item["result"] = module.result
                modules.append(item)
            return {
                "ok": True,
                "job_id": job.job_id,
                "revision": job.revision,
                "status": job.status,
                "modules": modules,
            }

    def parse_webshell_godzilla_key(
        self,
        job_id: str,
        *,
        key_text: str | None = None,
        key_file_name: str | None = None,
        key_file_bytes: bytes | None = None,
    ) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            module = job.modules.get("attack:WebShellDetector")
            module_result = dict(module.result or {}) if module and module.result else None
            db_path = str(job.db_path)
        if not module_result:
            raise HTTPError("当前项目还没有 WebShellDetector 结果")

        parser = GodzillaParser()
        contexts = self._collect_godzilla_session_contexts(module_result)
        if not contexts:
            raise HTTPError("当前样本没有可用的哥斯拉 SESSION/XOR/Base64 流量")

        detected_keys = self._collect_godzilla_detected_keys(contexts)
        candidates, source_meta = self._resolve_godzilla_key_candidates(
            key_text=key_text,
            key_file_name=key_file_name,
            key_file_bytes=key_file_bytes,
        )
        detected_candidates = self._expand_godzilla_key_candidates(
            detected_keys,
            raw_strategy_label="流量中检测到",
            derived_strategy_prefix="流量中检测到后派生",
        )
        if detected_candidates:
            if candidates:
                candidates = self._merge_godzilla_key_candidates(candidates, detected_candidates)
                source_meta = {
                    **source_meta,
                    "detected_key_count": len(detected_keys),
                }
            else:
                candidates = detected_candidates
                source_meta = {
                    "mode": "traffic_detected",
                    "label": detected_keys[0] if len(detected_keys) == 1 else f"{len(detected_keys)} 个密钥",
                    "input_count": len(detected_keys),
                    "detected_key_count": len(detected_keys),
                }
        if not candidates:
            raise HTTPError("请输入密钥、文件路径，或选择一个密钥文件")

        matched_key = None
        matched_context = None
        matched_candidate = None
        for context in contexts:
            for candidate in candidates:
                if parser.session_key_matches_markers(
                    pass_name=context["pass_param"],
                    left=context["marker_left"],
                    right=context["marker_right"],
                    key=str(candidate.get("value") or ""),
                ):
                    matched_key = str(candidate.get("value") or "")
                    matched_context = context
                    matched_candidate = candidate
                    break
            if matched_key is not None:
                break

        exact_match = matched_key is not None
        if matched_key is None and int(source_meta.get("input_count") or 0) == 1 and candidates:
            matched_candidate = self._preferred_godzilla_key_candidate(candidates)
            matched_key = str((matched_candidate or {}).get("value") or "")

        if matched_key is None:
            return {
                "matched": False,
                "exact_match": False,
                "candidate_source": source_meta,
                "candidate_count": len(candidates),
                "candidate_input_count": int(source_meta.get("input_count") or 0),
                "detected_key": detected_keys[0] if len(detected_keys) == 1 else "",
                "detected_keys": detected_keys,
                "detected_key_count": len(detected_keys),
                "contexts": contexts,
            }

        decoded_contexts: list[dict] = []
        for context in contexts:
            transactions = self._extract_godzilla_session_transactions(
                db_path=db_path,
                uri=context["uri"],
                pass_param=context["pass_param"],
            )
            entries: list[dict] = []
            for item in transactions:
                request_decoded = parser.decode_session_request_with_key(
                    body=item["request_body"],
                    key=matched_key,
                    pass_name=context["pass_param"],
                )
                response_decoded = parser.decode_session_response_with_key(
                    body=item["response_body"],
                    key=matched_key,
                ) if item.get("response_body") else None
                entries.append(
                    {
                        "request_packet_index": item.get("request_packet_index"),
                        "response_packet_index": item.get("response_packet_index"),
                        "request": request_decoded,
                        "response": response_decoded,
                    }
                )
            decoded_contexts.append(
                {
                    **context,
                    "entry_count": len(entries),
                    "entries": entries,
                }
            )

        return {
            "matched": True,
            "exact_match": exact_match,
            "matched_context": matched_context,
            "candidate_source": source_meta,
            "candidate_count": len(candidates),
            "candidate_input_count": int(source_meta.get("input_count") or 0),
            "detected_key": detected_keys[0] if len(detected_keys) == 1 else "",
            "detected_keys": detected_keys,
            "detected_key_count": len(detected_keys),
            "used_key": matched_key,
            "matched_input": str((matched_candidate or {}).get("source") or ""),
            "matched_derivation": str((matched_candidate or {}).get("strategy_label") or ""),
            "contexts": decoded_contexts,
        }

    def parse_sql_injection_bool(
        self,
        job_id: str,
        *,
        true_marker: str | None = None,
    ) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            module = job.modules.get("attack:SQLInjectionDetector")
            module_result = dict(module.result or {}) if module and module.result else None
            db_path = str(job.db_path)
        if not module_result:
            raise HTTPError("当前项目还没有 SQLInjectionDetector 结果")

        contexts = self._collect_sqli_bool_contexts(module_result)
        if not contexts:
            raise HTTPError("当前样本没有可用的 Bool 盲注流量")

        marker = str(true_marker or "").strip()
        response_texts = self._load_http_payloads_by_packet_indexes(
            db_path=db_path,
            packet_indexes=[
                int(entry["response_packet_index"])
                for context in contexts
                for entry in (context.get("entries") or [])
                if self._safe_int(entry.get("response_packet_index")) is not None
            ],
        ) if marker else {}

        parsed_contexts = [
            self._parse_sqli_bool_context(
                context,
                true_marker=marker,
                response_texts=response_texts,
            )
            for context in contexts
        ]
        best_context = max(parsed_contexts, key=lambda item: len(str(item.get("restored_text") or "")), default=None)
        return {
            "matched": any(str(item.get("restored_text") or "") for item in parsed_contexts),
            "analysis_mode": "marker_text" if marker else "response_length",
            "analysis_label": "响应正文包含指定字符串" if marker else "响应长度聚类",
            "true_marker": marker,
            "context_count": len(parsed_contexts),
            "best_text": str((best_context or {}).get("restored_text") or ""),
            "contexts": parsed_contexts,
        }

    def parse_tls_keylog(
        self,
        job_id: str,
        *,
        key_text: str | None = None,
        key_file_name: str | None = None,
        key_file_bytes: bytes | None = None,
    ) -> dict:
        job = self._get_job(job_id)
        normalized_keylog, source_meta = resolve_tls_keylog_text(
            key_text=key_text,
            key_file_name=key_file_name,
            key_file_bytes=key_file_bytes,
        )
        if not normalized_keylog:
            raise HTTPError("请输入 TLS keylog、本地文件路径，或选择一个 keylog 文件")

        return self._parse_tls_keylog_report(
            job=job,
            normalized_keylog=normalized_keylog,
            source_meta=source_meta,
            progress_callback=None,
        )

    def start_tls_decrypt_task(
        self,
        job_id: str,
        *,
        key_text: str | None = None,
        key_file_name: str | None = None,
        key_file_bytes: bytes | None = None,
    ) -> dict:
        job = self._get_job(job_id)
        normalized_keylog, source_meta = resolve_tls_keylog_text(
            key_text=key_text,
            key_file_name=key_file_name,
            key_file_bytes=key_file_bytes,
        )
        if not normalized_keylog:
            raise HTTPError("请输入 TLS keylog、本地文件路径，或选择一个 keylog 文件")

        key_hash = hashlib.sha1(normalized_keylog.encode("utf-8", errors="ignore")).hexdigest()[:12]
        with job.lock:
            current_task = job.tls_decrypt
            if current_task and current_task.status == "running":
                if current_task.key_hash == key_hash:
                    return {"ok": True, "task": self._tls_decrypt_snapshot(current_task)}
                raise HTTPError("已有 TLS 解密任务在运行，请等待当前任务完成")

            if current_task and current_task.status == "completed" and current_task.key_hash == key_hash and current_task.result:
                return {"ok": True, "task": self._tls_decrypt_snapshot(current_task)}

            total_packets = self._tls_decrypt_total_packets(job)
            started_at = _now_iso()
            task = TLSDecryptExecution(
                task_id=uuid4().hex,
                key_hash=key_hash,
                status="running",
                stage="initializing",
                message="已接收 keylog，准备重新解析 TLS / HTTP 流量",
                keylog_source=source_meta,
                created_at=started_at,
                started_at=started_at,
                updated_at=started_at,
                progress=_module_progress_payload(processed=0, total=total_packets),
            )
            job.tls_decrypt = task

        worker = Thread(
            target=self._run_tls_decrypt_task,
            args=(job_id, task.task_id, normalized_keylog, source_meta),
            daemon=True,
            name=f"tls-decrypt-{job_id[:6]}",
        )
        worker.start()
        return {"ok": True, "task": self._tls_decrypt_snapshot(task)}

    def tls_decrypt_status(self, job_id: str) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            task = job.tls_decrypt
            return {"ok": True, "task": self._tls_decrypt_snapshot(task)}

    def _run_tls_decrypt_task(
        self,
        job_id: str,
        task_id: str,
        normalized_keylog: str,
        source_meta: dict,
    ) -> None:
        job = self._get_job(job_id)

        def update_progress(stage: str, processed: int, total: int | None, message: str) -> None:
            with job.lock:
                task = job.tls_decrypt
                if task is None or task.task_id != task_id or task.status != "running":
                    return
                task.stage = stage
                task.message = message
                task.updated_at = _now_iso()
                task.progress = _module_progress_payload(processed=processed, total=total)

        total_packets = self._tls_decrypt_total_packets(job)
        update_progress("initializing", 0, total_packets, "正在校验 keylog 并准备 TLS 解密任务")

        try:
            result = self._parse_tls_keylog_report(
                job=job,
                normalized_keylog=normalized_keylog,
                source_meta=source_meta,
                progress_callback=update_progress,
            )
        except Exception as exc:
            with job.lock:
                task = job.tls_decrypt
                if task is None or task.task_id != task_id:
                    return
                task.status = "error"
                task.stage = "error"
                task.message = "TLS 解密失败"
                task.error = str(exc)
                task.finished_at = _now_iso()
                task.updated_at = task.finished_at
            return

        with job.lock:
            task = job.tls_decrypt
            if task is None or task.task_id != task_id:
                return
            task.status = "completed"
            task.stage = "completed"
            task.message = "TLS 解密完成"
            task.result = result
            task.finished_at = _now_iso()
            task.updated_at = task.finished_at
            total = task.progress.get("total")
            processed = int(result.get("summary", {}).get("packet_count") or task.progress.get("processed") or 0)
            task.progress = _module_progress_payload(processed=processed, total=total or processed)

        if self._publish_tls_http_module_result(
            job=job,
            tls_result=result,
            started_at=task.started_at,
            finished_at=task.finished_at,
        ):
            self._persist_job(job)

    def _parse_tls_keylog_report(
        self,
        *,
        job: AnalysisJob,
        normalized_keylog: str,
        source_meta: dict,
        progress_callback: Callable[[str, int, int | None, str], None] | None,
    ) -> dict:
        with job.lock:
            pcap_path = str(job.temp_path)
            max_packets = job.max_packets
            project_dir = str(job.project_dir or "")
            total_packets = self._tls_decrypt_total_packets(job)

        if progress_callback is not None:
            progress_callback("packet_read", 0, total_packets, "正在使用 TLS keylog 重新读取 pcap")

        service = build_default_pipeline_service()
        if project_dir:
            service.http_export_root = Path(project_dir) / "artifacts"
        report = service.analyze_file(
            pcap_path,
            max_packets=max_packets,
            enabled_protocols=["TLS", "HTTP"],
            enabled_attacks=[],
            tls_keylog_text=normalized_keylog,
            progress_callback=(
                (lambda stage, processed, total: progress_callback(
                    stage,
                    processed,
                    total,
                    "正在使用 TLS keylog 重新读取 pcap" if stage == "packet_read" else "正在汇总解密后的 TLS / HTTP 结果",
                ))
                if progress_callback is not None
                else None
            ),
            progress_total=total_packets,
        )

        if progress_callback is not None:
            progress_callback(
                "finalizing",
                int(report.packet_count or 0),
                total_packets or int(report.packet_count or 0),
                "正在提取 TLS / HTTP 结果并整理命中信息",
            )

        detailed_views = report.stats.get("detailed_views", {})
        tls_detail = dict(detailed_views.get("TLS") or {})
        http_detail = dict(detailed_views.get("HTTP") or {})
        requests = list(http_detail.get("requests") or [])
        uploads = list(http_detail.get("uploads") or [])
        flag_hits = self._extract_tls_flag_hits(requests=requests, uploads=uploads)
        return {
            "keylog_source": source_meta,
            "summary": {
                "packet_count": report.packet_count,
                "protocol_event_count": report.stats.get("protocol_event_count", 0),
                "tls_session_count": int(tls_detail.get("session_count") or 0),
                "http_request_count": int(http_detail.get("request_count") or 0),
                "http_upload_count": int(http_detail.get("upload_count") or 0),
                "flag_hit_count": len(flag_hits),
            },
            "tls_detail": tls_detail,
            "http_detail": http_detail,
            "flag_hits": flag_hits,
        }

    def _publish_tls_http_module_result(
        self,
        *,
        job: AnalysisJob,
        tls_result: dict,
        started_at: str | None,
        finished_at: str | None,
    ) -> bool:
        module_result = self._build_tls_http_module_result(tls_result)
        module_key = "protocol:HTTP"

        with job.lock:
            module = job.modules.get(module_key)
            if module is None:
                module = ModuleExecution(module_type="protocol", module_name="HTTP")
                job.modules[module_key] = module

            module.run_id += 1
            module.status = "completed"
            module.started_at = started_at or module.started_at or module.created_at
            module.finished_at = finished_at or _now_iso()
            module.error = None
            module.result = module_result
            module.stop_requested = False
            module.process = None
            module.watcher = None
            module.result_path = None
            module.progress_path = None
            job.bump_revision()

        return True

    def _build_tls_http_module_result(self, tls_result: dict) -> dict:
        http_detail = dict(tls_result.get("http_detail") or {})
        requests = list(http_detail.get("requests") or [])
        uploads = list(http_detail.get("uploads") or [])
        upload_points = list(http_detail.get("upload_points") or [])
        site_pages = list(http_detail.get("site_pages") or [])
        http_request_count = int(http_detail.get("request_count") or tls_result.get("summary", {}).get("http_request_count") or 0)
        http_upload_count = int(http_detail.get("upload_count") or tls_result.get("summary", {}).get("http_upload_count") or len(uploads) or 0)

        http_detail["requests"] = requests
        http_detail["uploads"] = uploads
        http_detail["upload_points"] = upload_points
        http_detail["site_pages"] = site_pages
        http_detail["request_count"] = http_request_count
        http_detail["upload_count"] = http_upload_count

        return {
            "module": {"type": "protocol", "name": "HTTP"},
            "summary": {
                "packet_count": int(tls_result.get("summary", {}).get("packet_count") or 0),
                "protocol_event_count": http_request_count,
                "alert_count": 0,
            },
            "detail": http_detail,
            "meta": {
                "source": "tls_decrypt",
                "label": "TLS 解密重跑",
                "keylog_source": tls_result.get("keylog_source") or {},
                "tls_summary": {
                    "tls_session_count": int(tls_result.get("summary", {}).get("tls_session_count") or 0),
                    "flag_hit_count": int(tls_result.get("summary", {}).get("flag_hit_count") or 0),
                    "http_upload_count": http_upload_count,
                },
                "flag_hits": list(tls_result.get("flag_hits") or []),
            },
            "debug": {
                "tls_decrypt": {
                    "http_request_count": http_request_count,
                    "http_upload_count": http_upload_count,
                }
            },
        }

    def _tls_decrypt_total_packets(self, job: AnalysisJob) -> int | None:
        for value in (job.packet_count, job.source_packet_count, job.target_packet_count):
            if isinstance(value, int) and value > 0:
                return value
        return None

    def _tls_decrypt_snapshot(self, task: TLSDecryptExecution | None) -> dict | None:
        if task is None:
            return None
        return {
            "task_id": task.task_id,
            "status": task.status,
            "stage": task.stage,
            "message": task.message,
            "keylog_source": task.keylog_source,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "finished_at": task.finished_at,
            "updated_at": task.updated_at,
            "elapsed_ms": _elapsed_ms(task.started_at, task.finished_at),
            "progress": dict(task.progress or {}),
            "error": task.error,
            "result": task.result,
        }

    def _extract_tls_flag_hits(self, *, requests: list[dict], uploads: list[dict]) -> list[str]:
        hits: list[str] = []
        seen: set[str] = set()
        for row in [*(requests or []), *(uploads or [])]:
            text = "\n".join(
                [
                    str(row.get("uri") or ""),
                    str(row.get("payload_preview") or ""),
                    str(row.get("preview") or ""),
                    str(row.get("upload_summary") or ""),
                ]
            )
            for match in re.findall(r"flag\{[^}\r\n]{1,256}\}", text, flags=re.IGNORECASE):
                flag = str(match).strip()
                if not flag or flag in seen:
                    continue
                seen.add(flag)
                hits.append(flag)
        return hits

    def _collect_godzilla_session_contexts(self, module_result: dict) -> list[dict]:
        alerts = module_result.get("alerts") or []
        rows_by_signature: dict[tuple[str, str, str, str], dict] = {}
        for alert in alerts:
            evidence = alert.get("evidence") or {}
            if str(evidence.get("stage") or "") != "request":
                continue
            if str(evidence.get("godzilla_variant_id") or "") != "godzilla_php_xor_base64_session_v1":
                continue
            markers = evidence.get("session_markers") or {}
            left = str(markers.get("left") or "").strip().lower()
            right = str(markers.get("right") or "").strip().lower()
            pass_param = str(markers.get("pass") or "pass").strip() or "pass"
            uri = self._normalize_http_path(str(evidence.get("uri") or ""))
            if not left or not right or not uri:
                continue
            signature = (uri, pass_param, left, right)
            request_packet_index = (alert.get("packet_indexes") or [None])[0]
            loader_param = str(evidence.get("loader_param") or "").strip()
            payload_name = str(evidence.get("payload_name") or "").strip()
            session_key = str(evidence.get("session_key") or "").strip()

            row = rows_by_signature.get(signature)
            if row is None:
                rows_by_signature[signature] = {
                    "uri": uri,
                    "pass_param": pass_param,
                    "marker_left": left,
                    "marker_right": right,
                    "loader_param": loader_param or None,
                    "payload_name": payload_name or None,
                    "session_key": session_key or None,
                    "request_packet_index": request_packet_index,
                }
                continue

            if not row.get("loader_param") and loader_param:
                row["loader_param"] = loader_param
            if not row.get("payload_name") and payload_name:
                row["payload_name"] = payload_name
            if not row.get("session_key") and session_key:
                row["session_key"] = session_key
            current_index = self._safe_int(row.get("request_packet_index"))
            next_index = self._safe_int(request_packet_index)
            if current_index is None or (next_index is not None and next_index < current_index):
                row["request_packet_index"] = request_packet_index

        rows = list(rows_by_signature.values())
        rows.sort(key=lambda item: self._safe_int(item.get("request_packet_index")) or -1)
        return rows

    def _collect_sqli_bool_contexts(self, module_result: dict) -> list[dict]:
        alerts = module_result.get("alerts") or []
        rows_by_signature: dict[tuple[str, str, str, str, str], dict] = {}
        seen_entries: set[tuple[tuple[str, str, str, str, str], int, int, int, str]] = set()

        for alert in alerts:
            evidence = alert.get("evidence") or {}
            if str(evidence.get("sqli_type") or "") != "bool_blind":
                continue
            method = str(evidence.get("method") or "").strip().upper()
            uri_path = self._normalize_http_path(str(evidence.get("uri_path") or evidence.get("uri") or ""))
            param_location = str(evidence.get("param_location") or "").strip() or "query"
            param_name = str(evidence.get("param_name") or "").strip()
            target_expression = str(evidence.get("target_expression") or "").strip()
            if not uri_path or not param_name:
                continue

            signature = (method, uri_path, param_location, param_name, target_expression)
            context = rows_by_signature.get(signature)
            if context is None:
                context = {
                    "method": method,
                    "uri_path": uri_path,
                    "uri": str(evidence.get("uri") or "").strip() or uri_path,
                    "host": str(evidence.get("host") or "").strip() or None,
                    "param_location": param_location,
                    "param_name": param_name,
                    "injection_point": str(evidence.get("injection_point") or "").strip() or f"{method} {uri_path} :: {param_location}.{param_name}",
                    "target_expression": target_expression or None,
                    "entries": [],
                }
                rows_by_signature[signature] = context

            request_packet_index = self._safe_int(evidence.get("request_packet_index"))
            response_packet_index = self._safe_int(evidence.get("response_packet_index"))
            position = self._safe_int(evidence.get("position"))
            candidate_char = str(evidence.get("candidate_char") or "")
            entry_signature = (
                signature,
                request_packet_index if request_packet_index is not None else -1,
                response_packet_index if response_packet_index is not None else -1,
                position if position is not None else -1,
                candidate_char,
            )
            if entry_signature in seen_entries:
                continue
            seen_entries.add(entry_signature)

            context["entries"].append(
                {
                    "request_packet_index": request_packet_index,
                    "response_packet_index": response_packet_index,
                    "request_frame_number": self._safe_int(evidence.get("request_frame_number")),
                    "response_frame_number": self._safe_int(evidence.get("response_frame_number")),
                    "position": position,
                    "candidate_char": candidate_char,
                    "response_length": self._safe_int(evidence.get("response_length")),
                    "response_status_code": str(evidence.get("response_status_code") or "").strip() or None,
                    "response_preview": str(evidence.get("response_preview") or "").strip(),
                    "response_bool_hint": str(evidence.get("response_bool_hint") or "").strip() or None,
                    "bool_expression": str(evidence.get("bool_expression") or "").strip(),
                }
            )

        rows = list(rows_by_signature.values())
        for row in rows:
            entries = list(row.get("entries") or [])
            entries.sort(
                key=lambda item: (
                    self._safe_int(item.get("position")) or -1,
                    self._safe_int(item.get("request_packet_index")) or -1,
                )
            )
            row["entries"] = entries
            row["entry_count"] = len(entries)
        rows.sort(key=lambda item: str(item.get("injection_point") or ""))
        return rows

    def _parse_sqli_bool_context(
        self,
        context: dict,
        *,
        true_marker: str,
        response_texts: dict[int, str],
    ) -> dict:
        entries = list(context.get("entries") or [])
        entries_by_position: dict[int, list[dict]] = {}
        for entry in entries:
            position = self._safe_int(entry.get("position"))
            if position is None or position <= 0:
                continue
            entries_by_position.setdefault(position, []).append(entry)

        length_info = self._infer_sqli_true_lengths(entries)
        true_lengths = set(length_info.get("true_lengths") or [])
        restored_chars: list[str] = []
        resolved_positions: list[dict] = []
        stop_reason = "completed"

        for position in sorted(entries_by_position):
            candidates = sorted(
                entries_by_position[position],
                key=lambda item: (
                    self._safe_int(item.get("request_packet_index")) or -1,
                    str(item.get("candidate_char") or ""),
                ),
            )
            if true_marker:
                true_candidates = [
                    item
                    for item in candidates
                    if true_marker and true_marker in str(
                        response_texts.get(
                            (
                                self._safe_int(item.get("response_packet_index"))
                                if self._safe_int(item.get("response_packet_index")) is not None
                                else -1
                            ),
                            "",
                        )
                    )
                ]
            else:
                true_candidates = [
                    item
                    for item in candidates
                    if self._safe_int(item.get("response_length")) in true_lengths
                ]

            resolved_char = str(true_candidates[0].get("candidate_char") or "") if len(true_candidates) == 1 else ""
            resolved_positions.append(
                {
                    "position": position,
                    "candidate_count": len(candidates),
                    "true_candidate_count": len(true_candidates),
                    "resolved": len(true_candidates) == 1,
                    "resolved_char": resolved_char,
                    "max_response_length": max(
                        [self._safe_int(item.get("response_length")) or 0 for item in candidates],
                        default=0,
                    ),
                    "true_request_packet_index": (true_candidates[0].get("request_packet_index") if len(true_candidates) == 1 else None),
                    "true_response_packet_index": (true_candidates[0].get("response_packet_index") if len(true_candidates) == 1 else None),
                    "true_response_length": (true_candidates[0].get("response_length") if len(true_candidates) == 1 else None),
                    "true_response_preview": str((true_candidates[0].get("response_preview") if len(true_candidates) == 1 else "") or ""),
                    "candidate_chars": [str(item.get("candidate_char") or "") for item in candidates[:12]],
                }
            )

            if len(true_candidates) == 1:
                restored_chars.append(resolved_char)
                continue
            if restored_chars:
                stop_reason = "ambiguous_true_candidate" if len(true_candidates) > 1 else "no_true_candidate"
                break

        restored_text = "".join(restored_chars)
        return {
            "method": context.get("method"),
            "uri_path": context.get("uri_path"),
            "uri": context.get("uri"),
            "host": context.get("host"),
            "param_location": context.get("param_location"),
            "param_name": context.get("param_name"),
            "injection_point": context.get("injection_point"),
            "target_expression": context.get("target_expression"),
            "entry_count": len(entries),
            "position_count": len(entries_by_position),
            "resolved_position_count": len(restored_text),
            "restored_text": restored_text,
            "stop_reason": stop_reason,
            "analysis_mode": "marker_text" if true_marker else "response_length",
            "true_marker": true_marker,
            "true_length_values": sorted(true_lengths),
            "length_strategy": str(length_info.get("strategy") or ""),
            "length_split_gap": length_info.get("split_gap"),
            "response_length_distribution": list(length_info.get("distribution") or []),
            "positions": resolved_positions,
        }

    def _infer_sqli_true_lengths(self, entries: list[dict]) -> dict:
        counter: Counter[int] = Counter()
        for entry in entries:
            length = self._safe_int(entry.get("response_length"))
            if length is not None and length > 0:
                counter[length] += 1

        lengths = sorted(counter.keys())
        if not lengths:
            return {"strategy": "empty", "true_lengths": [], "distribution": []}
        if len(lengths) == 1:
            return {
                "strategy": "single_length",
                "true_lengths": [lengths[0]],
                "distribution": [(str(length), count) for length, count in counter.most_common()],
            }

        gaps = [
            (lengths[idx + 1] - lengths[idx], lengths[idx], lengths[idx + 1])
            for idx in range(len(lengths) - 1)
        ]
        split_gap, lower, upper = max(gaps, key=lambda item: item[0])
        if split_gap >= 2:
            return {
                "strategy": "gap_split",
                "true_lengths": [value for value in lengths if value >= upper],
                "split_gap": split_gap,
                "distribution": [(str(length), count) for length, count in counter.most_common()],
            }

        max_length = max(lengths)
        return {
            "strategy": "max_window",
            "true_lengths": [value for value in lengths if value >= max_length - 1],
            "split_gap": split_gap,
            "distribution": [(str(length), count) for length, count in counter.most_common()],
        }

    def _load_http_payloads_by_packet_indexes(self, *, db_path: str, packet_indexes: list[int]) -> dict[int, str]:
        indexes = sorted({int(index) for index in packet_indexes if isinstance(index, int) and index >= 0})
        if not indexes:
            return {}

        conn = sqlite3.connect(db_path)
        try:
            rows: dict[int, str] = {}
            batch_size = 400
            for offset in range(0, len(indexes), batch_size):
                batch = indexes[offset: offset + batch_size]
                placeholders = ",".join("?" for _ in batch)
                cursor = conn.execute(
                    f"SELECT idx, packet_json FROM packets WHERE idx IN ({placeholders})",
                    batch,
                )
                for idx, packet_json in cursor.fetchall():
                    payload = json.loads(packet_json)
                    packet = PacketRecord(**payload)
                    http = packet.raw.get("http", {}) if isinstance(packet.raw, dict) else {}
                    body = str(packet.payload_text or http.get("file_data") or "")
                    rows[int(idx)] = body
            return rows
        finally:
            conn.close()

    def _collect_godzilla_detected_keys(self, contexts: list[dict]) -> list[str]:
        rows: list[str] = []
        seen: set[str] = set()
        for context in contexts:
            value = str(context.get("session_key") or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            rows.append(value)
        return rows

    def _extract_godzilla_session_transactions(self, *, db_path: str, uri: str, pass_param: str) -> list[dict]:
        target_uri = self._normalize_http_path(uri)
        requests: dict[int, dict] = {}
        transactions: list[dict] = []
        for packet in _stream_packets_from_db(db_path=db_path, fetch_size=self.module_db_fetch_size):
            http = packet.raw.get("http", {}) if isinstance(packet.raw, dict) else {}
            if not isinstance(http, dict):
                continue

            method = str(http.get("request_method") or "").upper()
            if method:
                request_uri = self._normalize_http_path(str(http.get("request_uri") or http.get("request_full_uri") or ""))
                if request_uri != target_uri:
                    continue
                request_body = str(packet.payload_text or http.get("file_data") or "")
                params = parse_qs(request_body, keep_blank_values=True)
                if pass_param not in params:
                    continue
                frame_number = packet.index + 1
                requests[frame_number] = {
                    "request_packet_index": packet.index,
                    "response_packet_index": None,
                    "request_body": request_body,
                    "response_body": "",
                }
                continue

            request_in = self._safe_int(http.get("request_in"))
            if request_in is None:
                continue
            pending = requests.get(request_in)
            if pending is None:
                continue
            transaction = {
                **pending,
                "response_packet_index": packet.index,
                "response_body": str(packet.payload_text or http.get("file_data") or ""),
            }
            transactions.append(transaction)
            requests.pop(request_in, None)

        if requests:
            transactions.extend(sorted(requests.values(), key=lambda item: int(item.get("request_packet_index") or -1)))
        transactions.sort(key=lambda item: int(item.get("request_packet_index") or -1))
        return transactions

    def _resolve_godzilla_key_candidates(
        self,
        *,
        key_text: str | None,
        key_file_name: str | None,
        key_file_bytes: bytes | None,
    ) -> tuple[list[dict[str, str]], dict]:
        if key_file_bytes:
            raw_candidates = self._split_godzilla_key_lines(key_file_bytes)
            return self._expand_godzilla_key_candidates(raw_candidates), {
                "mode": "upload_file",
                "label": key_file_name or "uploaded",
                "input_count": len(raw_candidates),
            }

        text = str(key_text or "").strip()
        if not text:
            return [], {"mode": "empty", "label": ""}

        file_path = self._normalize_local_input_path(text)
        if file_path and file_path.is_file():
            raw_candidates = self._split_godzilla_key_lines(file_path.read_bytes())
            return self._expand_godzilla_key_candidates(raw_candidates), {
                "mode": "path_file",
                "label": str(file_path),
                "input_count": len(raw_candidates),
            }

        lines = [item.strip() for item in text.splitlines() if item.strip()]
        if len(lines) > 1:
            return self._expand_godzilla_key_candidates(lines), {
                "mode": "inline_lines",
                "label": f"{len(lines)} lines",
                "input_count": len(lines),
            }
        return self._expand_godzilla_key_candidates([text]), {
            "mode": "single_key",
            "label": text,
            "input_count": 1,
        }

    def _split_godzilla_key_lines(self, payload: bytes) -> list[str]:
        for encoding in ("utf-8", "gb18030", "latin1"):
            try:
                text = payload.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            text = payload.decode("latin1", errors="replace")
        seen: set[str] = set()
        rows: list[str] = []
        for line in text.splitlines():
            candidate = line.strip().strip("\ufeff")
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            rows.append(candidate)
        return rows

    def _expand_godzilla_key_candidates(
        self,
        values: list[str],
        *,
        raw_strategy_label: str = "原始输入",
        derived_strategy_prefix: str = "",
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()

        def append(value: str, *, source: str, strategy: str, strategy_label: str) -> None:
            candidate = str(value or "").strip()
            if not candidate or candidate in seen:
                return
            seen.add(candidate)
            rows.append(
                {
                    "value": candidate,
                    "source": str(source or "").strip(),
                    "strategy": strategy,
                    "strategy_label": strategy_label,
                }
            )

        for raw in values:
            source = str(raw or "").strip()
            if not source:
                continue
            append(source, source=source, strategy="raw", strategy_label=raw_strategy_label)

            digest = hashlib.md5(source.encode("utf-8", errors="ignore")).hexdigest().lower()
            prefix = f"{derived_strategy_prefix} " if derived_strategy_prefix else ""
            append(digest[:16], source=source, strategy="md5_first16", strategy_label=f"{prefix}MD5 前 16 位")
            append(digest, source=source, strategy="md5_full32", strategy_label=f"{prefix}完整 MD5 32 位")
            append(digest[16:], source=source, strategy="md5_last16", strategy_label=f"{prefix}MD5 后 16 位")

        return rows

    def _merge_godzilla_key_candidates(
        self,
        primary: list[dict[str, str]],
        extra: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()
        for candidate in [*(primary or []), *(extra or [])]:
            value = str(candidate.get("value") or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            rows.append(candidate)
        return rows

    def _preferred_godzilla_key_candidate(self, candidates: list[dict[str, str]]) -> dict[str, str] | None:
        if not candidates:
            return None

        for strategy in ("raw", "md5_first16", "md5_full32", "md5_last16"):
            for candidate in candidates:
                value = str(candidate.get("value") or "").strip()
                if str(candidate.get("strategy") or "") != strategy:
                    continue
                if strategy == "raw" and self._looks_like_godzilla_key(value):
                    return candidate
                if strategy != "raw":
                    return candidate

        return candidates[0]

    def _looks_like_godzilla_key(self, value: str) -> bool:
        text = str(value or "").strip()
        return bool(text) and len(text) in {16, 32} and all(ch in "0123456789abcdefABCDEF" for ch in text)

    def _normalize_local_input_path(self, raw_path: str) -> Path | None:
        return normalize_local_input_path(raw_path)

    def _normalize_http_path(self, raw_uri: str) -> str:
        parsed = urlsplit(str(raw_uri or ""))
        return parsed.path or str(raw_uri or "")

    def _safe_int(self, value: object) -> int | None:
        try:
            return int(str(value).strip())
        except Exception:
            return None

    def shutdown(self) -> None:
        with self.lock:
            if self._shutdown_done:
                return
            self._shutdown_done = True
            jobs = list(self.jobs.values())

        for job in jobs:
            with job.lock:
                modules = list(job.modules.values())
                temp_path = job.temp_path
                db_path = job.db_path
                parse_thread = job.parse_thread
                managed_temp = job.managed_temp
                project_dir = job.project_dir

            for module in modules:
                self._terminate_process(module.process)
                self._safe_remove_file(module.result_path)
                self._safe_remove_file(module.progress_path)

            with job.lock:
                if job.status == "parsing":
                    job.status = "error"
                    job.parse_error = job.parse_error or "服务关闭前基础解析未完成。"
                    job.finished_at = _now_iso()
                    job.progress_updated_at = job.finished_at
                for module in job.modules.values():
                    if module.status == "running":
                        module.status = "stopped"
                        module.finished_at = _now_iso()
                        module.error = None
                        module.result = None
                    module.process = None
                    module.watcher = None
                    module.result_path = None
                    module.progress_path = None
            self._persist_job(job)

            if parse_thread and parse_thread.is_alive():
                parse_thread.join(timeout=1.0)

            if managed_temp and not project_dir:
                self._safe_remove_file(temp_path)
            if not job.project_dir:
                self._safe_remove_file(db_path)

    def _run_base_parse(self, job_id: str) -> None:
        job = self._get_job(job_id)
        with job.lock:
            job.status = "parsing"
            job.started_at = _now_iso()
            job.progress_updated_at = job.started_at
            job.bump_revision()

        conn = sqlite3.connect(job.db_path, timeout=60)
        batch: list[tuple[int, str]] = []
        parsed_count = 0
        basic_protocol_counter: Counter[str] = Counter()
        split_files: list[str] = []
        split_dir: Optional[str] = None

        try:
            self._initialize_packet_progress(job)
            if self._should_parallel_parse(job):
                parsed_count, split_files, split_dir, basic_protocol_counter = self._run_parallel_base_parse(
                    job=job,
                    conn=conn,
                    batch=batch,
                )
            else:
                parsed_count, basic_protocol_counter = self._run_sequential_base_parse(job=job, conn=conn, batch=batch)

            with job.lock:
                job.packet_count = parsed_count
                job.status = "parsed"
                job.finished_at = _now_iso()
                job.progress_updated_at = job.finished_at
                job.basic_protocol_distribution = _normalize_basic_protocol_counter(basic_protocol_counter)
                job.bump_revision()
        except Exception as exc:
            with job.lock:
                job.status = "error"
                job.parse_error = str(exc)
                job.finished_at = _now_iso()
                job.progress_updated_at = job.finished_at
                job.bump_revision()
            self._persist_job(job)
            return
        finally:
            conn.close()
            for path in split_files:
                self._safe_remove_file(path)
            if split_dir:
                try:
                    os.rmdir(split_dir)
                except OSError:
                    pass

        self._persist_job(job)
        self._start_pending_modules(job_id)

    def _initialize_packet_progress(self, job: AnalysisJob) -> None:
        source_packet_count: Optional[int] = None
        source_packet_count_estimated = False
        try:
            loader = PcapLoader(job.temp_path)
            source_packet_count, source_packet_count_estimated = loader.get_packet_count(allow_estimate=False)
        except Exception:
            source_packet_count = None
            source_packet_count_estimated = False

        target_packet_count = job.max_packets
        if source_packet_count is not None:
            target_packet_count = (
                min(source_packet_count, job.max_packets) if job.max_packets is not None else source_packet_count
            )

        with job.lock:
            job.source_packet_count = source_packet_count
            job.source_packet_count_estimated = source_packet_count_estimated
            job.target_packet_count = target_packet_count
            job.progress_updated_at = _now_iso()
            job.bump_revision()

    def _update_parse_progress(
        self,
        job: AnalysisJob,
        parsed_count: int,
        *,
        force_revision: bool = False,
    ) -> float:
        now_monotonic = time.monotonic()
        now_iso = _now_iso()
        should_bump_revision = force_revision

        with job.lock:
            last_updated_at = job.progress_updated_at
            job.packet_count = parsed_count
            job.progress_updated_at = now_iso
            if not should_bump_revision:
                should_bump_revision = parsed_count == 0 or last_updated_at is None
            if should_bump_revision:
                job.bump_revision()

        return now_monotonic

    def _touch_parse_progress(self, job: AnalysisJob) -> None:
        with job.lock:
            job.progress_updated_at = _now_iso()
            job.bump_revision()

    def _increment_parse_progress(self, job: AnalysisJob, delta: int) -> None:
        if delta <= 0:
            return

        with job.lock:
            job.packet_count += delta
            job.progress_updated_at = _now_iso()

    def _should_parallel_parse(self, job: AnalysisJob) -> bool:
        try:
            file_size = os.path.getsize(job.temp_path)
        except OSError:
            return False
        return (
            file_size >= self.parallel_parse_threshold_bytes
            and (os.cpu_count() or 1) > 1
            and job.max_packets is None
        )

    def _run_sequential_base_parse(
        self,
        *,
        job: AnalysisJob,
        conn: sqlite3.Connection,
        batch: list[tuple[int, str]],
    ) -> tuple[int, Counter[str]]:
        parser = self.pipeline_service.packet_parser
        parsed_count = 0
        basic_protocol_counter: Counter[str] = Counter()
        last_revision_refresh = time.monotonic()
        with job.lock:
            job.parse_mode = "sequential"
        for packet in parser.parse_file(job.temp_path, tls_keylog_text=job.tls_keylog_text):
            with job.lock:
                if job.max_packets is not None and parsed_count >= job.max_packets:
                    break

            batch.append((packet.index, _packet_record_to_json(packet)))
            parsed_count += 1
            _update_basic_protocol_counter(basic_protocol_counter, packet)

            if len(batch) >= self.db_flush_size:
                self._flush_packet_batch(conn, batch)

            force_revision = parsed_count % 200 == 0 or (time.monotonic() - last_revision_refresh) >= 1.0
            progress_mark = self._update_parse_progress(job, parsed_count, force_revision=force_revision)
            if force_revision:
                last_revision_refresh = progress_mark

        self._flush_packet_batch(conn, batch)
        return parsed_count, basic_protocol_counter

    def _merge_chunk_output(
        self,
        *,
        conn: sqlite3.Connection,
        batch: list[tuple[int, str]],
        output_path: str,
        start_index: int,
    ) -> int:
        next_index = start_index
        with open(output_path, "r", encoding="utf-8") as fp:
            for line in fp:
                packet_json = line.rstrip("\n")
                if not packet_json:
                    continue
                batch.append((next_index, packet_json))
                next_index += 1
                if len(batch) >= self.db_flush_size:
                    self._flush_packet_batch(conn, batch)
        return next_index

    def _run_parallel_base_parse(
        self,
        *,
        job: AnalysisJob,
        conn: sqlite3.Connection,
        batch: list[tuple[int, str]],
    ) -> tuple[int, list[str], Optional[str], Counter[str]]:
        loader = PcapLoader(job.temp_path)
        split_files = loader.split_pcap(target_chunk_size_mb=self.split_target_mb)
        split_files = [path for path in split_files if path != job.temp_path]

        if not split_files:
            with job.lock:
                job.parse_mode = "sequential"
            parsed_count, basic_protocol_counter = self._run_sequential_base_parse(job=job, conn=conn, batch=batch)
            return parsed_count, [], None, basic_protocol_counter

        worker_count = min(len(split_files), self.parallel_parse_max_workers, max(2, os.cpu_count() or 2))
        parsed_count = 0
        basic_protocol_counter: Counter[str] = Counter()
        split_dir = os.path.dirname(split_files[0]) if split_files else None
        chunk_output_paths = [
            os.path.join(split_dir or tempfile.gettempdir(), f".parsed_chunk_{chunk_index:05d}.jsonl")
            for chunk_index, _ in enumerate(split_files)
        ]
        with job.lock:
            job.parse_mode = "parallel"
            job.packet_count = 0

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            pending = {
                executor.submit(
                    _parse_packet_chunk,
                    split_file,
                    progress_callback=lambda delta, target_job=job: self._increment_parse_progress(target_job, delta),
                    output_path=output_path,
                    tls_keylog_text=job.tls_keylog_text,
                )
                : chunk_index
                for chunk_index, (split_file, output_path) in enumerate(zip(split_files, chunk_output_paths))
            }
            completed_results: dict[int, dict] = {}
            next_chunk_index = 0
            while pending:
                done, _ = wait(tuple(pending), timeout=1.0, return_when=FIRST_COMPLETED)
                if not done:
                    self._touch_parse_progress(job)
                    continue

                for future in done:
                    chunk_index = pending.pop(future)
                    completed_results[chunk_index] = future.result()

                while next_chunk_index in completed_results:
                    result = completed_results.pop(next_chunk_index)
                    _merge_basic_protocol_counter(basic_protocol_counter, result.get("basic_protocol_distribution"))
                    output_path = str(result.get("output_path") or "")
                    if output_path:
                        parsed_count = self._merge_chunk_output(
                            conn=conn,
                            batch=batch,
                            output_path=output_path,
                            start_index=parsed_count,
                        )
                        self._safe_remove_file(output_path)
                    next_chunk_index += 1

        self._flush_packet_batch(conn, batch)
        for output_path in chunk_output_paths:
            self._safe_remove_file(output_path)
        return parsed_count, split_files, split_dir, basic_protocol_counter

    def _flush_packet_batch(self, conn: sqlite3.Connection, batch: list[tuple[int, str]]) -> None:
        if not batch:
            return
        conn.executemany(
            "INSERT OR REPLACE INTO packets (idx, packet_json) VALUES (?, ?)",
            batch,
        )
        conn.commit()
        batch.clear()

    def _start_pending_modules(self, job_id: str) -> None:
        job = self._get_job(job_id)
        with job.lock:
            pending_keys = [
                key for key, module in job.modules.items() if module.status == "pending" and not module.stop_requested
            ]
        for key in pending_keys:
            self._submit_module(job_id, key)

    def _submit_module(self, job_id: str, module_key: str) -> None:
        job = self._get_job(job_id)
        with job.lock:
            module = job.modules.get(module_key)
            if not module or module.stop_requested:
                return

            module.status = "running"
            module.started_at = _now_iso()
            module.finished_at = None
            module.error = None
            module.result = None
            module.stop_requested = False
            module.run_id += 1
            run_id = module.run_id

            fd, result_path = tempfile.mkstemp(prefix=f"module_{job.job_id[:8]}_", suffix=".json")
            os.close(fd)
            module.result_path = result_path
            fd, progress_path = tempfile.mkstemp(prefix=f"module_{job.job_id[:8]}_", suffix=".progress.json")
            os.close(fd)
            module.progress_path = progress_path

            process = Process(
                target=_module_worker,
                kwargs={
                    "db_path": job.db_path,
                    "module_type": module.module_type,
                    "module_name": module.module_name,
                    "source": job.temp_path or job.filename,
                    "result_path": result_path,
                    "fetch_size": self.module_db_fetch_size,
                    "progress_path": progress_path,
                    "total_packets": job.packet_count,
                },
                daemon=True,
                name=f"mod-{job.job_id[:6]}-{module.module_name}",
            )
            module.process = process
            job.bump_revision()

        process.start()

        watcher = Thread(
            target=self._watch_module_process,
            args=(job_id, module_key, run_id),
            daemon=True,
            name=f"watch-{job.job_id[:6]}-{module.module_name}",
        )
        with job.lock:
            module = job.modules.get(module_key)
            if module and module.run_id == run_id:
                module.watcher = watcher
        self._persist_job(job)
        watcher.start()

    def _watch_module_process(self, job_id: str, module_key: str, run_id: int) -> None:
        job = self._get_job(job_id)
        with job.lock:
            module = job.modules.get(module_key)
            if not module or module.run_id != run_id:
                return
            process = module.process
            result_path = module.result_path
            progress_path = module.progress_path

        if process:
            process.join()

        payload = None
        if result_path and os.path.exists(result_path):
            try:
                with open(result_path, "r", encoding="utf-8") as fp:
                    payload = json.load(fp)
            except Exception:
                payload = {"ok": False, "error": "结果文件读取失败"}

        with job.lock:
            module = job.modules.get(module_key)
            if not module or module.run_id != run_id:
                self._safe_remove_file(result_path)
                self._safe_remove_file(progress_path)
                return

            module.process = None
            module.watcher = None

            if module.stop_requested:
                module.status = "stopped"
                module.finished_at = _now_iso()
                module.error = None
                module.result = None
            elif payload and payload.get("ok"):
                module.status = "completed"
                module.finished_at = _now_iso()
                module.error = None
                module.result = payload.get("result")
            else:
                module.status = "error"
                module.finished_at = _now_iso()
                if payload and payload.get("error"):
                    module.error = str(payload["error"])
                elif process is not None and process.exitcode is not None:
                    module.error = f"模块进程退出码: {process.exitcode}"
                else:
                    module.error = "模块执行失败"
                module.result = None

            module.result_path = None
            module.progress_path = None
            job.bump_revision()

        self._persist_job(job)
        self._safe_remove_file(result_path)
        self._safe_remove_file(progress_path)

    def _validate_module(self, module_type: str, module_name: str) -> None:
        if module_type == "protocol":
            if module_name not in self.protocol_names:
                raise HTTPError(f"未知协议模块: {module_name}")
            return
        if module_type == "attack":
            if module_name not in self.attack_names:
                raise HTTPError(f"未知攻击模块: {module_name}")
            return
        raise HTTPError(f"未知模块类型: {module_type}")

    def _get_job(self, job_id: str) -> AnalysisJob:
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                for item in self.jobs.values():
                    if item.project_id == job_id:
                        job = item
                        break
        if not job:
            raise HTTPError(f"任务不存在: {job_id}")
        return job

    def _module_snapshot(self, module: ModuleExecution) -> dict:
        progress = None
        if module.status == "running":
            progress = _read_module_progress(module.progress_path)
        return {
            "module_type": module.module_type,
            "module_name": module.module_name,
            "status": module.status,
            "created_at": module.created_at,
            "started_at": module.started_at,
            "finished_at": module.finished_at,
            "error": module.error,
            "progress": progress,
        }

    def _project_delete_block_reason(
        self,
        *,
        status: str,
        pending_module_count: int,
        running_module_count: int,
    ) -> Optional[str]:
        if status in {"queued", "parsing"}:
            return "基础解析尚未完成"
        if running_module_count > 0:
            return f"仍有 {running_module_count} 个模块运行中"
        if pending_module_count > 0:
            return f"仍有 {pending_module_count} 个模块待启动"
        return None

    def _terminate_process(self, process: Optional[Process]) -> None:
        if process is None:
            return
        if process.pid is None:
            return
        if not process.is_alive():
            try:
                process.join(timeout=0.2)
            except Exception:
                return
            return
        process.terminate()
        try:
            process.join(timeout=1.0)
        except Exception:
            return
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            try:
                process.join(timeout=1.0)
            except Exception:
                return

    def _safe_remove_file(self, path: Optional[str]) -> None:
        if not path:
            return
        try:
            os.remove(path)
        except OSError:
            return


class HTTPError(Exception):
    pass
