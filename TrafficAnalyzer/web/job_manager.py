from __future__ import annotations

import atexit
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from multiprocessing import Process
import os
import sqlite3
import tempfile
from threading import RLock, Thread
import time
import traceback
from typing import Callable, Dict, Iterator, Optional
from uuid import uuid4

from TrafficAnalyzer.config import LARGE_PCAP_THRESHOLD
from TrafficAnalyzer.core.loader import PcapLoader
from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.parsers.packet_parser import PacketParser
from TrafficAnalyzer.pipeline import build_default_pipeline_service


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _parse_packet_chunk(
    pcap_path: str,
    progress_callback: Callable[[int], None] | None = None,
    progress_interval: int = 1000,
) -> dict:
    parser = PacketParser()
    records: list[dict] = []
    pending_progress = 0
    last_progress_at = time.monotonic()

    for record in parser.parse_file(pcap_path):
        records.append(asdict(record))
        pending_progress += 1

        should_report = pending_progress >= progress_interval or (time.monotonic() - last_progress_at) >= 1.0
        if progress_callback and should_report:
            progress_callback(pending_progress)
            pending_progress = 0
            last_progress_at = time.monotonic()

    if progress_callback and pending_progress:
        progress_callback(pending_progress)

    return {
        "pcap_path": pcap_path,
        "packet_count": len(records),
        "records": records,
    }


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
    return {
        "summary": {
            "packet_count": report.packet_count,
            "protocol_event_count": report.stats.get("protocol_event_count", 0),
            "alert_count": report.stats.get("alert_count", 0),
        },
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
                _merge_protocol_detail(detail, top_counters, partial.get("detail", {}))
                _merge_debug(debug_acc, partial.get("debug", {}))

        for key, counter in top_counters.items():
            limit = 20 if key == "top_func_codes" else 30
            detail[key] = counter.most_common(limit)

        return {
            "module": {"type": module_type, "name": module_name},
            "summary": summary,
            "detail": detail,
            "debug": _finalize_debug(debug_acc),
        }

    alerts: list[dict] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        for partial in executor.map(_analyze_chunk_map, tasks):
            part_summary = partial.get("summary", {})
            summary["packet_count"] += int(part_summary.get("packet_count", 0))
            summary["protocol_event_count"] += int(part_summary.get("protocol_event_count", 0))
            summary["alert_count"] += int(part_summary.get("alert_count", 0))
            alerts.extend(partial.get("alerts", []))
            _merge_debug(debug_acc, partial.get("debug", {}))

    return {
        "module": {"type": module_type, "name": module_name},
        "summary": summary,
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
) -> None:
    try:
        map_reducible_attacks = {"SQLInjectionDetector", "BehinderDetector"}
        enable_mapreduce = module_type == "protocol" or (
            module_type == "attack" and module_name in map_reducible_attacks
        )

        if enable_mapreduce:
            result = _run_mapreduce_worker(
                db_path=db_path,
                module_type=module_type,
                module_name=module_name,
                source=source,
                fetch_size=fetch_size,
            )
            _write_json_atomic(result_path, {"ok": True, "result": result})
            return

        service = build_default_pipeline_service()
        packet_stream = _stream_packets_from_db(db_path=db_path, fetch_size=fetch_size)

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
            result = {
                "module": {"type": module_type, "name": module_name},
                "summary": {
                    "packet_count": report.packet_count,
                    "protocol_event_count": report.stats.get("protocol_event_count", 0),
                    "alert_count": report.stats.get("alert_count", 0),
                },
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

    @property
    def key(self) -> str:
        return f"{self.module_type}:{self.module_name}"


@dataclass
class AnalysisJob:
    job_id: str
    filename: str
    temp_path: str
    db_path: str
    max_packets: Optional[int]
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
    revision: int = 0
    modules: Dict[str, ModuleExecution] = field(default_factory=dict)
    parse_thread: Optional[Thread] = field(default=None, repr=False)
    lock: RLock = field(default_factory=RLock, repr=False)

    def bump_revision(self) -> None:
        self.revision += 1


class JobManager:
    def __init__(
        self,
        db_flush_size: int = 500,
        module_db_fetch_size: int = 2000,
        parallel_parse_threshold_bytes: int = LARGE_PCAP_THRESHOLD,
        split_target_mb: float = 64.0,
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
        self.split_target_mb = split_target_mb
        self._shutdown_done = False
        atexit.register(self.shutdown)

    def list_modules(self) -> dict:
        return self.module_catalog

    def create_job(
        self,
        filename: str,
        temp_path: str,
        max_packets: Optional[int],
        managed_temp: bool = True,
    ) -> str:
        job_id = uuid4().hex
        db_file = tempfile.NamedTemporaryFile(prefix=f"traffic_{job_id[:8]}_", suffix=".sqlite3", delete=False)
        db_path = db_file.name
        db_file.close()
        _init_packet_db(db_path)

        job = AnalysisJob(
            job_id=job_id,
            filename=filename,
            temp_path=temp_path,
            db_path=db_path,
            max_packets=max_packets,
            managed_temp=managed_temp,
        )
        parse_thread = Thread(target=self._run_base_parse, args=(job_id,), daemon=True, name=f"parse-{job_id[:6]}")
        job.parse_thread = parse_thread

        with self.lock:
            self.jobs[job_id] = job

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
        return self._module_snapshot(module)

    def remove_module(self, job_id: str, module_type: str, module_name: str) -> dict:
        job = self._get_job(job_id)
        key = f"{module_type}:{module_name}"

        process: Optional[Process] = None
        result_path: Optional[str] = None
        with job.lock:
            module = job.modules.get(key)
            if not module:
                return {"removed": False, "reason": "module_not_found"}
            module.stop_requested = True
            module.status = "stopped"
            module.finished_at = _now_iso()
            module.error = None
            module.result = None
            process = module.process
            result_path = module.result_path
            job.bump_revision()

        self._terminate_process(process)
        self._safe_remove_file(result_path)
        return {"removed": True, "module": self._module_snapshot(module)}

    def job_status(self, job_id: str) -> dict:
        job = self._get_job(job_id)
        with job.lock:
            modules = [self._module_snapshot(m) for m in job.modules.values()]
            running_modules = sum(1 for m in modules if m["status"] == "running")
            completed_modules = sum(1 for m in modules if m["status"] == "completed")
            active_modules = sum(1 for m in modules if m["status"] != "stopped")
            protocol_events = 0
            alerts = 0
            progress_percent = None
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
                    "max_packets": job.max_packets,
                    "parse_error": job.parse_error,
                    "parse_mode": job.parse_mode,
                    "revision": job.revision,
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
                        "active_modules": active_modules,
                        "running_modules": running_modules,
                        "completed_modules": completed_modules,
                        "protocol_event_count": protocol_events,
                        "alert_count": alerts,
                    },
                    "modules": modules,
                },
            }

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

            for module in modules:
                self._terminate_process(module.process)
                self._safe_remove_file(module.result_path)

            if parse_thread and parse_thread.is_alive():
                parse_thread.join(timeout=1.0)

            if managed_temp:
                self._safe_remove_file(temp_path)
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
        split_files: list[str] = []
        split_dir: Optional[str] = None

        try:
            self._initialize_packet_progress(job)
            if self._should_parallel_parse(job):
                parsed_count, split_files, split_dir = self._run_parallel_base_parse(
                    job=job,
                    conn=conn,
                    batch=batch,
                )
            else:
                parsed_count = self._run_sequential_base_parse(job=job, conn=conn, batch=batch)

            with job.lock:
                job.packet_count = parsed_count
                job.status = "parsed"
                job.finished_at = _now_iso()
                job.progress_updated_at = job.finished_at
                job.bump_revision()
        except Exception as exc:
            with job.lock:
                job.status = "error"
                job.parse_error = str(exc)
                job.finished_at = _now_iso()
                job.progress_updated_at = job.finished_at
                job.bump_revision()
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
            if job.managed_temp:
                self._safe_remove_file(job.temp_path)

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
    ) -> int:
        parser = self.pipeline_service.packet_parser
        parsed_count = 0
        last_revision_refresh = time.monotonic()
        with job.lock:
            job.parse_mode = "sequential"
        for packet in parser.parse_file(job.temp_path):
            with job.lock:
                if job.max_packets is not None and parsed_count >= job.max_packets:
                    break

            batch.append((packet.index, json.dumps(asdict(packet), ensure_ascii=False)))
            parsed_count += 1

            if len(batch) >= self.db_flush_size:
                self._flush_packet_batch(conn, batch)

            force_revision = parsed_count % 200 == 0 or (time.monotonic() - last_revision_refresh) >= 1.0
            progress_mark = self._update_parse_progress(job, parsed_count, force_revision=force_revision)
            if force_revision:
                last_revision_refresh = progress_mark

        self._flush_packet_batch(conn, batch)
        return parsed_count

    def _run_parallel_base_parse(
        self,
        *,
        job: AnalysisJob,
        conn: sqlite3.Connection,
        batch: list[tuple[int, str]],
    ) -> tuple[int, list[str], Optional[str]]:
        loader = PcapLoader(job.temp_path)
        split_files = loader.split_pcap(target_chunk_size_mb=self.split_target_mb)
        split_files = [path for path in split_files if path != job.temp_path]

        if not split_files:
            with job.lock:
                job.parse_mode = "sequential"
            return self._run_sequential_base_parse(job=job, conn=conn, batch=batch), [], None

        worker_count = min(len(split_files), max(2, os.cpu_count() or 2))
        parsed_count = 0
        split_dir = os.path.dirname(split_files[0]) if split_files else None
        with job.lock:
            job.parse_mode = "parallel"
            job.packet_count = 0

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            pending = {
                executor.submit(
                    _parse_packet_chunk,
                    split_file,
                    progress_callback=lambda delta, target_job=job: self._increment_parse_progress(target_job, delta),
                )
                for split_file in split_files
            }
            while pending:
                done, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                if not done:
                    self._touch_parse_progress(job)
                    continue

                for future in done:
                    result = future.result()
                    records = result.get("records", [])
                    for record in records:
                        record["index"] = parsed_count
                        batch.append((parsed_count, json.dumps(record, ensure_ascii=False)))
                        parsed_count += 1

                        if len(batch) >= self.db_flush_size:
                            self._flush_packet_batch(conn, batch)

        self._flush_packet_batch(conn, batch)
        return parsed_count, split_files, split_dir

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

            process = Process(
                target=_module_worker,
                kwargs={
                    "db_path": job.db_path,
                    "module_type": module.module_type,
                    "module_name": module.module_name,
                    "source": job.filename,
                    "result_path": result_path,
                    "fetch_size": self.module_db_fetch_size,
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
        watcher.start()

    def _watch_module_process(self, job_id: str, module_key: str, run_id: int) -> None:
        job = self._get_job(job_id)
        with job.lock:
            module = job.modules.get(module_key)
            if not module or module.run_id != run_id:
                return
            process = module.process
            result_path = module.result_path

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
            job.bump_revision()

        self._safe_remove_file(result_path)

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
        if not job:
            raise HTTPError(f"任务不存在: {job_id}")
        return job

    def _module_snapshot(self, module: ModuleExecution) -> dict:
        return {
            "module_type": module.module_type,
            "module_name": module.module_name,
            "status": module.status,
            "created_at": module.created_at,
            "started_at": module.started_at,
            "finished_at": module.finished_at,
            "error": module.error,
        }

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
