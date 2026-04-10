from __future__ import annotations

import base64
import hashlib
import mimetypes
from collections import Counter, deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import re
import time
from typing import Any, Callable
from typing import Iterable, List, Optional
from urllib.parse import unquote, urlsplit

from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AnalysisReport, AttackAlert, PacketRecord, ProtocolEvent
from TrafficAnalyzer.parsers import PacketParser
from TrafficAnalyzer.protocols import BaseProtocolParser, build_protocol_parsers
from TrafficAnalyzer.utils.artifact_utils import artifact_raw_url, artifact_viewer_url


class PipelineService:
    """
    三阶段流量分析流水线:
    1) 包解析
    2) 协议解析
    3) 攻击检测
    """

    def __init__(
        self,
        packet_parser: Optional[PacketParser] = None,
        protocol_parsers: Optional[List[BaseProtocolParser]] = None,
        attack_detectors: Optional[List[BaseAttackDetector]] = None,
    ):
        self.packet_parser = packet_parser or PacketParser()
        self.protocol_parsers = protocol_parsers or build_protocol_parsers()
        self.attack_detectors = attack_detectors or build_attack_detectors()
        self.source = "in-memory"
        self.http_export_root = Path.cwd() / "data" / "webshell_exports"

    def analyze_file(
        self,
        pcap_path: str,
        max_packets: Optional[int] = None,
        enabled_protocols: Optional[List[str]] = None,
        enabled_attacks: Optional[List[str]] = None,
        tls_keylog_text: str | None = None,
        tls_keylog_file: str | None = None,
        progress_callback: Callable[[str, int, int | None], None] | None = None,
        progress_total: int | None = None,
    ) -> AnalysisReport:
        selected_parsers = self._select_protocol_parsers(enabled_protocols)
        selected_detectors = self._select_attack_detectors(enabled_attacks)
        selected_parsers = self._expand_protocol_parsers_for_attacks(selected_parsers, selected_detectors)
        packets = self.packet_parser.parse_file(
            pcap_path,
            protocol_parsers=selected_parsers,
            tls_keylog_text=tls_keylog_text,
            tls_keylog_file=tls_keylog_file,
        )
        return self.analyze_packets(
            packets,
            source=pcap_path,
            max_packets=max_packets,
            enabled_protocols=[parser.name for parser in selected_parsers],
            enabled_attacks=[detector.name for detector in selected_detectors],
            progress_callback=progress_callback,
            progress_total=progress_total,
        )

    def analyze_packets(
        self,
        packets: Iterable[PacketRecord],
        source: str = "in-memory",
        max_packets: Optional[int] = None,
        enabled_protocols: Optional[List[str]] = None,
        enabled_attacks: Optional[List[str]] = None,
        progress_callback: Callable[[str, int, int | None], None] | None = None,
        progress_total: int | None = None,
    ) -> AnalysisReport:
        started_at = datetime.now(timezone.utc)
        start_total = time.perf_counter()
        self.source = source or "in-memory"

        selected_parsers = self._select_protocol_parsers(enabled_protocols)
        selected_detectors = self._select_attack_detectors(enabled_attacks)
        selected_parsers = self._expand_protocol_parsers_for_attacks(selected_parsers, selected_detectors)

        for detector in selected_detectors:
            detector.set_context(source)
            detector.reset()

        for parser in selected_parsers:
            reset = getattr(parser, "reset", None)
            if callable(reset):
                reset()

        protocol_events: List[ProtocolEvent] = []
        alerts: List[AttackAlert] = []
        packet_count = 0
        packet_read_seconds = 0.0
        protocol_parse_seconds = 0.0
        attack_detect_seconds = 0.0
        finalize_seconds = 0.0
        parser_event_counter: Counter[str] = Counter()
        detector_alert_counter: Counter[str] = Counter()
        debug_errors: List[dict] = []
        max_debug_errors = 30
        last_progress_report = time.monotonic()

        packet_iter = iter(packets)
        if progress_callback is not None:
            progress_callback("packet_read", 0, progress_total)
        while True:
            if max_packets is not None and packet_count >= max_packets:
                break

            read_start = time.perf_counter()
            try:
                packet = next(packet_iter)
            except StopIteration:
                break
            packet_read_seconds += time.perf_counter() - read_start
            packet_count += 1
            if progress_callback is not None:
                now = time.monotonic()
                if packet_count == 1 or packet_count % 200 == 0 or (now - last_progress_report) >= 1.0:
                    progress_callback("packet_read", packet_count, progress_total)
                    last_progress_report = now

            packet_protocol_events: List[ProtocolEvent] = []
            for parser in selected_parsers:
                parser_start = time.perf_counter()
                try:
                    if not parser.match(packet):
                        continue
                    event = parser.parse(packet)
                    if event is None:
                        continue
                    protocol_events.append(event)
                    packet_protocol_events.append(event)
                    parser_event_counter[parser.name] += 1
                except Exception as exc:
                    if len(debug_errors) < max_debug_errors:
                        debug_errors.append(
                            {
                                "stage": "protocol_parse",
                                "component": parser.name,
                                "packet_index": packet.index,
                                "error": str(exc),
                            }
                        )
                finally:
                    protocol_parse_seconds += time.perf_counter() - parser_start

            for detector in selected_detectors:
                detector_start = time.perf_counter()
                try:
                    detector_alerts = detector.analyze(packet, packet_protocol_events)
                    if detector_alerts:
                        alerts.extend(detector_alerts)
                        detector_alert_counter[detector.name] += len(detector_alerts)
                except Exception as exc:
                    if len(debug_errors) < max_debug_errors:
                        debug_errors.append(
                            {
                                "stage": "attack_detect",
                                "component": detector.name,
                                "packet_index": packet.index,
                                "error": str(exc),
                            }
                        )
                finally:
                    attack_detect_seconds += time.perf_counter() - detector_start

        if progress_callback is not None:
            progress_callback("finalizing", packet_count, progress_total or packet_count)

        for detector in selected_detectors:
            finalize_start = time.perf_counter()
            try:
                detector_alerts = detector.finalize()
                if detector_alerts:
                    alerts.extend(detector_alerts)
                    detector_alert_counter[detector.name] += len(detector_alerts)
            except Exception as exc:
                if len(debug_errors) < max_debug_errors:
                    debug_errors.append(
                        {
                            "stage": "attack_finalize",
                            "component": detector.name,
                            "error": str(exc),
                        }
                    )
            finally:
                finalize_seconds += time.perf_counter() - finalize_start

        protocol_counter = Counter(evt.protocol for evt in protocol_events)
        severity_counter = Counter(alert.severity for alert in alerts)
        total_seconds = time.perf_counter() - start_total
        finished_at = datetime.now(timezone.utc)

        detailed_views = self._build_detailed_views(protocol_events)
        attack_detailed_views = self._build_attack_detailed_views(alerts)

        debug_info = {
            "generated_at": finished_at.isoformat(),
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "pipeline_components": {
                "protocol_parsers": [parser.name for parser in selected_parsers],
                "attack_detectors": [detector.name for detector in selected_detectors],
            },
            "stage_ms": {
                "packet_read": round(packet_read_seconds * 1000, 2),
                "protocol_parse": round(protocol_parse_seconds * 1000, 2),
                "attack_detect": round(attack_detect_seconds * 1000, 2),
                "attack_finalize": round(finalize_seconds * 1000, 2),
                "total": round(total_seconds * 1000, 2),
            },
            "throughput": {
                "packets_per_second": round(packet_count / total_seconds, 2) if total_seconds > 0 else 0.0
            },
            "component_outputs": {
                "protocol_event_count_by_parser": dict(parser_event_counter),
                "alert_count_by_detector": dict(detector_alert_counter),
            },
            "error_count": len(debug_errors),
            "errors": debug_errors,
        }

        stats = {
            "protocol_distribution": dict(protocol_counter),
            "alert_severity_distribution": dict(severity_counter),
            "alert_count": len(alerts),
            "protocol_event_count": len(protocol_events),
            "packet_count": packet_count,
            "selected_modules": {
                "protocols": [parser.name for parser in selected_parsers],
                "attacks": [detector.name for detector in selected_detectors],
            },
            "detailed_views": detailed_views,
            "attack_detailed_views": attack_detailed_views,
            "debug": debug_info,
        }

        return AnalysisReport(
            pcap_path=source,
            packet_count=packet_count,
            protocol_events=protocol_events,
            alerts=alerts,
            stats=stats,
        )

    def report_to_dict(self, report: AnalysisReport) -> dict:
        return asdict(report)

    def list_modules(self) -> dict:
        return {
            "protocols": [
                {
                    "name": parser.name,
                    "description": getattr(parser, "description", parser.name),
                }
                for parser in self.protocol_parsers
            ],
            "attacks": [
                {
                    "name": detector.name,
                    "description": getattr(detector, "description", detector.name),
                }
                for detector in self.attack_detectors
            ],
        }

    def _select_protocol_parsers(self, enabled_protocols: Optional[List[str]]) -> List[BaseProtocolParser]:
        if enabled_protocols is None:
            return list(self.protocol_parsers)
        allow = set(enabled_protocols)
        return [parser for parser in self.protocol_parsers if parser.name in allow]

    def _select_attack_detectors(self, enabled_attacks: Optional[List[str]]) -> List[BaseAttackDetector]:
        if enabled_attacks is None:
            return list(self.attack_detectors)
        allow = set(enabled_attacks)
        return [detector for detector in self.attack_detectors if detector.name in allow]

    def _expand_protocol_parsers_for_attacks(
        self,
        protocol_parsers: List[BaseProtocolParser],
        attack_detectors: List[BaseAttackDetector],
    ) -> List[BaseProtocolParser]:
        if not attack_detectors:
            return list(protocol_parsers)

        parser_map = {parser.name: parser for parser in self.protocol_parsers}
        selected = {parser.name: parser for parser in protocol_parsers}
        for detector in attack_detectors:
            for protocol_name in detector.required_protocols():
                if protocol_name not in selected and protocol_name in parser_map:
                    selected[protocol_name] = parser_map[protocol_name]
        ordered = [parser for parser in self.protocol_parsers if parser.name in selected]
        return ordered

    def _build_detailed_views(self, protocol_events: List[ProtocolEvent], limit_per_protocol: int = 300) -> dict:
        details: dict[str, dict[str, Any]] = {}
        grouped: dict[str, list[ProtocolEvent]] = {}
        for event in protocol_events:
            grouped.setdefault(event.protocol, []).append(event)

        for protocol, events in grouped.items():
            if protocol == "FTP":
                details["FTP"] = self._ftp_details(events, limit_per_protocol)
            elif protocol == "HTTP":
                details["HTTP"] = self._http_details(events, limit_per_protocol)
            elif protocol == "DNS":
                details["DNS"] = self._dns_details(events, limit_per_protocol)
            elif protocol == "TLS":
                details["TLS"] = self._tls_details(events, limit_per_protocol)
            elif protocol == "Modbus":
                details["Modbus"] = self._modbus_details(events, limit_per_protocol)
            elif protocol == "USB":
                details["USB"] = self._usb_details(events, limit_per_protocol)
            else:
                details[protocol] = {
                    "records": [
                        {
                            "packet_index": e.packet_index,
                            "timestamp": e.timestamp,
                            "src_ip": e.src_ip,
                            "dst_ip": e.dst_ip,
                            **(e.details or {}),
                        }
                        for e in events[:limit_per_protocol]
                    ],
                    "record_count": len(events),
                }
        return details

    def _ftp_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        commands: list[dict[str, Any]] = []
        transfer_rows: dict[str, dict[str, Any]] = {}
        username_profiles: dict[str, dict[str, Any]] = {}
        control_stream_state: dict[str, dict[str, Any]] = {}
        username_counter: Counter[str] = Counter()
        command_counter: Counter[str] = Counter()

        for event in events:
            detail = event.details or {}
            entry_type = str(detail.get("entry_type") or "").strip().lower()
            control_stream = str(detail.get("control_stream") or event.flow_id or "").strip()
            state = control_stream_state.setdefault(control_stream, {"last_username": None})

            if entry_type in {"request", "response"}:
                command = str(detail.get("command") or "").upper().strip() or None
                response_code = str(detail.get("response_code") or "").strip() or None
                username = str(detail.get("username") or state.get("last_username") or "").strip() or None
                password = str(detail.get("password") or "").strip() or None
                transfer_id = str(detail.get("transfer_id") or "").strip() or None

                if command == "USER" and username:
                    state["last_username"] = username
                    profile = username_profiles.setdefault(
                        username,
                        {
                            "username": username,
                            "_passwords": [],
                            "_streams": set(),
                            "login_success_count": 0,
                            "command_count": 0,
                        },
                    )
                    profile["_streams"].add(control_stream)
                    username_counter[username] += 1

                if username:
                    profile = username_profiles.setdefault(
                        username,
                        {
                            "username": username,
                            "_passwords": [],
                            "_streams": set(),
                            "login_success_count": 0,
                            "command_count": 0,
                        },
                    )
                    profile["_streams"].add(control_stream)
                    profile["command_count"] = int(profile.get("command_count") or 0) + 1
                    if password and password not in profile["_passwords"]:
                        profile["_passwords"].append(password)
                    if response_code == "230":
                        profile["login_success_count"] = int(profile.get("login_success_count") or 0) + 1

                if command:
                    command_counter[command] += 1

                if transfer_id:
                    row = transfer_rows.setdefault(
                        transfer_id,
                        {
                            "transfer_id": transfer_id,
                            "control_stream": control_stream,
                            "command": command or None,
                            "argument": detail.get("argument"),
                            "filename": detail.get("filename"),
                            "transfer_direction": detail.get("transfer_direction"),
                            "data_connection_mode": detail.get("data_connection_mode"),
                            "request_packet_index": event.packet_index if entry_type == "request" else None,
                            "response_150_packet_index": None,
                            "response_226_packet_index": None,
                            "src_ip": event.src_ip,
                            "dst_ip": event.dst_ip,
                            "_data": bytearray(),
                            "chunk_count": 0,
                            "byte_count": 0,
                        },
                    )
                    if command and not row.get("command"):
                        row["command"] = command
                    if detail.get("argument") and not row.get("argument"):
                        row["argument"] = detail.get("argument")
                    if detail.get("filename") and not row.get("filename"):
                        row["filename"] = detail.get("filename")
                    if detail.get("transfer_direction") and not row.get("transfer_direction"):
                        row["transfer_direction"] = detail.get("transfer_direction")
                    if detail.get("data_connection_mode") and not row.get("data_connection_mode"):
                        row["data_connection_mode"] = detail.get("data_connection_mode")
                    if entry_type == "request":
                        row["request_packet_index"] = event.packet_index
                    if response_code == "150":
                        row["response_150_packet_index"] = event.packet_index
                    if response_code == "226":
                        row["response_226_packet_index"] = event.packet_index

                commands.append(
                    {
                        "packet_index": event.packet_index,
                        "timestamp": event.timestamp,
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "control_stream": control_stream,
                        "entry_type": entry_type,
                        "command": command,
                        "argument": detail.get("argument"),
                        "response_code": response_code,
                        "response_text": detail.get("response_text"),
                        "username": username,
                        "password": password,
                        "transfer_id": transfer_id,
                    }
                )
                continue

            if entry_type != "data":
                continue

            transfer_id = str(detail.get("transfer_id") or "").strip()
            if not transfer_id:
                continue

            row = transfer_rows.setdefault(
                transfer_id,
                {
                    "transfer_id": transfer_id,
                    "control_stream": control_stream,
                    "command": detail.get("command"),
                    "argument": detail.get("argument"),
                    "filename": detail.get("filename"),
                    "transfer_direction": detail.get("transfer_direction"),
                    "data_connection_mode": detail.get("data_connection_mode"),
                    "request_packet_index": None,
                    "response_150_packet_index": None,
                    "response_226_packet_index": None,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "_data": bytearray(),
                    "chunk_count": 0,
                    "byte_count": 0,
                },
            )
            chunk_bytes = self._ftp_payload_to_bytes(detail.get("chunk_hex"))
            if not chunk_bytes:
                continue
            row["_data"].extend(chunk_bytes)
            row["chunk_count"] = int(row.get("chunk_count") or 0) + 1
            row["byte_count"] = int(row.get("byte_count") or 0) + len(chunk_bytes)

        export_context = self._ftp_export_context()
        files: list[dict[str, Any]] = []
        for index, transfer in enumerate(transfer_rows.values(), start=1):
            data = bytes(transfer.pop("_data", bytearray()))
            row = {
                "transfer_id": transfer.get("transfer_id"),
                "control_stream": transfer.get("control_stream"),
                "command": transfer.get("command"),
                "argument": transfer.get("argument"),
                "filename": transfer.get("filename"),
                "display_path": self._ftp_transfer_display_path(transfer),
                "transfer_direction": transfer.get("transfer_direction"),
                "data_connection_mode": transfer.get("data_connection_mode"),
                "request_packet_index": transfer.get("request_packet_index"),
                "response_150_packet_index": transfer.get("response_150_packet_index"),
                "response_226_packet_index": transfer.get("response_226_packet_index"),
                "chunk_count": int(transfer.get("chunk_count") or 0),
                "byte_count": int(transfer.get("byte_count") or len(data)),
                "preview": self._ftp_preview_text(data),
            }
            exported = self._maybe_export_ftp_transfer(export_context=export_context, transfer=row, data=data, transfer_index=index)
            if exported:
                row.update(exported)
            files.append(row)

        username_rows: list[dict[str, Any]] = []
        for profile in username_profiles.values():
            passwords = list(profile.get("_passwords") or [])
            streams = sorted(str(item) for item in profile.get("_streams") or set())
            username_rows.append(
                {
                    "username": profile.get("username"),
                    "passwords": passwords,
                    "password_count": len(passwords),
                    "has_password": bool(passwords),
                    "login_success_count": int(profile.get("login_success_count") or 0),
                    "control_streams": streams,
                    "command_count": int(profile.get("command_count") or 0),
                }
            )

        username_rows.sort(
            key=lambda item: (
                -int(item.get("login_success_count") or 0),
                -int(item.get("password_count") or 0),
                str(item.get("username") or ""),
            )
        )
        commands.sort(key=lambda item: int(item.get("packet_index") or -1))
        files.sort(
            key=lambda item: (
                str(item.get("display_path") or ""),
                int(item.get("request_packet_index") or -1),
            )
        )

        return {
            "records": commands[:limit],
            "record_count": len(events),
            "commands": commands[:400],
            "command_count": len(commands),
            "files": files[:200],
            "transfer_count": len(files),
            "exported_transfer_count": sum(1 for item in files if item.get("url")),
            "usernames": username_rows,
            "username_count": len(username_rows),
            "top_usernames": username_counter.most_common(50),
            "top_commands": command_counter.most_common(50),
        }

    def _http_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        requests = []
        uploads = []
        host_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        status_counter: Counter[str] = Counter()
        upload_filename_counter: Counter[str] = Counter()
        pending_requests: dict[str, deque[int]] = {}
        request_records: dict[int, dict[str, Any]] = {}
        response_records_by_request: dict[int, dict[str, Any]] = {}
        response_records_by_packet: dict[int, dict[str, Any]] = {}

        for event in events:
            detail = event.details or {}
            method = str(detail.get("method") or "").upper().strip() or None
            status_code = str(detail.get("status_code") or "").strip() or None
            flow_id = str(event.flow_id or "")
            host = str(detail.get("host") or "").strip()
            uri = str(detail.get("uri") or "").strip()
            uri_path = self._normalize_http_uri_path(uri)
            content_type = str(detail.get("content_type") or "").strip() or None
            request_packet_index = self._frame_to_packet_index(detail.get("request_in"))
            response_packet_index = self._frame_to_packet_index(detail.get("response_in"))
            normalized_payload = self._normalize_http_payload_text(detail.get("payload"))
            queue = pending_requests.setdefault(flow_id, deque())

            if method:
                if host:
                    host_counter[host] += 1
                if uri_path:
                    path_counter[uri_path] += 1
                queue.append(event.packet_index)
                upload_rows = self._extract_http_uploads(
                    packet_index=event.packet_index,
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    method=method,
                    host=host,
                    uri=uri,
                    content_type=content_type,
                    payload=detail.get("payload"),
                )
                if upload_rows:
                    uploads.extend(upload_rows)
                    for item in upload_rows:
                        filename = str(item.get("filename") or "").strip()
                        if filename:
                            upload_filename_counter[filename] += 1
                request_records[event.packet_index] = {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "uri_path": uri_path,
                    "response_packet_index": response_packet_index,
                    "upload_count": len(upload_rows),
                    "upload_summary": ", ".join(
                        str(item.get("filename") or item.get("field_name") or "").strip()
                        for item in upload_rows
                        if str(item.get("filename") or item.get("field_name") or "").strip()
                    ) or None,
                }
                continue

            if status_code:
                status_counter[status_code] += 1

            if request_packet_index is None and queue:
                request_packet_index = queue[0]
            if request_packet_index is not None:
                while queue:
                    queued_packet_index = queue[0]
                    if queued_packet_index < request_packet_index:
                        queue.popleft()
                        continue
                    if queued_packet_index == request_packet_index:
                        queue.popleft()
                    break

            response_record = {
                "packet_index": event.packet_index,
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "request_packet_index": request_packet_index,
                "status_code": status_code,
                "content_type": content_type,
                "payload": normalized_payload,
            }
            response_records_by_packet[event.packet_index] = response_record
            if request_packet_index is not None:
                response_records_by_request[request_packet_index] = response_record
                linked_request = request_records.get(request_packet_index)
                if linked_request is not None:
                    linked_request["response_packet_index"] = event.packet_index

        export_context = self._http_rebuild_export_context()
        uploads = self._finalize_http_uploads(
            uploads=uploads,
            export_context=export_context,
        )
        upload_points = self._build_http_upload_points(uploads)
        site_pages = self._build_http_site_pages(
            request_records=request_records,
            response_records_by_request=response_records_by_request,
            export_context=export_context,
        )

        for event in events[:limit]:
            detail = event.details or {}
            method = str(detail.get("method") or "").upper().strip() or None
            status_code = str(detail.get("status_code") or "").strip() or None
            direction = "request" if method else "response"
            host = str(detail.get("host") or "").strip()
            uri = str(detail.get("uri") or "").strip()
            content_type = str(detail.get("content_type") or "").strip() or None
            request_packet_index = self._frame_to_packet_index(detail.get("request_in"))
            response_packet_index = self._frame_to_packet_index(detail.get("response_in"))

            linked_request = None
            if direction == "request":
                linked_response = response_records_by_request.get(event.packet_index)
                if linked_response is not None:
                    response_packet_index = linked_response.get("packet_index")
                request_packet_index = event.packet_index
                linked_request = request_records.get(event.packet_index)
            else:
                response_record = response_records_by_packet.get(event.packet_index)
                if response_record is not None and request_packet_index is None:
                    request_packet_index = response_record.get("request_packet_index")
                if request_packet_index is not None:
                    linked_request = request_records.get(request_packet_index)
                    if linked_request is not None:
                        host = host or str(linked_request.get("host") or "")
                        uri = uri or str(linked_request.get("uri") or "")
                        method = method or str(linked_request.get("method") or "") or None
                response_packet_index = event.packet_index

            normalized_payload = self._normalize_http_payload_text(detail.get("payload"))
            requests.append(
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "direction": direction,
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "status_code": status_code,
                    "content_type": content_type,
                    "user_agent": detail.get("user_agent"),
                    "linked_packet_index": response_packet_index if direction == "request" else request_packet_index,
                    "request_packet_index": event.packet_index if direction == "request" else request_packet_index,
                    "response_packet_index": response_packet_index,
                    "payload_preview": self._trim_text(normalized_payload, 240),
                    "upload_count": int((linked_request or {}).get("upload_count") or 0),
                    "upload_summary": (linked_request or {}).get("upload_summary"),
                }
            )

        return {
            "requests": requests,
            "request_count": len(events),
            "uploads": uploads[:200],
            "upload_count": len(uploads),
            "top_upload_filenames": upload_filename_counter.most_common(50),
            "top_upload_filenames_total": len(upload_filename_counter),
            "upload_points": upload_points,
            "upload_points_total": len(upload_points),
            "upload_files_exported": sum(1 for item in uploads if item.get("url")),
            "upload_targets_total": len(
                {
                    str(item.get("server_ip") or item.get("host") or "").strip()
                    for item in upload_points
                    if str(item.get("server_ip") or item.get("host") or "").strip()
                }
            ),
            "top_hosts": host_counter.most_common(200),
            "top_paths": path_counter.most_common(200),
            "top_status_codes": status_counter.most_common(50),
            "top_hosts_total": len(host_counter),
            "top_paths_total": len(path_counter),
            "top_status_codes_total": len(status_counter),
            "site_pages": site_pages,
            "site_pages_total": len(site_pages),
            "site_hosts_total": len({str(item.get("server_ip") or "").strip() for item in site_pages if str(item.get("server_ip") or "").strip()}),
            "site_pages_exported": sum(1 for item in site_pages if item.get("url")),
        }

    def _frame_to_packet_index(self, value: Any) -> int | None:
        try:
            number = int(str(value).strip())
        except Exception:
            return None
        return number - 1 if number > 0 else None

    def _ftp_export_context(self) -> tuple[Path, Path] | None:
        source = str(self.source or "").strip()
        if not source or source in {"in-memory", "unit-test"}:
            return None

        source_path = Path(source)
        if not source_path.exists():
            return None

        export_root = self.http_export_root
        try:
            export_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.stem) or "capture"
        source_hash = hashlib.sha1(str(source_path.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
        capture_dir = export_root / "ftp_rebuild" / f"{safe_stem}_{source_hash}"
        try:
            capture_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        return export_root, capture_dir

    def _maybe_export_ftp_transfer(
        self,
        *,
        export_context: tuple[Path, Path] | None,
        transfer: dict[str, Any],
        data: bytes,
        transfer_index: int,
    ) -> dict[str, Any] | None:
        if export_context is None or not data:
            return None

        export_root, capture_dir = export_context
        direction_dir = "downloads" if str(transfer.get("transfer_direction") or "") == "server_to_client" else "uploads"
        export_dir = capture_dir / direction_dir
        export_parts = self._ftp_transfer_parts(transfer=transfer, transfer_index=transfer_index)
        export_path = export_dir.joinpath(*export_parts)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_bytes(data)
        relative = export_path.relative_to(export_root).as_posix()
        return {
            "saved_path": str(export_path),
            "saved_name": export_path.name,
            "saved_size": len(data),
            "url": artifact_raw_url(relative),
            "viewer_url": artifact_viewer_url(relative),
        }

    def _ftp_transfer_parts(self, *, transfer: dict[str, Any], transfer_index: int) -> list[str]:
        raw_name = str(transfer.get("filename") or transfer.get("argument") or "").strip()
        if not raw_name and str(transfer.get("command") or "").upper() == "LIST":
            packet_index = int(transfer.get("request_packet_index") or 0)
            return [f"listing_pkt{packet_index:06d}_{transfer_index:03d}.txt"]

        decoded = unquote(raw_name)
        raw_parts = [part for part in re.split(r"[\\/]+", decoded) if part and part not in {".", ".."}]
        safe_parts = [
            self._sanitize_http_rebuild_name(part, fallback=f"segment_{idx}")
            for idx, part in enumerate(raw_parts, start=1)
        ]
        if safe_parts:
            return safe_parts

        packet_index = int(transfer.get("request_packet_index") or 0)
        command_name = self._sanitize_http_rebuild_name(str(transfer.get("command") or "ftp"), fallback="ftp")
        return [f"{command_name}_pkt{packet_index:06d}_{transfer_index:03d}.bin"]

    def _ftp_transfer_display_path(self, transfer: dict[str, Any]) -> str:
        raw_name = str(transfer.get("filename") or transfer.get("argument") or "").strip()
        if raw_name:
            return raw_name
        command = str(transfer.get("command") or "").upper().strip() or "FTP"
        packet_index = int(transfer.get("request_packet_index") or 0)
        if command == "LIST":
            return f"listing/pkt_{packet_index:06d}.txt"
        return f"{command.lower()}/pkt_{packet_index:06d}.bin"

    def _ftp_payload_to_bytes(self, value: Any) -> bytes:
        compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
        if not compact or len(compact) % 2 != 0:
            return b""
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return b""

    def _ftp_preview_text(self, data: bytes) -> str:
        if not data:
            return ""
        for encoding in ("utf-8", "gb18030", "latin-1"):
            try:
                text = data.decode(encoding)
            except Exception:
                continue
            return self._trim_text(text.replace("\r\n", "\n"), 200)
        return self._trim_text(data.hex(), 200)

    def _normalize_http_payload_text(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        repaired = self._repair_json_text(text)
        return repaired if repaired else text

    def _normalize_http_upload_payload_text(self, value: Any) -> str:
        text = str(value or "")
        if not text:
            return ""
        had_newline = "\n" in text or "\r" in text
        repaired = (
            text.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\r", "\n")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
        )
        if not had_newline and "rn" in repaired:
            repaired = repaired.replace("rnrn", "\n\n").replace("rn", "\n")
        return repaired

    def _extract_http_uploads(
        self,
        *,
        packet_index: int,
        timestamp: float | None,
        src_ip: str | None,
        dst_ip: str | None,
        method: str | None,
        host: str,
        uri: str,
        content_type: str | None,
        payload: Any,
    ) -> list[dict[str, Any]]:
        method_upper = str(method or "").upper().strip()
        content_type_text = str(content_type or "").strip()
        content_type_lower = content_type_text.lower()
        payload_text = self._normalize_http_upload_payload_text(payload)
        if method_upper not in {"POST", "PUT", "PATCH"} or not payload_text.strip():
            return []

        request_meta = {
            "packet_index": packet_index,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "server_ip": dst_ip,
            "host": host or None,
            "uri": uri,
            "uri_path": self._normalize_http_uri_path(uri) or "/",
            "method": method_upper,
            "request_content_type": content_type_text or None,
        }

        if "multipart/form-data" in content_type_lower or "content-disposition: form-data" in payload_text.lower():
            return self._parse_http_multipart_uploads(
                payload_text=payload_text,
                content_type=content_type_text,
                request_meta=request_meta,
            )

        binary_markers = (
            "application/octet-stream",
            "application/zip",
            "application/x-zip",
            "application/x-rar",
            "application/x-7z",
            "application/pdf",
            "image/",
            "audio/",
            "video/",
        )
        if any(marker in content_type_lower for marker in binary_markers):
            preview = self._trim_text(self._normalize_http_payload_text(payload_text), 200)
            return [
                {
                    **request_meta,
                    "upload_type": "raw_body",
                    "field_name": None,
                    "filename": None,
                    "part_content_type": content_type_text or None,
                    "size": len(payload_text.encode("utf-8", errors="ignore")),
                    "preview": preview,
                    "_body_text": payload_text,
                }
            ]

        return []

    def _parse_http_multipart_uploads(
        self,
        *,
        payload_text: str,
        content_type: str,
        request_meta: dict[str, Any],
    ) -> list[dict[str, Any]]:
        boundary_match = re.search(r'boundary="?([^";]+)"?', str(content_type or ""), flags=re.IGNORECASE)
        boundary = str(boundary_match.group(1) if boundary_match else "").strip()
        if not boundary:
            first_line = str(payload_text.split("\n", 1)[0] or "").strip()
            if first_line.startswith("--") and len(first_line) > 2:
                boundary = first_line[2:]
        if not boundary:
            return []

        parts = payload_text.split(f"--{boundary}")
        uploads: list[dict[str, Any]] = []
        for part in parts:
            chunk = str(part or "").strip()
            if not chunk or chunk == "--":
                continue

            header_text, separator, body = chunk.partition("\n\n")
            if not separator:
                continue

            headers: dict[str, str] = {}
            for line in header_text.splitlines():
                key, colon, value = line.partition(":")
                if not colon:
                    continue
                headers[key.strip().lower()] = value.strip()

            disposition = str(headers.get("content-disposition") or "")
            name_match = re.search(r'name="([^"]+)"', disposition, flags=re.IGNORECASE)
            filename_match = re.search(r'filename="([^"]*)"', disposition, flags=re.IGNORECASE)
            field_name = str(name_match.group(1) if name_match else "").strip() or None
            filename = str(filename_match.group(1) if filename_match else "").strip() or None
            part_content_type = str(headers.get("content-type") or "").strip() or None
            if not filename and not part_content_type:
                continue

            normalized_body = body.rstrip("\n")
            uploads.append(
                {
                    **request_meta,
                    "upload_type": "multipart_file" if filename else "multipart_part",
                    "field_name": field_name,
                    "filename": filename,
                    "part_content_type": part_content_type,
                    "size": len(normalized_body.encode("utf-8", errors="ignore")),
                    "preview": self._trim_text(self._normalize_http_payload_text(normalized_body), 200),
                    "_body_text": normalized_body,
                }
            )

        return uploads

    def _finalize_http_uploads(
        self,
        *,
        uploads: list[dict[str, Any]],
        export_context: tuple[Path, Path] | None,
    ) -> list[dict[str, Any]]:
        finalized: list[dict[str, Any]] = []
        for upload_index, upload in enumerate(uploads, start=1):
            row = self._public_http_upload_row(upload)
            exported = self._maybe_export_http_upload(
                export_context=export_context,
                upload_row=upload,
                upload_index=upload_index,
            )
            if exported:
                row.update(exported)
            finalized.append(row)
        return finalized

    def _public_http_upload_row(self, upload: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in upload.items()
            if not str(key).startswith("_")
        }

    def _build_http_upload_points(self, uploads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        points: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for row in uploads:
            server_ip = str(row.get("server_ip") or row.get("dst_ip") or "").strip() or "unknown_server"
            host = str(row.get("host") or "").strip()
            method = str(row.get("method") or "").upper().strip() or "POST"
            uri_path = str(row.get("uri_path") or row.get("uri") or "").strip() or "/"
            key = (server_ip, host, method, uri_path)

            point = points.get(key)
            if point is None:
                point = {
                    "server_ip": server_ip,
                    "host": host or None,
                    "method": method,
                    "uri": str(row.get("uri") or "").strip() or uri_path,
                    "uri_path": uri_path,
                    "files": [],
                    "_request_packets": set(),
                }
                points[key] = point

            packet_index = row.get("packet_index")
            if packet_index is not None:
                point["_request_packets"].add(packet_index)

            point["files"].append(
                {
                    "packet_index": row.get("packet_index"),
                    "timestamp": row.get("timestamp"),
                    "field_name": row.get("field_name"),
                    "filename": row.get("filename"),
                    "saved_name": row.get("saved_name"),
                    "upload_type": row.get("upload_type"),
                    "content_type": row.get("part_content_type") or row.get("request_content_type"),
                    "size": row.get("saved_size") or row.get("size"),
                    "preview": row.get("preview"),
                    "url": row.get("url"),
                    "viewer_url": row.get("viewer_url"),
                }
            )

        results: list[dict[str, Any]] = []
        for point in points.values():
            request_packets = sorted(
                int(item)
                for item in point.pop("_request_packets", set())
                if item is not None
            )
            files = list(point.get("files") or [])
            files.sort(
                key=lambda item: (
                    int(item.get("packet_index") or -1),
                    str(item.get("filename") or item.get("saved_name") or ""),
                )
            )
            point["files"] = files
            point["request_count"] = len(request_packets)
            point["request_packets"] = request_packets
            point["upload_count"] = len(files)
            point["exported_count"] = sum(1 for item in files if item.get("url"))
            point["latest_packet_index"] = request_packets[-1] if request_packets else None
            results.append(point)

        results.sort(
            key=lambda item: (
                -int(item.get("upload_count") or 0),
                -(int(item.get("latest_packet_index")) if item.get("latest_packet_index") is not None else -1),
                str(item.get("server_ip") or ""),
                str(item.get("uri_path") or ""),
            )
        )
        return results

    def _normalize_http_uri_path(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            parsed = urlsplit(text)
        except Exception:
            parsed = None

        if parsed is not None:
            path = str(parsed.path or "").strip()
            if path:
                return path
            if str(parsed.scheme or "").strip() and str(parsed.netloc or "").strip():
                return "/"

        return text.split("?", 1)[0].split("#", 1)[0].strip()

    def _build_http_site_pages(
        self,
        *,
        request_records: dict[int, dict[str, Any]],
        response_records_by_request: dict[int, dict[str, Any]],
        export_context: tuple[Path, Path] | None = None,
    ) -> list[dict[str, Any]]:
        site_pages: list[dict[str, Any]] = []

        for request_packet_index in sorted(request_records):
            request_record = request_records[request_packet_index]
            if str(request_record.get("method") or "").upper() != "GET":
                continue

            response_record = response_records_by_request.get(request_packet_index)
            if response_record is None:
                continue
            if str(response_record.get("status_code") or "").strip() != "200":
                continue

            uri = str(request_record.get("uri") or "").strip()
            uri_path = str(request_record.get("uri_path") or "").strip() or self._normalize_http_uri_path(uri) or "/"
            server_ip = str(request_record.get("dst_ip") or response_record.get("src_ip") or "").strip() or "unknown_server"
            exported = self._maybe_export_http_page(
                export_context=export_context,
                server_ip=server_ip,
                uri_path=uri_path,
                content_type=str(response_record.get("content_type") or ""),
                payload=response_record.get("payload"),
            )

            page = {
                "server_ip": server_ip,
                "host": str(request_record.get("host") or "").strip() or None,
                "uri": uri or uri_path,
                "uri_path": uri_path,
                "request_packet_index": request_packet_index,
                "response_packet_index": response_record.get("packet_index"),
                "content_type": response_record.get("content_type"),
            }
            if exported:
                page.update(exported)
            site_pages.append(page)

        return site_pages

    def _http_rebuild_export_context(self) -> tuple[Path, Path] | None:
        source = str(self.source or "").strip()
        if not source or source in {"in-memory", "unit-test"}:
            return None

        source_path = Path(source)
        if not source_path.exists():
            return None

        export_root = self.http_export_root
        export_root.mkdir(parents=True, exist_ok=True)
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.stem) or "capture"
        source_hash = hashlib.sha1(str(source_path.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
        capture_dir = export_root / "http_rebuild" / f"{safe_stem}_{source_hash}"
        capture_dir.mkdir(parents=True, exist_ok=True)
        return export_root, capture_dir

    def _maybe_export_http_page(
        self,
        *,
        export_context: tuple[Path, Path] | None,
        server_ip: str,
        uri_path: str,
        content_type: str,
        payload: Any,
    ) -> dict[str, Any] | None:
        if export_context is None:
            return None

        data = self._http_payload_to_bytes(payload)
        if not data:
            return None

        export_root, capture_dir = export_context
        server_dir = capture_dir / self._sanitize_http_rebuild_name(server_ip, fallback="unknown_server")
        export_parts = self._safe_http_rebuild_parts(uri_path=uri_path, content_type=content_type)
        export_path = server_dir.joinpath(*export_parts)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_bytes(data)
        relative = export_path.relative_to(export_root).as_posix()
        return {
            "saved_path": str(export_path),
            "url": artifact_raw_url(relative),
            "viewer_url": artifact_viewer_url(relative),
            "saved_name": export_path.name,
            "saved_size": len(data),
        }

    def _maybe_export_http_upload(
        self,
        *,
        export_context: tuple[Path, Path] | None,
        upload_row: dict[str, Any],
        upload_index: int,
    ) -> dict[str, Any] | None:
        if export_context is None:
            return None

        data = self._http_payload_to_bytes(upload_row.get("_body_text"))
        if not data:
            return None

        export_root, capture_dir = export_context
        server_ip = str(upload_row.get("server_ip") or upload_row.get("dst_ip") or "").strip() or "unknown_server"
        uri_path = str(upload_row.get("uri_path") or upload_row.get("uri") or "").strip() or "/"
        export_dir = (
            capture_dir
            / "http_uploads"
            / self._sanitize_http_rebuild_name(server_ip, fallback="unknown_server")
            / Path(*self._safe_http_upload_dir_parts(uri_path))
        )
        export_dir.mkdir(parents=True, exist_ok=True)
        export_path = export_dir / self._http_upload_export_name(upload_row=upload_row, upload_index=upload_index)
        export_path.write_bytes(data)
        relative = export_path.relative_to(export_root).as_posix()
        return {
            "saved_path": str(export_path),
            "url": artifact_raw_url(relative),
            "viewer_url": artifact_viewer_url(relative),
            "saved_name": export_path.name,
            "saved_size": len(data),
        }

    def _http_payload_to_bytes(self, value: Any) -> bytes:
        text = str(value or "")
        if not text:
            return b""

        compact = re.sub(r"[\s:]+", "", text)
        if len(compact) >= 32 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            try:
                return bytes.fromhex(compact)
            except ValueError:
                pass

        return text.encode("utf-8", errors="replace")

    def _safe_http_rebuild_parts(self, *, uri_path: str, content_type: str) -> list[str]:
        normalized_path = self._normalize_http_uri_path(uri_path) or "/"
        decoded_path = unquote(normalized_path)
        raw_parts = [part for part in re.split(r"[\\/]+", decoded_path) if part and part not in {".", ".."}]
        safe_parts = [
            self._sanitize_http_rebuild_name(part, fallback=f"segment_{idx}")
            for idx, part in enumerate(raw_parts, start=1)
        ]

        extension = self._http_rebuild_extension(content_type)
        if not safe_parts:
            return [f"index{extension}"]

        if normalized_path.endswith("/") or not self._http_path_has_extension(safe_parts[-1]):
            return safe_parts + [f"index{extension}"]
        return safe_parts

    def _safe_http_upload_dir_parts(self, uri_path: str) -> list[str]:
        normalized_path = self._normalize_http_uri_path(uri_path) or "/"
        decoded_path = unquote(normalized_path)
        raw_parts = [part for part in re.split(r"[\\/]+", decoded_path) if part and part not in {".", ".."}]
        safe_parts = [
            self._sanitize_http_rebuild_name(part, fallback=f"segment_{idx}")
            for idx, part in enumerate(raw_parts, start=1)
        ]
        return safe_parts or ["root"]

    def _http_upload_export_name(self, *, upload_row: dict[str, Any], upload_index: int) -> str:
        packet_index = int(upload_row.get("packet_index") or 0)
        filename = str(upload_row.get("filename") or "").strip()
        field_name = str(upload_row.get("field_name") or "").strip()
        content_type = str(upload_row.get("part_content_type") or upload_row.get("request_content_type") or "")

        raw_name = Path(filename).name if filename else ""
        safe_name = self._sanitize_http_rebuild_name(raw_name, fallback="")
        if not safe_name:
            label = self._sanitize_http_rebuild_name(field_name, fallback="upload")
            safe_name = f"{label}{self._http_rebuild_extension(content_type)}"
        elif not self._http_path_has_extension(safe_name):
            safe_name = f"{safe_name}{self._http_rebuild_extension(content_type)}"

        prefix = f"pkt{packet_index:06d}_u{upload_index:03d}"
        return f"{prefix}_{safe_name}"

    def _http_rebuild_extension(self, content_type: str) -> str:
        normalized = str(content_type or "").split(";", 1)[0].strip().lower()
        if not normalized:
            return ".bin"

        special_extensions = {
            "application/javascript": ".js",
            "text/javascript": ".js",
            "application/json": ".json",
            "text/json": ".json",
            "image/jpeg": ".jpg",
            "image/svg+xml": ".svg",
        }
        if normalized in special_extensions:
            return special_extensions[normalized]

        guessed = mimetypes.guess_extension(normalized, strict=False)
        if guessed:
            return ".txt" if guessed == ".ksh" else guessed
        if normalized.startswith("text/"):
            return ".txt"
        return ".bin"

    def _http_path_has_extension(self, value: str) -> bool:
        suffix = Path(value).suffix
        return bool(suffix and len(suffix) <= 10)

    def _sanitize_http_rebuild_name(self, value: str, *, fallback: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._")
        return safe or fallback

    def _repair_json_text(self, text: str) -> str:
        value = str(text or "").strip()
        if not value:
            return ""

        repaired = value
        repaired = re.sub(r'^\{([A-Za-z0-9_@.-]+)"\s*:', r'{"\1":', repaired, count=1)
        repaired = re.sub(r'^\[([A-Za-z0-9_@.-]+)"\s*:', r'["\1":', repaired, count=1)
        if repaired.endswith('"') and repaired[:1] in {"{", "["} and repaired.count('"') % 2 == 1:
            repaired = repaired[:-1]
        if repaired.startswith('"') and repaired.endswith('"') and '\\"' in repaired:
            repaired = repaired[1:-1].replace('\\"', '"')
        return repaired

    def _dns_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        queries = []
        query_counter: Counter[str] = Counter()
        analysis_rows = []
        for event in events:
            detail = event.details or {}
            qname = str(detail.get("query_name") or "").strip()
            response = str(detail.get("response") or "").strip()
            if qname:
                query_counter[qname] += 1
            row = {
                "packet_index": event.packet_index,
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "query_name": qname,
                "query_type": detail.get("query_type"),
                "response": response,
                "rcode": detail.get("rcode"),
            }
            analysis_rows.append(row)
            if len(queries) < limit:
                queries.append(row)

        hidden_analysis = self._analyze_dns_hidden_payloads(analysis_rows)
        analysis_limit = min(len(analysis_rows), 5000)
        return {
            "queries": queries,
            "query_count": len(events),
            "top_queries": query_counter.most_common(30),
            "field_options": [
                {"value": "query_name", "label": "查询域名"},
                {"value": "response", "label": "响应值"},
            ],
            "analysis_rows": analysis_rows[:analysis_limit],
            "analysis_row_count": len(analysis_rows),
            "analysis_truncated": len(analysis_rows) > analysis_limit,
            "suspicious_patterns": hidden_analysis.get("patterns", []),
            "decoded_candidates": hidden_analysis.get("decoded_candidates", []),
        }

    def _analyze_dns_hidden_payloads(self, rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        field_labels = {
            "query_name": "查询域名",
            "response": "响应值",
        }
        extractors = [
            ("first_label", "按 . 取第 1 段", "."),
            ("full_value", "完整字段", ""),
        ]
        patterns: list[dict[str, Any]] = []
        decoded_candidates: list[dict[str, Any]] = []
        seen_patterns: set[tuple[str, str, str]] = set()
        seen_candidates: set[tuple[str, str, str, str]] = set()

        for field, field_label in field_labels.items():
            for extractor, extractor_label, delimiter in extractors:
                extracted_values = [
                    self._extract_dns_payload_segment(row.get(field), extractor=extractor, delimiter=delimiter)
                    for row in rows
                ]
                non_empty_values = [value for value in extracted_values if value]
                if not non_empty_values:
                    continue

                hex_matches = [value for value in non_empty_values if self._looks_like_hex(value)]
                hex_ratio = len(hex_matches) / len(non_empty_values)
                if hex_matches and hex_ratio >= 0.6:
                    pattern_key = (field, extractor, "hex")
                    if pattern_key not in seen_patterns:
                        seen_patterns.add(pattern_key)
                        patterns.append(
                            {
                                "field": field,
                                "field_label": field_label,
                                "extractor": extractor,
                                "extractor_label": extractor_label,
                                "match_kind": "hex",
                                "match_ratio": round(hex_ratio * 100, 2),
                                "matched_count": len(hex_matches),
                                "total_count": len(non_empty_values),
                                "joined_preview": self._trim_text("".join(hex_matches), 240),
                                "samples": hex_matches[:8],
                            }
                        )
                    candidate = self._decode_dns_text_chain("".join(hex_matches), initial_mode="hex")
                    if candidate:
                        candidate_key = (field, extractor, "hex", str(candidate.get("decoded_text") or ""))
                        if candidate_key not in seen_candidates:
                            seen_candidates.add(candidate_key)
                            decoded_candidates.append(
                                {
                                    "title": f"{field_label} / {extractor_label} / hex 链式解码",
                                    "field": field,
                                    "field_label": field_label,
                                    "extractor": extractor,
                                    "extractor_label": extractor_label,
                                    "input_kind": "hex",
                                    "joined_length": len("".join(hex_matches)),
                                    "joined_preview": self._trim_text("".join(hex_matches), 240),
                                    "decode_chain": candidate.get("decode_chain"),
                                    "decode_layers": candidate.get("decode_layers"),
                                    "decoded_preview": self._trim_text(candidate.get("decoded_text"), 400),
                                    "decoded_text": self._trim_text(candidate.get("decoded_text"), 4000),
                                }
                            )

                base64_matches = [value for value in non_empty_values if self._looks_like_base64(value)]
                base64_ratio = len(base64_matches) / len(non_empty_values)
                if base64_matches and base64_ratio >= 0.75:
                    pattern_key = (field, extractor, "base64")
                    if pattern_key not in seen_patterns:
                        seen_patterns.add(pattern_key)
                        patterns.append(
                            {
                                "field": field,
                                "field_label": field_label,
                                "extractor": extractor,
                                "extractor_label": extractor_label,
                                "match_kind": "base64",
                                "match_ratio": round(base64_ratio * 100, 2),
                                "matched_count": len(base64_matches),
                                "total_count": len(non_empty_values),
                                "joined_preview": self._trim_text("".join(base64_matches), 240),
                                "samples": base64_matches[:8],
                            }
                        )
                    candidate = self._decode_dns_text_chain("".join(base64_matches), initial_mode="base64")
                    if candidate:
                        candidate_key = (field, extractor, "base64", str(candidate.get("decoded_text") or ""))
                        if candidate_key not in seen_candidates:
                            seen_candidates.add(candidate_key)
                            decoded_candidates.append(
                                {
                                    "title": f"{field_label} / {extractor_label} / base64 链式解码",
                                    "field": field,
                                    "field_label": field_label,
                                    "extractor": extractor,
                                    "extractor_label": extractor_label,
                                    "input_kind": "base64",
                                    "joined_length": len("".join(base64_matches)),
                                    "joined_preview": self._trim_text("".join(base64_matches), 240),
                                    "decode_chain": candidate.get("decode_chain"),
                                    "decode_layers": candidate.get("decode_layers"),
                                    "decoded_preview": self._trim_text(candidate.get("decoded_text"), 400),
                                    "decoded_text": self._trim_text(candidate.get("decoded_text"), 4000),
                                }
                            )

        return {
            "patterns": patterns,
            "decoded_candidates": decoded_candidates,
        }

    def _extract_dns_payload_segment(self, value: Any, *, extractor: str, delimiter: str = ".") -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if extractor == "first_label" and delimiter:
            return text.split(delimiter)[0].strip()
        if extractor == "last_label" and delimiter:
            return text.rsplit(delimiter, 1)[-1].strip()
        if extractor == "joined_labels" and delimiter:
            return "".join(part.strip() for part in text.split(delimiter) if part.strip())
        return text

    def _looks_like_hex(self, value: str) -> bool:
        text = str(value or "").strip()
        return bool(text) and re.fullmatch(r"[0-9a-fA-F]+", text) is not None

    def _looks_like_base64(self, value: str) -> bool:
        text = str(value or "").strip()
        return bool(text) and len(text) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", text) is not None

    def _decode_dns_text_chain(self, value: str, *, initial_mode: str) -> dict[str, Any] | None:
        current = str(value or "").strip()
        if not current:
            return None

        steps: list[str] = []
        if initial_mode == "hex":
            decoded = self._decode_dns_hex_text(current)
            if decoded is None:
                return None
            current = decoded
            steps.append("hex")
        elif initial_mode == "base64":
            decoded = self._decode_dns_base64_text(current)
            if decoded is None:
                return None
            current = decoded
            steps.append("base64")

        for _ in range(8):
            next_text, step = self._decode_dns_next_text_layer(current)
            if next_text is None or not step or next_text == current:
                break
            current = next_text
            steps.append(step)

        return {
            "decoded_text": current,
            "decode_chain": " -> ".join(steps) if steps else initial_mode,
            "decode_layers": len(steps),
        }

    def _decode_dns_next_text_layer(self, value: str) -> tuple[str | None, str | None]:
        text = str(value or "").strip()
        if not text:
            return None, None
        if self._looks_like_hex(text) and len(text) % 2 == 0:
            decoded = self._decode_dns_hex_text(text)
            if decoded is not None and decoded != text:
                return decoded, "hex"
        if self._looks_like_base64(text):
            decoded = self._decode_dns_base64_text(text)
            if decoded is not None and decoded != text:
                return decoded, "base64"
        return None, None

    def _decode_dns_hex_text(self, value: str) -> str | None:
        text = str(value or "").strip()
        if not self._looks_like_hex(text) or len(text) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            return None
        return self._decode_dns_bytes_to_text(raw)

    def _decode_dns_base64_text(self, value: str) -> str | None:
        text = str(value or "").strip()
        if not self._looks_like_base64(text):
            return None
        normalized = text.replace("-", "+").replace("_", "/")
        padding = (-len(normalized)) % 4
        normalized = f"{normalized}{'=' * padding}"
        try:
            raw = base64.b64decode(normalized, validate=True)
        except Exception:
            return None
        return self._decode_dns_bytes_to_text(raw)

    def _decode_dns_bytes_to_text(self, raw: bytes) -> str | None:
        if not raw:
            return None
        for encoding in ("utf-8", "latin1"):
            try:
                text = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            if self._text_printable_ratio(text) >= 0.85:
                return text
        return None

    def _text_printable_ratio(self, value: str) -> float:
        text = str(value or "")
        if not text:
            return 0.0
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        return printable / len(text)

    def _build_attack_detailed_views(self, alerts: List[AttackAlert], limit_per_detector: int = 300) -> dict:
        details: dict[str, dict[str, Any]] = {}
        grouped: dict[str, list[AttackAlert]] = {}
        for alert in alerts:
            detector_name = alert.detector or str(alert.evidence.get("detector") or alert.rule_id)
            grouped.setdefault(detector_name, []).append(alert)

        for detector_name, detector_alerts in grouped.items():
            if detector_name == "WebShellDetector":
                details[detector_name] = self._webshell_attack_details(detector_alerts, limit_per_detector)
            elif detector_name == "SQLInjectionDetector":
                details[detector_name] = self._sqli_attack_details(detector_alerts, limit_per_detector)
            else:
                details[detector_name] = self._generic_attack_details(detector_alerts, limit_per_detector)
        return details

    def _generic_attack_details(self, alerts: List[AttackAlert], limit: int) -> dict:
        records = []
        rule_counter: Counter[str] = Counter()
        severity_counter: Counter[str] = Counter()
        for alert in alerts[:limit]:
            rule_counter[alert.rule_id] += 1
            severity_counter[alert.severity] += 1
            records.append(
                {
                    "packet_index": alert.packet_indexes[0] if alert.packet_indexes else None,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "name": alert.name,
                    "description": alert.description,
                }
            )
        return {
            "records": records,
            "record_count": len(alerts),
            "top_rules": rule_counter.most_common(20),
            "top_severity": severity_counter.most_common(10),
        }

    def _webshell_attack_details(self, alerts: List[AttackAlert], limit: int) -> dict:
        records = []
        family_counter: Counter[str] = Counter()
        variant_counter: Counter[str] = Counter()
        parser_counter: Counter[str] = Counter()
        operation_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        rule_counter: Counter[str] = Counter()
        request_alerts = [alert for alert in alerts if str((alert.evidence or {}).get("stage") or "") == "request"]
        orphan_response_alerts = [
            alert
            for alert in alerts
            if str((alert.evidence or {}).get("stage") or "") == "response"
            and not (alert.evidence or {}).get("linked_request_packet_index")
        ]
        visible_alerts = (request_alerts + orphan_response_alerts)[:limit]

        for alert in visible_alerts:
            detail = alert.evidence or {}
            family_hint = str(detail.get("family_hint") or "")
            family_variant = str(detail.get("family_variant") or "")
            family_parser = str(detail.get("family_parser") or "")
            parsed_operation = str(detail.get("parsed_operation") or "")
            uri = str(detail.get("uri") or "")
            if family_hint:
                family_counter[family_hint] += 1
            if family_variant:
                variant_counter[family_variant] += 1
            if family_parser:
                parser_counter[family_parser] += 1
            if parsed_operation:
                operation_counter[parsed_operation] += 1
            if uri:
                path_counter[uri] += 1
            rule_counter[alert.rule_id] += 1
            records.append(
                {
                    "packet_index": alert.packet_indexes[0] if alert.packet_indexes else None,
                    "response_packet_index": detail.get("linked_response_packet_index"),
                    "request_packet_index": detail.get("linked_request_packet_index"),
                    "possible_webshell": self._webshell_family_label(alert, detail),
                    "interaction_command": self._webshell_interaction_command(detail),
                    "php_script": self._trim_text(self._webshell_php_script(detail), 4000),
                    "log_output": self._trim_text(self._webshell_log_output(alert, detail), 1600),
                    "exported_artifacts": list(detail.get("exported_artifacts") or []),
                    "family_variant": family_variant or None,
                    "parsed_operation": parsed_operation or None,
                    "target_path": detail.get("target_path"),
                    "output": self._trim_text(detail.get("output"), 240),
                }
            )
        specific_labels = [
            item.get("possible_webshell")
            for item in records
            if str(item.get("family_variant") or "").strip() or str(item.get("possible_webshell") or "").startswith("可能是")
        ]
        detected_webshells = self._ordered_unique_texts(specific_labels or [item.get("possible_webshell") for item in records])
        interaction_commands = self._ordered_unique_texts(item.get("interaction_command") for item in records)
        php_scripts = self._ordered_unique_texts(item.get("php_script") for item in records)
        log_entries = self._ordered_unique_texts(item.get("log_output") for item in records)
        return {
            "records": records,
            "record_count": len(visible_alerts),
            "supported_webshell_types": self._supported_webshell_types(),
            "supported_family_options": self._supported_webshell_family_options(),
            "detected_webshells": detected_webshells,
            "interaction_commands": interaction_commands,
            "php_scripts": php_scripts,
            "log_entries": log_entries,
            "top_rules": rule_counter.most_common(20),
            "top_families": family_counter.most_common(20),
            "top_variants": variant_counter.most_common(20),
            "top_family_parsers": parser_counter.most_common(20),
            "top_operations": operation_counter.most_common(20),
            "top_paths": path_counter.most_common(30),
        }

    def _sqli_attack_details(self, alerts: List[AttackAlert], limit: int) -> dict:
        records = []
        type_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        param_counter: Counter[str] = Counter()
        point_counter: Counter[str] = Counter()
        response_length_counter: Counter[str] = Counter()

        for alert in alerts[:limit]:
            detail = alert.evidence or {}
            sqli_type = str(detail.get("sqli_type") or "")
            method = str(detail.get("method") or "")
            uri_path = str(detail.get("uri_path") or detail.get("uri") or "")
            param_name = str(detail.get("param_name") or "")
            param_location = str(detail.get("param_location") or "")
            injection_point = str(detail.get("injection_point") or "") or self._sqli_injection_point(detail)
            response_length = detail.get("response_length")
            if sqli_type:
                type_counter[sqli_type] += 1
            if uri_path:
                path_counter[uri_path] += 1
            if param_name:
                param_counter[f"{param_location}.{param_name}" if param_location else param_name] += 1
            if injection_point:
                point_counter[injection_point] += 1
            if response_length is not None:
                response_length_counter[str(response_length)] += 1

            records.append(
                {
                    "packet_index": alert.packet_indexes[0] if alert.packet_indexes else None,
                    "request_packet_index": detail.get("request_packet_index"),
                    "response_packet_index": detail.get("response_packet_index"),
                    "possible_sqli": self._sqli_type_label(detail),
                    "sqli_type": sqli_type or None,
                    "method": method or None,
                    "uri_path": uri_path or None,
                    "param_name": param_name or None,
                    "param_location": param_location or None,
                    "injection_point": injection_point or None,
                    "target_expression": self._trim_text(detail.get("target_expression"), 240),
                    "bool_position": detail.get("position"),
                    "bool_candidate": detail.get("candidate_char"),
                    "bool_expression": self._trim_text(detail.get("bool_expression"), 320),
                    "response_length": response_length,
                    "response_preview": self._trim_text(detail.get("response_preview"), 220),
                    "response_bool_hint": detail.get("response_bool_hint"),
                }
            )

        detected_types = self._ordered_unique_texts(self._sqli_type_label(item) for item in (alert.evidence or {} for alert in alerts))
        injection_points = self._ordered_unique_texts(item.get("injection_point") for item in records)
        target_expressions = self._ordered_unique_texts(item.get("target_expression") for item in records)
        return {
            "records": records,
            "record_count": len(alerts),
            "supported_sqli_types": self._supported_sqli_types(),
            "supported_type_options": self._supported_sqli_type_options(),
            "detected_sqli_types": detected_types,
            "injection_points": injection_points,
            "target_expressions": target_expressions,
            "top_types": [(self._sqli_type_label({"sqli_type": name}), count) for name, count in type_counter.most_common(20)],
            "top_paths": path_counter.most_common(30),
            "top_params": param_counter.most_common(30),
            "top_injection_points": point_counter.most_common(30),
            "top_response_lengths": response_length_counter.most_common(20),
        }

    def _supported_sqli_types(self) -> list[str]:
        return [item["label"] for item in self._supported_sqli_type_options()]

    def _supported_sqli_type_options(self) -> list[dict[str, str]]:
        return [
            {"value": "bool_blind", "label": "Bool 盲注"},
        ]

    def _sqli_type_label(self, detail: dict | None) -> str:
        sqli_type = str((detail or {}).get("sqli_type") or "").strip()
        if sqli_type == "bool_blind":
            return "可能是 Bool 盲注 SQL 注入"
        return "可能是 SQL 注入"

    def _sqli_injection_point(self, detail: dict | None) -> str:
        item = detail or {}
        method = str(item.get("method") or "").strip()
        uri_path = str(item.get("uri_path") or item.get("uri") or "").strip() or "/"
        param_location = str(item.get("param_location") or "").strip()
        param_name = str(item.get("param_name") or "").strip()
        if method and param_name:
            scope = f"{param_location}.{param_name}" if param_location else param_name
            return f"{method} {uri_path} :: {scope}"
        if method:
            return f"{method} {uri_path}"
        return uri_path

    def _supported_webshell_types(self) -> list[str]:
        return [item["label"] for item in self._supported_webshell_family_options()]

    def _supported_webshell_family_options(self) -> list[dict[str, str]]:
        return [
            {"value": "china_chopper_like", "label": "中国菜刀类 PHP WebShell"},
            {"value": "cookie_exec_like", "label": "Cookie 命令执行类 PHP WebShell"},
            {"value": "godzilla_like", "label": "哥斯拉类 PHP WebShell"},
        ]

    def _tls_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        sessions = []
        sni_counter: Counter[str] = Counter()
        for event in events[:limit]:
            detail = event.details or {}
            sni = str(detail.get("sni") or "")
            if sni:
                sni_counter[sni] += 1
            sessions.append(
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "sni": sni,
                    "version": detail.get("version"),
                    "cipher_suite": detail.get("cipher_suite"),
                }
            )
        return {
            "sessions": sessions,
            "session_count": len(events),
            "top_sni": sni_counter.most_common(30),
        }

    def _modbus_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        operations = []
        func_counter: Counter[str] = Counter()
        for event in events[:limit]:
            detail = event.details or {}
            func = str(detail.get("func_code") or "")
            if func:
                func_counter[func] += 1
            operations.append(
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "trans_id": detail.get("trans_id"),
                    "unit_id": detail.get("unit_id"),
                    "func_code": detail.get("func_code"),
                    "reference_num": detail.get("reference_num"),
                }
            )
        return {
            "operations": operations,
            "operation_count": len(events),
            "top_func_codes": func_counter.most_common(20),
        }

    def _usb_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        device_profiles: dict[str, dict[str, Any]] = {}
        devices_seen: set[str] = set()
        devices_order: list[str] = []
        hid_events: list[ProtocolEvent] = []
        storage_events: list[ProtocolEvent] = []

        for event in events:
            detail = event.details or {}
            device_id = str(detail.get("device_address") or "").strip()
            if device_id and device_id not in devices_seen:
                devices_seen.add(device_id)
                devices_order.append(device_id)
            profile = self._usb_get_device_profile(device_profiles, detail)
            if profile is not None:
                self._usb_update_device_profile(profile, detail)
            if str(detail.get("report_hex") or "").strip():
                hid_events.append(event)
            if str(detail.get("kind") or "").startswith("usbms_"):
                storage_events.append(event)

        mouse_reports: list[dict[str, Any]] = []
        mouse_points: list[dict[str, Any]] = []
        mouse_draw_segments_all: list[dict[str, Any]] = []
        mouse_cursor_state: dict[str, dict[str, int]] = {}
        mouse_segment_state: dict[str, list[dict[str, Any]]] = {}
        keyboard_reports: list[dict[str, Any]] = []
        keyboard_events: list[dict[str, Any]] = []
        keyboard_state: dict[str, dict[str, Any]] = {}
        keyboard_full_parts: list[str] = []

        for event in hid_events:
            detail = event.details or {}
            device_id = str(detail.get("device_address") or "").strip()
            profile = device_profiles.get(device_id or "")
            report = self._usb_decode_report_bytes(detail.get("report_hex"))
            if not report:
                continue

            role = self._usb_choose_report_role(report=report, device_profile=profile)
            if role == "mouse":
                decoded = self._usb_decode_mouse_report(report)
                if decoded is None:
                    continue
                state_key = device_id or str(event.flow_id or f"packet:{event.packet_index}")
                cursor = mouse_cursor_state.get(state_key)
                if cursor is None:
                    cursor = {"x": 0, "y": 0}
                    mouse_cursor_state[state_key] = cursor
                cursor["x"] += decoded["dx"]
                cursor["y"] += decoded["dy"]
                mouse_row = {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "device_address": device_id or None,
                    "vendor_id": self._usb_profile_value(profile, "vendor_id"),
                    "product_id": self._usb_profile_value(profile, "product_id"),
                    "report_hex": report.hex(),
                    "buttons": decoded["buttons"],
                    "left_button": decoded["left_button"],
                    "right_button": decoded["right_button"],
                    "middle_button": decoded["middle_button"],
                    "dx": decoded["dx"],
                    "dy": decoded["dy"],
                    "wheel": decoded["wheel"],
                    "x": cursor["x"],
                    "y": cursor["y"],
                }
                mouse_reports.append(mouse_row)
                mouse_point = {
                    "packet_index": event.packet_index,
                    "device_address": device_id or None,
                    "x": cursor["x"],
                    "y": cursor["y"],
                    "left_button": decoded["left_button"],
                    "right_button": decoded["right_button"],
                    "middle_button": decoded["middle_button"],
                }
                mouse_points.append(mouse_point)
                if decoded["left_button"]:
                    mouse_segment_state.setdefault(state_key, []).append(mouse_point)
                else:
                    self._usb_close_mouse_draw_segment(mouse_draw_segments_all, mouse_segment_state, state_key)
                if profile is not None:
                    profile["mouse_report_count"] = int(profile.get("mouse_report_count") or 0) + 1
                continue

            if role == "keyboard":
                state_key = device_id or str(event.flow_id or f"packet:{event.packet_index}")
                previous = keyboard_state.get(state_key) or {
                    "pressed_codes": [],
                }
                decoded = self._usb_decode_keyboard_report(report, previous)
                keyboard_state[state_key] = {"pressed_codes": decoded["pressed_codes"]}
                keyboard_row = {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "device_address": device_id or None,
                    "vendor_id": self._usb_profile_value(profile, "vendor_id"),
                    "product_id": self._usb_profile_value(profile, "product_id"),
                    "report_hex": report.hex(),
                    "modifiers": decoded["modifiers"],
                    "pressed_codes": decoded["pressed_codes"],
                    "new_keys": decoded["new_keys"],
                    "tokens": decoded["tokens"],
                }
                keyboard_reports.append(keyboard_row)
                keyboard_events.extend(
                    {
                        "packet_index": event.packet_index,
                        "device_address": device_id or None,
                        **item,
                    }
                    for item in decoded["events"]
                )
                keyboard_full_parts.extend(decoded["tokens"])
                if profile is not None:
                    profile["keyboard_report_count"] = int(profile.get("keyboard_report_count") or 0) + 1

        for state_key in list(mouse_segment_state):
            self._usb_close_mouse_draw_segment(mouse_draw_segments_all, mouse_segment_state, state_key)

        keyboard_full_text = "".join(keyboard_full_parts)
        keyboard_edited_text = self._usb_replay_keyboard_events(keyboard_events)
        storage = self._usb_build_storage_details(storage_events, device_profiles, limit)
        limited_mouse_reports = mouse_reports[:limit]
        limited_keyboard_reports = keyboard_reports[:limit]
        limited_keyboard_events = keyboard_events[:limit]
        mouse_draw_min_segment_points = 3
        mouse_draw_segments = [
            segment
            for segment in mouse_draw_segments_all
            if int(segment.get("point_count") or 0) >= mouse_draw_min_segment_points
        ]
        mouse_draw_point_count = sum(int(segment.get("point_count") or 0) for segment in mouse_draw_segments)
        mouse_draw_bbox = self._usb_bbox(
            [point for segment in mouse_draw_segments for point in (segment.get("points") or [])]
        )

        devices: list[dict[str, Any]] = []
        for device_id in devices_order:
            profile = device_profiles.get(device_id) or {"device_address": device_id}
            roles = sorted(str(item) for item in (profile.get("roles") or set()) if str(item))
            devices.append(
                {
                    "device_address": device_id or None,
                    "vendor_id": self._usb_profile_value(profile, "vendor_id"),
                    "product_id": self._usb_profile_value(profile, "product_id"),
                    "interface_classes": list(profile.get("interface_classes") or []),
                    "interface_subclasses": list(profile.get("interface_subclasses") or []),
                    "interface_protocols": list(profile.get("interface_protocols") or []),
                    "roles": roles,
                    "report_count": int(profile.get("report_count") or 0),
                    "mouse_report_count": int(profile.get("mouse_report_count") or 0),
                    "keyboard_report_count": int(profile.get("keyboard_report_count") or 0),
                    "storage_command_count": int(profile.get("storage_command_count") or 0),
                    "storage_write_count": int(profile.get("storage_write_count") or 0),
                }
            )

        mouse_bbox = self._usb_bbox(mouse_points)
        return {
            "records": [
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "device_address": (event.details or {}).get("device_address"),
                    "kind": (event.details or {}).get("kind"),
                    "report_hex": (event.details or {}).get("report_hex"),
                    "vendor_id": (event.details or {}).get("vendor_id"),
                    "product_id": (event.details or {}).get("product_id"),
                }
                for event in events[:limit]
            ],
            "record_count": len(events),
            "device_count": len(devices),
            "hid_report_count": len(hid_events),
            "mouse_report_count": len(mouse_reports),
            "keyboard_report_count": len(keyboard_reports),
            "storage_event_count": len(storage_events),
            "devices": devices,
            "mouse": {
                "reports": limited_mouse_reports,
                "report_count": len(mouse_reports),
                "trace_points": mouse_points,
                "trace_point_count": len(mouse_points),
                "bbox": mouse_bbox,
                "draw_segments": mouse_draw_segments,
                "draw_segment_count": len(mouse_draw_segments),
                "draw_segment_total_count": len(mouse_draw_segments_all),
                "draw_noise_segment_count": max(0, len(mouse_draw_segments_all) - len(mouse_draw_segments)),
                "draw_point_count": mouse_draw_point_count,
                "draw_bbox": mouse_draw_bbox,
                "draw_min_segment_points": mouse_draw_min_segment_points,
            },
            "keyboard": {
                "reports": limited_keyboard_reports,
                "report_count": len(keyboard_reports),
                "events": limited_keyboard_events,
                "event_count": len(keyboard_events),
                "full_text": keyboard_full_text,
                "edited_text": keyboard_edited_text,
            },
            "storage": storage,
        }

    def _usb_get_device_profile(self, profiles: dict[str, dict[str, Any]], detail: dict[str, Any]) -> dict[str, Any] | None:
        device_id = str(detail.get("device_address") or "").strip()
        if not device_id:
            return None
        profile = profiles.get(device_id)
        if profile is None:
            profile = {
                "device_address": device_id,
                "vendor_id": None,
                "product_id": None,
                "interface_classes": [],
                "interface_subclasses": [],
                "interface_protocols": [],
                "roles": set(),
                "report_count": 0,
                "mouse_report_count": 0,
                "keyboard_report_count": 0,
                "storage_command_count": 0,
                "storage_write_count": 0,
            }
            profiles[device_id] = profile
        return profile

    def _usb_update_device_profile(self, profile: dict[str, Any], detail: dict[str, Any]) -> None:
        vendor_id = str(detail.get("vendor_id") or "").strip() or None
        product_id = str(detail.get("product_id") or "").strip() or None
        if vendor_id and not profile.get("vendor_id"):
            profile["vendor_id"] = vendor_id
        if product_id and not profile.get("product_id"):
            profile["product_id"] = product_id

        classes = self._usb_parse_csv_ints(detail.get("interface_classes"))
        subclasses = self._usb_parse_csv_ints(detail.get("interface_subclasses"))
        protocols = self._usb_parse_csv_ints(detail.get("interface_protocols"))
        if classes:
            profile["interface_classes"] = self._usb_merge_unique_int_lists(profile.get("interface_classes"), classes)
        if subclasses:
            profile["interface_subclasses"] = self._usb_merge_unique_int_lists(profile.get("interface_subclasses"), subclasses)
        if protocols:
            profile["interface_protocols"] = self._usb_merge_unique_int_lists(profile.get("interface_protocols"), protocols)

        roles = profile.get("roles")
        if not isinstance(roles, set):
            roles = set(str(item) for item in (roles or []) if str(item))
            profile["roles"] = roles
        paired = list(zip(classes, protocols)) if classes and protocols and len(classes) == len(protocols) else []
        hid_protocols = [protocol for interface_class, protocol in paired if interface_class == 0x03]
        if not hid_protocols and 0x03 in classes and len(protocols) == 1:
            hid_protocols = list(protocols)
        if any(value == 0x01 for value in hid_protocols):
            roles.add("keyboard")
        if any(value == 0x02 for value in hid_protocols):
            roles.add("mouse")
        if any(value == 0x08 for value in classes):
            roles.add("storage")

        if str(detail.get("report_hex") or "").strip():
            profile["report_count"] = int(profile.get("report_count") or 0) + 1

    def _usb_merge_unique_int_lists(self, current: Any, values: list[int]) -> list[int]:
        merged = [int(item) for item in (current or [])]
        seen = set(merged)
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)
        return merged

    def _usb_parse_csv_ints(self, value: Any) -> list[int]:
        text = str(value or "").strip()
        if not text:
            return []
        rows: list[int] = []
        for item in text.split(","):
            normalized = str(item or "").strip()
            if not normalized:
                continue
            try:
                rows.append(int(normalized, 16 if normalized.lower().startswith("0x") else 10))
            except ValueError:
                continue
        return rows

    def _usb_profile_value(self, profile: dict[str, Any] | None, key: str) -> Any:
        if not profile:
            return None
        value = profile.get(key)
        return value if value not in ("", None) else None

    def _usb_close_mouse_draw_segment(
        self,
        segments: list[dict[str, Any]],
        segment_state: dict[str, list[dict[str, Any]]],
        state_key: str,
    ) -> None:
        points = list(segment_state.pop(state_key, []) or [])
        if not points:
            return
        segments.append(
            {
                "device_address": points[0].get("device_address"),
                "packet_index_start": points[0].get("packet_index"),
                "packet_index_end": points[-1].get("packet_index"),
                "point_count": len(points),
                "bbox": self._usb_bbox(points),
                "points": points,
            }
        )

    def _usb_decode_report_bytes(self, value: Any) -> bytes:
        text = str(value or "").strip().replace(":", "").replace(" ", "")
        if not text:
            return b""
        try:
            return bytes.fromhex(text)
        except ValueError:
            return b""

    def _usb_choose_report_role(self, *, report: bytes, device_profile: dict[str, Any] | None) -> str | None:
        roles = set(str(item) for item in ((device_profile or {}).get("roles") or set()) if str(item))
        if len(roles) == 1:
            return next(iter(roles))

        keyboard_guess = self._usb_looks_like_keyboard_report(report)
        mouse_guess = self._usb_looks_like_mouse_report(report)
        if mouse_guess and not keyboard_guess:
            return "mouse"
        if keyboard_guess and not mouse_guess:
            return "keyboard"
        if "mouse" in roles:
            return "mouse"
        if "keyboard" in roles:
            return "keyboard"
        return None

    def _usb_looks_like_mouse_report(self, report: bytes) -> bool:
        if len(report) >= 6:
            dx = int.from_bytes(report[2:4], "little", signed=True)
            dy = int.from_bytes(report[4:6], "little", signed=True)
            if dx != 0 or dy != 0:
                return True
        if len(report) >= 4:
            dx = int.from_bytes(report[1:2], "little", signed=True)
            dy = int.from_bytes(report[2:3], "little", signed=True)
            if dx != 0 or dy != 0:
                return True
        return False

    def _usb_looks_like_keyboard_report(self, report: bytes) -> bool:
        if len(report) != 8 or report[1] != 0:
            return False
        keycodes = [item for item in report[2:8] if item]
        if not keycodes:
            return False
        return all(self._usb_is_reasonable_keyboard_keycode(code) for code in keycodes)

    def _usb_is_reasonable_keyboard_keycode(self, code: int) -> bool:
        return (
            0x04 <= code <= 0x73
            or code in {0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x39, 0x4C, 0x4F, 0x50, 0x51, 0x52}
        )

    def _usb_decode_mouse_report(self, report: bytes) -> dict[str, Any] | None:
        if len(report) >= 6:
            button_mask = report[0]
            dx = int.from_bytes(report[2:4], "little", signed=True)
            dy = int.from_bytes(report[4:6], "little", signed=True)
            wheel = int.from_bytes(report[6:7], "little", signed=True) if len(report) >= 7 else 0
        elif len(report) >= 4:
            button_mask = report[0]
            dx = int.from_bytes(report[1:2], "little", signed=True)
            dy = int.from_bytes(report[2:3], "little", signed=True)
            wheel = int.from_bytes(report[3:4], "little", signed=True)
        else:
            return None
        return {
            "buttons": button_mask,
            "left_button": bool(button_mask & 0x01),
            "right_button": bool(button_mask & 0x02),
            "middle_button": bool(button_mask & 0x04),
            "dx": dx,
            "dy": dy,
            "wheel": wheel,
        }

    def _usb_decode_keyboard_report(self, report: bytes, previous: dict[str, Any] | None) -> dict[str, Any]:
        modifiers = report[0] if len(report) >= 1 else 0
        pressed_codes = [code for code in report[2:8] if code] if len(report) >= 8 else []
        previous_codes = [int(code) for code in (previous or {}).get("pressed_codes") or []]
        previous_set = set(previous_codes)
        new_keys = [code for code in pressed_codes if code not in previous_set]
        tokens: list[str] = []
        events: list[dict[str, Any]] = []
        for code in new_keys:
            decoded = self._usb_keyboard_key_event(code=code, modifiers=modifiers)
            tokens.append(decoded["token"])
            events.append(decoded)
        return {
            "modifiers": modifiers,
            "pressed_codes": pressed_codes,
            "new_keys": new_keys,
            "tokens": tokens,
            "events": events,
        }

    def _usb_keyboard_key_event(self, *, code: int, modifiers: int) -> dict[str, Any]:
        shift = bool(modifiers & 0x22)
        ctrl = bool(modifiers & 0x11)
        alt = bool(modifiers & 0x44)
        key = self._usb_keyboard_keycode_to_token(code=code, shift=shift)
        return {
            "keycode": code,
            "keycode_hex": f"0x{code:02x}",
            "shift": shift,
            "ctrl": ctrl,
            "alt": alt,
            "token": key["token"],
            "text": key["text"],
            "action": key["action"],
            "label": key["label"],
        }

    def _usb_keyboard_keycode_to_token(self, *, code: int, shift: bool) -> dict[str, str]:
        letters = {
            **{0x04 + idx: chr(ord("a") + idx) for idx in range(26)},
        }
        digits = {
            0x1E: ("1", "!"),
            0x1F: ("2", "@"),
            0x20: ("3", "#"),
            0x21: ("4", "$"),
            0x22: ("5", "%"),
            0x23: ("6", "^"),
            0x24: ("7", "&"),
            0x25: ("8", "*"),
            0x26: ("9", "("),
            0x27: ("0", ")"),
        }
        punctuation = {
            0x2D: ("-", "_"),
            0x2E: ("=", "+"),
            0x2F: ("[", "{"),
            0x30: ("]", "}"),
            0x31: ("\\", "|"),
            0x33: (";", ":"),
            0x34: ("'", "\""),
            0x35: ("`", "~"),
            0x36: (",", "<"),
            0x37: (".", ">"),
            0x38: ("/", "?"),
        }
        special = {
            0x28: {"token": "\n", "text": "\n", "action": "insert", "label": "Enter"},
            0x29: {"token": "<ESC>", "text": "", "action": "noop", "label": "Esc"},
            0x2A: {"token": "<BS>", "text": "", "action": "backspace", "label": "Backspace"},
            0x2B: {"token": "\t", "text": "\t", "action": "insert", "label": "Tab"},
            0x2C: {"token": " ", "text": " ", "action": "insert", "label": "Space"},
            0x39: {"token": "<CAPSLOCK>", "text": "", "action": "noop", "label": "CapsLock"},
            0x4C: {"token": "<DEL>", "text": "", "action": "delete", "label": "Delete"},
            0x4F: {"token": "<RIGHT>", "text": "", "action": "right", "label": "Right"},
            0x50: {"token": "<LEFT>", "text": "", "action": "left", "label": "Left"},
            0x51: {"token": "<DOWN>", "text": "", "action": "down", "label": "Down"},
            0x52: {"token": "<UP>", "text": "", "action": "up", "label": "Up"},
        }
        if code in special:
            return special[code]
        if code in letters:
            ch = letters[code]
            char = ch.upper() if shift else ch
            return {"token": char, "text": char, "action": "insert", "label": char}
        if code in digits:
            normal, shifted = digits[code]
            char = shifted if shift else normal
            return {"token": char, "text": char, "action": "insert", "label": char}
        if code in punctuation:
            normal, shifted = punctuation[code]
            char = shifted if shift else normal
            return {"token": char, "text": char, "action": "insert", "label": char}
        return {"token": f"<0x{code:02x}>", "text": "", "action": "noop", "label": f"0x{code:02x}"}

    def _usb_replay_keyboard_events(self, events: list[dict[str, Any]]) -> str:
        buffer: list[str] = []
        cursor = 0
        for event in events:
            action = str(event.get("action") or "noop")
            text = str(event.get("text") or "")
            if action == "insert":
                if not text:
                    continue
                for ch in text:
                    buffer.insert(cursor, ch)
                    cursor += 1
                continue
            if action == "backspace":
                if cursor > 0:
                    cursor -= 1
                    buffer.pop(cursor)
                continue
            if action == "delete":
                if cursor < len(buffer):
                    buffer.pop(cursor)
                continue
            if action == "left":
                cursor = max(0, cursor - 1)
                continue
            if action == "right":
                cursor = min(len(buffer), cursor + 1)
                continue
            if action == "up" or action == "down":
                continue
        return "".join(buffer)

    def _usb_bbox(self, points: list[dict[str, Any]]) -> dict[str, int] | None:
        if not points:
            return None
        xs = [int(point.get("x") or 0) for point in points]
        ys = [int(point.get("y") or 0) for point in points]
        return {
            "min_x": min(xs),
            "max_x": max(xs),
            "min_y": min(ys),
            "max_y": max(ys),
            "width": max(xs) - min(xs),
            "height": max(ys) - min(ys),
        }

    def _usb_build_storage_details(
        self,
        events: list[ProtocolEvent],
        device_profiles: dict[str, dict[str, Any]],
        limit: int,
    ) -> dict[str, Any]:
        if not events:
            return self._usb_empty_storage_detail()

        pending: dict[str, dict[str, Any]] = {}
        commands: list[dict[str, Any]] = []

        for event in events:
            detail = event.details or {}
            device_id = str(detail.get("device_address") or "").strip()
            if not device_id:
                continue
            kind = str(detail.get("kind") or "").strip()
            if kind == "usbms_cbw":
                current = pending.pop(device_id, None)
                if current is not None:
                    commands.append(self._usb_finalize_storage_command(current, complete=False))
                pending[device_id] = {
                    "device_address": device_id,
                    "cbw_packet_index": event.packet_index,
                    "csw_packet_index": None,
                    "tag": str(detail.get("tag") or "").strip() or None,
                    "opcode": str(detail.get("opcode") or "").strip() or None,
                    "opcode_name": str(detail.get("opcode_name") or "").strip() or None,
                    "direction": str(detail.get("data_direction") or "").strip() or None,
                    "transfer_length": int(detail.get("transfer_length") or 0),
                    "transfer_blocks": detail.get("transfer_blocks"),
                    "lba": detail.get("lba"),
                    "status": None,
                    "status_text": None,
                    "residue": None,
                    "data_packet_indexes": [],
                    "payload_chunks": [],
                }
                continue

            current = pending.get(device_id)
            if current is None:
                continue
            if kind == "usbms_data":
                payload_hex = str(detail.get("payload_hex") or "").strip().lower()
                if payload_hex:
                    current["payload_chunks"].append(payload_hex)
                    current["data_packet_indexes"].append(event.packet_index)
                continue
            if kind == "usbms_csw":
                current["csw_packet_index"] = event.packet_index
                current["status"] = detail.get("status")
                current["status_text"] = str(detail.get("status_text") or "").strip() or None
                current["residue"] = detail.get("residue")
                commands.append(self._usb_finalize_storage_command(current, complete=True))
                pending.pop(device_id, None)

        for current in pending.values():
            commands.append(self._usb_finalize_storage_command(current, complete=False))

        for command in commands:
            profile = device_profiles.get(str(command.get("device_address") or "").strip())
            if profile is not None:
                profile["storage_command_count"] = int(profile.get("storage_command_count") or 0) + 1

        writes, sector_map = self._usb_build_storage_writes(commands, device_profiles)
        export_context = self._usb_storage_export_context()
        writes = self._usb_export_storage_writes(writes, export_context=export_context)
        exfat = self._usb_parse_exfat_sector_map(sector_map)
        exfat = self._usb_export_exfat_files(exfat, sector_map=sector_map, export_context=export_context)
        return {
            "commands": [self._usb_public_storage_command(command) for command in commands[:limit]],
            "command_count": len(commands),
            "writes": [self._usb_public_storage_write(write) for write in writes[:limit]],
            "write_count": len(writes),
            "write_export_count": sum(1 for item in writes if item.get("url")),
            "sector_count": len(sector_map),
            "exfat": exfat,
        }

    def _usb_empty_storage_detail(self) -> dict[str, Any]:
        return {
            "commands": [],
            "command_count": 0,
            "writes": [],
            "write_count": 0,
            "write_export_count": 0,
            "sector_count": 0,
            "exfat": {
                "detected": False,
                "files": [],
                "file_count": 0,
                "exported_file_count": 0,
                "root_sector_count": 0,
            },
        }

    def _usb_finalize_storage_command(self, current: dict[str, Any], *, complete: bool) -> dict[str, Any]:
        payload_chunks = [str(item or "").strip() for item in current.get("payload_chunks") or []]
        payload_bytes = b""
        for chunk in payload_chunks:
            if not chunk:
                continue
            try:
                payload_bytes += bytes.fromhex(chunk)
            except ValueError:
                continue
        payload_sha1 = hashlib.sha1(payload_bytes).hexdigest() if payload_bytes else None
        return {
            "device_address": current.get("device_address"),
            "cbw_packet_index": current.get("cbw_packet_index"),
            "csw_packet_index": current.get("csw_packet_index"),
            "data_packet_indexes": list(current.get("data_packet_indexes") or []),
            "data_packet_count": len(current.get("data_packet_indexes") or []),
            "tag": current.get("tag"),
            "opcode": current.get("opcode"),
            "opcode_name": current.get("opcode_name"),
            "direction": current.get("direction"),
            "transfer_length": int(current.get("transfer_length") or 0),
            "transfer_blocks": current.get("transfer_blocks"),
            "lba": current.get("lba"),
            "status": current.get("status"),
            "status_text": current.get("status_text"),
            "residue": current.get("residue"),
            "complete": complete and current.get("csw_packet_index") is not None,
            "payload_bytes": payload_bytes,
            "payload_length": len(payload_bytes),
            "payload_preview_hex": payload_bytes[:64].hex() if payload_bytes else "",
            "payload_sha1": payload_sha1,
        }

    def _usb_public_storage_command(self, command: dict[str, Any]) -> dict[str, Any]:
        return {
            "device_address": command.get("device_address"),
            "cbw_packet_index": command.get("cbw_packet_index"),
            "csw_packet_index": command.get("csw_packet_index"),
            "data_packet_count": command.get("data_packet_count"),
            "tag": command.get("tag"),
            "opcode": command.get("opcode"),
            "opcode_name": command.get("opcode_name"),
            "direction": command.get("direction"),
            "transfer_length": command.get("transfer_length"),
            "transfer_blocks": command.get("transfer_blocks"),
            "lba": command.get("lba"),
            "status": command.get("status"),
            "status_text": command.get("status_text"),
            "residue": command.get("residue"),
            "complete": command.get("complete"),
            "payload_length": command.get("payload_length"),
            "payload_preview_hex": command.get("payload_preview_hex"),
            "payload_sha1": command.get("payload_sha1"),
        }

    def _usb_build_storage_writes(
        self,
        commands: list[dict[str, Any]],
        device_profiles: dict[str, dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[int, bytes]]:
        writes: list[dict[str, Any]] = []
        sector_map: dict[int, bytes] = {}

        for command in commands:
            payload_bytes = bytes(command.get("payload_bytes") or b"")
            if (
                str(command.get("direction") or "") != "out"
                or str(command.get("opcode") or "").lower() != "0x2a"
                or command.get("lba") is None
                or not payload_bytes
            ):
                continue

            block_size = self._usb_guess_storage_block_size(command)
            if block_size <= 0:
                continue
            sector_count = len(payload_bytes) // block_size
            if sector_count <= 0:
                continue

            first_lba = int(command.get("lba") or 0)
            for sector_index in range(sector_count):
                start = sector_index * block_size
                end = start + block_size
                chunk = payload_bytes[start:end]
                if len(chunk) != block_size:
                    continue
                sector_map[first_lba + sector_index] = chunk

            writes.append(
                {
                    "device_address": command.get("device_address"),
                    "cbw_packet_index": command.get("cbw_packet_index"),
                    "csw_packet_index": command.get("csw_packet_index"),
                    "tag": command.get("tag"),
                    "opcode": command.get("opcode"),
                    "opcode_name": command.get("opcode_name"),
                    "block_size": block_size,
                    "sector_count": sector_count,
                    "first_lba": first_lba,
                    "last_lba": first_lba + sector_count - 1,
                    "payload_length": command.get("payload_length"),
                    "payload_sha1": command.get("payload_sha1"),
                    "complete": command.get("complete"),
                    "status_text": command.get("status_text"),
                    "_payload_bytes": payload_bytes,
                }
            )

            profile = device_profiles.get(str(command.get("device_address") or "").strip())
            if profile is not None:
                profile["storage_write_count"] = int(profile.get("storage_write_count") or 0) + 1

        return writes, sector_map

    def _usb_public_storage_write(self, write: dict[str, Any]) -> dict[str, Any]:
        return {
            "device_address": write.get("device_address"),
            "cbw_packet_index": write.get("cbw_packet_index"),
            "csw_packet_index": write.get("csw_packet_index"),
            "tag": write.get("tag"),
            "opcode": write.get("opcode"),
            "opcode_name": write.get("opcode_name"),
            "block_size": write.get("block_size"),
            "sector_count": write.get("sector_count"),
            "first_lba": write.get("first_lba"),
            "last_lba": write.get("last_lba"),
            "payload_length": write.get("payload_length"),
            "payload_sha1": write.get("payload_sha1"),
            "complete": write.get("complete"),
            "status_text": write.get("status_text"),
            "saved_path": write.get("saved_path"),
            "saved_name": write.get("saved_name"),
            "saved_size": write.get("saved_size"),
            "url": write.get("url"),
            "viewer_url": write.get("viewer_url"),
        }

    def _usb_storage_export_context(self) -> tuple[Path, Path] | None:
        source = str(self.source or "").strip()
        if not source or source in {"in-memory", "unit-test"}:
            return None

        source_path = Path(source)
        if not source_path.exists():
            return None

        export_root = self.http_export_root
        try:
            export_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.stem) or "capture"
        source_hash = hashlib.sha1(str(source_path.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
        capture_dir = export_root / "usb_storage" / f"{safe_stem}_{source_hash}"
        try:
            capture_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        return export_root, capture_dir

    def _usb_export_storage_writes(
        self,
        writes: list[dict[str, Any]],
        *,
        export_context: tuple[Path, Path] | None,
    ) -> list[dict[str, Any]]:
        if export_context is None:
            return writes

        export_root, capture_dir = export_context
        exported_rows: list[dict[str, Any]] = []
        for write_index, write in enumerate(writes, start=1):
            row = dict(write)
            data = bytes(row.get("_payload_bytes") or b"")
            if not data:
                exported_rows.append(row)
                continue

            device_dir = capture_dir / "writes" / f"device_{self._sanitize_http_rebuild_name(str(row.get('device_address') or ''), fallback='unknown')}"
            device_dir.mkdir(parents=True, exist_ok=True)
            export_name = self._usb_write_export_name(write=row, write_index=write_index)
            export_path = device_dir / export_name
            export_path.write_bytes(data)
            relative = export_path.relative_to(export_root).as_posix()
            row.update(
                {
                    "saved_path": str(export_path),
                    "saved_name": export_path.name,
                    "saved_size": len(data),
                    "url": artifact_raw_url(relative),
                    "viewer_url": artifact_viewer_url(relative),
                }
            )
            exported_rows.append(row)
        return exported_rows

    def _usb_write_export_name(self, *, write: dict[str, Any], write_index: int) -> str:
        packet_index = int(write.get("cbw_packet_index") or 0)
        first_lba = int(write.get("first_lba") or 0)
        sector_count = int(write.get("sector_count") or 0)
        opcode_name = self._sanitize_http_rebuild_name(str(write.get("opcode_name") or write.get("opcode") or "write"), fallback="write")
        return f"pkt{packet_index:06d}_w{write_index:03d}_{opcode_name}_lba{first_lba:08d}_n{sector_count:05d}.bin"

    def _usb_guess_storage_block_size(self, command: dict[str, Any]) -> int:
        payload_length = int(command.get("payload_length") or 0)
        transfer_blocks = int(command.get("transfer_blocks") or 0)
        transfer_length = int(command.get("transfer_length") or 0)
        candidates: list[int] = []
        if transfer_blocks > 0 and payload_length >= transfer_blocks and payload_length % transfer_blocks == 0:
            candidates.append(payload_length // transfer_blocks)
        if transfer_blocks > 0 and transfer_length >= transfer_blocks and transfer_length % transfer_blocks == 0:
            candidates.append(transfer_length // transfer_blocks)
        for candidate in candidates:
            if candidate >= 128 and candidate <= 65536 and candidate & (candidate - 1) == 0:
                return candidate
        return 512

    def _usb_parse_exfat_sector_map(self, sector_map: dict[int, bytes]) -> dict[str, Any]:
        if not sector_map:
            return {
                "detected": False,
                "files": [],
                "file_count": 0,
                "exported_file_count": 0,
                "root_sector_count": 0,
            }

        boot = None
        for lba in sorted(sector_map):
            boot = self._usb_parse_exfat_boot_sector(lba, sector_map[lba])
            if boot is not None:
                break
        if boot is None:
            return {
                "detected": False,
                "files": [],
                "file_count": 0,
                "exported_file_count": 0,
                "root_sector_count": 0,
            }

        root_dir_first_lba = self._usb_exfat_cluster_to_lba(boot, int(boot.get("root_cluster") or 0))
        sectors_per_cluster = int(boot.get("sectors_per_cluster") or 0)
        root_sectors = [
            (lba, sector_map[lba])
            for lba in sorted(sector_map)
            if root_dir_first_lba is not None
            and sectors_per_cluster > 0
            and root_dir_first_lba <= lba < root_dir_first_lba + sectors_per_cluster
        ]
        files = self._usb_parse_exfat_root_directory(root_sectors, boot)
        return {
            **boot,
            "detected": True,
            "root_dir_first_lba": root_dir_first_lba,
            "root_sector_count": len(root_sectors),
            "files": files,
            "file_count": len(files),
            "exported_file_count": 0,
        }

    def _usb_export_exfat_files(
        self,
        exfat: dict[str, Any],
        *,
        sector_map: dict[int, bytes],
        export_context: tuple[Path, Path] | None,
    ) -> dict[str, Any]:
        if not exfat.get("detected"):
            return exfat

        files = [dict(item) for item in (exfat.get("files") or [])]
        if not files:
            exported = dict(exfat)
            exported["files"] = files
            exported["exported_file_count"] = 0
            return exported

        bytes_per_sector = int(exfat.get("bytes_per_sector") or 512)
        sectors_per_cluster = int(exfat.get("sectors_per_cluster") or 1)
        cluster_size = max(1, bytes_per_sector * sectors_per_cluster)
        exported_count = 0

        for file_index, row in enumerate(files, start=1):
            size = int(row.get("size") or 0)
            first_lba = row.get("first_lba")
            no_fat_chain = bool(row.get("no_fat_chain"))
            can_extract = size > 0 and first_lba is not None and (size <= cluster_size or no_fat_chain)
            if not can_extract:
                row["export_status"] = "unsupported_layout"
                continue

            sector_count = (size + bytes_per_sector - 1) // bytes_per_sector
            start_lba = int(first_lba)
            missing_lbas = [
                start_lba + sector_offset
                for sector_offset in range(sector_count)
                if (start_lba + sector_offset) not in sector_map
            ]
            row["required_sector_count"] = sector_count
            row["captured_sector_count"] = sector_count - len(missing_lbas)
            if missing_lbas:
                row["export_status"] = "incomplete_capture"
                row["missing_lbas"] = missing_lbas[:16]
                continue

            data = b"".join(sector_map[start_lba + sector_offset] for sector_offset in range(sector_count))[:size]
            row["export_status"] = "ready"
            if export_context is None or not data:
                continue

            export_root, capture_dir = export_context
            files_dir = capture_dir / "files"
            files_dir.mkdir(parents=True, exist_ok=True)
            export_name = self._usb_exfat_export_name(file_row=row, file_index=file_index)
            export_path = files_dir / export_name
            export_path.write_bytes(data)
            relative = export_path.relative_to(export_root).as_posix()
            row.update(
                {
                    "saved_path": str(export_path),
                    "saved_name": export_path.name,
                    "saved_size": len(data),
                    "url": artifact_raw_url(relative),
                    "viewer_url": artifact_viewer_url(relative),
                    "export_status": "exported",
                }
            )
            exported_count += 1

        exported = dict(exfat)
        exported["files"] = files
        exported["file_count"] = len(files)
        exported["exported_file_count"] = exported_count
        return exported

    def _usb_exfat_export_name(self, *, file_row: dict[str, Any], file_index: int) -> str:
        filename = str(file_row.get("filename") or "").strip()
        safe_name = self._sanitize_http_rebuild_name(Path(filename).name, fallback="")
        if not safe_name:
            safe_name = f"file_{file_index:03d}.bin"
        start_cluster = int(file_row.get("start_cluster") or 0)
        return f"f{file_index:03d}_c{start_cluster:08d}_{safe_name}"

    def _usb_parse_exfat_boot_sector(self, lba: int, sector: bytes) -> dict[str, Any] | None:
        if len(sector) < 512:
            return None
        if sector[3:11] != b"EXFAT   " or sector[510:512] != b"\x55\xaa":
            return None
        bytes_per_sector_shift = sector[108]
        sectors_per_cluster_shift = sector[109]
        bytes_per_sector = 1 << bytes_per_sector_shift
        sectors_per_cluster = 1 << sectors_per_cluster_shift
        return {
            "boot_lba": lba,
            "partition_offset": int.from_bytes(sector[64:72], "little"),
            "volume_length": int.from_bytes(sector[72:80], "little"),
            "fat_offset": int.from_bytes(sector[80:84], "little"),
            "fat_length": int.from_bytes(sector[84:88], "little"),
            "cluster_heap_offset": int.from_bytes(sector[88:92], "little"),
            "cluster_count": int.from_bytes(sector[92:96], "little"),
            "root_cluster": int.from_bytes(sector[96:100], "little"),
            "volume_serial": f"0x{int.from_bytes(sector[100:104], 'little'):08x}",
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
        }

    def _usb_exfat_cluster_to_lba(self, boot: dict[str, Any], cluster: int) -> int | None:
        if cluster < 2:
            return None
        boot_lba = int(boot.get("boot_lba") or 0)
        cluster_heap_offset = int(boot.get("cluster_heap_offset") or 0)
        sectors_per_cluster = int(boot.get("sectors_per_cluster") or 0)
        return boot_lba + cluster_heap_offset + (cluster - 2) * sectors_per_cluster

    def _usb_parse_exfat_root_directory(
        self,
        sectors: list[tuple[int, bytes]],
        boot: dict[str, Any],
    ) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None

        def finalize_current() -> None:
            nonlocal current
            if current is None:
                return
            filename = "".join(current.get("name_parts") or [])
            name_length = int(current.get("name_length") or 0)
            if name_length > 0:
                filename = filename[:name_length]
            start_cluster = current.get("start_cluster")
            first_lba = None
            if start_cluster is not None:
                first_lba = self._usb_exfat_cluster_to_lba(boot, int(start_cluster))
            files.append(
                {
                    "filename": filename or None,
                    "continuation_count": current.get("continuation_count"),
                    "secondary_seen": current.get("secondary_seen"),
                    "incomplete": int(current.get("secondary_seen") or 0) < int(current.get("continuation_count") or 0),
                    "attributes": current.get("attributes"),
                    "stream_flags": current.get("stream_flags"),
                    "no_fat_chain": bool(current.get("no_fat_chain")),
                    "start_cluster": start_cluster,
                    "size": current.get("size"),
                    "valid_data_length": current.get("valid_data_length"),
                    "first_lba": first_lba,
                    "entry_lba": current.get("entry_lba"),
                    "entry_slot": current.get("entry_slot"),
                }
            )
            current = None

        for lba, sector in sectors:
            for offset in range(0, len(sector), 32):
                entry = sector[offset : offset + 32]
                if len(entry) < 32:
                    continue
                entry_type = entry[0]
                if entry_type == 0x00:
                    finalize_current()
                    break
                if entry_type == 0x85:
                    finalize_current()
                    current = {
                        "entry_lba": lba,
                        "entry_slot": offset // 32,
                        "continuation_count": entry[1],
                        "secondary_seen": 0,
                        "attributes": f"0x{int.from_bytes(entry[4:6], 'little'):04x}",
                        "name_parts": [],
                        "name_length": 0,
                        "start_cluster": None,
                        "size": None,
                        "valid_data_length": None,
                    }
                    continue
                if current is None:
                    continue
                if not (entry_type & 0x80):
                    continue
                current["secondary_seen"] = int(current.get("secondary_seen") or 0) + 1
                if entry_type == 0xC0:
                    stream_flags = entry[1]
                    current["name_length"] = entry[3]
                    current["stream_flags"] = f"0x{stream_flags:02x}"
                    current["no_fat_chain"] = bool(stream_flags & 0x02)
                    current["valid_data_length"] = int.from_bytes(entry[8:16], "little")
                    current["start_cluster"] = int.from_bytes(entry[20:24], "little")
                    current["size"] = int.from_bytes(entry[24:32], "little")
                elif entry_type == 0xC1:
                    current.setdefault("name_parts", []).append(self._usb_decode_exfat_name_fragment(entry[2:32]))
                if int(current.get("secondary_seen") or 0) >= int(current.get("continuation_count") or 0):
                    finalize_current()
        finalize_current()
        return files

    def _usb_decode_exfat_name_fragment(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-16le", errors="ignore").rstrip("\x00")
        except Exception:
            return ""

    def _webshell_family_label(self, alert: AttackAlert, detail: dict[str, Any]) -> str:
        custom_label = str(detail.get("webshell_label") or "").strip()
        if custom_label:
            return custom_label
        family_variant = str(detail.get("family_variant") or "")
        if family_variant == "china_chopper_like":
            return "可能是中国菜刀类 PHP WebShell"
        if family_variant == "cookie_exec_like":
            return "可能是 Cookie 命令执行类 PHP WebShell"
        if family_variant == "godzilla_like":
            return "可能是哥斯拉类 PHP WebShell"
        if family_variant == "assert_loader_like":
            return "可能是 Assert Loader WebShell"
        if family_variant == "php_eval_loader":
            return "可能是 PHP Eval Loader WebShell"
        if family_variant == "encrypted_http_loader":
            return "可能是加密型 HTTP WebShell"
        return alert.name

    def _webshell_interaction_command(self, detail: dict[str, Any]) -> str | None:
        transcript = str(detail.get("terminal_transcript") or "").strip()
        if transcript:
            return transcript
        command = str(detail.get("terminal_command") or "").strip()
        if command:
            return command
        output_summary = str(detail.get("output_summary") or "").strip()
        return output_summary or None

    def _webshell_php_script(self, detail: dict[str, Any]) -> str | None:
        script_source = str(detail.get("php_script_source") or "").strip()
        if script_source:
            return script_source
        for item in detail.get("encoded_artifacts") or []:
            if item.get("field") == "action" and item.get("decoded_kind") == "php":
                return str(item.get("decoded_preview") or "") or None
        payload_preview = str(detail.get("payload_preview") or "").strip()
        return payload_preview or None

    def _webshell_log_output(self, alert: AttackAlert, detail: dict[str, Any]) -> str:
        lines = []
        packet_index = alert.packet_indexes[0] if alert.packet_indexes else None
        linked_response = detail.get("linked_response_packet_index")
        linked_request = detail.get("linked_request_packet_index")
        uri = str(detail.get("uri") or "").strip()
        output = str(detail.get("output") or "").strip()
        output_summary = str(detail.get("output_summary") or "").strip()

        packet_line = f"packet={packet_index}" if packet_index is not None else ""
        if linked_response is not None:
            packet_line = f"{packet_line}, response={linked_response}" if packet_line else f"response={linked_response}"
        if linked_request is not None:
            packet_line = f"{packet_line}, request={linked_request}" if packet_line else f"request={linked_request}"
        if packet_line:
            lines.append(packet_line)
        if uri:
            lines.append(f"uri={uri}")
        crypto_summary = str(detail.get("crypto_summary") or "").strip()
        if crypto_summary:
            lines.append(f"crypto={crypto_summary}")
        session_markers = detail.get("session_markers") or {}
        marker_p = str(session_markers.get("p") or "").strip()
        marker_kh = str(session_markers.get("kh") or "").strip()
        marker_kf = str(session_markers.get("kf") or "").strip()
        if marker_p:
            lines.append(f"marker_p={marker_p}")
        if marker_kh:
            lines.append(f"marker_kh={marker_kh}")
        if marker_kf:
            lines.append(f"marker_kf={marker_kf}")
        marker_left = str(session_markers.get("left") or "").strip()
        marker_right = str(session_markers.get("right") or "").strip()
        marker_pass = str(session_markers.get("pass") or "").strip()
        if marker_left:
            lines.append(f"marker_left={marker_left}")
        if marker_right:
            lines.append(f"marker_right={marker_right}")
        if marker_pass:
            lines.append(f"pass_param={marker_pass}")
        loader_param = str(detail.get("loader_param") or "").strip()
        payload_name = str(detail.get("payload_name") or "").strip()
        session_key = str(detail.get("session_key") or "").strip()
        if loader_param:
            lines.append(f"loader_param={loader_param}")
        if payload_name:
            lines.append(f"payload_name={payload_name}")
        if session_key:
            lines.append(f"session_key={session_key}")
        request_cookie_name = str(detail.get("request_cookie_name") or "").strip()
        response_cookie_name = str(detail.get("response_cookie_name") or "").strip()
        response_delimiter = str(detail.get("response_delimiter") or "").strip()
        if request_cookie_name:
            lines.append(f"request_cookie={request_cookie_name}")
        if response_cookie_name:
            lines.append(f"response_cookie={response_cookie_name}")
        if response_delimiter:
            lines.append(f"response_delimiter={response_delimiter}")
        exports = detail.get("exported_artifacts") or []
        for item in exports:
            name = str(item.get("name") or "").strip()
            url = str(item.get("url") or "").strip()
            path = str(item.get("path") or "").strip()
            size = item.get("size")
            if name:
                lines.append(f"export_name={name}")
            if url:
                lines.append(f"export_url={url}")
            if path:
                lines.append(f"export_path={path}")
            if size is not None:
                lines.append(f"export_size={size}")
        parsed_output = detail.get("parsed_output") or {}
        zip_members = [str(item).strip() for item in (parsed_output.get("zip_members") or []) if str(item).strip()]
        if zip_members:
            lines.append(f"archive_members={', '.join(zip_members)}")
        archive_comment = str(parsed_output.get("archive_comment") or "").strip()
        if archive_comment:
            lines.append(f"archive_comment={archive_comment}")
        if output_summary and not exports:
            lines.append(output_summary)
        elif output and not exports:
            lines.append(output)
        if not lines:
            lines.append(alert.description)
        return "\n".join(lines)

    def _ordered_unique_texts(self, values: Iterable[Any], limit: int = 80) -> list[str]:
        items: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = str(value or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            items.append(text)
            if len(items) >= limit:
                break
        return items

    def _trim_text(self, value: Any, size: int) -> str:
        text = str(value or "")
        if len(text) <= size:
            return text
        return text[: size - 3] + "..."


def build_default_pipeline_service() -> PipelineService:
    return PipelineService()
