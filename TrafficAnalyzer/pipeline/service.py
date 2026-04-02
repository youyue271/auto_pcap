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
from typing import Any
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
    ) -> AnalysisReport:
        selected_parsers = self._select_protocol_parsers(enabled_protocols)
        selected_detectors = self._select_attack_detectors(enabled_attacks)
        selected_parsers = self._expand_protocol_parsers_for_attacks(selected_parsers, selected_detectors)
        packets = self.packet_parser.parse_file(pcap_path, protocol_parsers=selected_parsers)
        return self.analyze_packets(
            packets,
            source=pcap_path,
            max_packets=max_packets,
            enabled_protocols=[parser.name for parser in selected_parsers],
            enabled_attacks=[detector.name for detector in selected_detectors],
        )

    def analyze_packets(
        self,
        packets: Iterable[PacketRecord],
        source: str = "in-memory",
        max_packets: Optional[int] = None,
        enabled_protocols: Optional[List[str]] = None,
        enabled_attacks: Optional[List[str]] = None,
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

        packet_iter = iter(packets)
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
            if protocol == "HTTP":
                details["HTTP"] = self._http_details(events, limit_per_protocol)
            elif protocol == "DNS":
                details["DNS"] = self._dns_details(events, limit_per_protocol)
            elif protocol == "TLS":
                details["TLS"] = self._tls_details(events, limit_per_protocol)
            elif protocol == "Modbus":
                details["Modbus"] = self._modbus_details(events, limit_per_protocol)
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

    def _http_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        requests = []
        host_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        status_counter: Counter[str] = Counter()
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

        site_pages = self._build_http_site_pages(
            request_records=request_records,
            response_records_by_request=response_records_by_request,
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
                }
            )

        return {
            "requests": requests,
            "request_count": len(events),
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

    def _normalize_http_payload_text(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        repaired = self._repair_json_text(text)
        return repaired if repaired else text

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
    ) -> list[dict[str, Any]]:
        export_context = self._http_rebuild_export_context()
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
