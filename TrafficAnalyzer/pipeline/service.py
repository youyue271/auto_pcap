from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import time
from typing import Any
from typing import Iterable, List, Optional

from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AnalysisReport, AttackAlert, PacketRecord, ProtocolEvent
from TrafficAnalyzer.parsers import PacketParser
from TrafficAnalyzer.protocols import BaseProtocolParser, build_protocol_parsers


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

        selected_parsers = self._select_protocol_parsers(enabled_protocols)
        selected_detectors = self._select_attack_detectors(enabled_attacks)

        for detector in selected_detectors:
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
        for event in events[:limit]:
            detail = event.details or {}
            uri = str(detail.get("uri") or "")
            host = str(detail.get("host") or "")
            if host:
                host_counter[host] += 1
            if uri:
                path_counter[uri] += 1
            requests.append(
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "method": detail.get("method"),
                    "host": host,
                    "uri": uri,
                    "status_code": detail.get("status_code"),
                    "content_type": detail.get("content_type"),
                    "user_agent": detail.get("user_agent"),
                    "payload_preview": self._trim_text(detail.get("payload"), 240),
                }
            )
        return {
            "requests": requests,
            "request_count": len(events),
            "top_hosts": host_counter.most_common(20),
            "top_paths": path_counter.most_common(30),
        }

    def _dns_details(self, events: List[ProtocolEvent], limit: int) -> dict:
        queries = []
        query_counter: Counter[str] = Counter()
        for event in events[:limit]:
            detail = event.details or {}
            qname = str(detail.get("query_name") or "")
            if qname:
                query_counter[qname] += 1
            queries.append(
                {
                    "packet_index": event.packet_index,
                    "timestamp": event.timestamp,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "query_name": qname,
                    "query_type": detail.get("query_type"),
                    "response": detail.get("response"),
                    "rcode": detail.get("rcode"),
                }
            )
        return {
            "queries": queries,
            "query_count": len(events),
            "top_queries": query_counter.most_common(30),
        }

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

    def _trim_text(self, value: Any, size: int) -> str:
        text = str(value or "")
        if len(text) <= size:
            return text
        return text[: size - 3] + "..."


def build_default_pipeline_service() -> PipelineService:
    return PipelineService()
