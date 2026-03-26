from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Iterable, List, Optional

from TrafficAnalyzer.analyzers.protocols import build_protocol_parsers
from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AnalysisReport, AttackAlert, PacketRecord, ProtocolEvent
from TrafficAnalyzer.parsers import PacketParser
from TrafficAnalyzer.protocols.base import BaseProtocolParser


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

    def analyze_file(self, pcap_path: str, max_packets: Optional[int] = None) -> AnalysisReport:
        packets = self.packet_parser.parse_file(pcap_path)
        return self.analyze_packets(packets, source=pcap_path, max_packets=max_packets)

    def analyze_packets(
        self,
        packets: Iterable[PacketRecord],
        source: str = "in-memory",
        max_packets: Optional[int] = None,
    ) -> AnalysisReport:
        for detector in self.attack_detectors:
            detector.reset()

        protocol_events: List[ProtocolEvent] = []
        alerts: List[AttackAlert] = []
        packet_count = 0

        for packet in packets:
            if max_packets is not None and packet_count >= max_packets:
                break
            packet_count += 1

            packet_protocol_events: List[ProtocolEvent] = []
            for parser in self.protocol_parsers:
                if not parser.match(packet):
                    continue
                event = parser.parse(packet)
                if event is None:
                    continue
                protocol_events.append(event)
                packet_protocol_events.append(event)

            for detector in self.attack_detectors:
                detector_alerts = detector.analyze(packet, packet_protocol_events)
                if detector_alerts:
                    alerts.extend(detector_alerts)

        for detector in self.attack_detectors:
            detector_alerts = detector.finalize()
            if detector_alerts:
                alerts.extend(detector_alerts)

        protocol_counter = Counter(evt.protocol for evt in protocol_events)
        severity_counter = Counter(alert.severity for alert in alerts)
        stats = {
            "protocol_distribution": dict(protocol_counter),
            "alert_severity_distribution": dict(severity_counter),
            "alert_count": len(alerts),
            "protocol_event_count": len(protocol_events),
            "packet_count": packet_count,
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


def build_default_pipeline_service() -> PipelineService:
    return PipelineService()

