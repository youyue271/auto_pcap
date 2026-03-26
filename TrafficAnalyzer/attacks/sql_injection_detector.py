from __future__ import annotations

import re
from typing import List

from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent


class SQLInjectionDetector(BaseAttackDetector):
    name = "SQLInjectionDetector"

    _STRONG_PATTERNS = [
        re.compile(r"\bunion\b.{0,30}\bselect\b", re.IGNORECASE),
        re.compile(r"\binformation_schema\b", re.IGNORECASE),
        re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
        re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
    ]
    _WEAK_PATTERNS = [
        re.compile(r"(\%27|')\s*or\s+1=1", re.IGNORECASE),
        re.compile(r"(\-\-|\#|/\*)", re.IGNORECASE),
        re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
        re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
    ]

    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        alerts: List[AttackAlert] = []
        for event in protocol_events:
            if event.protocol != "HTTP":
                continue

            data = " ".join(
                [
                    str(event.details.get("uri") or ""),
                    str(event.details.get("payload") or ""),
                    str(event.details.get("host") or ""),
                ]
            )
            if not data.strip():
                continue

            score = 0
            matched = []
            for pattern in self._STRONG_PATTERNS:
                if pattern.search(data):
                    score += 2
                    matched.append(pattern.pattern)
            for pattern in self._WEAK_PATTERNS:
                if pattern.search(data):
                    score += 1
                    matched.append(pattern.pattern)

            if score < 2:
                continue

            severity = "high" if score >= 3 else "medium"
            confidence = min(0.55 + (score * 0.12), 0.98)
            alerts.append(
                AttackAlert(
                    rule_id="ATTACK.SQL_INJECTION",
                    name="疑似 SQL 注入",
                    severity=severity,
                    confidence=round(confidence, 2),
                    description="HTTP 请求中出现 SQL 注入特征模式",
                    packet_indexes=[packet.index],
                    flow_id=packet.flow_id,
                    evidence={
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "uri": event.details.get("uri"),
                        "matched_patterns": matched,
                    },
                )
            )
        return alerts

