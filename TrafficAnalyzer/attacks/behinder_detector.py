from __future__ import annotations

import re
from typing import List

from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent


class BehinderDetector(BaseAttackDetector):
    """
    冰蝎(Behinder)启发式检测:
    - Webshell 常见后缀的 POST 请求
    - application/octet-stream 负载
    - 负载疑似高熵/长 base64 文本
    """

    name = "BehinderDetector"
    description = "检测疑似冰蝎WebShell流量（路径、方法、负载与内容类型联合特征）"

    def required_protocols(self) -> list[str]:
        return ["HTTP"]

    _WEBSHELL_PATH = re.compile(r"\.(jsp|jspx|php|aspx?)($|\?)", re.IGNORECASE)
    _BASE64ISH = re.compile(r"^[A-Za-z0-9+/=\s]+$")

    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        alerts: List[AttackAlert] = []
        for event in protocol_events:
            if event.protocol != "HTTP":
                continue

            details = event.details
            method = str(details.get("method") or "").upper()
            uri = str(details.get("uri") or "")
            content_type = str(details.get("content_type") or "").lower()
            payload = str(details.get("payload") or "")

            score = 0
            reasons = []

            if method == "POST":
                score += 1
                reasons.append("POST 请求")

            if self._WEBSHELL_PATH.search(uri):
                score += 2
                reasons.append("命中 webshell 常见路径后缀")

            if "application/octet-stream" in content_type:
                score += 2
                reasons.append("Content-Type 为 application/octet-stream")

            payload_len = len(payload)
            if payload_len > 120 and self._BASE64ISH.match(payload):
                score += 1
                reasons.append("长 payload 且疑似 base64")

            if "pass=" in uri.lower() or "pass=" in payload.lower():
                score += 1
                reasons.append("存在 pass 参数")

            if score < 4:
                continue

            alerts.append(
                AttackAlert(
                    rule_id="ATTACK.BEHINDER",
                    name="疑似冰蝎 WebShell 流量",
                    severity="high",
                    confidence=min(0.65 + 0.07 * score, 0.97),
                    description="HTTP 流量命中多项冰蝎行为特征",
                    detector=self.name,
                    packet_indexes=[packet.index],
                    flow_id=packet.flow_id,
                    evidence={
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "uri": uri,
                        "content_type": content_type,
                        "payload_len": payload_len,
                        "reasons": reasons,
                    },
                )
            )

        return alerts
