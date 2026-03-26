from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class HTTPProtocolParser(BaseProtocolParser):
    name = "HTTP"

    def match(self, packet: PacketRecord) -> bool:
        return "http" in packet.layers or (packet.highest_layer or "").upper() == "HTTP"

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        http = packet.raw.get("http", {})
        details = {
            "method": http.get("request_method"),
            "host": http.get("host"),
            "uri": http.get("request_uri") or http.get("request_full_uri"),
            "user_agent": http.get("user_agent"),
            "content_type": http.get("content_type"),
            "status_code": http.get("response_code"),
            "payload": http.get("file_data") or packet.payload_text,
        }
        return ProtocolEvent(
            protocol=self.name,
            packet_index=packet.index,
            timestamp=packet.timestamp,
            flow_id=packet.flow_id,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            details=details,
        )

