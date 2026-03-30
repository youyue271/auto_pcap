from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class HTTPProtocolParser(BaseProtocolParser):
    name = "HTTP"
    description = "解析 HTTP 请求/响应，提取方法、主机、URI、UA、内容类型与负载预览"

    def required_fields(self) -> list[str]:
        return [
            "http.request.method",
            "http.host",
            "http.request.uri",
            "http.request.full_uri",
            "http.user_agent",
            "http.content_type",
            "http.response.code",
            "http.file_data",
            "http.request.line",
        ]

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
