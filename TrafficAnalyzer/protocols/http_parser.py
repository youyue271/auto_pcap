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
            "http.cookie",
            "http.set_cookie",
            "http.content_type",
            "http.content_encoding",
            "http.transfer_encoding",
            "http.response.code",
            "http.file_data",
            "http.request.line",
            "http.request_in",
            "http.response_in",
            "tcp.stream",
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
            "cookie": http.get("cookie"),
            "set_cookie": http.get("set_cookie"),
            "content_type": http.get("content_type"),
            "content_encoding": http.get("content_encoding"),
            "transfer_encoding": http.get("transfer_encoding"),
            "status_code": http.get("response_code"),
            "payload": packet.payload_text or http.get("file_data"),
            "request_in": http.get("request_in"),
            "response_in": http.get("response_in"),
            "tcp_stream": packet.raw.get("tcp", {}).get("stream"),
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
