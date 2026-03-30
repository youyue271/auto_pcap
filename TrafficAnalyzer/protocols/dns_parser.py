from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class DNSProtocolParser(BaseProtocolParser):
    name = "DNS"
    description = "解析 DNS 查询与响应，提取域名、记录类型、返回码等字段"

    def required_fields(self) -> list[str]:
        return [
            "dns.qry.name",
            "dns.qry.type",
            "dns.resp.name",
            "dns.flags.rcode",
            "dns.a",
        ]

    def match(self, packet: PacketRecord) -> bool:
        return "dns" in packet.layers

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        dns = packet.raw.get("dns", {})
        details = {
            "query_name": dns.get("qry_name"),
            "query_type": dns.get("qry_type"),
            "response": dns.get("resp_name"),
            "rcode": dns.get("flags_rcode"),
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
