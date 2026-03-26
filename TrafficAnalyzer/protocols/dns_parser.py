from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class DNSProtocolParser(BaseProtocolParser):
    name = "DNS"

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

