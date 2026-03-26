from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class TLSProtocolParser(BaseProtocolParser):
    name = "TLS"

    def match(self, packet: PacketRecord) -> bool:
        return "tls" in packet.layers or "ssl" in packet.layers

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        tls = packet.raw.get("tls", {})
        ssl = packet.raw.get("ssl", {})
        layer = tls or ssl
        details = {
            "sni": layer.get("handshake_extensions_server_name"),
            "version": layer.get("record_version"),
            "cipher_suite": layer.get("handshake_ciphersuite"),
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

