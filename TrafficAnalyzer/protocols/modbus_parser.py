from __future__ import annotations

from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class ModbusProtocolParser(BaseProtocolParser):
    name = "Modbus"

    def match(self, packet: PacketRecord) -> bool:
        return "mbtcp" in packet.layers or "modbus" in packet.layers

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        mb = packet.raw.get("mbtcp", {}) or packet.raw.get("modbus", {})
        details = {
            "trans_id": mb.get("trans_id"),
            "unit_id": mb.get("unit_id"),
            "func_code": mb.get("func_code"),
            "reference_num": mb.get("reference_num"),
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

