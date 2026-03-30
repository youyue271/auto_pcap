from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent


class BaseProtocolParser(ABC):
    name = "base"

    @abstractmethod
    def match(self, packet: PacketRecord) -> bool:
        pass

    @abstractmethod
    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        pass

    def required_fields(self) -> list[str]:
        """
        返回该协议解析器在 fast path 下需要的 tshark 字段。
        """
        return []
