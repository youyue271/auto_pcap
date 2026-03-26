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

