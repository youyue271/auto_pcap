from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent


class BaseAttackDetector(ABC):
    name = "base"

    @abstractmethod
    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        pass

    def finalize(self) -> List[AttackAlert]:
        return []

    def reset(self) -> None:
        return None

