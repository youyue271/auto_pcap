from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent


class PortScanDetector(BaseAttackDetector):
    name = "PortScanDetector"
    description = "检测源地址在短时间内访问大量目的端口的扫描行为"

    def __init__(self, threshold: int = 10, time_window: float = 5.0):
        self.threshold = threshold
        self.time_window = time_window
        self.windows: Dict[str, Deque[Tuple[float, int, int]]] = defaultdict(deque)
        self.emitted_bucket: Set[Tuple[str, int]] = set()

    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        del protocol_events
        if not packet.src_ip or packet.dst_port in (None, 0):
            return []

        win = self.windows[packet.src_ip]
        win.append((packet.timestamp, int(packet.dst_port), packet.index))

        while win and packet.timestamp - win[0][0] > self.time_window:
            win.popleft()

        unique_ports = {item[1] for item in win}
        if len(unique_ports) < self.threshold:
            return []

        bucket = (packet.src_ip, int(packet.timestamp // self.time_window))
        if bucket in self.emitted_bucket:
            return []

        self.emitted_bucket.add(bucket)
        packet_indexes = [item[2] for item in win]
        return [
            AttackAlert(
                rule_id="ATTACK.PORT_SCAN",
                name="潜在端口扫描",
                severity="high",
                confidence=0.9,
                description=f"{self.time_window:.1f}秒内访问了 {len(unique_ports)} 个不同端口",
                packet_indexes=packet_indexes,
                flow_id=packet.flow_id,
                evidence={
                    "src_ip": packet.src_ip,
                    "unique_ports": sorted(unique_ports),
                    "window_seconds": self.time_window,
                },
            )
        ]

    def reset(self) -> None:
        self.windows.clear()
        self.emitted_bucket.clear()
