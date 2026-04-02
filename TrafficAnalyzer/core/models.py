from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PacketRecord:
    index: int
    timestamp: float
    flow_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    length: Optional[int] = None
    highest_layer: Optional[str] = None
    transport_layer: Optional[str] = None
    layers: List[str] = field(default_factory=list)
    payload_text: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtocolEvent:
    protocol: str
    packet_index: int
    timestamp: float
    flow_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackAlert:
    rule_id: str
    name: str
    severity: str
    confidence: float
    description: str
    detector: Optional[str] = None
    packet_indexes: List[int] = field(default_factory=list)
    flow_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    pcap_path: str
    packet_count: int
    protocol_events: List[ProtocolEvent] = field(default_factory=list)
    alerts: List[AttackAlert] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
