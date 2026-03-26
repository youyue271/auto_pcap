from __future__ import annotations

from typing import Any, Dict, Generator

from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.utils.flow_utils import get_flow_id


class PacketParser:
    """
    Stage 1: PCAP 包解析。
    将 pyshark packet 转换为统一 PacketRecord，供后续协议/攻击分析使用。
    """

    def __init__(self, keep_packets: bool = False):
        self.keep_packets = keep_packets

    def parse_file(self, pcap_path: str) -> Generator[PacketRecord, None, None]:
        pyshark = self._load_pyshark()
        cap = pyshark.FileCapture(pcap_path, keep_packets=self.keep_packets)

        try:
            for idx, packet in enumerate(cap):
                rec = self._packet_to_record(packet, idx)
                if rec is not None:
                    yield rec
        finally:
            cap.close()

    def _load_pyshark(self):
        try:
            import pyshark  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "未安装 pyshark。请先执行: pip install pyshark"
            ) from exc
        return pyshark

    def _packet_to_record(self, packet: Any, idx: int) -> PacketRecord | None:
        try:
            packet_meta: Dict[str, Any] = {
                "timestamp": float(packet.sniff_timestamp),
                "length": self._safe_int(getattr(packet, "length", None)),
                "highest_layer": getattr(packet, "highest_layer", None),
                "transport_layer": getattr(packet, "transport_layer", None),
                "layers": [layer.layer_name.lower() for layer in packet.layers],
            }

            if hasattr(packet, "ip"):
                packet_meta["src_ip"] = packet.ip.src
                packet_meta["dst_ip"] = packet.ip.dst
                packet_meta["proto"] = str(packet.ip.proto)
            elif hasattr(packet, "ipv6"):
                packet_meta["src_ip"] = packet.ipv6.src
                packet_meta["dst_ip"] = packet.ipv6.dst
                packet_meta["proto"] = str(packet.ipv6.nxt)

            if hasattr(packet, "tcp"):
                packet_meta["src_port"] = self._safe_int(getattr(packet.tcp, "srcport", None))
                packet_meta["dst_port"] = self._safe_int(getattr(packet.tcp, "dstport", None))
                packet_meta["flags"] = getattr(packet.tcp, "flags", None)
            elif hasattr(packet, "udp"):
                packet_meta["src_port"] = self._safe_int(getattr(packet.udp, "srcport", None))
                packet_meta["dst_port"] = self._safe_int(getattr(packet.udp, "dstport", None))

            raw_layers = {}
            for layer in packet.layers:
                layer_name = layer.layer_name.lower()
                raw_layers[layer_name] = self._extract_layer_fields(layer)

            payload_text = self._guess_payload_text(raw_layers)
            packet_meta["payload_text"] = payload_text

            flow_id = get_flow_id(packet_meta)
            return PacketRecord(
                index=idx,
                timestamp=packet_meta["timestamp"],
                flow_id=flow_id,
                src_ip=packet_meta.get("src_ip"),
                dst_ip=packet_meta.get("dst_ip"),
                src_port=packet_meta.get("src_port"),
                dst_port=packet_meta.get("dst_port"),
                proto=packet_meta.get("proto"),
                length=packet_meta.get("length"),
                highest_layer=packet_meta.get("highest_layer"),
                transport_layer=packet_meta.get("transport_layer"),
                layers=packet_meta.get("layers", []),
                payload_text=payload_text,
                raw=raw_layers,
            )
        except Exception:
            return None

    def _extract_layer_fields(self, layer: Any) -> Dict[str, str]:
        data: Dict[str, str] = {}
        field_names = getattr(layer, "field_names", [])
        for field_name in field_names:
            try:
                value = getattr(layer, field_name)
            except Exception:
                continue
            if value is None:
                continue
            value_str = str(value).strip()
            if not value_str:
                continue
            data[field_name] = value_str
        return data

    def _guess_payload_text(self, raw_layers: Dict[str, Dict[str, str]]) -> str:
        http = raw_layers.get("http", {})
        if http:
            for key in ("file_data", "request_uri", "request_full_uri", "request_line"):
                if key in http:
                    return http[key]

        tcp = raw_layers.get("tcp", {})
        if "payload" in tcp:
            return tcp["payload"]

        data_layer = raw_layers.get("data", {})
        for key in ("data", "data_data"):
            if key in data_layer:
                return data_layer[key]
        return ""

    def _safe_int(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except Exception:
            return None

