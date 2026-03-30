from __future__ import annotations

import csv
import gc
import logging
import os
import shutil
import subprocess
from dataclasses import asdict
from typing import Any, Dict, Generator, Iterable, Optional, Sequence

from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.utils.flow_utils import get_flow_id

logger = logging.getLogger(__name__)


class PacketParser:
    """
    Stage 1: PCAP 包解析。
    默认使用 tshark fields 快速路径，只提取后续解析需要的字段。
    当 tshark 不可用时，回退到 pyshark 全量解析。
    """

    BASE_FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "ipv6.src",
        "ipv6.dst",
        "ipv6.nxt",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "udp.srcport",
        "udp.dstport",
    ]

    def __init__(self, keep_packets: bool = False, mode: str = "fast"):
        self.keep_packets = keep_packets
        self.mode = mode

    def parse_file(
        self,
        pcap_path: str,
        protocol_parsers: Optional[Sequence[Any]] = None,
    ) -> Generator[PacketRecord, None, None]:
        if self.mode == "pyshark" or shutil.which("tshark") is None:
            yield from self._parse_file_pyshark(pcap_path)
            return

        selected_protocol_parsers = self._resolve_protocol_parsers(protocol_parsers)
        field_names = self._build_field_list(selected_protocol_parsers)
        try:
            yield from self._parse_file_tshark(pcap_path, field_names)
        except Exception as exc:
            logger.warning("tshark fast path failed, fallback to pyshark: %s", exc)
            yield from self._parse_file_pyshark(pcap_path)

    def _resolve_protocol_parsers(self, protocol_parsers: Optional[Sequence[Any]]) -> list[Any]:
        if protocol_parsers is not None:
            return list(protocol_parsers)

        try:
            from TrafficAnalyzer.protocols import build_protocol_parsers
        except Exception:
            return []
        return build_protocol_parsers()

    def _build_field_list(self, protocol_parsers: Sequence[Any]) -> list[str]:
        fields = list(self.BASE_FIELDS)
        seen = set(fields)
        for parser in protocol_parsers:
            for field in getattr(parser, "required_fields", lambda: [])():
                if field not in seen:
                    seen.add(field)
                    fields.append(field)
        return fields

    def _parse_file_tshark(self, pcap_path: str, field_names: Sequence[str]) -> Generator[PacketRecord, None, None]:
        cmd = [
            "tshark",
            "-r",
            pcap_path,
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in field_names:
            cmd.extend(["-e", field])

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        assert proc.stdout is not None
        reader = csv.reader(proc.stdout, delimiter="\t", quotechar='"', escapechar="\\")
        closed_early = False
        try:
            for index, row in enumerate(reader):
                if not row:
                    continue
                if len(row) < len(field_names):
                    row.extend([""] * (len(field_names) - len(row)))
                record = self._row_to_record(index, field_names, row)
                if record is not None:
                    yield record
        except GeneratorExit:
            closed_early = True
            raise
        finally:
            stdout = proc.stdout
            if stdout is not None:
                stdout.close()
            stderr_stream = proc.stderr
            try:
                if closed_early:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        proc.kill()
                        proc.wait(timeout=5)
                else:
                    stderr = stderr_stream.read() if stderr_stream else ""
                    ret = proc.wait()
                    if ret != 0:
                        raise RuntimeError(f"tshark exited with {ret}: {stderr.strip()}")
            finally:
                if stderr_stream is not None:
                    stderr_stream.close()

    def _row_to_record(self, index: int, field_names: Sequence[str], row: Sequence[str]) -> PacketRecord | None:
        try:
            data = dict(zip(field_names, row))
            frame_protocols = str(data.get("frame.protocols") or "").lower()
            layers = [part for part in frame_protocols.split(":") if part]

            packet_meta: Dict[str, Any] = {
                "timestamp": self._safe_float(data.get("frame.time_epoch")),
                "length": self._safe_int(data.get("frame.len")),
                "highest_layer": layers[-1].upper() if layers else None,
                "transport_layer": self._transport_layer_from_layers(layers),
                "layers": layers,
            }

            src_ip = data.get("ip.src") or data.get("ipv6.src")
            dst_ip = data.get("ip.dst") or data.get("ipv6.dst")
            if src_ip:
                packet_meta["src_ip"] = src_ip
            if dst_ip:
                packet_meta["dst_ip"] = dst_ip

            proto = data.get("ip.proto") or data.get("ipv6.nxt")
            if proto:
                packet_meta["proto"] = str(proto)

            if data.get("tcp.srcport") is not None or data.get("tcp.dstport") is not None:
                packet_meta["src_port"] = self._safe_int(data.get("tcp.srcport"))
                packet_meta["dst_port"] = self._safe_int(data.get("tcp.dstport"))
                if "tcp" not in layers:
                    layers.append("tcp")
            elif data.get("udp.srcport") is not None or data.get("udp.dstport") is not None:
                packet_meta["src_port"] = self._safe_int(data.get("udp.srcport"))
                packet_meta["dst_port"] = self._safe_int(data.get("udp.dstport"))
                if "udp" not in layers:
                    layers.append("udp")

            if data.get("tcp.flags") is not None:
                packet_meta["flags"] = data.get("tcp.flags")

            raw_layers = self._build_raw_layers(data, layers)
            payload_text = self._guess_payload_text(raw_layers)
            packet_meta["payload_text"] = payload_text

            flow_id = get_flow_id(packet_meta)
            return PacketRecord(
                index=index,
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
        except Exception as exc:
            logger.debug("fast parse failed for packet %s: %s", index, exc)
            return None

    def _build_raw_layers(self, data: Dict[str, str], layers: list[str]) -> Dict[str, Dict[str, str]]:
        raw_layers: Dict[str, Dict[str, str]] = {}

        http_fields = {
            "request_method": data.get("http.request.method"),
            "host": data.get("http.host"),
            "request_uri": data.get("http.request.uri"),
            "request_full_uri": data.get("http.request.full_uri"),
            "user_agent": data.get("http.user_agent"),
            "content_type": data.get("http.content_type"),
            "response_code": data.get("http.response.code"),
            "file_data": data.get("http.file_data"),
            "request_line": data.get("http.request.line"),
        }
        http_fields = {k: v for k, v in http_fields.items() if v not in (None, "")}
        if http_fields or "http" in layers:
            raw_layers["http"] = http_fields

        dns_fields = {
            "qry_name": data.get("dns.qry.name"),
            "qry_type": data.get("dns.qry.type"),
            "resp_name": data.get("dns.resp.name"),
            "flags_rcode": data.get("dns.flags.rcode"),
            "a": data.get("dns.a"),
        }
        dns_fields = {k: v for k, v in dns_fields.items() if v not in (None, "")}
        if dns_fields or "dns" in layers:
            raw_layers["dns"] = dns_fields

        tls_fields = {
            "handshake_extensions_server_name": data.get("tls.handshake.extensions_server_name")
            or data.get("ssl.handshake.extensions_server_name"),
            "record_version": data.get("tls.record.version") or data.get("ssl.record.version"),
            "handshake_ciphersuite": data.get("tls.handshake.ciphersuite")
            or data.get("ssl.handshake.ciphersuite"),
        }
        tls_fields = {k: v for k, v in tls_fields.items() if v not in (None, "")}
        if tls_fields or "tls" in layers or "ssl" in layers:
            raw_layers["tls"] = tls_fields
            raw_layers["ssl"] = tls_fields

        mbtcp_fields = {
            "trans_id": data.get("mbtcp.trans_id"),
            "unit_id": data.get("mbtcp.unit_id"),
            "prot_id": data.get("mbtcp.prot_id"),
            "len": data.get("mbtcp.len"),
        }
        mbtcp_fields = {k: v for k, v in mbtcp_fields.items() if v not in (None, "")}
        modbus_fields = {
            "func_code": data.get("modbus.func_code"),
            "reference_num": data.get("modbus.reference_num"),
            "unit_id": data.get("modbus.unit_id"),
        }
        modbus_fields = {k: v for k, v in modbus_fields.items() if v not in (None, "")}
        if mbtcp_fields or "mbtcp" in layers:
            raw_layers["mbtcp"] = mbtcp_fields
        if modbus_fields or "modbus" in layers:
            raw_layers["modbus"] = modbus_fields

        return raw_layers

    def _transport_layer_from_layers(self, layers: list[str]) -> Optional[str]:
        if "tcp" in layers:
            return "tcp"
        if "udp" in layers:
            return "udp"
        return None

    def _parse_file_pyshark(self, pcap_path: str) -> Generator[PacketRecord, None, None]:
        pyshark = self._load_pyshark()
        cap = pyshark.FileCapture(pcap_path, keep_packets=self.keep_packets)

        try:
            for idx, packet in enumerate(cap):
                rec = self._packet_to_record(packet, idx)
                if rec is not None:
                    yield rec
        finally:
            cap.close()
            gc.collect()

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

    def _safe_float(self, value: Any) -> float:
        try:
            return float(value)
        except Exception:
            return 0.0
