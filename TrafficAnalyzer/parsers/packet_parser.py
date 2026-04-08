from __future__ import annotations

import csv
import gc
import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zlib
from typing import Any, Dict, Generator, Iterable, Optional, Sequence

from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.utils.tls_keylog import normalize_tls_keylog_text, resolve_tls_keylog_text
from TrafficAnalyzer.utils.flow_utils import get_flow_id

logger = logging.getLogger(__name__)


def _configure_csv_field_limit() -> None:
    limit = sys.maxsize
    while limit > 0:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


_configure_csv_field_limit()


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
        "usb.src",
        "usb.dst",
        "usb.device_address",
        "usb.urb_type",
        "usb.transfer_type",
        "usb.control_stage",
        "usb.endpoint_address",
        "usb.endpoint_address.direction",
        "usb.endpoint_address.number",
        "usb.data_len",
        "usb.idVendor",
        "usb.idProduct",
        "usb.bInterfaceClass",
        "usb.bInterfaceSubClass",
        "usb.bInterfaceProtocol",
        "usb.capdata",
        "usbhid.data",
        "http.content_encoding",
        "http.transfer_encoding",
        "data.data",
    ]

    def __init__(
        self,
        keep_packets: bool = False,
        mode: str = "fast",
        tls_keylog_text: str | None = None,
        tls_keylog_file: str | None = None,
    ):
        self.keep_packets = keep_packets
        self.mode = mode
        self.tls_keylog_text = tls_keylog_text
        self.tls_keylog_file = tls_keylog_file

    def parse_file(
        self,
        pcap_path: str,
        protocol_parsers: Optional[Sequence[Any]] = None,
        tls_keylog_text: str | None = None,
        tls_keylog_file: str | None = None,
    ) -> Generator[PacketRecord, None, None]:
        resolved_tls_keylog_text = self._resolve_tls_keylog_text(
            tls_keylog_text=tls_keylog_text,
            tls_keylog_file=tls_keylog_file,
        )
        tls_keylog_path = self._create_tls_keylog_tempfile(resolved_tls_keylog_text)
        try:
            if self.mode == "pyshark" or shutil.which("tshark") is None:
                yield from self._parse_file_pyshark(pcap_path, tls_keylog_path=tls_keylog_path)
                return

            selected_protocol_parsers = self._resolve_protocol_parsers(protocol_parsers)
            field_names = self._build_field_list(selected_protocol_parsers)
            capture_usb_raw = self._should_capture_usb_raw(selected_protocol_parsers)
            next_expected_index = 0
            try:
                for packet in self._parse_file_tshark(
                    pcap_path,
                    field_names,
                    tls_keylog_path=tls_keylog_path,
                    capture_usb_raw=capture_usb_raw,
                ):
                    if packet.index > next_expected_index:
                        yield from self._parse_file_pyshark(
                            pcap_path,
                            start_index=next_expected_index,
                            stop_index=packet.index,
                            tls_keylog_path=tls_keylog_path,
                        )
                    yield packet
                    next_expected_index = packet.index + 1
            except Exception as exc:
                logger.warning("tshark fast path failed, fallback to pyshark: %s", exc)
                yield from self._parse_file_pyshark(
                    pcap_path,
                    start_index=next_expected_index,
                    tls_keylog_path=tls_keylog_path,
                )
        finally:
            self._remove_tls_keylog_tempfile(tls_keylog_path)

    def _resolve_protocol_parsers(self, protocol_parsers: Optional[Sequence[Any]]) -> list[Any]:
        if protocol_parsers is not None:
            return list(protocol_parsers)

        try:
            from TrafficAnalyzer.protocols import build_protocol_parsers
        except Exception:
            return []
        return build_protocol_parsers()

    def _should_capture_usb_raw(self, protocol_parsers: Sequence[Any]) -> bool:
        return any(str(getattr(parser, "name", "")).upper() == "USB" for parser in protocol_parsers)

    def _build_field_list(self, protocol_parsers: Sequence[Any]) -> list[str]:
        fields = list(self.BASE_FIELDS)
        seen = set(fields)
        for parser in protocol_parsers:
            for field in getattr(parser, "required_fields", lambda: [])():
                if field not in seen:
                    seen.add(field)
                    fields.append(field)
        return fields

    def _resolve_tls_keylog_text(
        self,
        *,
        tls_keylog_text: str | None,
        tls_keylog_file: str | None,
    ) -> str | None:
        text_input = self.tls_keylog_text if tls_keylog_text is None else tls_keylog_text
        file_input = self.tls_keylog_file if tls_keylog_file is None else tls_keylog_file

        if text_input is not None and str(text_input).strip():
            normalized = normalize_tls_keylog_text(str(text_input))
            if not normalized:
                raise ValueError("未解析到有效的 TLS keylog 记录")
            return normalized

        if file_input is not None and str(file_input).strip():
            normalized, _ = resolve_tls_keylog_text(key_text=str(file_input))
            if not normalized:
                raise ValueError(f"TLS keylog 文件无效或不存在: {file_input}")
            return normalized

        return None

    def _create_tls_keylog_tempfile(self, tls_keylog_text: str | None) -> str | None:
        if not tls_keylog_text:
            return None

        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="trafficanalyzer-tls-",
            suffix=".keys",
            delete=False,
        )
        try:
            handle.write(tls_keylog_text)
            if not tls_keylog_text.endswith("\n"):
                handle.write("\n")
            return handle.name
        finally:
            handle.close()

    def _remove_tls_keylog_tempfile(self, path: str | None) -> None:
        if not path:
            return
        try:
            os.remove(path)
        except OSError:
            pass

    def _parse_file_tshark(
        self,
        pcap_path: str,
        field_names: Sequence[str],
        tls_keylog_path: str | None = None,
        capture_usb_raw: bool = False,
    ) -> Generator[PacketRecord, None, None]:
        cmd = ["tshark", "-r", pcap_path]
        if tls_keylog_path:
            cmd.extend(["-o", f"tls.keylog_file:{tls_keylog_path}"])
        cmd.extend(
            [
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
        )
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

        usb_raw_iter = None
        next_usb_raw: dict[str, Any] | None = None
        if capture_usb_raw:
            try:
                usb_raw_iter = self._iter_usb_raw_records(pcap_path)
                next_usb_raw = next(usb_raw_iter, None)
            except Exception as exc:
                logger.warning("usb raw enrichment disabled: %s", exc)
                usb_raw_iter = None
                next_usb_raw = None

        assert proc.stdout is not None
        reader = csv.reader(proc.stdout, delimiter="\t", quotechar='"', escapechar="\\")
        cancelled = False
        try:
            for index, row in enumerate(reader):
                if not row:
                    continue
                if len(row) < len(field_names):
                    row.extend([""] * (len(field_names) - len(row)))
                record = self._row_to_record(index, field_names, row)
                if record is not None:
                    if usb_raw_iter is not None:
                        while next_usb_raw is not None and int(next_usb_raw.get("packet_index") or -1) < record.index:
                            next_usb_raw = next(usb_raw_iter, None)
                        if next_usb_raw is not None and int(next_usb_raw.get("packet_index") or -1) == record.index:
                            self._attach_usb_raw_record(record, next_usb_raw)
                            next_usb_raw = next(usb_raw_iter, None)
                    yield record
        except GeneratorExit:
            cancelled = True
            raise
        finally:
            stdout = proc.stdout
            if stdout is not None:
                stdout.close()
            stderr_stream = proc.stderr
            try:
                if cancelled:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                stderr = stderr_stream.read() if stderr_stream else ""
                ret = proc.wait()
                if ret != 0 and not cancelled:
                    raise RuntimeError(f"tshark exited with {ret}: {stderr.strip()}")
            finally:
                if stderr_stream is not None:
                    stderr_stream.close()

    def _iter_usb_raw_records(self, pcap_path: str) -> Generator[dict[str, Any], None, None]:
        cmd = [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            "usb",
            "-T",
            "ek",
            "-x",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        assert proc.stdout is not None
        cancelled = False
        try:
            for line in proc.stdout:
                row = line.strip()
                if not row or row.startswith('{"index"'):
                    continue
                try:
                    payload = json.loads(row)
                except json.JSONDecodeError:
                    continue
                layers = payload.get("layers")
                if not isinstance(layers, dict):
                    continue
                record = self._extract_usb_raw_record(layers)
                if record is not None:
                    yield record
        except GeneratorExit:
            cancelled = True
            raise
        finally:
            stdout = proc.stdout
            if stdout is not None:
                stdout.close()
            stderr_stream = proc.stderr
            try:
                if cancelled:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                stderr = stderr_stream.read() if stderr_stream else ""
                ret = proc.wait()
                if ret != 0 and not cancelled:
                    raise RuntimeError(f"tshark usb raw enrichment exited with {ret}: {stderr.strip()}")
            finally:
                if stderr_stream is not None:
                    stderr_stream.close()

    def _extract_usb_raw_record(self, layers: dict[str, Any]) -> dict[str, Any] | None:
        frame = layers.get("frame") or {}
        if not isinstance(frame, dict):
            return None
        packet_index = self._safe_int(frame.get("frame_frame_number"))
        if packet_index is None or packet_index <= 0:
            return None

        frame_raw_hex = self._ek_hex(layers.get("frame_raw"))
        usb_raw_hex = self._ek_hex(layers.get("usb_raw"))
        usbms_raw_hex = self._ek_hex(layers.get("usbms_raw"))
        scsi_raw_hex = self._ek_hex(layers.get("scsi_raw"))
        payload_raw_hex = ""
        if frame_raw_hex and usb_raw_hex and frame_raw_hex.startswith(usb_raw_hex):
            payload_raw_hex = frame_raw_hex[len(usb_raw_hex) :]
        elif usbms_raw_hex:
            payload_raw_hex = usbms_raw_hex
        elif scsi_raw_hex:
            payload_raw_hex = scsi_raw_hex

        scsi_layer = layers.get("scsi") or {}
        scsi_request_frame = None
        if isinstance(scsi_layer, dict):
            scsi_request_frame = (
                scsi_layer.get("scsi_scsi_request_frame")
                or scsi_layer.get("scsi_request_frame")
            )

        return {
            "packet_index": packet_index - 1,
            "frame_raw_hex": frame_raw_hex,
            "usb_raw_hex": usb_raw_hex,
            "usbms_raw_hex": usbms_raw_hex,
            "scsi_raw_hex": scsi_raw_hex,
            "payload_raw_hex": payload_raw_hex,
            "scsi_request_frame": str(scsi_request_frame or "").strip() or None,
        }

    def _attach_usb_raw_record(self, record: PacketRecord, usb_raw: dict[str, Any]) -> None:
        usb_layer = dict(record.raw.get("usb") or {})
        usb_layer["frame_raw_hex"] = str(usb_raw.get("frame_raw_hex") or "").strip()
        usb_layer["usb_raw_hex"] = str(usb_raw.get("usb_raw_hex") or "").strip()
        usb_layer["payload_raw_hex"] = str(usb_raw.get("payload_raw_hex") or "").strip()
        record.raw["usb"] = {k: v for k, v in usb_layer.items() if v not in (None, "")}

        usbms_raw_hex = str(usb_raw.get("usbms_raw_hex") or "").strip()
        if usbms_raw_hex:
            usbms_layer = dict(record.raw.get("usbms") or {})
            usbms_layer["raw_hex"] = usbms_raw_hex
            record.raw["usbms"] = usbms_layer

        scsi_raw_hex = str(usb_raw.get("scsi_raw_hex") or "").strip()
        scsi_request_frame = str(usb_raw.get("scsi_request_frame") or "").strip()
        if scsi_raw_hex or scsi_request_frame:
            scsi_layer = dict(record.raw.get("scsi") or {})
            if scsi_raw_hex:
                scsi_layer["raw_hex"] = scsi_raw_hex
            if scsi_request_frame:
                scsi_layer["request_frame"] = scsi_request_frame
            record.raw["scsi"] = scsi_layer

    def _ek_hex(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip().lower()
        if isinstance(value, list):
            for item in value:
                text = self._ek_hex(item)
                if text:
                    return text
        if isinstance(value, dict):
            raw_value = value.get("raw")
            if raw_value is not None:
                return self._ek_hex(raw_value)
        return ""

    def _row_to_record(self, index: int, field_names: Sequence[str], row: Sequence[str]) -> PacketRecord | None:
        try:
            data = dict(zip(field_names, row))
            frame_protocols = str(data.get("frame.protocols") or "").lower()
            layers = [part for part in frame_protocols.split(":") if part]
            frame_number = self._safe_int(data.get("frame.number"))
            packet_index = frame_number - 1 if frame_number is not None and frame_number > 0 else index

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
                index=packet_index,
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
            "cookie": data.get("http.cookie"),
            "set_cookie": data.get("http.set_cookie"),
            "content_type": data.get("http.content_type"),
            "content_encoding": data.get("http.content_encoding"),
            "transfer_encoding": data.get("http.transfer_encoding"),
            "response_code": data.get("http.response.code"),
            "file_data": data.get("http.file_data"),
            "request_line": data.get("http.request.line"),
            "request_in": data.get("http.request_in"),
            "response_in": data.get("http.response_in"),
        }
        http_fields = {k: v for k, v in http_fields.items() if v not in (None, "")}
        if http_fields or "http" in layers:
            raw_layers["http"] = http_fields

        tcp_fields = {
            "stream": data.get("tcp.stream"),
        }
        tcp_fields = {k: v for k, v in tcp_fields.items() if v not in (None, "")}
        if tcp_fields or "tcp" in layers:
            raw_layers["tcp"] = tcp_fields

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

        usb_fields = {
            "src": data.get("usb.src"),
            "dst": data.get("usb.dst"),
            "device_address": data.get("usb.device_address"),
            "urb_type": data.get("usb.urb_type"),
            "transfer_type": data.get("usb.transfer_type"),
            "control_stage": data.get("usb.control_stage"),
            "endpoint_address": data.get("usb.endpoint_address"),
            "endpoint_address_direction": data.get("usb.endpoint_address.direction"),
            "endpoint_address_number": data.get("usb.endpoint_address.number"),
            "data_len": data.get("usb.data_len"),
            "idVendor": data.get("usb.idVendor"),
            "idProduct": data.get("usb.idProduct"),
            "bInterfaceClass": data.get("usb.bInterfaceClass"),
            "bInterfaceSubClass": data.get("usb.bInterfaceSubClass"),
            "bInterfaceProtocol": data.get("usb.bInterfaceProtocol"),
            "capdata": data.get("usb.capdata"),
        }
        usb_fields = {k: v for k, v in usb_fields.items() if v not in (None, "")}
        if usb_fields or "usb" in layers:
            raw_layers["usb"] = usb_fields

        usbhid_fields = {
            "data": data.get("usbhid.data"),
        }
        usbhid_fields = {k: v for k, v in usbhid_fields.items() if v not in (None, "")}
        if usbhid_fields or "usbhid" in layers:
            raw_layers["usbhid"] = usbhid_fields

        data_fields = {
            "data": data.get("data.data"),
        }
        data_fields = {k: v for k, v in data_fields.items() if v not in (None, "")}
        if data_fields or "data" in layers:
            raw_layers["data"] = data_fields

        return raw_layers

    def _transport_layer_from_layers(self, layers: list[str]) -> Optional[str]:
        if "tcp" in layers:
            return "tcp"
        if "udp" in layers:
            return "udp"
        return None

    def _parse_file_pyshark(
        self,
        pcap_path: str,
        start_index: int = 0,
        stop_index: int | None = None,
        tls_keylog_path: str | None = None,
    ) -> Generator[PacketRecord, None, None]:
        pyshark = self._load_pyshark()
        capture_kwargs: Dict[str, Any] = {"keep_packets": self.keep_packets}
        if tls_keylog_path:
            capture_kwargs["override_prefs"] = {"tls.keylog_file": tls_keylog_path}
        cap = pyshark.FileCapture(pcap_path, **capture_kwargs)

        try:
            for idx, packet in enumerate(cap):
                if idx < start_index:
                    continue
                if stop_index is not None and idx >= stop_index:
                    break
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
            repaired_body = self._normalize_http_payload_text(http=http, data_layer=raw_layers.get("data", {}))
            if repaired_body:
                return repaired_body
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
        usbhid = raw_layers.get("usbhid", {})
        if "data" in usbhid:
            return usbhid["data"]
        return ""

    def _normalize_http_payload_text(self, *, http: Dict[str, str], data_layer: Dict[str, str]) -> str:
        file_data = str(http.get("file_data") or "")
        raw_hex = str((data_layer or {}).get("data") or "").strip()
        repaired = self._decode_http_body_from_hex(
            raw_hex=raw_hex,
            content_type=str(http.get("content_type") or ""),
            content_encoding=str(http.get("content_encoding") or ""),
        )
        if repaired and (not file_data or "\ufffd" in file_data):
            return repaired
        return file_data or repaired

    def _decode_http_body_from_hex(self, *, raw_hex: str, content_type: str, content_encoding: str) -> str:
        if not raw_hex:
            return ""
        hex_text = re.sub(r"[^0-9a-fA-F]", "", raw_hex)
        if not hex_text or len(hex_text) % 2 != 0:
            return ""
        try:
            body = bytes.fromhex(hex_text)
        except ValueError:
            return ""

        encoding = str(content_encoding or "").lower()
        try:
            if "gzip" in encoding or body.startswith(b"\x1f\x8b"):
                body = gzip.decompress(body)
            elif "deflate" in encoding:
                try:
                    body = zlib.decompress(body)
                except zlib.error:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
        except Exception:
            return ""

        charset_match = re.search(r"charset\s*=\s*([A-Za-z0-9._-]+)", str(content_type or ""), re.IGNORECASE)
        candidates: list[str] = []
        if charset_match:
            candidates.append(charset_match.group(1))
        candidates.extend(["utf-8", "gb18030", "gbk"])

        seen: set[str] = set()
        for charset in candidates:
            normalized = charset.strip().lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            try:
                return body.decode(normalized)
            except Exception:
                continue
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
