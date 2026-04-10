from __future__ import annotations

from typing import Any, Optional

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class USBProtocolParser(BaseProtocolParser):
    name = "USB"
    description = "解析 USB / USB HID 流量，提取设备、端点、HID 原始报文与鼠标/键盘候选数据"

    def required_fields(self) -> list[str]:
        return [
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
        ]

    def match(self, packet: PacketRecord) -> bool:
        return (
            "usb" in packet.layers
            or "usbhid" in packet.layers
            or "usbms" in packet.layers
            or bool(packet.raw.get("usb"))
            or bool(packet.raw.get("usbhid"))
            or bool(packet.raw.get("usbms"))
            or bool(packet.raw.get("scsi"))
        )

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        usb = dict(packet.raw.get("usb") or {})
        usbhid = dict(packet.raw.get("usbhid") or {})
        usbms = dict(packet.raw.get("usbms") or {})
        scsi = dict(packet.raw.get("scsi") or {})
        if not usb and not usbhid and not usbms and not scsi:
            return None

        report_hex = str(usbhid.get("data") or usb.get("capdata") or "").strip().lower()
        source = str(usb.get("src") or "").strip()
        destination = str(usb.get("dst") or "").strip()
        device_address = str(usb.get("device_address") or "").strip()
        endpoint_number = str(usb.get("endpoint_address_number") or "").strip()
        endpoint_direction = str(usb.get("endpoint_address_direction") or "").strip()

        flow_parts = [
            f"dev{device_address}" if device_address else "",
            f"ep{endpoint_number}" if endpoint_number else "",
            f"dir{endpoint_direction}" if endpoint_direction else "",
            source or "",
            destination or "",
        ]
        flow_id = "usb:" + ":".join(part for part in flow_parts if part)

        storage_detail = self._parse_storage_detail(packet, usb, usbms, scsi)
        detail_kind = "hid_report" if report_hex else "usb_event"
        if storage_detail is not None:
            detail_kind = str(storage_detail.get("kind") or detail_kind)

        details = {
            "kind": detail_kind,
            "source": source or None,
            "destination": destination or None,
            "device_address": device_address or None,
            "endpoint_address": str(usb.get("endpoint_address") or "").strip() or None,
            "endpoint_number": endpoint_number or None,
            "endpoint_direction": endpoint_direction or None,
            "transfer_type": str(usb.get("transfer_type") or "").strip() or None,
            "urb_type": str(usb.get("urb_type") or "").strip() or None,
            "control_stage": str(usb.get("control_stage") or "").strip() or None,
            "data_len": self._safe_int(usb.get("data_len")),
            "vendor_id": str(usb.get("idVendor") or "").strip() or None,
            "product_id": str(usb.get("idProduct") or "").strip() or None,
            "interface_classes": str(usb.get("bInterfaceClass") or "").strip() or None,
            "interface_subclasses": str(usb.get("bInterfaceSubClass") or "").strip() or None,
            "interface_protocols": str(usb.get("bInterfaceProtocol") or "").strip() or None,
            "report_hex": report_hex or None,
            "report_length": (len(report_hex) // 2) if report_hex else 0,
        }
        if storage_detail is not None:
            details.update(storage_detail)
        return ProtocolEvent(
            protocol=self.name,
            packet_index=packet.index,
            timestamp=packet.timestamp,
            flow_id=flow_id,
            src_ip=source or None,
            dst_ip=destination or None,
            details=details,
        )

    def _parse_storage_detail(
        self,
        packet: PacketRecord,
        usb: dict[str, Any],
        usbms: dict[str, Any],
        scsi: dict[str, Any],
    ) -> dict[str, Any] | None:
        payload_hex = str(usb.get("payload_raw_hex") or "").strip().lower()
        if not payload_hex:
            return None

        is_storage_packet = (
            "usbms" in packet.layers
            or bool(usbms)
            or bool(scsi)
            or self._usb_has_interface_class(usb, 0x08)
        )
        if not is_storage_packet:
            return None

        payload = self._decode_hex(payload_hex)
        if not payload:
            return None

        detail: dict[str, Any] = {
            "payload_hex": payload_hex,
            "payload_length": len(payload),
            "payload_preview_hex": payload_hex[:128],
        }
        if len(payload) >= 31 and payload[:4] == b"USBC":
            tag = int.from_bytes(payload[4:8], "little")
            transfer_length = int.from_bytes(payload[8:12], "little")
            flags = payload[12]
            lun = payload[13]
            cdb_length = min(payload[14] & 0x1F, max(0, len(payload) - 15))
            cdb = payload[15 : 15 + cdb_length]
            opcode = cdb[0] if cdb else None
            lba = None
            transfer_blocks = None
            if len(cdb) >= 10 and opcode in {0x28, 0x2A}:
                lba = int.from_bytes(cdb[2:6], "big")
                transfer_blocks = int.from_bytes(cdb[7:9], "big")
            detail.update(
                {
                    "kind": "usbms_cbw",
                    "tag": f"0x{tag:08x}",
                    "data_direction": "in" if flags & 0x80 else "out",
                    "transfer_length": transfer_length,
                    "flags": f"0x{flags:02x}",
                    "lun": lun,
                    "cdb_length": cdb_length,
                    "cdb_hex": cdb.hex(),
                    "opcode": f"0x{opcode:02x}" if opcode is not None else None,
                    "opcode_name": self._storage_opcode_name(opcode),
                    "lba": lba,
                    "transfer_blocks": transfer_blocks,
                }
            )
            return detail

        if len(payload) >= 13 and payload[:4] == b"USBS":
            tag = int.from_bytes(payload[4:8], "little")
            residue = int.from_bytes(payload[8:12], "little")
            status = payload[12]
            detail.update(
                {
                    "kind": "usbms_csw",
                    "tag": f"0x{tag:08x}",
                    "residue": residue,
                    "status": status,
                    "status_text": self._storage_csw_status_name(status),
                }
            )
            return detail

        request_frame = str(scsi.get("request_frame") or "").strip() or None
        detail.update(
            {
                "kind": "usbms_data",
                "data_direction": "in" if str(usb.get("endpoint_address_direction") or "").strip() == "1" else "out",
                "request_frame": request_frame,
            }
        )
        return detail

    def _usb_has_interface_class(self, usb: dict[str, Any], value: int) -> bool:
        classes = str(usb.get("bInterfaceClass") or "").strip().split(",")
        for item in classes:
            text = item.strip().lower()
            if not text:
                continue
            try:
                if int(text, 0) == value:
                    return True
            except ValueError:
                continue
        return False

    def _decode_hex(self, value: str) -> bytes:
        try:
            return bytes.fromhex(value)
        except ValueError:
            return b""

    def _safe_int(self, value: Any) -> int | None:
        try:
            return int(str(value), 0)
        except Exception:
            return None

    def _storage_opcode_name(self, opcode: int | None) -> str | None:
        names = {
            0x12: "INQUIRY",
            0x1A: "MODE_SENSE_6",
            0x25: "READ_CAPACITY_10",
            0x28: "READ_10",
            0x2A: "WRITE_10",
        }
        if opcode is None:
            return None
        return names.get(opcode, f"OP_{opcode:02X}")

    def _storage_csw_status_name(self, status: int) -> str:
        names = {
            0x00: "passed",
            0x01: "failed",
            0x02: "phase_error",
        }
        return names.get(status, f"0x{status:02x}")
