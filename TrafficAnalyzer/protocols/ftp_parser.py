from __future__ import annotations

from typing import Any, Optional
import re

from TrafficAnalyzer.core.models import PacketRecord, ProtocolEvent
from TrafficAnalyzer.protocols.base import BaseProtocolParser


class FTPProtocolParser(BaseProtocolParser):
    name = "FTP"
    description = "解析 FTP 控制流与数据流，提取用户名、口令、命令序列和传输文件"

    def __init__(self) -> None:
        self.control_states: dict[str, dict[str, Any]] = {}
        self.transfer_index = 0

    def reset(self) -> None:
        self.control_states.clear()
        self.transfer_index = 0

    def required_fields(self) -> list[str]:
        return [
            "ftp.request.command",
            "ftp.request.arg",
            "ftp.response.code",
            "ftp.response.arg",
            "tcp.stream",
            "tcp.payload",
        ]

    def match(self, packet: PacketRecord) -> bool:
        if packet.raw.get("ftp"):
            return True
        return self._find_transfer_for_packet(packet) is not None

    def parse(self, packet: PacketRecord) -> Optional[ProtocolEvent]:
        ftp = packet.raw.get("ftp", {}) if isinstance(packet.raw, dict) else {}
        tcp = packet.raw.get("tcp", {}) if isinstance(packet.raw, dict) else {}
        tcp_stream = str(tcp.get("stream") or "").strip()

        if ftp or packet.src_port == 21 or packet.dst_port == 21:
            details = self._parse_control_packet(packet=packet, ftp=ftp, tcp_stream=tcp_stream)
            if details is None:
                return None
            return ProtocolEvent(
                protocol=self.name,
                packet_index=packet.index,
                timestamp=packet.timestamp,
                flow_id=packet.flow_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                details=details,
            )

        transfer = self._find_transfer_for_packet(packet)
        payload_hex = str(tcp.get("payload") or "").strip()
        if transfer is None or not payload_hex:
            return None

        payload_bytes = self._payload_hex_to_bytes(payload_hex)
        direction = self._transfer_packet_direction(transfer, packet)
        if direction is None:
            return None

        transfer["status"] = "data"
        transfer["last_packet_index"] = packet.index
        return ProtocolEvent(
            protocol=self.name,
            packet_index=packet.index,
            timestamp=packet.timestamp,
            flow_id=packet.flow_id,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            details={
                "entry_type": "data",
                "control_stream": transfer.get("control_stream"),
                "transfer_id": transfer.get("transfer_id"),
                "command": transfer.get("command"),
                "filename": transfer.get("filename"),
                "argument": transfer.get("argument"),
                "transfer_direction": transfer.get("transfer_direction"),
                "data_connection_mode": transfer.get("data_connection_mode"),
                "chunk_direction": direction,
                "chunk_hex": payload_hex,
                "chunk_size": len(payload_bytes),
            },
        )

    def _parse_control_packet(self, *, packet: PacketRecord, ftp: dict[str, Any], tcp_stream: str) -> dict[str, Any] | None:
        command = str(ftp.get("request_command") or "").upper().strip()
        argument = str(ftp.get("request_arg") or "")
        response_code = str(ftp.get("response_code") or "").strip()
        response_text = str(ftp.get("response_arg") or "")

        if not tcp_stream:
            return None

        state = self.control_states.setdefault(
            tcp_stream,
            {
                "client_ip": packet.src_ip,
                "server_ip": packet.dst_ip,
                "pending_port": None,
                "pending_pasv": None,
                "transfers": [],
                "last_username": None,
            },
        )
        if packet.dst_port == 21:
            state["client_ip"] = packet.src_ip
            state["server_ip"] = packet.dst_ip
        elif packet.src_port == 21:
            state["client_ip"] = packet.dst_ip
            state["server_ip"] = packet.src_ip

        details: dict[str, Any] = {
            "entry_type": "request" if command else "response",
            "control_stream": tcp_stream,
            "command": command or None,
            "argument": argument or None,
            "response_code": response_code or None,
            "response_text": response_text or None,
        }

        if command:
            if command == "PORT":
                state["pending_port"] = self._parse_port_argument(argument)
                state["pending_pasv"] = None
            elif command == "USER":
                state["last_username"] = argument.strip() or None
                details["username"] = state["last_username"]
            elif command == "PASS":
                details["password"] = argument
                details["username"] = state.get("last_username")
            elif command in {"LIST", "RETR", "STOR", "APPE"}:
                transfer = self._create_transfer(state=state, command=command, argument=argument, tcp_stream=tcp_stream, packet=packet)
                if transfer is not None:
                    state["transfers"].append(transfer)
                    details["transfer_id"] = transfer.get("transfer_id")
                    details["transfer_direction"] = transfer.get("transfer_direction")
                    details["filename"] = transfer.get("filename")
                    details["data_connection_mode"] = transfer.get("data_connection_mode")
            return details

        if response_code:
            active_transfer = self._latest_open_transfer(state)
            if response_code == "227":
                state["pending_pasv"] = self._parse_pasv_response(response_text)
                state["pending_port"] = None
            elif response_code.startswith("150") and active_transfer is not None:
                active_transfer["status"] = "opening"
                active_transfer["response_150_packet_index"] = packet.index
                details["transfer_id"] = active_transfer.get("transfer_id")
            elif response_code.startswith("226") and active_transfer is not None:
                active_transfer["status"] = "completed"
                active_transfer["response_226_packet_index"] = packet.index
                details["transfer_id"] = active_transfer.get("transfer_id")
            elif response_code.startswith("230"):
                details["username"] = state.get("last_username")
            return details

        return None

    def _create_transfer(
        self,
        *,
        state: dict[str, Any],
        command: str,
        argument: str,
        tcp_stream: str,
        packet: PacketRecord,
    ) -> dict[str, Any] | None:
        self.transfer_index += 1
        transfer_direction = "server_to_client" if command in {"LIST", "RETR"} else "client_to_server"
        active_endpoint = state.get("pending_port")
        passive_endpoint = state.get("pending_pasv")
        mode = "active" if active_endpoint else "passive" if passive_endpoint else "unknown"
        filename = argument.strip() or None

        transfer = {
            "transfer_id": f"ftp-{tcp_stream}-{self.transfer_index}",
            "control_stream": tcp_stream,
            "command": command,
            "argument": argument or None,
            "filename": filename,
            "transfer_direction": transfer_direction,
            "data_connection_mode": mode,
            "client_ip": state.get("client_ip") or packet.src_ip,
            "server_ip": state.get("server_ip") or packet.dst_ip,
            "client_port": (active_endpoint or {}).get("client_port"),
            "server_port": (passive_endpoint or {}).get("server_port"),
            "request_packet_index": packet.index,
            "status": "requested",
            "response_150_packet_index": None,
            "response_226_packet_index": None,
            "last_packet_index": packet.index,
        }
        return transfer

    def _latest_open_transfer(self, state: dict[str, Any]) -> dict[str, Any] | None:
        for transfer in reversed(state.get("transfers") or []):
            if str(transfer.get("status") or "") != "completed":
                return transfer
        return None

    def _find_transfer_for_packet(self, packet: PacketRecord) -> dict[str, Any] | None:
        tcp = packet.raw.get("tcp", {}) if isinstance(packet.raw, dict) else {}
        if not str(tcp.get("payload") or "").strip():
            return None

        for state in self.control_states.values():
            for transfer in reversed(state.get("transfers") or []):
                if str(transfer.get("status") or "") == "completed":
                    continue
                if self._transfer_packet_direction(transfer, packet) is not None:
                    return transfer
        return None

    def _transfer_packet_direction(self, transfer: dict[str, Any], packet: PacketRecord) -> str | None:
        mode = str(transfer.get("data_connection_mode") or "")
        direction = str(transfer.get("transfer_direction") or "")
        client_ip = str(transfer.get("client_ip") or "")
        server_ip = str(transfer.get("server_ip") or "")
        client_port = transfer.get("client_port")
        server_port = transfer.get("server_port")

        if mode == "active" and client_ip and server_ip and client_port is not None:
            if packet.src_ip == server_ip and packet.dst_ip == client_ip and packet.dst_port == client_port:
                return "server_to_client"
            if packet.src_ip == client_ip and packet.src_port == client_port and packet.dst_ip == server_ip:
                return "client_to_server"

        if mode == "passive" and client_ip and server_ip and server_port is not None:
            if packet.src_ip == server_ip and packet.src_port == server_port and packet.dst_ip == client_ip:
                return "server_to_client"
            if packet.src_ip == client_ip and packet.dst_ip == server_ip and packet.dst_port == server_port:
                return "client_to_server"

        if direction == "server_to_client" and client_ip and server_ip:
            if packet.src_ip == server_ip and packet.dst_ip == client_ip:
                return "server_to_client"
        if direction == "client_to_server" and client_ip and server_ip:
            if packet.src_ip == client_ip and packet.dst_ip == server_ip:
                return "client_to_server"
        return None

    def _parse_port_argument(self, value: str) -> dict[str, Any] | None:
        parts = [item.strip() for item in str(value or "").split(",") if item.strip()]
        if len(parts) != 6:
            return None
        try:
            ip = ".".join(parts[:4])
            port = (int(parts[4]) * 256) + int(parts[5])
        except ValueError:
            return None
        return {"client_ip": ip, "client_port": port}

    def _parse_pasv_response(self, value: str) -> dict[str, Any] | None:
        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", str(value or ""))
        if match is None:
            return None
        ip = ".".join(match.group(idx) for idx in range(1, 5))
        port = (int(match.group(5)) * 256) + int(match.group(6))
        return {"server_ip": ip, "server_port": port}

    def _payload_hex_to_bytes(self, value: str) -> bytes:
        compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
        if not compact or len(compact) % 2 != 0:
            return b""
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return b""
