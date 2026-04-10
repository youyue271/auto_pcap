from __future__ import annotations

from collections import defaultdict
import re
from typing import Any, List
from urllib.parse import parse_qs, urlsplit

from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent


class SQLInjectionDetector(BaseAttackDetector):
    name = "SQLInjectionDetector"
    description = "检测 HTTP Bool 盲注流量，定位注入点并关联真假响应"

    _BOOL_SUBSTR_PATTERN = re.compile(
        r"""
        (?is)
        \bif\s*\(
            \s*\(?\s*
            substr\s*\(\s*\((?P<target>.+?)\)\s*,\s*(?P<position>\d+)\s*,\s*1\s*\)
            \s*=\s*["'](?P<char>.*?)["']\s*
            \)\s*,\s*(?P<true_branch>-?\d+)\s*,\s*(?P<false_branch>-?\d+)\s*
        \)
        """,
        re.VERBOSE,
    )
    _ASCII_SUBSTR_COMPARE_PATTERN = re.compile(
        r"""
        (?is)
        \bascii\s*\(\s*
            substr\s*\(\s*\((?P<target>.+?)\)\s*,\s*(?P<position>\d+)\s*,\s*1\s*\)
        \s*\)\s*
        (?P<operator>>=|<=|=|>|<)\s*(?P<threshold>-?\d+)
        """,
        re.VERBOSE,
    )
    _LENGTH_COMPARE_PATTERN = re.compile(
        r"""
        (?is)
        \blength\s*\(\s*\((?P<target>.+?)\)\s*\)\s*
        (?P<operator>>=|<=|=|>|<)\s*(?P<threshold>-?\d+)
        """,
        re.VERBOSE,
    )
    _TRUE_HINTS = ("好耶", "存在", "found", "success", "welcome")
    _FALSE_HINTS = ("不存在", "未找到", "啊哦", "not found", "error")

    def __init__(self) -> None:
        self.pending_by_request_frame: dict[int, list[dict[str, Any]]] = defaultdict(list)

    def required_protocols(self) -> list[str]:
        return ["HTTP"]

    def reset(self) -> None:
        self.pending_by_request_frame.clear()

    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        alerts: List[AttackAlert] = []
        for event in protocol_events:
            if event.protocol != "HTTP":
                continue

            detail = event.details or {}
            method = str(detail.get("method") or "").upper().strip()
            if method:
                request_frame = packet.index + 1
                matches = self._extract_bool_matches(
                    method=method,
                    uri=str(detail.get("uri") or ""),
                    payload=str(detail.get("payload") or ""),
                    host=str(detail.get("host") or ""),
                    tcp_stream=detail.get("tcp_stream"),
                    packet=packet,
                )
                if matches:
                    self.pending_by_request_frame[request_frame].extend(matches)
                continue

            request_in = self._safe_int(detail.get("request_in"))
            if request_in is None:
                continue

            matches = self.pending_by_request_frame.pop(request_in, [])
            if not matches:
                continue

            response_body = str(detail.get("payload") or "")
            response_length = len(response_body)
            response_preview = self._preview_text(response_body, size=220)
            response_hint = self._response_truth_hint(response_body)

            for match in matches:
                alerts.append(
                    AttackAlert(
                        rule_id="ATTACK.SQLI.BOOL_BLIND",
                        name="疑似 SQL Bool 盲注",
                        severity="high",
                        confidence=0.96,
                        description="HTTP 请求/响应表现为 Bool 盲注特征",
                        detector=self.name,
                        packet_indexes=[
                            int(match.get("request_packet_index") or packet.index),
                            packet.index,
                        ],
                        flow_id=str(match.get("flow_id") or packet.flow_id or ""),
                        evidence={
                            **match,
                            "attack_type": "sql_injection",
                            "sqli_type": "bool_blind",
                            "possible_sqli": "可能是 Bool 盲注 SQL 注入",
                            "request_frame_number": request_in,
                            "response_packet_index": packet.index,
                            "response_frame_number": packet.index + 1,
                            "response_status_code": detail.get("status_code"),
                            "response_length": response_length,
                            "response_preview": response_preview,
                            "response_bool_hint": response_hint or None,
                            "detector": self.name,
                        },
                    )
                )

        return alerts

    def _extract_bool_matches(
        self,
        *,
        method: str,
        uri: str,
        payload: str,
        host: str,
        tcp_stream: object,
        packet: PacketRecord,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int, str, str, int]] = set()
        parsed = urlsplit(uri)
        uri_path = parsed.path or str(uri or "")

        for param_name, param_location, value in self._iter_request_params(method=method, uri=uri, payload=payload):
            matched = self._parse_bool_expression(value)
            if matched is None:
                continue
            signature = (
                str(param_name or "").strip(),
                str(matched.get("target_expression") or "").strip(),
                int(matched.get("position") or 0),
                str(matched.get("candidate_char") or ""),
                str(matched.get("compare_kind") or ""),
                int(matched.get("compare_value") or 0),
            )
            if signature in seen:
                continue
            seen.add(signature)
            rows.append(
                {
                    "method": method,
                    "host": host or None,
                    "uri": uri or None,
                    "uri_path": uri_path or None,
                    "param_name": param_name,
                    "injection_point": self._format_injection_point(
                        method=method,
                        uri_path=uri_path,
                        param_location=param_location,
                        param_name=param_name,
                    ),
                    "bool_expression": str(value or ""),
                    "target_expression": matched.get("target_expression"),
                    "position": matched.get("position"),
                    "candidate_char": matched.get("candidate_char"),
                    "param_location": param_location,
                    "compare_kind": matched.get("compare_kind"),
                    "compare_operator": matched.get("compare_operator"),
                    "compare_value": matched.get("compare_value"),
                    "true_branch": matched.get("true_branch"),
                    "false_branch": matched.get("false_branch"),
                    "request_packet_index": packet.index,
                    "flow_id": packet.flow_id,
                    "tcp_stream": str(tcp_stream or "").strip() or None,
                }
            )
        return rows

    def _iter_request_params(self, *, method: str, uri: str, payload: str) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        parsed = urlsplit(uri)
        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            for value in values:
                rows.append((str(name), "query", str(value)))

        if method in {"POST", "PUT", "PATCH", "DELETE"} and payload and "=" in payload:
            for name, values in parse_qs(payload, keep_blank_values=True).items():
                for value in values:
                    rows.append((str(name), "body", str(value)))
        return rows

    def _parse_bool_expression(self, value: str) -> dict[str, Any] | None:
        text = str(value or "").strip()
        if not text:
            return None
        match = self._BOOL_SUBSTR_PATTERN.search(text)
        if match is not None:
            candidate_char = str(match.group("char") or "")
            if len(candidate_char) != 1:
                return None

            target_expression = self._normalize_target_expression(str(match.group("target") or ""))
            position = self._safe_int(match.group("position"))
            if not target_expression or position is None or position <= 0:
                return None

            return {
                "target_expression": target_expression,
                "position": position,
                "candidate_char": candidate_char,
                "compare_kind": "substr_eq",
                "compare_operator": "=",
                "compare_value": ord(candidate_char),
                "true_branch": self._safe_int(match.group("true_branch")),
                "false_branch": self._safe_int(match.group("false_branch")),
            }

        match = self._ASCII_SUBSTR_COMPARE_PATTERN.search(text)
        if match is not None:
            target_expression = self._normalize_target_expression(str(match.group("target") or ""))
            position = self._safe_int(match.group("position"))
            threshold = self._safe_int(match.group("threshold"))
            operator = str(match.group("operator") or "").strip()
            if not target_expression or position is None or position <= 0 or threshold is None or not operator:
                return None

            return {
                "target_expression": target_expression,
                "position": position,
                "candidate_char": None,
                "compare_kind": "ascii_substr_compare",
                "compare_operator": operator,
                "compare_value": threshold,
                "true_branch": None,
                "false_branch": None,
            }

        match = self._LENGTH_COMPARE_PATTERN.search(text)
        if match is None:
            return None

        target_expression = self._normalize_target_expression(str(match.group("target") or ""))
        threshold = self._safe_int(match.group("threshold"))
        operator = str(match.group("operator") or "").strip()
        if not target_expression or threshold is None or not operator:
            return None

        return {
            "target_expression": target_expression,
            "position": None,
            "candidate_char": None,
            "compare_kind": "length_compare",
            "compare_operator": operator,
            "compare_value": threshold,
            "true_branch": None,
            "false_branch": None,
        }

    def _format_injection_point(self, *, method: str, uri_path: str, param_location: str, param_name: str) -> str:
        location = "query" if param_location == "query" else "body"
        target = str(uri_path or "") or "/"
        return f"{method} {target} :: {location}.{param_name}"

    def _preview_text(self, body: str, *, size: int) -> str:
        text = re.sub(r"<[^>]+>", " ", str(body or ""))
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) <= size:
            return text
        return text[: size - 3] + "..."

    def _response_truth_hint(self, body: str) -> str:
        text = str(body or "")
        for marker in self._TRUE_HINTS:
            if marker and marker in text:
                return "true"
        for marker in self._FALSE_HINTS:
            if marker and marker in text:
                return "false"
        return ""

    def _normalize_space(self, value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()

    def _normalize_target_expression(self, value: str) -> str:
        text = self._normalize_space(value)
        while text.startswith("(") and text.endswith(")"):
            inner = text[1:-1].strip()
            if not inner or not self._has_balanced_parentheses(inner):
                break
            text = inner
        return self._normalize_space(text)

    def _has_balanced_parentheses(self, value: str) -> bool:
        depth = 0
        for char in str(value or ""):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0

    def _safe_int(self, value: object) -> int | None:
        try:
            return int(str(value).strip())
        except Exception:
            return None
