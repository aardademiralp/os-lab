#!/usr/bin/env python3
"""Scope and authorization guard engine for PENT-20 Pentest Session Scribe.

Enforces strict fail-closed validation against ``scope.json`` using only the
Python standard library (``ipaddress``, ``json``, ``re``, ``shlex``,
``urllib.parse``). Never performs DNS lookups or network requests.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import re
import shlex
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SCOPE_PATH = Path(__file__).with_name("scope.json")
MAX_SCOPE_BYTES = 256 * 1024
MAX_TARGET_LENGTH = 2048
MAX_COMMAND_LENGTH = 4096

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)){0,3}$")
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"`<>]+", re.IGNORECASE)
_SHELL_METACHAR_TOKENS = (";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r")
_ALLOWED_SCHEMES = {"http", "https", "ws", "wss", "tcp", "ssh"}
_FILE_EXT_ALLOWLIST = {
    "py", "json", "jsonl", "md", "txt", "log", "sig", "key", "sh", "ps1",
    "csv", "xml", "html", "yml", "yaml", "js", "ts", "apk", "so",
}
_FORBIDDEN_WILDCARD_DOMAINS = {"*", "*.*", "*.com", "*.net", "*.org", "*.io", "com.*", "net.*", "org.*"}


class ScopeViolationError(PermissionError):
    """Raised whenever a target, port, or command violates the authorized scope."""

    def __init__(
        self,
        target: str,
        reason: str,
        violation_type: str = "OUT_OF_SCOPE",
        rule: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.target = target
        self.reason = reason
        self.violation_type = violation_type
        self.rule = rule

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "ScopeViolationError",
            "violation_type": self.violation_type,
            "target": self.target,
            "reason": self.reason,
            "rule": self.rule,
        }


@dataclass(frozen=True)
class ScopeCheckResult:
    """Outcome of checking a target/port/command against the loaded scope."""

    allowed: bool
    target: str
    matched_rule: str | None
    reason: str
    port: int | None = None
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
            "port": self.port,
            "command": self.command,
        }


def _strip_ipv4_mapped(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_ip_literal(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return _strip_ipv4_mapped(ipaddress.ip_address(value))
    except ValueError:
        return None


def _has_control_or_edge_ws(value: str) -> bool:
    if value != value.strip():
        return True
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _extract_ports_from_spec(spec: str) -> list[int]:
    """Parse nmap-style port specs like '22,80,443' or '8080-8081'."""
    ports: list[int] = []
    for part in spec.split(","):
        item = part.strip()
        if not item:
            raise ScopeViolationError(spec, f"Empty port specification in '{spec}'.", "OUT_OF_SCOPE_PORT")
        if "-" in item:
            bounds = item.split("-")
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise ScopeViolationError(spec, f"Invalid port range '{item}'.", "OUT_OF_SCOPE_PORT")
            start, end = int(bounds[0]), int(bounds[1])
            if start < 1 or end > 65535 or start > end:
                raise ScopeViolationError(spec, f"Port range '{item}' is out of 1-65535 bounds.", "OUT_OF_SCOPE_PORT")
            if end - start > 1024:
                raise ScopeViolationError(
                    spec,
                    f"Broad port range '{item}' exceeds safe per-step inspection limit and is out of scope.",
                    "OUT_OF_SCOPE_PORT",
                )
            ports.extend(range(start, end + 1))
        else:
            if not item.isdigit():
                raise ScopeViolationError(spec, f"Invalid port number '{item}'.", "OUT_OF_SCOPE_PORT")
            p = int(item)
            if p < 1 or p > 65535:
                raise ScopeViolationError(spec, f"Port {p} is outside valid range 1-65535.", "OUT_OF_SCOPE_PORT")
            ports.append(p)
    return ports


class ScopeGuard:
    """Validates targets, ports, and commands against an authorized scope manifest."""

    def __init__(
        self,
        scope_path: str | Path | None = None,
        scope_data: dict[str, Any] | None = None,
    ) -> None:
        self.scope_path: Path | None = None
        if scope_data is not None:
            raw_data = scope_data
            if scope_path is not None:
                self.scope_path = Path(scope_path)
        else:
            resolved = Path(scope_path) if scope_path is not None else DEFAULT_SCOPE_PATH
            self.scope_path = resolved
            raw_data = self._read_scope_file(resolved)

        self._raw = self._validate_manifest(raw_data)
        self.session_id: str = str(self._raw.get("session_id", "pent20-lab-session"))
        self.name: str = str(self._raw.get("name", "Authorized Lab Scope"))
        self.authorization: str = str(self._raw["authorization"])
        self.expires: _dt.date | None = self._parse_expires(self._raw.get("expires"))
        self.allowed_cidrs: tuple[str, ...] = tuple(self._raw["allowed_cidrs"])
        self.allowed_domains: tuple[str, ...] = tuple(d.lower() for d in self._raw["allowed_domains"])
        self.allowed_ports: frozenset[int] = frozenset(int(p) for p in self._raw["allowed_ports"])
        self.allowed_commands: frozenset[str] = frozenset(c.lower() for c in self._raw["allowed_commands"])
        self.forbidden_flags: tuple[str, ...] = tuple(str(f) for f in self._raw.get("forbidden_flags", ()))

        self._networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for cidr in self.allowed_cidrs:
            net = ipaddress.ip_network(cidr, strict=True)
            if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
                # Normalize ::ffff:127.0.0.0/104 style rules if encountered
                prefix = max(0, net.prefixlen - 96)
                v4 = ipaddress.IPv4Network((net.network_address.ipv4_mapped, prefix), strict=False)
                self._networks.append((cidr, v4))
            else:
                self._networks.append((cidr, net))

        self._exact_domains: set[str] = set()
        self._wildcard_suffixes: list[tuple[str, str]] = []
        for pattern in self.allowed_domains:
            if pattern.startswith("*."):
                suffix = pattern[1:]  # keeps leading dot, e.g. ".lab.local"
                self._wildcard_suffixes.append((pattern, suffix))
            else:
                self._exact_domains.add(pattern)

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeGuard":
        return cls(scope_path=path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeGuard":
        return cls(scope_data=data)

    @staticmethod
    def _read_scope_file(path: Path) -> dict[str, Any]:
        if not path.exists() or not path.is_file():
            raise ScopeViolationError(
                str(path),
                f"Scope manifest not found or not a regular file: {path}",
                violation_type="MISSING_SCOPE",
            )
        size = path.stat().st_size
        if size > MAX_SCOPE_BYTES:
            raise ScopeViolationError(
                str(path),
                f"Scope manifest exceeds maximum allowed size ({MAX_SCOPE_BYTES} bytes).",
                violation_type="INVALID_SCOPE",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScopeViolationError(
                str(path),
                f"Failed to parse scope manifest JSON: {exc}",
                violation_type="INVALID_SCOPE",
            ) from exc
        if not isinstance(data, dict):
            raise ScopeViolationError(
                str(path),
                "Scope manifest root must be a JSON object.",
                violation_type="INVALID_SCOPE",
            )
        return data

    @staticmethod
    def _parse_expires(expires_val: Any) -> _dt.date | None:
        if expires_val is None:
            return None
        if not isinstance(expires_val, str) or not _DATE_RE.match(expires_val):
            raise ScopeViolationError(
                str(expires_val),
                "Scope 'expires' field must be in YYYY-MM-DD format.",
                violation_type="INVALID_SCOPE",
            )
        try:
            parsed = _dt.date.fromisoformat(expires_val)
        except ValueError as exc:
            raise ScopeViolationError(
                expires_val,
                f"Invalid scope expiration date: {expires_val}",
                violation_type="INVALID_SCOPE",
            ) from exc
        if _dt.date.today() > parsed:
            raise ScopeViolationError(
                expires_val,
                f"Scope manifest expired on {expires_val}.",
                violation_type="EXPIRED_SCOPE",
            )
        return parsed

    @staticmethod
    def _validate_manifest(data: dict[str, Any]) -> dict[str, Any]:
        required = ("authorization", "allowed_cidrs", "allowed_domains", "allowed_ports", "allowed_commands")
        for key in required:
            if key not in data:
                raise ScopeViolationError(
                    key,
                    f"Scope manifest missing required field '{key}'.",
                    violation_type="INVALID_SCOPE",
                )
        auth = data["authorization"]
        if not isinstance(auth, str) or not auth.strip():
            raise ScopeViolationError(
                "authorization",
                "Scope manifest must include non-empty 'authorization' text.",
                violation_type="INVALID_SCOPE",
            )
        for list_key in ("allowed_cidrs", "allowed_domains", "allowed_commands"):
            val = data[list_key]
            if not isinstance(val, list) or not all(isinstance(x, str) and x.strip() for x in val):
                raise ScopeViolationError(
                    list_key,
                    f"Scope field '{list_key}' must be a list of non-empty strings.",
                    violation_type="INVALID_SCOPE",
                )
        ports = data["allowed_ports"]
        if not isinstance(ports, list) or not all(
            isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports
        ):
            raise ScopeViolationError(
                "allowed_ports",
                "Scope field 'allowed_ports' must be a list of integers between 1 and 65535.",
                violation_type="INVALID_SCOPE",
            )
        for cidr in data["allowed_cidrs"]:
            try:
                net = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ScopeViolationError(
                    cidr,
                    f"Invalid CIDR entry '{cidr}' in scope manifest: {exc}",
                    violation_type="INVALID_SCOPE",
                ) from exc
            if net.prefixlen == 0:
                raise ScopeViolationError(
                    cidr,
                    f"Wildcard CIDR '{cidr}' is forbidden in scope manifest.",
                    violation_type="INVALID_SCOPE",
                )
        for domain in data["allowed_domains"]:
            low = domain.lower()
            if low in _FORBIDDEN_WILDCARD_DOMAINS or "*" in low[2:] or (low.startswith("*") and not low.startswith("*.")):
                raise ScopeViolationError(
                    domain,
                    f"Overly broad or invalid domain rule '{domain}' is forbidden.",
                    violation_type="INVALID_SCOPE",
                )
        return data

    def _parse_target(self, target: str) -> tuple[str, int | None]:
        if not isinstance(target, str) or not target:
            raise ScopeViolationError(str(target), "Target must be a non-empty string.", "MALFORMED_TARGET")
        if len(target) > MAX_TARGET_LENGTH:
            raise ScopeViolationError(target[:64], "Target exceeds maximum allowed length.", "MALFORMED_TARGET")
        if _has_control_or_edge_ws(target) or any(ch.isspace() for ch in target):
            raise ScopeViolationError(target, "Target contains whitespace or control characters.", "MALFORMED_TARGET")

        lower = target.lower()
        if lower.startswith("file:"):
            raise ScopeViolationError(target, "file:// URLs are not network targets and are refused.", "MALFORMED_TARGET")

        port: int | None = None
        host = target

        if "://" in target:
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
                raise ScopeViolationError(
                    target,
                    f"Unsupported URL scheme '{parsed.scheme}' in target.",
                    "MALFORMED_TARGET",
                )
            if parsed.username is not None or parsed.password is not None:
                raise ScopeViolationError(
                    target,
                    "URL userinfo (user@host) is refused to prevent host spoofing.",
                    "MALFORMED_TARGET",
                )
            if not parsed.hostname:
                raise ScopeViolationError(target, "URL target has no hostname.", "MALFORMED_TARGET")
            host = parsed.hostname
            try:
                port = parsed.port
            except ValueError as exc:
                raise ScopeViolationError(target, f"Invalid port in URL '{target}'.", "MALFORMED_TARGET") from exc
        else:
            # Handle bare IPv6, [IPv6]:port, [IPv6], host:port, or plain host
            bare_ip = _parse_ip_literal(target)
            if bare_ip is not None:
                host = str(bare_ip)
            elif target.startswith("["):
                match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]{1,5}))?", target)
                if not match:
                    raise ScopeViolationError(target, f"Malformed bracketed target '{target}'.", "MALFORMED_TARGET")
                host = match.group(1)
                if _parse_ip_literal(host) is None:
                    raise ScopeViolationError(target, f"Bracketed target '{target}' must contain a valid IPv6 address.", "MALFORMED_TARGET")
                if match.group(2) is not None:
                    port = int(match.group(2))
            elif target.count(":") == 1:
                host_part, port_part = target.split(":", 1)
                if not host_part or not port_part.isdigit():
                    raise ScopeViolationError(target, f"Malformed host:port target '{target}'.", "MALFORMED_TARGET")
                host = host_part
                port = int(port_part)
            elif ":" in target:
                raise ScopeViolationError(target, f"Malformed IPv6 or port syntax in '{target}'.", "MALFORMED_TARGET")

        if port is not None and not (1 <= port <= 65535):
            raise ScopeViolationError(target, f"Port {port} is outside valid range 1-65535.", "OUT_OF_SCOPE_PORT")

        if "%" in host:
            raise ScopeViolationError(target, "Interface zone IDs (%) in addresses are refused.", "MALFORMED_TARGET")

        return host, port

    def _check_host(self, host: str, original_target: str) -> str:
        ip_obj = _parse_ip_literal(host)
        if ip_obj is not None:
            for rule_text, net in self._networks:
                if ip_obj.version == net.version and ip_obj in net:
                    return rule_text
            raise ScopeViolationError(
                original_target,
                f"Target IP {ip_obj} is out of scope. Allowed CIDRs: {', '.join(self.allowed_cidrs)}",
                violation_type="OUT_OF_SCOPE_IP",
            )

        norm = host.lower().rstrip(".")
        if not norm:
            raise ScopeViolationError(original_target, "Empty hostname after normalization.", "MALFORMED_TARGET")
        if _NUMERIC_HOST_RE.match(norm):
            raise ScopeViolationError(
                original_target,
                f"Ambiguous numeric/non-standard IP spelling '{host}' is refused.",
                violation_type="MALFORMED_TARGET",
            )
        if not _HOSTNAME_RE.match(norm):
            raise ScopeViolationError(
                original_target,
                f"Invalid or non-ASCII hostname '{host}'.",
                violation_type="MALFORMED_TARGET",
            )

        if norm in self._exact_domains:
            return norm
        for rule_text, suffix in self._wildcard_suffixes:
            if norm.endswith(suffix) and len(norm) > len(suffix):
                return rule_text

        raise ScopeViolationError(
            original_target,
            f"Target domain '{norm}' is out of scope. Allowed domains: {', '.join(self.allowed_domains)}",
            violation_type="OUT_OF_SCOPE_DOMAIN",
        )

    def _check_port(self, port: int | None, context_target: str) -> None:
        if port is None:
            return
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            raise ScopeViolationError(
                context_target,
                f"Invalid port value: {port}",
                violation_type="OUT_OF_SCOPE_PORT",
            )
        if port not in self.allowed_ports:
            allowed_sorted = ", ".join(str(p) for p in sorted(self.allowed_ports))
            raise ScopeViolationError(
                context_target,
                f"Port {port} is not in allowed_ports ({allowed_sorted}).",
                violation_type="OUT_OF_SCOPE_PORT",
            )

    def _looks_like_domain_token(self, token: str) -> bool:
        if not token or token.startswith("-") or "/" in token or "\\" in token or "=" in token:
            return False
        if "." not in token:
            return False
        parts = token.lower().rstrip(".").split(".")
        if len(parts) < 2:
            return False
        tld = parts[-1]
        if tld in _FILE_EXT_ALLOWLIST:
            return False
        return all(re.fullmatch(_LABEL, p) for p in parts)

    def _check_command(self, command: str) -> None:
        if not isinstance(command, str) or not command.strip():
            raise ScopeViolationError(str(command), "Command must be a non-empty string.", "FORBIDDEN_COMMAND")
        if len(command) > MAX_COMMAND_LENGTH:
            raise ScopeViolationError(command[:64], "Command exceeds maximum allowed length.", "FORBIDDEN_COMMAND")

        for meta in _SHELL_METACHAR_TOKENS:
            if meta in command:
                raise ScopeViolationError(
                    command,
                    f"Command contains forbidden shell metacharacter/chaining token '{meta.strip() or repr(meta)}'.",
                    violation_type="FORBIDDEN_COMMAND",
                )

        cmd_lower = command.lower()
        for bad_flag in self.forbidden_flags:
            if " " in bad_flag and bad_flag.lower() in cmd_lower:
                raise ScopeViolationError(
                    command,
                    f"Command contains forbidden pattern '{bad_flag}'.",
                    violation_type="FORBIDDEN_FLAG",
                    rule=bad_flag,
                )

        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise ScopeViolationError(
                command,
                f"Malformed command quoting: {exc}",
                violation_type="FORBIDDEN_COMMAND",
            ) from exc

        if not tokens:
            raise ScopeViolationError(command, "Command produced no executable tokens.", "FORBIDDEN_COMMAND")

        raw_exe = os.path.basename(tokens[0]).lower()
        base_exe = raw_exe[:-4] if raw_exe.endswith(".exe") else raw_exe
        if base_exe not in self.allowed_commands and raw_exe not in self.allowed_commands:
            raise ScopeViolationError(
                command,
                f"Command '{raw_exe}' is not in allowed_commands ({', '.join(sorted(self.allowed_commands))}).",
                violation_type="FORBIDDEN_COMMAND",
            )

        forbidden_lower = {f.lower() for f in self.forbidden_flags if " " not in f}
        expect_port_spec = False
        expect_script_arg = False

        for idx, tok in enumerate(tokens[1:], start=1):
            tok_lower = tok.lower()
            if tok_lower in forbidden_lower:
                raise ScopeViolationError(
                    command,
                    f"Forbidden flag '{tok}' is blocked by scope policy.",
                    violation_type="FORBIDDEN_FLAG",
                    rule=tok,
                )

            # Catch split "--script exploit" form as well as "--script=exploit"
            if expect_script_arg:
                expect_script_arg = False
                if f"--script={tok_lower}" in forbidden_lower:
                    raise ScopeViolationError(
                        command,
                        f"Forbidden script argument '--script {tok}' is blocked by scope policy.",
                        violation_type="FORBIDDEN_FLAG",
                        rule=f"--script={tok}",
                    )
            if tok_lower == "--script":
                expect_script_arg = True

            # Check port specifications like "-p 22,80" or "-p8080"
            if expect_port_spec:
                expect_port_spec = False
                for p in _extract_ports_from_spec(tok):
                    self._check_port(p, command)
                continue
            if tok_lower in ("-p", "--ports"):
                expect_port_spec = True
                continue
            if tok_lower.startswith("-p") and len(tok_lower) > 2 and tok_lower[2].isdigit():
                for p in _extract_ports_from_spec(tok[2:]):
                    self._check_port(p, command)
                continue

            # Inspect any embedded URLs inside token
            for embedded_url in _URL_IN_TEXT_RE.findall(tok):
                u_host, u_port = self._parse_target(embedded_url)
                self._check_host(u_host, embedded_url)
                self._check_port(u_port, embedded_url)

            # Inspect direct URL, IP, host:port, or domain tokens
            if "://" in tok:
                t_host, t_port = self._parse_target(tok)
                self._check_host(t_host, tok)
                self._check_port(t_port, tok)
            elif _parse_ip_literal(tok) is not None:
                self._check_host(tok, tok)
            elif not tok.startswith("-") and re.fullmatch(r"(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}", tok):
                t_host, t_port = self._parse_target(tok)
                self._check_host(t_host, tok)
                self._check_port(t_port, tok)
            elif self._looks_like_domain_token(tok):
                self._check_host(tok, tok)

        if expect_port_spec:
            raise ScopeViolationError(command, "Flag '-p' requires a port specification.", "OUT_OF_SCOPE_PORT")

    def verify(
        self,
        target: str,
        command: str | None = None,
        port: int | None = None,
    ) -> ScopeCheckResult:
        """Verify target, optional port, and optional command; raise ScopeViolationError if refused."""
        host, parsed_port = self._parse_target(target)
        matched_rule = self._check_host(host, target)

        effective_port = port if port is not None else parsed_port
        if port is not None and parsed_port is not None and port != parsed_port:
            raise ScopeViolationError(
                target,
                f"Conflicting ports specified: target port {parsed_port} vs explicit port {port}.",
                violation_type="OUT_OF_SCOPE_PORT",
            )
        self._check_port(effective_port, target)

        if command is not None:
            self._check_command(command)

        port_note = f" (port {effective_port})" if effective_port is not None else ""
        return ScopeCheckResult(
            allowed=True,
            target=target,
            matched_rule=matched_rule,
            reason=f"Target '{host}'{port_note} matches authorized rule '{matched_rule}'.",
            port=effective_port,
            command=command,
        )

    def check(
        self,
        target: str,
        command: str | None = None,
        port: int | None = None,
    ) -> ScopeCheckResult:
        """Non-raising version of verify()."""
        try:
            return self.verify(target, command=command, port=port)
        except ScopeViolationError as exc:
            return ScopeCheckResult(
                allowed=False,
                target=target,
                matched_rule=None,
                reason=exc.reason,
                port=port,
                command=command,
            )

    def check_target(self, target: str, port: int | None = None) -> ScopeCheckResult:
        return self.verify(target, command=None, port=port)

    def check_command(self, command: str) -> ScopeCheckResult:
        self._check_command(command)
        return ScopeCheckResult(
            allowed=True,
            target="",
            matched_rule="allowed_commands",
            reason="Command passed allowlist and forbidden-flag checks.",
            command=command,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "name": self.name,
            "authorization": self.authorization,
            "expires": self.expires.isoformat() if self.expires else None,
            "allowed_cidrs": list(self.allowed_cidrs),
            "allowed_domains": list(self.allowed_domains),
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_commands": sorted(self.allowed_commands),
            "forbidden_flags": list(self.forbidden_flags),
        }
