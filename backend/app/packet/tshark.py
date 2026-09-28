import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from app.config import settings
from app.core.exceptions import AnalyzerError
from app.packet.field_map import IKE_DISPLAY_FILTER, IKE_JSON_LAYERS, METADATA_FIELDS, PREFERENCES, required_fields

PROTOCOL_LABELS = {
    "ip": "IPv4", "ipv6": "IPv6", "udp": "UDP", "tcp": "TCP", "udpencap": "UDP-Encap",
    "isakmp": "IKE", "esp": "ESP", "ah": "AH",
}


@dataclass(frozen=True)
class TSharkCapabilities:
    available: bool
    executable: str | None = None
    version: str | None = None
    fields: frozenset[str] | None = None
    preferences: frozenset[str] | None = None
    error: str | None = None

    @property
    def missing_fields(self) -> list[str]:
        return [] if self.fields is None else sorted(required_fields() - self.fields)

    @property
    def missing_preferences(self) -> list[str]:
        return [] if self.preferences is None else sorted(set(PREFERENCES) - self.preferences)


@dataclass
class PacketRecord:
    frame_number: int
    timestamp: float | None
    length: int
    protocols: list[str]
    ip_len: int | None = None
    ip_hdr_len: int | None = None
    ipv6_plen: int | None = None
    udp_length: int | None = None
    ip_src: str | None = None
    ip_dst: str | None = None
    ipv6_src: str | None = None
    ipv6_dst: str | None = None
    udp_srcport: int | None = None
    udp_dstport: int | None = None
    esp_spi: str | None = None
    esp_sequence: int | None = None
    esp_next_header: int | None = None
    ah_spi: str | None = None
    ah_sequence: int | None = None

    @property
    def ip_version(self) -> str | None:
        for protocol in self.protocols:
            if protocol in ("ip", "ipv6"):
                return "IPv4" if protocol == "ip" else "IPv6"
        return None

    @property
    def ip_total_length(self) -> int | None:
        """Length of the outermost IP packet (header included)."""
        if self.ip_version == "IPv4":
            return self.ip_len
        return self.ipv6_plen + 40 if self.ipv6_plen is not None else None

    @property
    def esp_payload_length(self) -> int | None:
        """Bytes after the 8-byte ESP header (IV + ciphertext + ICV), or None when not measurable."""
        if not self.esp_spi:
            return None
        if "udpencap" in self.protocols and self.udp_length:
            return self.udp_length - 8 - 8
        if self.ip_version == "IPv4" and self.ip_len and self.ip_hdr_len:
            return self.ip_len - self.ip_hdr_len - 8
        if self.ip_version == "IPv6" and self.ipv6_plen:
            return self.ipv6_plen - 8  # assumes no IPv6 extension headers before ESP
        return None

    @property
    def src(self) -> str | None:
        return self.ip_src if self.ip_version == "IPv4" else self.ipv6_src

    @property
    def dst(self) -> str | None:
        return self.ip_dst if self.ip_version == "IPv4" else self.ipv6_dst


@dataclass
class TSharkResult:
    packet_count: int
    detected_protocols: list[str]
    packets: list[PacketRecord]
    ike_packets: list[dict]
    version: str | None
    warnings: list[str] = field(default_factory=list)


_probe_cache: dict[str, TSharkCapabilities] = {}
_probe_lock = Lock()


def _names(output: str, kind: str, column: int) -> frozenset[str]:
    names = set()
    for line in output.splitlines():
        parts = line.split("\t")
        if kind == "pref":
            # defaultprefs lines look like "#esp.enable_null_encryption_decode_heuristic: FALSE"
            name = line.lstrip("#").split(":", 1)[0].strip()
            if name and not line.startswith("# ") and "." in name:
                names.add(name)
        elif len(parts) > column and parts[0] == kind:
            names.add(parts[column])
    return frozenset(names)


def probe(executable: str) -> TSharkCapabilities:
    """Resolve TShark and record which fields/preferences this version supports.

    Successful probes are cached per executable; failures are retried on the next call.
    """
    with _probe_lock:
        if executable in _probe_cache:
            return _probe_cache[executable]
        resolved = shutil.which(executable)
        if not resolved:
            return TSharkCapabilities(False, error="TShark is not installed or not on PATH. Set TSHARK_PATH to its full path.")
        try:
            version = subprocess.run([resolved, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False)
            fields = subprocess.run([resolved, "-G", "fields"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)
            prefs = subprocess.run([resolved, "-G", "defaultprefs"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return TSharkCapabilities(False, executable=resolved, error=f"Unable to query TShark: {exc}")
        if version.returncode != 0:
            return TSharkCapabilities(False, executable=resolved, error=f"TShark --version failed: {version.stderr.strip()[:200]}")
        capabilities = TSharkCapabilities(
            available=True,
            executable=resolved,
            version=version.stdout.splitlines()[0] if version.stdout else "unknown",
            fields=_names(fields.stdout, "F", 2) if fields.returncode == 0 else None,
            preferences=_names(prefs.stdout, "pref", 0) if prefs.returncode == 0 else None,
        )
        _probe_cache[executable] = capabilities
        return capabilities


def _int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


class TSharkService:
    def __init__(self, executable: str | None = None, timeout: int | None = None):
        self.executable = executable or settings.tshark_path
        self.timeout = timeout or settings.tshark_timeout_seconds

    def capabilities(self) -> TSharkCapabilities:
        return probe(self.executable)

    def availability(self) -> dict:
        caps = self.capabilities()
        if not caps.available:
            return {"available": False, "error": caps.error}
        return {
            "available": True,
            "version": caps.version,
            "field_check": "not verified" if caps.fields is None else ("ok" if not caps.missing_fields else "missing fields"),
            "missing_fields": caps.missing_fields,
            "missing_preferences": caps.missing_preferences,
        }

    def _run(self, caps: TSharkCapabilities, args: list[str], stage: str, warnings: list[str]) -> str:
        # Arguments are passed as a list and never through a shell; the path is server-generated.
        try:
            completed = subprocess.run(
                [caps.executable, *args], capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=self.timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AnalyzerError(f"TShark timed out after {self.timeout} seconds during {stage}.") from exc
        except OSError as exc:
            raise AnalyzerError(f"Unable to execute TShark: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr.strip() or "unknown TShark error")[:500]
            if not completed.stdout.strip():
                raise AnalyzerError(f"TShark rejected the capture: {detail}")
            # Truncated or partly damaged captures still yield the packets read before the damage.
            warnings.append(f"TShark reported a problem during {stage}; results cover the packets it could read: {detail}")
        return completed.stdout

    def _preference_args(self, caps: TSharkCapabilities) -> list[str]:
        args: list[str] = []
        for name, value in PREFERENCES.items():
            if caps.preferences is not None and name in caps.preferences:
                args += ["-o", f"{name}:{value}"]
        return args

    def packet_records(self, pcap_path: Path, warnings: list[str] | None = None) -> list[PacketRecord]:
        """Per-packet metadata only (one TShark pass); enough for traffic features."""
        caps = self.capabilities()
        if not caps.available:
            raise AnalyzerError(caps.error or "TShark is unavailable.")
        warnings = [] if warnings is None else warnings
        columns = [(name, tshark_field) for name, tshark_field in METADATA_FIELDS.items() if caps.fields is None or tshark_field in caps.fields]
        field_args = [arg for _, tshark_field in columns for arg in ("-e", tshark_field)]
        output = self._run(
            caps,
            ["-n", "-r", str(pcap_path), *self._preference_args(caps), "-T", "fields", "-E", "header=n", "-E", "separator=/t", "-E", "occurrence=f", *field_args],
            "packet metadata extraction",
            warnings,
        )
        return [record for line in output.splitlines() if (record := self._record(line, columns))]

    def analyze(self, pcap_path: Path) -> TSharkResult:
        caps = self.capabilities()
        if not caps.available:
            raise AnalyzerError(caps.error or "TShark is unavailable.")
        warnings: list[str] = []
        if caps.missing_fields:
            warnings.append(f"This TShark version lacks fields the parser uses; they are reported as unavailable: {', '.join(caps.missing_fields)}")
        prefs = self._preference_args(caps)
        packets = self.packet_records(pcap_path, warnings)

        ike_output = self._run(
            caps,
            ["-n", "-r", str(pcap_path), *prefs, "-Y", IKE_DISPLAY_FILTER, "-T", "json", "-J", IKE_JSON_LAYERS, "--no-duplicate-keys"],
            "IKE dissection",
            warnings,
        )
        try:
            ike_packets = json.loads(ike_output) if ike_output.strip() else []
        except json.JSONDecodeError as exc:
            raise AnalyzerError("TShark returned invalid JSON for IKE packets.") from exc

        protocols = {PROTOCOL_LABELS[p] for packet in packets for p in packet.protocols if p in PROTOCOL_LABELS}
        return TSharkResult(len(packets), sorted(protocols), packets, ike_packets, caps.version, warnings)

    @staticmethod
    def _record(line: str, columns: list[tuple[str, str]]) -> PacketRecord | None:
        values = dict(zip((name for name, _ in columns), line.split("\t")))
        frame_number = _int(values.get("frame_number"))
        if frame_number is None:
            return None
        protocols = [p for p in (values.get("protocols") or "").split(":") if p]
        # The ESP-NULL heuristic occasionally decodes encrypted payload bytes as an AH header
        # (seen as "esp:ah:ax25" in a real phone capture). Real AH is never nested inside ESP,
        # so an AH layer after ESP is decoding noise, not AH traffic.
        nested_ah = "esp" in protocols and "ah" in protocols and protocols.index("ah") > protocols.index("esp")
        return PacketRecord(
            frame_number=frame_number,
            timestamp=_float(values.get("timestamp")),
            length=_int(values.get("length")) or 0,
            protocols=protocols,
            ip_len=_int(values.get("ip_len")),
            ip_hdr_len=_int(values.get("ip_hdr_len")),
            ipv6_plen=_int(values.get("ipv6_plen")),
            udp_length=_int(values.get("udp_length")),
            ip_src=values.get("ip_src") or None,
            ip_dst=values.get("ip_dst") or None,
            ipv6_src=values.get("ipv6_src") or None,
            ipv6_dst=values.get("ipv6_dst") or None,
            udp_srcport=_int(values.get("udp_srcport")),
            udp_dstport=_int(values.get("udp_dstport")),
            esp_spi=values.get("esp_spi") or None,
            esp_sequence=_int(values.get("esp_sequence")),
            esp_next_header=_int(values.get("esp_next_header")),
            ah_spi=None if nested_ah else values.get("ah_spi") or None,
            ah_sequence=None if nested_ah else _int(values.get("ah_sequence")),
        )
