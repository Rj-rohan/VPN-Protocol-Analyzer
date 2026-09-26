"""Live capture: record from a network interface with dumpcap, analyse it while it runs,
then hand the finished capture to the normal analysis pipeline.

Safety: the interface must be one that `dumpcap -D` lists (exact match), the capture
filter comes from a fixed preset (never user text), duration and size are capped,
dumpcap is started with an argument list (no shell), and only one capture runs at a time.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from app.config import settings

logger = logging.getLogger(__name__)

FILTERS = {
    "ipsec": "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50 or ip6 proto 51",
    "all": "",
}
SNAPSHOT_MAX_BYTES = 20 * 1024 * 1024  # rolling re-analysis re-reads the file, so it stops beyond this size
_INTERFACE_LINE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")


class LiveCaptureError(Exception):
    pass


def dumpcap_executable() -> str | None:
    if settings.dumpcap_path:
        return shutil.which(settings.dumpcap_path)
    tshark = shutil.which(settings.tshark_path)
    if tshark:
        sibling = Path(tshark).with_name("dumpcap.exe" if tshark.lower().endswith(".exe") else "dumpcap")
        if sibling.exists():
            return str(sibling)
    return shutil.which("dumpcap")


def list_interfaces() -> list[dict]:
    executable = dumpcap_executable()
    if not executable:
        raise LiveCaptureError("dumpcap was not found. Install Wireshark/dumpcap or set DUMPCAP_PATH.")
    try:
        completed = subprocess.run([executable, "-D"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LiveCaptureError(f"Could not list interfaces: {exc}") from exc
    if completed.returncode != 0:
        raise LiveCaptureError(f"dumpcap could not list interfaces: {completed.stderr.strip()[:300]}")
    interfaces = []
    for line in completed.stdout.splitlines():
        if match := _INTERFACE_LINE.match(line):
            number, name, description = match.groups()
            interfaces.append({"index": int(number), "name": name, "description": description or name})
    return interfaces


@dataclass
class LiveSession:
    id: UUID
    user_id: UUID
    user_email: str
    interface: str
    interface_label: str
    capture_filter: str
    duration_seconds: int
    path: Path
    started_at: float = field(default_factory=time.time)
    status: str = "capturing"          # capturing -> analysing -> completed | failed
    stop_requested: bool = False
    process: subprocess.Popen | None = None
    snapshot: dict = field(default_factory=dict)
    analysis_id: UUID | None = None
    error: str | None = None
    ended_at: float | None = None

    def as_dict(self) -> dict:
        now = self.ended_at or time.time()
        return {
            "id": str(self.id), "status": self.status, "interface": self.interface_label, "filter": self.capture_filter,
            "duration_seconds": self.duration_seconds, "elapsed_seconds": round(min(now - self.started_at, self.duration_seconds), 1),
            "started_at": datetime.fromtimestamp(self.started_at, timezone.utc).isoformat(timespec="seconds"),
            "bytes_captured": self.path.stat().st_size if self.path.exists() else 0,
            "snapshot": self.snapshot, "analysis_id": str(self.analysis_id) if self.analysis_id else None,
            "error": self.error, "owner": self.user_email,
        }


class LiveCaptureManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.sessions: dict[UUID, LiveSession] = {}

    @property
    def active(self) -> LiveSession | None:
        return next((s for s in self.sessions.values() if s.status in ("capturing", "analysing")), None)

    def start(self, user, interface: str, duration: int, preset: str) -> LiveSession:
        if preset not in FILTERS:
            raise LiveCaptureError(f"Unknown filter preset {preset!r}.")
        duration = max(5, min(int(duration), settings.live_capture_max_seconds))
        known = {i["name"]: i for i in list_interfaces()}
        if interface not in known:
            raise LiveCaptureError("Unknown interface; choose one from the list.")
        executable = dumpcap_executable()
        live_dir = settings.storage_dir.parent / "live"
        live_dir.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self.active:
                raise LiveCaptureError("A live capture is already running. Stop it or wait until it finishes.")
            session_id = uuid4()
            session = LiveSession(id=session_id, user_id=user.id, user_email=user.email, interface=interface,
                                  interface_label=known[interface]["description"], capture_filter=preset, duration_seconds=duration,
                                  path=live_dir / f"{session_id}.pcapng")
            args = [executable, "-i", interface, "-a", f"duration:{duration}", "-a", f"filesize:{settings.live_capture_max_megabytes * 1024}",
                    "-w", str(session.path), "-q"]
            if FILTERS[preset]:
                args += ["-f", FILTERS[preset]]
            # A separate process group lets us send Ctrl+Break (Windows) / SIGINT so dumpcap closes the file cleanly.
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            try:
                session.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=flags)
            except OSError as exc:
                raise LiveCaptureError(f"Could not start dumpcap: {exc}") from exc
            self.sessions[session_id] = session
        threading.Thread(target=self._supervise, args=(session,), name=f"live-{session_id}", daemon=True).start()
        return session

    def stop(self, session: LiveSession) -> None:
        session.stop_requested = True
        process = session.process
        if process and process.poll() is None:
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
            except (OSError, ValueError):
                process.terminate()

    def _supervise(self, session: LiveSession) -> None:
        from app.packet.parser import analyze_pcap

        process = session.process
        last_snapshot = 0.0
        worker: threading.Thread | None = None
        while process.poll() is None:
            time.sleep(0.5)
            due = time.time() - last_snapshot >= settings.live_snapshot_interval_seconds
            if due and session.path.exists() and (worker is None or not worker.is_alive()):
                last_snapshot = time.time()
                if session.path.stat().st_size > SNAPSHOT_MAX_BYTES:
                    session.snapshot = {**session.snapshot, "paused": "Capture too large for rolling analysis; the full analysis runs when it ends."}
                else:
                    # Rolling analysis runs beside the capture so a slow snapshot never delays stopping.
                    worker = threading.Thread(target=lambda: setattr(session, "snapshot", self._snapshot(session, analyze_pcap)), daemon=True)
                    worker.start()
        if worker is not None:
            worker.join(timeout=30)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        session.ended_at = time.time()
        stderr = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
        if not session.path.exists() or session.path.stat().st_size == 0:
            session.status, session.error = "failed", f"dumpcap produced no capture: {stderr.strip()[-300:] or 'unknown error'}"
            return
        session.status = "analysing"
        if session.path.stat().st_size <= SNAPSHOT_MAX_BYTES:
            session.snapshot = self._snapshot(session, analyze_pcap)
        try:
            session.analysis_id = self._hand_over(session)
            session.status = "completed"
        except Exception as exc:  # the capture file is kept for inspection
            logger.exception("Live capture hand-over failed")
            session.status, session.error = "failed", f"Could not queue the analysis: {exc}"

    @staticmethod
    def _snapshot(session: LiveSession, analyze_pcap) -> dict:
        """Rolling view of what has been captured so far (a truncated tail is fine; TShark reports it as a warning)."""
        try:
            result = analyze_pcap(session.path)
        except Exception as exc:  # e.g. the file has no complete packet yet
            return {**session.snapshot, "error": str(exc)[:200]}
        features, assessment = result["features"], result["security"]["assessment"]
        traffic = features["traffic"]["features"]
        return {
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "packets": result["packet_count"], "protocols": result["detected_protocols"],
            "ipsec_detected": features["detection"]["ipsec_detected"], "ike_version": features["protocol"]["ike_version"]["value"],
            "esp_packets": features["packet_statistics"]["esp_packet_count"], "ike_messages": features["packet_statistics"]["ike_message_count"],
            "spis": features["sa"]["spi_values"]["value"], "packets_per_second": round(traffic.get("packets_per_second", 0.0), 1),
            "encryption": features["cryptography"]["encryption_algorithm"]["value"], "dh_group": features["cryptography"]["dh_group"]["value"],
            "security_score": assessment["security_score"], "risk_level": assessment["risk_level"], "findings": assessment["finding_count"],
        }

    @staticmethod
    def _hand_over(session: LiveSession) -> UUID:
        """Store the finished capture like an upload and queue the full analysis."""
        from app.core.audit import audit
        from app.core.models import User
        from app.db.repositories import create_analysis, create_capture
        from app.worker import get_queue

        content = session.path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        stamp = datetime.fromtimestamp(session.started_at, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"live-{stamp}.pcapng"
        settings.storage_dir.mkdir(parents=True, exist_ok=True)
        stored = settings.storage_dir / f"{digest[:16]}_{filename}"
        if not stored.exists():
            shutil.move(str(session.path), stored)
        else:
            session.path.unlink(missing_ok=True)
        queue = get_queue()
        with queue.session_factory() as db:
            user = db.get(User, session.user_id)
            capture = create_capture(db, user, filename, stored, digest, len(content), "pcapng")
            analysis = create_analysis(db, capture)
            audit(db, "live.completed", user, resource_type="analysis", resource_id=analysis.id,
                  detail={"interface": session.interface_label, "seconds": round(session.ended_at - session.started_at, 1),
                          "bytes": len(content), "stopped_early": session.stop_requested})
            db.commit()
            analysis_id = analysis.id
        queue.enqueue(analysis_id)
        return analysis_id


manager = LiveCaptureManager()
