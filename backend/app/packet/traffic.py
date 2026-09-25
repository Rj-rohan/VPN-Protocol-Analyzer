"""Encrypted-traffic metadata for traffic classification and charts.

Only outer, observable properties are used: packet sizes, timing and direction
of ESP/AH packets. Payload contents are never inspected.
"""
from __future__ import annotations

from statistics import mean, pstdev

from app.packet import esp
from app.packet.ike import IkeMessage
from app.packet.tshark import PacketRecord

BURST_GAP_SECONDS = 0.005
SIZE_BINS = ((0, 128), (128, 256), (256, 512), (512, 1024), (1024, 1400), (1400, 1_000_000))
MAX_TIMELINE_POINTS = 300


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower, upper = int(position), min(int(position) + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _summary(values: list[float], prefix: str, unit: str) -> dict:
    return {
        f"avg_{prefix}_{unit}": mean(values) if values else 0.0,
        f"std_{prefix}_{unit}": pstdev(values) if len(values) > 1 else 0.0,
        f"min_{prefix}_{unit}": min(values) if values else 0.0,
        f"max_{prefix}_{unit}": max(values) if values else 0.0,
        **{f"p{int(q * 100)}_{prefix}_{unit}": _percentile(values, q) for q in (0.1, 0.25, 0.5, 0.75, 0.9)},
    }


IDLE_GAP_SECONDS = 1.0


def _direction_stats(packets: list[PacketRecord], direction: str, duration: float) -> dict:
    """Size, rate and gap statistics for one direction; apps differ most in how the two directions behave."""
    sizes = [float(p.length) for p in packets]
    gaps = [(b.timestamp - a.timestamp) * 1000 for a, b in zip(packets, packets[1:])]
    return {
        f"avg_packet_size_{direction}_bytes": mean(sizes) if sizes else 0.0,
        f"std_packet_size_{direction}_bytes": pstdev(sizes) if len(sizes) > 1 else 0.0,
        f"packets_per_second_{direction}": len(packets) / duration if duration > 0 else 0.0,
        f"avg_interarrival_{direction}_ms": mean(gaps) if gaps else 0.0,
        f"p50_interarrival_{direction}_ms": _percentile(gaps, 0.5),
    }


SMALL_PACKET_BYTES = 150    # an ESP-wrapped TCP ACK or tiny control packet
LARGE_PACKET_BYTES = 1200   # a near-MTU data packet


def _pattern_stats(flow: list[PacketRecord], up: list[PacketRecord], down: list[PacketRecord], start: float, duration: float) -> dict:
    """Shape of the traffic over time: steady bulk transfer, chunked streaming, or sparse interaction."""
    seconds = max(1, int(duration) + 1)
    per_second = [0] * seconds
    for packet in flow:
        per_second[min(seconds - 1, int(packet.timestamp - start))] += packet.length
    average = mean(per_second)
    bursts = _burst_spans(flow)
    burst_bytes = [b for _, _, b in bursts]
    gaps = [later[0] - earlier[1] for earlier, later in zip(bursts, bursts[1:])]
    return {
        "small_packet_up_fraction": sum(1 for p in up if p.length <= SMALL_PACKET_BYTES) / len(up) if up else 0.0,
        "large_packet_down_fraction": sum(1 for p in down if p.length >= LARGE_PACKET_BYTES) / len(down) if down else 0.0,
        "bytes_per_second_cv": pstdev(per_second) / average if average else 0.0,
        "active_second_fraction": sum(1 for b in per_second if b) / seconds,
        "peak_to_mean_bytes_ratio": max(per_second) / average if average else 0.0,
        "avg_burst_bytes": mean(burst_bytes) if burst_bytes else 0.0,
        "max_burst_bytes": max(burst_bytes) if burst_bytes else 0.0,
        "avg_inter_burst_gap_ms": mean(gaps) * 1000 if gaps else 0.0,
        "std_inter_burst_gap_ms": pstdev(gaps) * 1000 if len(gaps) > 1 else 0.0,
    }


def _burst_spans(flow: list[PacketRecord]) -> list[tuple[float, float, int]]:
    """(start, end, bytes) of each run of packets separated by at most BURST_GAP_SECONDS."""
    spans: list[tuple[float, float, int]] = []
    for packet in flow:
        if spans and packet.timestamp - spans[-1][1] <= BURST_GAP_SECONDS:
            begin, _, size = spans[-1]
            spans[-1] = (begin, packet.timestamp, size + packet.length)
        else:
            spans.append((packet.timestamp, packet.timestamp, packet.length))
    return spans


def _idle_stats(times: list[float], duration: float) -> dict:
    """How much of the time the flow sits idle (chat and email are mostly idle; calls and streams are not)."""
    gaps = [b - a for a, b in zip(times, times[1:])]
    idle = [gap for gap in gaps if gap > IDLE_GAP_SECONDS]
    return {
        "idle_fraction": sum(idle) / duration if duration > 0 else 0.0,
        "idle_periods": len(idle),
        "max_idle_seconds": max(idle) if idle else 0.0,
    }


def _initiator(packets: list[PacketRecord], messages: list[IkeMessage], flow: list[PacketRecord]) -> tuple[str | None, str]:
    by_frame = {p.frame_number: p for p in packets}
    for message in messages:
        request = message.is_response is False if message.version == "IKEv2" else not message.responder_spi_set
        record = by_frame.get(message.frame_number)
        if request and record and record.src:
            return record.src, "IKE initiator"
    return (flow[0].src if flow else None), "sender of the first ESP/AH packet"


def _bursts(times: list[float]) -> list[int]:
    bursts: list[int] = []
    current = 1
    for previous, now in zip(times, times[1:]):
        if now - previous <= BURST_GAP_SECONDS:
            current += 1
        else:
            bursts.append(current)
            current = 1
    if times:
        bursts.append(current)
    return bursts


def _timeline(flow: list[PacketRecord], start: float, duration: float, initiator: str | None) -> list[dict]:
    if not flow:
        return []
    bucket = max(1.0, duration / MAX_TIMELINE_POINTS)
    points: dict[int, dict] = {}
    for packet in flow:
        index = int(((packet.timestamp or start) - start) / bucket)
        point = points.setdefault(index, {"t": round(index * bucket, 3), "packets": 0, "bytes_up": 0, "bytes_down": 0})
        point["packets"] += 1
        point["bytes_up" if packet.src == initiator else "bytes_down"] += packet.length
    return [points[key] for key in sorted(points)]


def extract_traffic_metadata(packets: list[PacketRecord], messages: list[IkeMessage]) -> dict:
    flow = sorted((p for p in packets if (p.esp_spi or p.ah_spi) and p.timestamp is not None), key=lambda p: p.timestamp)
    initiator, direction_basis = _initiator(packets, messages, flow)
    sizes = [float(p.length) for p in flow]
    times = [p.timestamp for p in flow]
    start = times[0] if times else 0.0
    duration = (times[-1] - start) if len(times) > 1 else 0.0
    gaps_ms = [(b - a) * 1000 for a, b in zip(times, times[1:])]
    up = [p for p in flow if p.src == initiator]
    bytes_up = sum(p.length for p in up)
    bytes_total = sum(p.length for p in flow)
    directions = [p.src == initiator for p in flow]
    direction_changes = sum(1 for a, b in zip(directions, directions[1:]) if a != b)
    bursts = _bursts(times)
    histogram = [{"range": f"{low}+" if high >= 1_000_000 else f"{low}-{high}", "packets": sum(1 for s in sizes if low <= s < high)}
                 for low, high in SIZE_BINS]

    down = [p for p in flow if p.src != initiator]
    features = {
        **_direction_stats(up, "up", duration),
        **_direction_stats(down, "down", duration),
        **_idle_stats(times, duration),
        **_pattern_stats(flow, up, down, start, duration),
        "flow_packet_count": len(flow),
        "duration_seconds": duration,
        "bytes_total": bytes_total,
        "bytes_up": bytes_up,
        "bytes_down": bytes_total - bytes_up,
        "uplink_ratio": bytes_up / bytes_total if bytes_total else 0.0,
        "packets_up": len(up),
        "packets_down": len(flow) - len(up),
        "packets_per_second": len(flow) / duration if duration > 0 else 0.0,
        "bytes_per_second": bytes_total / duration if duration > 0 else 0.0,
        **_summary(sizes, "packet_size", "bytes"),
        **_summary(gaps_ms, "interarrival", "ms"),
        "direction_changes": direction_changes,
        "direction_change_rate": direction_changes / (len(flow) - 1) if len(flow) > 1 else 0.0,
        "burst_count": len(bursts),
        "avg_burst_packets": mean(bursts) if bursts else 0.0,
        "max_burst_packets": max(bursts) if bursts else 0,
        **{f"size_bin_{index}_fraction": (item["packets"] / len(flow) if flow else 0.0) for index, item in enumerate(histogram)},
    }
    return {
        "source": "observed",
        "scope": "ESP/AH packets (outer headers, sizes and timing only)",
        "direction_basis": f"'up' is traffic sent by the {direction_basis}" if initiator else "direction unavailable",
        "features": {key: round(value, 6) if isinstance(value, float) else value for key, value in features.items()},
        "size_histogram": histogram,
        "timeline": _timeline(flow, start, duration, initiator),
    }
