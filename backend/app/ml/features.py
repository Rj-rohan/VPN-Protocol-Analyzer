"""Feature definitions shared by training and prediction.

BASE_FEATURES exist in both the synthetic CSV and real captures. FULL_FEATURES
add distribution, burst and direction statistics only real captures provide.
"""

TRAFFIC_CLASSES = ("Web", "Video", "VoIP", "Email", "Chat", "ICMP", "File-Transfer")

BASE_FEATURES = [
    "duration_seconds", "packet_count", "avg_packet_size_bytes", "std_packet_size_bytes", "packets_per_second",
    "bytes_total", "bytes_up", "bytes_down", "uplink_ratio", "avg_interarrival_ms",
]

FULL_FEATURES = BASE_FEATURES + [
    "min_packet_size_bytes", "max_packet_size_bytes",
    "p10_packet_size_bytes", "p25_packet_size_bytes", "p50_packet_size_bytes", "p75_packet_size_bytes", "p90_packet_size_bytes",
    "std_interarrival_ms", "p10_interarrival_ms", "p25_interarrival_ms", "p50_interarrival_ms", "p75_interarrival_ms", "p90_interarrival_ms",
    "packets_up", "packets_down", "bytes_per_second", "direction_changes", "direction_change_rate",
    "burst_count", "avg_burst_packets", "max_burst_packets",
    "size_bin_0_fraction", "size_bin_1_fraction", "size_bin_2_fraction", "size_bin_3_fraction", "size_bin_4_fraction", "size_bin_5_fraction",
    # Per-direction behaviour and idleness
    "avg_packet_size_up_bytes", "std_packet_size_up_bytes", "packets_per_second_up", "avg_interarrival_up_ms", "p50_interarrival_up_ms",
    "avg_packet_size_down_bytes", "std_packet_size_down_bytes", "packets_per_second_down", "avg_interarrival_down_ms", "p50_interarrival_down_ms",
    "idle_fraction", "idle_periods", "max_idle_seconds",
    # Temporal pattern: steady bulk transfer vs chunked streaming vs sparse interaction
    "small_packet_up_fraction", "large_packet_down_fraction", "bytes_per_second_cv", "active_second_fraction",
    "peak_to_mean_bytes_ratio", "avg_burst_bytes", "max_burst_bytes", "avg_inter_burst_gap_ms", "std_inter_burst_gap_ms",
]

# The analyzer calls the ESP/AH packet count `flow_packet_count`; the dataset calls it `packet_count`.
_RENAMES = {"flow_packet_count": "packet_count"}


def from_traffic_metadata(traffic_features: dict) -> dict[str, float]:
    """Map the analyzer's traffic metadata to model feature names."""
    mapped = {_RENAMES.get(key, key): value for key, value in traffic_features.items()}
    return {name: float(mapped.get(name, 0.0) or 0.0) for name in FULL_FEATURES}
