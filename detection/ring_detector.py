"""
Abuse-ring detection layer.

Catches coordinated fraud rings that individual-transaction scoring
misses: several devices that appear geographically co-located, run the
same firmware, and transact in the same bursts are likely operated by
one attacker, not independent merchants.

Approach (inspired by the Abuse Ring Sentinel track):
    1. Build a device similarity graph — devices are nodes; edges
       connect devices that share geo-city AND firmware version, with
       extra weight when both were active in the same 15-minute window.
    2. Run Louvain community detection to find clusters of connected
       devices.
    3. Score each community by how collectively abnormal its members
       are (burst / velocity rates) and emit a 0-100 ring_score per
       device, plus evidence for the risk layer.

Usage:
    from detection.ring_detector import add_ring_features
    df = add_ring_features(df)   # needs temporal features present
"""

import numpy as np
import pandas as pd

import networkx as nx
from networkx.algorithms.community import louvain_communities

# Minimum community size worth reporting as a potential ring.
MIN_COMMUNITY_SIZE = 2

# Weights for the device similarity graph.
CITY_FIRMWARE_EDGE_WEIGHT = 1.0
TEMPORAL_EDGE_WEIGHT = 0.5


def build_device_graph(df: pd.DataFrame) -> nx.Graph:
    """
    Build an undirected device similarity graph.

    Edge rules:
      * Same geo_city AND same dominant firmware version -> base edge.
      * Both devices active in the same 15-minute window -> +0.5 weight
        (catches burst co-activity across supposedly-independent POS).
    """

    g = nx.Graph()

    # Without geo/firmware signals there is no similarity evidence, so
    # build no edges at all (an all-UNKNOWN bucket would merge every
    # device into one fake ring).
    has_geo = "geo_city" in df.columns
    has_fw = "firmware_version" in df.columns
    if not (has_geo and has_fw):
        for dev in df["device_id"].unique():
            g.add_node(dev)
        return g

    device_meta = (
        df.groupby("device_id")
        .agg(
            geo_city=("geo_city", lambda s: s.mode().iloc[0] if not s.mode().empty else "UNKNOWN"),
            firmware_version=("firmware_version", lambda s: s.mode().iloc[0] if not s.mode().empty else "UNKNOWN"),
        )
        .reset_index()
    )

    for dev in device_meta["device_id"]:
        g.add_node(dev)

    # Device -> set of 15-minute windows it was active in.
    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        window = ts.dt.floor("15min")
        active_windows = df.assign(_w=window).groupby("device_id")["_w"].agg(set)
    else:
        active_windows = pd.Series(dtype=object)

    # City+firmware buckets: devices sharing both get an edge.
    for (city, fw), bucket in device_meta.groupby(["geo_city", "firmware_version"]):
        devices = list(bucket["device_id"])
        for i in range(len(devices)):
            for j in range(i + 1, len(devices)):
                a, b = devices[i], devices[j]
                w = CITY_FIRMWARE_EDGE_WEIGHT
                if a in active_windows.index and b in active_windows.index:
                    shared = len(active_windows[a] & active_windows[b])
                    w += TEMPORAL_EDGE_WEIGHT * min(shared, 3)
                if g.has_edge(a, b):
                    g[a][b]["weight"] += w
                else:
                    g.add_edge(a, b, weight=w)

    return g


def detect_communities(graph: nx.Graph):
    """
    Return a list of communities (lists of device ids) of size >=
    MIN_COMMUNITY_SIZE, ordered by descending suspicion potential.
    """

    if graph.number_of_nodes() == 0:
        return []

    communities = louvain_communities(graph, weight="weight", seed=42)
    return [
        sorted(c) for c in communities if len(c) >= MIN_COMMUNITY_SIZE
    ]


def score_communities(df: pd.DataFrame, communities) -> pd.DataFrame:
    """
    Compute a 0-100 ring_score per community (and thus per device).

    A community is suspicious when a large share of its members show
    bursty / high-velocity behavior (signs of a coordinated attack),
    amplified slightly by community size (bigger rings = more exposure).
    """

    if not communities:
        return pd.DataFrame(
            columns=["device_id", "ring_community_id", "ring_size", "ring_score"]
        )

    # Per-device abnormality summary. We use the MAX burst/velocity a
    # device ever hit — a device that burst once in its history is still
    # ring-relevant, whereas its mean stays low and would hide it.
    # Temporal features may be absent entirely (raw frames passed
    # directly) — default to 0 so the module degrades to structure-only
    # scoring instead of crashing.
    burst_col = "burst_count_5min" if "burst_count_5min" in df.columns else None
    velocity_col = "velocity_15min" if "velocity_15min" in df.columns else None

    agg_spec = {}
    if burst_col:
        agg_spec["_max_burst"] = (burst_col, "max")
    if velocity_col:
        agg_spec["_max_velocity"] = (velocity_col, "max")

    if agg_spec:
        dev_stats = df.groupby("device_id").agg(**agg_spec).reset_index()
    else:
        dev_stats = pd.DataFrame({"device_id": df["device_id"].unique()})
        dev_stats["_max_burst"] = 0.0
        dev_stats["_max_velocity"] = 0.0

    rows = []
    for idx, community in enumerate(communities, start=1):
        members = dev_stats[dev_stats["device_id"].isin(community)]
        if members.empty:
            continue

        bursty = (members["_max_burst"] >= 5).mean()
        fast = (members["_max_velocity"] >= 10).mean()
        collective = max(bursty, fast)

        # Size amplifier: rings of 3+ devices are far more likely to be
        # organized fraud than a pair of co-located terminals.
        size_factor = min(len(community) / 3.0, 1.0)

        ring_score = float(np.clip(100 * (0.75 * collective + 0.25 * size_factor), 0, 100))

        for dev in community:
            rows.append(
                {
                    "device_id": dev,
                    "ring_community_id": f"RING-{idx:03d}",
                    "ring_size": len(community),
                    "ring_score": round(ring_score, 2),
                }
            )

    return pd.DataFrame(rows)


def add_ring_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add ring detection columns to a transaction frame.

    Adds: ring_community_id, ring_size, ring_score (0-100). Transactions
    whose device is not in any ring get ring_score = 0. Requires the
    temporal features (burst_count_5min, velocity_15min) to be present.
    """

    df = df.copy()

    if "device_id" not in df.columns or df.empty:
        df["ring_community_id"] = ""
        df["ring_size"] = 0
        df["ring_score"] = 0.0
        return df

    graph = build_device_graph(df)
    communities = detect_communities(graph)
    scores = score_communities(df, communities)

    if scores.empty:
        df["ring_community_id"] = ""
        df["ring_size"] = 0
        df["ring_score"] = 0.0
        return df

    # Merge (left) and fill defaults for devices outside any ring.
    df = df.merge(
        scores,
        on="device_id",
        how="left",
    )
    df["ring_score"] = df["ring_score"].fillna(0.0)
    df["ring_size"] = df["ring_size"].fillna(0).astype(int)
    df["ring_community_id"] = df["ring_community_id"].fillna("")
    return df