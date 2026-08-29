"""
Synthetic transaction + device-telemetry generator.

Simulates payment terminal (POS/IoT device) transaction logs the way they'd
look coming off real hardware — including device-level signals (retry counts,
firmware version, uptime, ping gaps) that a typical fraud dataset ignores.
A small fraction of rows are seeded with realistic fraud patterns:
    - card_testing: many tiny transactions in a short burst from one device
    - device_spoof: sudden geo jump + firmware/uptime inconsistency
    - bust_out: one large transaction after a long dormant period
    - retry_storm: abnormal retry_count / last_ping_gap (protocol-level anomaly)

Usage:
    python generate_synthetic_data.py --rows 8000 --fraud_rate 0.03 --out transactions.csv
"""

import argparse
import csv
import random
import uuid
from datetime import datetime, timedelta

random.seed(42)

CITIES = [
    ("Mumbai", 19.0760, 72.8777),
    ("Delhi", 28.7041, 77.1025),
    ("Bengaluru", 12.9716, 77.5946),
    ("Nagpur", 21.1458, 79.0882),
    ("Pune", 18.5204, 73.8567),
    ("Chennai", 13.0827, 80.2707),
    ("Hyderabad", 17.3850, 78.4867),
    ("Kolkata", 22.5726, 88.3639),
]

FIRMWARE_VERSIONS = ["v2.1.0", "v2.1.1", "v2.2.0", "v2.3.0-beta"]


def random_device_pool(n_devices):
    """Pre-generate a pool of devices with a 'home city' and firmware."""
    devices = []
    for _ in range(n_devices):
        city = random.choice(CITIES)
        devices.append({
            "device_id": f"POS-{uuid.uuid4().hex[:8].upper()}",
            "merchant_id": f"MER-{uuid.uuid4().hex[:6].upper()}",
            "home_city": city,
            "firmware_version": random.choice(FIRMWARE_VERSIONS),
        })
    return devices


def normal_transaction(device, ts):
    city_name, lat, lon = device["home_city"]
    return {
        "transaction_id": str(uuid.uuid4()),
        "device_id": device["device_id"],
        "merchant_id": device["merchant_id"],
        "timestamp": ts.isoformat(),
        "transaction_amount": round(random.uniform(50, 5000), 2),
        "retry_count": random.choice([0, 0, 0, 1]),
        "device_uptime_hrs": round(random.uniform(1, 500), 1),
        "firmware_version": device["firmware_version"],
        "last_ping_gap_sec": round(random.uniform(0.5, 3.0), 2),
        "geo_city": city_name,
        "geo_lat": lat,
        "geo_lon": lon,
        "ip_consistency_flag": 1,
        "label": "normal",
        "fraud_type": "",
    }


def card_testing_burst(device, ts, count=12):
    """Many tiny transactions in a tight time window from the same device."""
    rows = []
    city_name, lat, lon = device["home_city"]
    for i in range(count):
        rows.append({
            "transaction_id": str(uuid.uuid4()),
            "device_id": device["device_id"],
            "merchant_id": device["merchant_id"],
            "timestamp": (ts + timedelta(seconds=i * random.uniform(1, 4))).isoformat(),
            "transaction_amount": round(random.uniform(1, 20), 2),
            "retry_count": random.choice([0, 1, 2]),
            "device_uptime_hrs": round(random.uniform(1, 500), 1),
            "firmware_version": device["firmware_version"],
            "last_ping_gap_sec": round(random.uniform(0.3, 1.5), 2),
            "geo_city": city_name,
            "geo_lat": lat,
            "geo_lon": lon,
            "ip_consistency_flag": 1,
            "label": "fraud",
            "fraud_type": "card_testing",
        })
    return rows


def device_spoof(device, ts):
    """Same device_id, but geo jumps to a random far city and firmware mismatches."""
    fake_city = random.choice([c for c in CITIES if c[0] != device["home_city"][0]])
    return {
        "transaction_id": str(uuid.uuid4()),
        "device_id": device["device_id"],
        "merchant_id": device["merchant_id"],
        "timestamp": ts.isoformat(),
        "transaction_amount": round(random.uniform(500, 8000), 2),
        "retry_count": random.choice([0, 1]),
        "device_uptime_hrs": round(random.uniform(0.1, 2), 1),  # suspiciously fresh boot
        "firmware_version": random.choice(FIRMWARE_VERSIONS),  # may mismatch known device fw
        "last_ping_gap_sec": round(random.uniform(4, 12), 2),  # abnormal gap
        "geo_city": fake_city[0],
        "geo_lat": fake_city[1],
        "geo_lon": fake_city[2],
        "ip_consistency_flag": 0,
        "label": "fraud",
        "fraud_type": "device_spoof",
    }


def bust_out(device, ts):
    """One very large transaction after implied dormancy (encoded via uptime + amount)."""
    city_name, lat, lon = device["home_city"]
    return {
        "transaction_id": str(uuid.uuid4()),
        "device_id": device["device_id"],
        "merchant_id": device["merchant_id"],
        "timestamp": ts.isoformat(),
        "transaction_amount": round(random.uniform(20000, 80000), 2),
        "retry_count": 0,
        "device_uptime_hrs": round(random.uniform(400, 900), 1),
        "firmware_version": device["firmware_version"],
        "last_ping_gap_sec": round(random.uniform(0.5, 2.0), 2),
        "geo_city": city_name,
        "geo_lat": lat,
        "geo_lon": lon,
        "ip_consistency_flag": 1,
        "label": "fraud",
        "fraud_type": "bust_out",
    }


def retry_storm(device, ts):
    """Protocol-level anomaly: high retry_count + large ping gap (mimics a device
    being tampered with / a UART-SPI-level handshake failure pattern)."""
    city_name, lat, lon = device["home_city"]
    return {
        "transaction_id": str(uuid.uuid4()),
        "device_id": device["device_id"],
        "merchant_id": device["merchant_id"],
        "timestamp": ts.isoformat(),
        "transaction_amount": round(random.uniform(100, 3000), 2),
        "retry_count": random.randint(6, 15),
        "device_uptime_hrs": round(random.uniform(1, 500), 1),
        "firmware_version": device["firmware_version"],
        "last_ping_gap_sec": round(random.uniform(8, 20), 2),
        "geo_city": city_name,
        "geo_lat": lat,
        "geo_lon": lon,
        "ip_consistency_flag": 1,
        "label": "fraud",
        "fraud_type": "retry_storm",
    }


def generate(rows, fraud_rate, n_devices, out_path):
    devices = random_device_pool(n_devices)
    start = datetime(2026, 8, 1)
    all_rows = []

    n_fraud_events = max(1, int(rows * fraud_rate))
    fraud_generators = [card_testing_burst, device_spoof, bust_out, retry_storm]

    # normal traffic
    for _ in range(rows):
        device = random.choice(devices)
        ts = start + timedelta(minutes=random.uniform(0, 60 * 24 * 20))
        all_rows.append(normal_transaction(device, ts))

    # fraud injections
    for _ in range(n_fraud_events):
        device = random.choice(devices)
        ts = start + timedelta(minutes=random.uniform(0, 60 * 24 * 20))
        gen = random.choice(fraud_generators)
        result = gen(device, ts)
        if isinstance(result, list):
            all_rows.extend(result)
        else:
            all_rows.append(result)

    all_rows.sort(key=lambda r: r["timestamp"])

    fieldnames = list(all_rows[0].keys())
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Wrote {len(all_rows)} rows ({n_fraud_events} fraud events injected) to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=8000, help="number of normal rows")
    parser.add_argument("--fraud_rate", type=float, default=0.03, help="fraud events as fraction of rows")
    parser.add_argument("--devices", type=int, default=150, help="number of unique devices in the pool")
    parser.add_argument("--out", type=str, default="transactions.csv")
    args = parser.parse_args()

    generate(args.rows, args.fraud_rate, args.devices, args.out)
