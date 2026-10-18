"""
RansomShield Network Telemetry Collector (Section 5)
Collects REAL host network connection data using psutil.net_connections().
Never fabricates connections. If access is unavailable, records NETWORK_MONITORING_UNAVAILABLE.

Collected fields per connection:
  timestamp, endpoint_id, process_instance_id (if resolvable),
  local_address, local_port, remote_address, remote_port,
  protocol, connection_status, source
"""
import logging
import psutil
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.models.entities import NetworkEvent
from backend.modules.process_identity import get_process_identity, build_process_instance_id

logger = logging.getLogger(__name__)

NETWORK_MONITORING_UNAVAILABLE = "NETWORK_MONITORING_UNAVAILABLE"
NETWORK_MONITORING_AVAILABLE = "NETWORK_MONITORING_AVAILABLE"

import socket

_PROTO_MAP = {
    socket.AF_INET: "IPv4",
    socket.AF_INET6: "IPv6",
}


def check_network_monitoring_available() -> dict:
    """
    Checks whether network connection monitoring is available on this host.
    Returns status dict.
    """
    try:
        conns = psutil.net_connections(kind="all")
        return {
            "status": NETWORK_MONITORING_AVAILABLE,
            "connection_count": len(conns),
            "source": "psutil.net_connections",
        }
    except psutil.AccessDenied:
        return {
            "status": NETWORK_MONITORING_UNAVAILABLE,
            "reason": "psutil.net_connections requires elevated privileges on this OS.",
            "source": "psutil.net_connections",
        }
    except Exception as e:
        return {
            "status": NETWORK_MONITORING_UNAVAILABLE,
            "reason": str(e),
            "source": "psutil.net_connections",
        }


def collect_network_snapshot(
    db: Session,
    endpoint_id: str,
    store: bool = True,
) -> dict:
    """
    Takes a real-time snapshot of active network connections on this host.
    Stores NetworkEvent records to the database if store=True.

    Returns summary dict with availability status and events collected.
    """
    availability = check_network_monitoring_available()
    if availability["status"] == NETWORK_MONITORING_UNAVAILABLE:
        logger.warning(f"[NetworkCollector] {availability['reason']}")
        return {
            "status": NETWORK_MONITORING_UNAVAILABLE,
            "reason": availability.get("reason", "Unknown"),
            "events_collected": 0,
        }

    try:
        conns = psutil.net_connections(kind="all")
    except Exception as e:
        return {
            "status": NETWORK_MONITORING_UNAVAILABLE,
            "reason": str(e),
            "events_collected": 0,
        }

    events_stored = []
    now = datetime.utcnow()

    for conn in conns:
        try:
            local_addr = conn.laddr.ip if conn.laddr else None
            local_port = conn.laddr.port if conn.laddr else None
            remote_addr = conn.raddr.ip if conn.raddr else None
            remote_port = conn.raddr.port if conn.raddr else None
            proto = _PROTO_MAP.get(conn.family, str(conn.family))
            status = conn.status if conn.status else "NONE"
            pid = conn.pid

            # Attempt to resolve process_instance_id
            process_instance_id = None
            if pid:
                identity = get_process_identity(pid)
                if identity:
                    process_instance_id = build_process_instance_id(
                        endpoint_id, pid, identity["creation_time"]
                    )

            event_dict = {
                "endpoint_id": endpoint_id,
                "timestamp": now,
                "process_instance_id": process_instance_id,
                "source_ip": local_addr,
                "source_port": local_port,
                "dest_ip": remote_addr,
                "dest_port": remote_port,
                "protocol": proto,
                "data_direction": "OUTBOUND" if remote_addr else "LISTEN",
                "bytes_transferred": 0,  # psutil does not expose per-connection bytes
            }
            events_stored.append(event_dict)

            if store:
                rec = NetworkEvent(**event_dict)
                db.add(rec)

        except Exception as e:
            logger.debug(f"[NetworkCollector] Skipped connection entry: {e}")
            continue

    if store and events_stored:
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error(f"[NetworkCollector] DB commit failed: {e}")

    return {
        "status": NETWORK_MONITORING_AVAILABLE,
        "events_collected": len(events_stored),
        "snapshot_time": now.isoformat(),
        "events": events_stored[:10],  # return sample
    }


def get_recent_network_events(
    db: Session,
    endpoint_id: str,
    limit: int = 50,
) -> List[dict]:
    """
    Retrieves stored NetworkEvent records for an endpoint from DB.
    """
    records = (
        db.query(NetworkEvent)
        .filter(NetworkEvent.endpoint_id == endpoint_id)
        .order_by(NetworkEvent.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "process_instance_id": r.process_instance_id,
            "local_address": r.source_ip,
            "local_port": r.source_port,
            "remote_address": r.dest_ip,
            "remote_port": r.dest_port,
            "protocol": r.protocol,
            "status": r.data_direction,
        }
        for r in records
    ]


class NetworkTelemetryCollector:
    def __init__(self):
        self.status = NETWORK_MONITORING_AVAILABLE

    def collect_active_connections(self) -> list:
        res = check_network_monitoring_available()
        if res["status"] == NETWORK_MONITORING_UNAVAILABLE:
            self.status = NETWORK_MONITORING_UNAVAILABLE
            return []
        try:
            conns = psutil.net_connections(kind="all")
            events = []
            for c in conns:
                events.append({
                    "pid": c.pid,
                    "local_address": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote_address": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status
                })
            return events
        except Exception:
            self.status = NETWORK_MONITORING_UNAVAILABLE
            return []

