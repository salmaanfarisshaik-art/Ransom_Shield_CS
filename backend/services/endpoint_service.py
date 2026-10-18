"""
RansomShield Endpoint Management Service
Handles registration, heartbeat processing, status management, and metrics recording.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models.entities import Endpoint, EndpointHeartbeatRecord, AuditLogRecord

logger = logging.getLogger(__name__)

# In-memory status store
endpoints_registry: Dict[str, Dict[str, Any]] = {}

class EndpointService:

    @staticmethod
    def register_endpoint(
        db: Session,
        endpoint_id: str = "local-host-01",
        hostname: str = "Test-VM",
        os_version: str = "Windows 10",
        agent_version: str = "2.5.0",
        ip_address: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Registers an endpoint or updates its registration timestamp."""
        now = datetime.utcnow()

        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == endpoint_id).first()
        if not ep:
            ep = Endpoint(
                endpoint_id=endpoint_id,
                hostname=hostname,
                os="Windows",
                os_version=os_version,
                agent_version=agent_version,
                ip_address=ip_address,
                status="ONLINE",
                last_seen=now,
                registration_time=now,
                health_status="HEALTHY"
            )
            db.add(ep)
        else:
            ep.hostname = hostname
            ep.os_version = os_version
            ep.agent_version = agent_version
            ep.ip_address = ip_address
            ep.last_seen = now
            if ep.status not in ("ISOLATED", "CONTAINED"):
                ep.status = "ONLINE"

        audit = AuditLogRecord(
            actor="AGENT",
            role="SYSTEM",
            action="ENDPOINT_REGISTERED",
            target=endpoint_id,
            result="SUCCESS"
        )
        db.add(audit)
        db.commit()

        ep_dict = {
            "endpoint_id": endpoint_id,
            "hostname": hostname,
            "os": os_version,
            "agent_version": agent_version,
            "ip_address": ip_address,
            "status": ep.status,
            "isolated": ep.status in ("ISOLATED", "CONTAINED", "isolated"),
            "last_seen": now.isoformat()
        }
        endpoints_registry[endpoint_id] = ep_dict
        logger.info(f"Registered endpoint {endpoint_id} ({hostname})")
        return ep_dict

    @staticmethod
    def record_heartbeat(
        db: Session,
        endpoint_id: str,
        cpu_percent: float = 0.0,
        ram_percent: float = 0.0,
        disk_usage: float = 0.0,
        network_kbps: float = 0.0,
        agent_status: str = "ONLINE"
    ) -> Dict[str, Any]:
        """Records periodic telemetry heartbeat from an endpoint agent."""
        now = datetime.utcnow()

        ep = db.query(Endpoint).filter(Endpoint.endpoint_id == endpoint_id).first()
        if ep:
            ep.last_seen = now
            if ep.status not in ("ISOLATED", "CONTAINED"):
                ep.status = agent_status
            db.commit()

        hb_rec = EndpointHeartbeatRecord(
            endpoint_id=endpoint_id,
            timestamp=now,
            cpu_percent=cpu_percent,
            ram_percent=ram_percent,
            disk_usage=disk_usage,
            network_kbps=network_kbps,
            agent_status=agent_status
        )
        db.add(hb_rec)
        db.commit()

        if endpoint_id in endpoints_registry:
            endpoints_registry[endpoint_id]["last_seen"] = now.isoformat()
            endpoints_registry[endpoint_id]["cpu"] = cpu_percent
            endpoints_registry[endpoint_id]["ram"] = ram_percent

        return {
            "endpoint_id": endpoint_id,
            "timestamp": now.isoformat(),
            "status": ep.status if ep else agent_status,
            "cpu_percent": cpu_percent,
            "ram_percent": ram_percent
        }
