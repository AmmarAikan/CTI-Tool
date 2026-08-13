from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.internal.wazuh_connector import nested_value


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def source_ip(record: RawRecord) -> str:
    value = nested_value(
        record.raw_data,
        "data.srcip",
        "data.src_ip",
        "data.source.ip",
        "source.ip",
        "srcip",
        "src_ip",
        "data.win.eventdata.ipAddress",
        "agent.ip",
    )
    if value:
        return str(value)
    agent = nested_value(record.raw_data, "agent.id", "agent.name") or record.external_id
    return f"unknown:{agent}"


@dataclass(slots=True)
class InternalSession:
    session_id: str
    source_ip: str
    source_type: str
    source_name: str
    started_at: datetime
    ended_at: datetime
    records: list[RawRecord]

    @property
    def raw_alerts(self) -> list[dict[str, Any]]:
        return [record.raw_data for record in self.records]


class InternalSessionizer:
    def __init__(self, idle_minutes: int = 30) -> None:
        self.idle_timeout = timedelta(minutes=idle_minutes)

    def build_sessions(self, records: list[RawRecord]) -> list[InternalSession]:
        grouped: dict[tuple[str, str, str], list[tuple[datetime, RawRecord]]] = {}
        for record in records:
            timestamp = parse_timestamp(record.published_at or record.collected_at)
            key = (record.source_type, record.source_name, source_ip(record))
            grouped.setdefault(key, []).append((timestamp, record))

        sessions: list[InternalSession] = []
        for (source_type, source_name, ip_address), alerts in grouped.items():
            alerts.sort(key=lambda item: item[0])
            current: list[tuple[datetime, RawRecord]] = []
            for timestamp, record in alerts:
                if current and timestamp - current[-1][0] > self.idle_timeout:
                    sessions.append(self._create(source_type, source_name, ip_address, current))
                    current = []
                current.append((timestamp, record))
            if current:
                sessions.append(self._create(source_type, source_name, ip_address, current))
        return sorted(sessions, key=lambda item: (item.started_at, item.source_type, item.source_ip))

    def _create(
        self,
        source_type: str,
        source_name: str,
        ip_address: str,
        alerts: list[tuple[datetime, RawRecord]],
    ) -> InternalSession:
        started_at = alerts[0][0]
        ended_at = alerts[-1][0]
        # The start of a source session is stable while an append-only log grows.
        # Excluding end/count lets a later collection update the same database row.
        basis = f"{source_type}:{ip_address}:{started_at.isoformat()}"
        session_id = f"session-{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:24]}"
        return InternalSession(
            session_id=session_id,
            source_ip=ip_address,
            source_type=source_type,
            source_name=source_name,
            started_at=started_at,
            ended_at=ended_at,
            records=[item[1] for item in alerts],
        )


# Backward-compatible name retained for the original Wazuh-specific imports.
WazuhSessionizer = InternalSessionizer
