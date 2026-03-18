"""Metrics and analytics for RETRO-Ollama."""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config.settings import BASE_DIR
from src.logging_config import get_logger

logger = get_logger("ptai.metrics")


@dataclass
class MetricEvent:
    """Metric event."""
    name: str
    value: float
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ScanMetric:
    """Scan metric."""
    target: str
    scan_type: str
    duration: float
    status: str
    findings_count: int = 0
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """Collects and stores metrics."""

    def __init__(self, metrics_file: Optional[Path] = None):
        self.metrics_file = metrics_file or (BASE_DIR / "metrics.json")
        self.events: List[MetricEvent] = []
        self.scan_metrics: List[ScanMetric] = []
        self._load()

    def _load(self) -> None:
        """Load metrics from file."""
        if self.metrics_file.exists():
            try:
                with open(self.metrics_file, "r") as f:
                    data = json.load(f)
                    self.events = [MetricEvent(**e) for e in data.get("events", [])]
                    self.scan_metrics = [ScanMetric(**s) for s in data.get("scans", [])]
            except Exception as e:
                logger.warning(f"Failed to load metrics: {e}")

    def _save(self) -> None:
        """Save metrics to file."""
        try:
            data = {
                "events": [
                    {"name": e.name, "value": e.value, "tags": e.tags, "timestamp": e.timestamp}
                    for e in self.events
                ],
                "scans": [
                    {
                        "target": s.target,
                        "scan_type": s.scan_type,
                        "duration": s.duration,
                        "status": s.status,
                        "findings_count": s.findings_count,
                        "timestamp": s.timestamp,
                    }
                    for s in self.scan_metrics
                ],
            }
            with open(self.metrics_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")

    def track_event(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Track an event."""
        event = MetricEvent(name=name, value=value, tags=tags or {})
        self.events.append(event)
        self._save()
        logger.debug(f"Tracked event: {name}={value}")

    def track_scan(
        self,
        target: str,
        scan_type: str,
        duration: float,
        status: str,
        findings_count: int = 0,
    ) -> None:
        """Track scan metric."""
        metric = ScanMetric(
            target=target,
            scan_type=scan_type,
            duration=duration,
            status=status,
            findings_count=findings_count,
        )
        self.scan_metrics.append(metric)
        self._save()
        logger.info(f"Tracked scan: {scan_type} on {target} - {status}")

    def get_events(self, name: Optional[str] = None, limit: int = 100) -> List[MetricEvent]:
        """Get events."""
        events = self.events
        if name:
            events = [e for e in events if e.name == name]
        return events[-limit:]

    def get_scan_metrics(
        self,
        scan_type: Optional[str] = None,
        days: Optional[int] = None,
        limit: int = 100,
    ) -> List[ScanMetric]:
        """Get scan metrics."""
        metrics = self.scan_metrics
        if scan_type:
            metrics = [m for m in metrics if m.scan_type == scan_type]
        if days:
            cutoff = time.time() - (days * 86400)
            metrics = [m for m in metrics if m.timestamp >= cutoff]
        return metrics[-limit:]

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        now = time.time()
        day_ago = now - 86400
        week_ago = now - 604800

        recent_scans = [s for s in self.scan_metrics if s.timestamp >= day_ago]
        week_scans = [s for s in self.scan_metrics if s.timestamp >= week_ago]

        total_scans = len(self.scan_metrics)
        successful_scans = len([s for s in self.scan_metrics if s.status == "success"])
        total_findings = sum(s.findings_count for s in self.scan_metrics)
        avg_duration = sum(s.duration for s in self.scan_metrics) / total_scans if total_scans > 0 else 0

        scan_types = {}
        for s in self.scan_metrics:
            scan_types[s.scan_type] = scan_types.get(s.scan_type, 0) + 1

        return {
            "total_scans": total_scans,
            "successful_scans": successful_scans,
            "failed_scans": total_scans - successful_scans,
            "total_findings": total_findings,
            "average_duration": round(avg_duration, 2),
            "scans_last_24h": len(recent_scans),
            "scans_last_7d": len(week_scans),
            "scan_types": scan_types,
            "success_rate": round((successful_scans / total_scans * 100) if total_scans > 0 else 0, 1),
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get dashboard data for visualization."""
        now = time.time()
        daily_scans = {}
        daily_findings = {}

        for i in range(7):
            day_start = now - ((i + 1) * 86400)
            day_end = now - (i * 86400)
            day_scans = [
                s for s in self.scan_metrics
                if day_start <= s.timestamp < day_end
            ]
            date_str = datetime.fromtimestamp(day_start).strftime("%Y-%m-%d")
            daily_scans[date_str] = len(day_scans)
            daily_findings[date_str] = sum(s.findings_count for s in day_scans)

        return {
            "daily_scans": dict(reversed(list(daily_scans.items()))),
            "daily_findings": dict(reversed(list(daily_findings.items()))),
            "summary": self.get_summary(),
        }

    def clear(self) -> None:
        """Clear all metrics."""
        self.events.clear()
        self.scan_metrics.clear()
        self._save()
        logger.info("Metrics cleared")


metrics_collector = MetricsCollector()


def track_scan_start(target: str, scan_type: str) -> float:
    """Track scan start and return start time."""
    start_time = time.time()
    logger.info(f"Starting scan: {scan_type} on {target}")
    return start_time


def track_scan_end(
    start_time: float,
    target: str,
    scan_type: str,
    status: str,
    findings_count: int = 0,
) -> float:
    """Track scan end and return duration."""
    duration = time.time() - start_time
    metrics_collector.track_scan(
        target=target,
        scan_type=scan_type,
        duration=duration,
        status=status,
        findings_count=findings_count,
    )
    return duration


def track_event(name: str, value: float = 1.0, **tags: str) -> None:
    """Track a custom event."""
    metrics_collector.track_event(name, value, tags)
