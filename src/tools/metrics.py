from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

class Metric:
    def __init__(self, name: str, value: float, category: str = "general"):
        self.name = name
        self.value = value
        self.category = category
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "category": self.category,
            "timestamp": self.timestamp.isoformat()
        }


class SecurityMetrics:
    def __init__(self):
        self.metrics: List[Metric] = []
        self.findings_by_severity: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        self.scans_by_type: Dict[str, int] = {}
        self.incidents_by_type: Dict[str, int] = {}
    
    def add_metric(self, name: str, value: float, category: str = "general"):
        metric = Metric(name, value, category)
        self.metrics.append(metric)
    
    def record_finding(self, severity: str):
        severity = severity.lower()
        if severity in self.findings_by_severity:
            self.findings_by_severity[severity] += 1
    
    def record_scan(self, scan_type: str):
        if scan_type not in self.scans_by_type:
            self.scans_by_type[scan_type] = 0
        self.scans_by_type[scan_type] += 1
    
    def record_incident(self, incident_type: str):
        if incident_type not in self.incidents_by_type:
            self.incidents_by_type[incident_type] = 0
        self.incidents_by_type[incident_type] += 1
    
    def get_risk_score(self) -> float:
        weights = {"critical": 10, "high": 7.5, "medium": 5, "low": 2.5, "info": 0}
        score = sum(
            count * weights.get(sev, 0) 
            for sev, count in self.findings_by_severity.items()
        )
        return round(score, 2)
    
    def get_total_findings(self) -> int:
        return sum(self.findings_by_severity.values())
    
    def get_summary(self) -> Dict:
        return {
            "total_findings": self.get_total_findings(),
            "findings_by_severity": self.findings_by_severity,
            "risk_score": self.get_risk_score(),
            "total_scans": sum(self.scans_by_type.values()),
            "scans_by_type": self.scans_by_type,
            "total_incidents": sum(self.incidents_by_type.values()),
            "incidents_by_type": self.incidents_by_type,
            "total_metrics": len(self.metrics)
        }
    
    def get_trend(self, days: int = 7) -> List[Dict]:
        cutoff = datetime.now() - timedelta(days=days)
        recent_metrics = [m for m in self.metrics if m.timestamp >= cutoff]
        
        trend = {}
        for metric in recent_metrics:
            date_key = metric.timestamp.strftime("%Y-%m-%d")
            if date_key not in trend:
                trend[date_key] = {"count": 0, "value": 0}
            trend[date_key]["count"] += 1
            trend[date_key]["value"] += metric.value
        
        return [
            {"date": date, "count": data["count"], "value": data["value"]}
            for date, data in sorted(trend.items())
        ]
    
    def export_json(self, filepath: str):
        data = {
            "summary": self.get_summary(),
            "findings_by_severity": self.findings_by_severity,
            "scans_by_type": self.scans_by_type,
            "incidents_by_type": self.incidents_by_type,
            "metrics": [m.to_dict() for m in self.metrics]
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
    
    def generate_dashboard_data(self) -> Dict:
        return {
            "summary": self.get_summary(),
            "risk_gauge": {
                "value": min(self.get_risk_score() / 100, 1.0),
                "label": self._get_risk_label()
            },
            "severity_distribution": self._get_severity_distribution(),
            "activity_timeline": self.get_trend(7),
            "top_scan_types": self._get_top_scan_types(5),
            "top_incident_types": self._get_top_incident_types(5)
        }
    
    def _get_risk_label(self) -> str:
        score = self.get_risk_score()
        if score >= 70:
            return "Crítico"
        elif score >= 50:
            return "Alto"
        elif score >= 30:
            return "Medio"
        elif score >= 10:
            return "Bajo"
        return "Mínimo"
    
    def _get_severity_distribution(self) -> Dict[str, float]:
        total = self.get_total_findings()
        if total == 0:
            return {}
        return {
            sev: round((count / total) * 100, 1)
            for sev, count in self.findings_by_severity.items()
        }
    
    def _get_top_scan_types(self, limit: int) -> List[Dict]:
        sorted_scans = sorted(
            self.scans_by_type.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        return [{"type": t, "count": c} for t, c in sorted_scans]
    
    def _get_top_incident_types(self, limit: int) -> List[Dict]:
        sorted_incidents = sorted(
            self.incidents_by_type.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        return [{"type": t, "count": c} for t, c in sorted_incidents]


security_metrics = SecurityMetrics()
