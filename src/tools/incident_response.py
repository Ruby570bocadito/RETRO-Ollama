from typing import Dict, List, Optional
from datetime import datetime
import json

INCIDENT_TYPES = {
    "malware_infection": {
        "severity": "critical",
        "steps": [
            "Aislar sistema infectado",
            "Recolectar muestra de malware",
            "Analizar comportamiento",
            "Identificar vector de infección",
            "Remover malware",
            "Restaurar desde backup limpio",
            "Monitorear"
        ]
    },
    "data_breach": {
        "severity": "critical",
        "steps": [
            "Confirmar brecha",
            "Contener propagación",
            "Identificar datos comprometidos",
            "Notificar autoridades (si aplica)",
            "Notificar afectados (si aplica)",
            "Remediar vulnerabilidad",
            "Documentar incidente"
        ]
    },
    "phishing_attack": {
        "severity": "high",
        "steps": [
            "Identificar emails de phishing",
            "Bloquear dominios/IPs maliciosas",
            "Revisar si credenciales fueron comprometidas",
            "Resetear contraseñas",
            "Educar usuarios",
            "Implementar filtros adicionales"
        ]
    },
    "ransomware": {
        "severity": "critical",
        "steps": [
            "Aislar sistemas afectados inmediatamente",
            "Identificar tipo de ransomware",
            "Verificar si hay decryptor disponible",
            "No pagar sin consultar",
            "Recolectar evidencia",
            "Restaurar desde backups",
            "Reportar a autoridades"
        ]
    },
    "unauthorized_access": {
        "severity": "high",
        "steps": [
            "Contener cuenta/sistema comprometido",
            "Revisar logs de acceso",
            "Identificar vector de ataque",
            "Resetear credenciales",
            "Implementar MFA",
            "Monitorear actividades"
        ]
    },
    "ddos_attack": {
        "severity": "medium",
        "steps": [
            "Verificar tráfico anómalo",
            "Contactar ISP/ proveedor",
            "Implementar mitigaciones",
            "Activar CDN/protección DDoS",
            "Documentar ataque"
        ]
    },
    "insider_threat": {
        "severity": "high",
        "steps": [
            "Investigar actividad sospechosa",
            "Documentar hallazgos",
            "Revocar accesos",
            "Coordinar con RRHH/Legal",
            "Implementar monitoreo"
        ]
    }
}

SEVERITY_LEVELS = {
    "critical": {"response_time": "1 hour", "escalation": "CISO + Executive"},
    "high": {"response_time": "4 hours", "escalation": "Security Manager"},
    "medium": {"response_time": "24 hours", "escalation": "Team Lead"},
    "low": {"response_time": "72 hours", "escalation": "Analyst"}
}

CONTACT_TEAM = {
    "security_analyst": "security@company.com",
    "soc_manager": "soc@company.com",
    "ciso": "ciso@company.com",
    "legal": "legal@company.com",
    "pr": "pr@company.com"
}


class Incident:
    def __init__(self, title: str, incident_type: str, description: str):
        self.id = f"INC-{datetime.now().strftime('%Y%m%d')}-{hash(title) % 10000:04d}"
        self.title = title
        self.incident_type = incident_type
        self.description = description
        self.status = "open"
        self.severity = INCIDENT_TYPES.get(incident_type, {}).get("severity", "medium")
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.assigned_to = None
        self.evidence = []
        self.notes = []
        self.timeline = []
    
    def add_evidence(self, evidence: str):
        self.evidence.append({
            "timestamp": datetime.now().isoformat(),
            "evidence": evidence
        })
        self.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Evidence added",
            "details": evidence
        })
    
    def add_note(self, note: str, author: str = "Analyst"):
        self.notes.append({
            "timestamp": datetime.now().isoformat(),
            "author": author,
            "note": note
        })
        self.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Note added",
            "author": author,
            "details": note
        })
    
    def update_status(self, status: str):
        self.status = status
        self.updated_at = datetime.now()
        self.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Status changed",
            "details": f"Status: {status}"
        })
    
    def assign(self, analyst: str):
        self.assigned_to = analyst
        self.updated_at = datetime.now()
        self.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Assigned",
            "details": f"Assigned to: {analyst}"
        })
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "type": self.incident_type,
            "description": self.description,
            "status": self.status,
            "severity": self.severity,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "assigned_to": self.assigned_to,
            "evidence": self.evidence,
            "notes": self.notes,
            "timeline": self.timeline
        }


class IncidentResponse:
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}
    
    def create_incident(self, title: str, incident_type: str, description: str) -> Incident:
        if incident_type not in INCIDENT_TYPES:
            raise ValueError(f"Invalid incident type: {incident_type}")
        
        incident = Incident(title, incident_type, description)
        self.incidents[incident.id] = incident
        
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "Incident created",
            "details": f"Type: {incident_type}, Severity: {incident.severity}"
        })
        
        return incident
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)
    
    def list_incidents(self, status: str = None, severity: str = None) -> List[Incident]:
        results = list(self.incidents.values())
        
        if status:
            results = [i for i in results if i.status == status]
        
        if severity:
            results = [i for i in results if i.severity == severity]
        
        return sorted(results, key=lambda x: x.created_at, reverse=True)
    
    def get_response_steps(self, incident_type: str) -> List[str]:
        return INCIDENT_TYPES.get(incident_type, {}).get("steps", [])
    
    def get_severity_info(self, severity: str) -> Dict:
        return SEVERITY_LEVELS.get(severity, {})
    
    def generate_incident_report(self, incident_id: str) -> str:
        incident = self.get_incident(incident_id)
        if not incident:
            return "Incident not found"
        
        steps = self.get_response_steps(incident.incident_type)
        severity_info = SEVERITY_LEVELS.get(incident.severity, {})
        
        report = f"""# Incident Report - {incident.id}

## Basic Information
- **Title**: {incident.title}
- **Type**: {incident.incident_type}
- **Severity**: {incident.severity.upper()}
- **Status**: {incident.status}
- **Created**: {incident.created_at.strftime('%Y-%m-%d %H:%M:%S')}
- **Updated**: {incident.updated_at.strftime('%Y-%m-%d %H:%M:%S')}
- **Assigned to**: {incident.assigned_to or 'Unassigned'}

## Description
{incident.description}

## Response Timeline
"""
        for entry in incident.timeline:
            report += f"- **{entry['timestamp']}**: {entry['action']} - {entry.get('details', '')}\n"
        
        report += f"""
## Recommended Response Steps
"""
        for i, step in enumerate(steps, 1):
            report += f"{i}. {step}\n"
        
        report += f"""
## Severity Response
- **Response Time**: {severity_info.get('response_time', 'N/A')}
- **Escalation**: {severity_info.get('escalation', 'N/A')}

## Evidence Collected
"""
        if incident.evidence:
            for ev in incident.evidence:
                report += f"- [{ev['timestamp']}] {ev['evidence']}\n"
        else:
            report += "No evidence collected yet.\n"
        
        report += f"""
## Notes
"""
        if incident.notes:
            for note in incident.notes:
                report += f"- [{note['timestamp']}] {note['author']}: {note['note']}\n"
        else:
            report += "No notes added.\n"
        
        return report


def create_incident(incident_type: str, title: str, description: str) -> Incident:
    """Función helper para crear incidente"""
    ir = IncidentResponse()
    return ir.create_incident(title, incident_type, description)


def get_incident_types() -> List[str]:
    """Lista tipos de incidentes"""
    return list(INCIDENT_TYPES.keys())
