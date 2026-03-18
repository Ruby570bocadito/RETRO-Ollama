import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.incident_response import (
    Incident,
    IncidentResponse,
    create_incident,
    get_incident_types,
    INCIDENT_TYPES,
    SEVERITY_LEVELS
)


class TestIncident:
    """Tests para Incident"""

    def test_incident_creation(self):
        """Crear incidente"""
        incident = Incident("Test", "malware_infection", "Description")
        assert incident.title == "Test"
        assert incident.incident_type == "malware_infection"
        assert incident.status == "open"

    def test_incident_id_format(self):
        """Formato de ID"""
        incident = Incident("Test", "phishing_attack", "Desc")
        assert "INC-" in incident.id

    def test_add_evidence(self):
        """Añadir evidencia"""
        incident = Incident("Test", "malware_infection", "Desc")
        incident.add_evidence("Malware sample captured")
        assert len(incident.evidence) == 1

    def test_add_note(self):
        """Añadir nota"""
        incident = Incident("Test", "malware_infection", "Desc")
        incident.add_note("Investigating", "John")
        assert len(incident.notes) == 1
        assert incident.notes[0]["author"] == "John"

    def test_update_status(self):
        """Actualizar estado"""
        incident = Incident("Test", "malware_infection", "Desc")
        incident.update_status("closed")
        assert incident.status == "closed"

    def test_assign(self):
        """Asignar analista"""
        incident = Incident("Test", "malware_infection", "Desc")
        incident.assign("Analyst1")
        assert incident.assigned_to == "Analyst1"

    def test_to_dict(self):
        """Convertir a dict"""
        incident = Incident("Test", "phishing_attack", "Desc")
        data = incident.to_dict()
        assert "id" in data
        assert "title" in data
        assert "status" in data


class TestIncidentResponse:
    """Tests para IncidentResponse"""

    def test_create_incident(self):
        """Crear incidente"""
        ir = IncidentResponse()
        incident = ir.create_incident("Test", "malware_infection", "Test description")
        assert incident.id in ir.incidents

    def test_create_invalid_type(self):
        """Tipo inválido"""
        ir = IncidentResponse()
        with pytest.raises(ValueError):
            ir.create_incident("Test", "invalid_type", "Desc")

    def test_get_incident(self):
        """Obtener incidente"""
        ir = IncidentResponse()
        incident = ir.create_incident("Test", "phishing_attack", "Desc")
        retrieved = ir.get_incident(incident.id)
        assert retrieved is not None
        assert retrieved.id == incident.id

    def test_list_incidents(self):
        """Listar incidentes"""
        ir = IncidentResponse()
        ir.create_incident("Test1", "phishing_attack", "Desc1")
        ir.create_incident("Test2", "malware_infection", "Desc2")
        incidents = ir.list_incidents()
        assert len(incidents) == 2

    def test_list_by_status(self):
        """Listar por estado"""
        ir = IncidentResponse()
        inc = ir.create_incident("Test", "phishing_attack", "Desc")
        inc.update_status("closed")
        closed = ir.list_incidents(status="closed")
        assert len(closed) == 1

    def test_list_by_severity(self):
        """Listar por severidad"""
        ir = IncidentResponse()
        ir.create_incident("Test", "ransomware", "Desc")
        critical = ir.list_incidents(severity="critical")
        assert len(critical) >= 1

    def test_get_response_steps(self):
        """Pasos de respuesta"""
        ir = IncidentResponse()
        steps = ir.get_response_steps("ransomware")
        assert len(steps) > 0
        assert "Aislar" in steps[0]

    def test_get_severity_info(self):
        """Info de severidad"""
        ir = IncidentResponse()
        info = ir.get_severity_info("critical")
        assert info["response_time"] == "1 hour"

    def test_generate_report(self):
        """Generar reporte"""
        ir = IncidentResponse()
        incident = ir.create_incident("Test", "phishing_attack", "Test desc")
        report = ir.generate_incident_report(incident.id)
        assert "Incident Report" in report
        assert incident.id in report


class TestIncidentTypes:
    """Tests para tipos de incidentes"""

    def test_incident_types_exist(self):
        """Tipos existen"""
        assert "ransomware" in INCIDENT_TYPES
        assert "phishing_attack" in INCIDENT_TYPES
        assert "data_breach" in INCIDENT_TYPES

    def test_all_have_severity(self):
        """Todos tienen severidad"""
        for inc_type, data in INCIDENT_TYPES.items():
            assert "severity" in data
            assert "steps" in data

    def test_severity_levels(self):
        """Niveles de severidad"""
        assert "critical" in SEVERITY_LEVELS
        assert "response_time" in SEVERITY_LEVELS["critical"]


class TestHelperFunctions:
    """Tests para funciones helper"""

    def test_create_incident_helper(self):
        """Función helper"""
        incident = create_incident("phishing_attack", "Test", "Desc")
        assert incident is not None

    def test_get_incident_types(self):
        """Obtener tipos"""
        types = get_incident_types()
        assert isinstance(types, list)
        assert len(types) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
