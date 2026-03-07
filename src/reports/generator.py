from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from jinja2 import Template
from src.config.settings import REPORTS_DIR

WEASYPRINT_AVAILABLE = False
try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except Exception:
    pass

REPORT_TEMPLATE = """# Reporte de Pentesting

## Información General

- **Fecha:** {{ date }}
- **Target:** {{ target }}
- **Tipo de Evaluación:** {{ assessment_type }}
- **Herramienta:** PTAI

---

## Resumen Ejecutivo

{{ executive_summary }}

---

## Alcance

- **Objetivos evaluados:** {{ scope }}
- **Técnicas utilizadas:** {{ techniques }}

---

## Hallazgos

{% for finding in findings %}
### {{ loop.index }}. {{ finding.title }}

**Severidad:** {{ finding.severity }}
**Descripción:** {{ finding.description }}

{% if finding.evidence %}
**Evidencia:**
```
{{ finding.evidence }}
```
{% endif %}

{% if finding.remediation %}
**Remediación:** {{ finding.remediation }}
{% endif %}

{% if finding.references %}
**Referencias:** {{ finding.references }}
{% endif %}

---

{% endfor %}

## Conclusiones

{{ conclusions }}

---

## Recomendaciones

{{ recommendations }}

---

*Reporte generado por PTAI - Pentesting AI Tool*
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Pentesting - {{ target }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { background: linear-gradient(135deg, #FF6B35, #ff8c5a); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { color: #fff; font-size: 2em; }
        h2 { color: #FF6B35; margin: 25px 0 15px; border-bottom: 2px solid #FF6B35; padding-bottom: 10px; }
        h3 { color: #00FF88; margin: 20px 0 10px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .info-box { background: #16213e; padding: 15px; border-radius: 8px; border-left: 4px solid #FF6B35; }
        .info-box strong { color: #FF6B35; }
        .finding { background: #16213e; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #00FF88; }
        .finding.critical { border-left-color: #FF4757; }
        .finding.high { border-left-color: #FF6B35; }
        .finding.medium { border-left-color: #FFD93D; }
        .finding.low { border-left-color: #00FF88; }
        .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
        .severity.critical { background: #FF4757; }
        .severity.high { background: #FF6B35; }
        .severity.medium { background: #FFD93D; color: #1a1a2e; }
        .severity.low { background: #00FF88; color: #1a1a2e; }
        code { background: #0f0f23; padding: 2px 8px; border-radius: 4px; font-family: 'Cascadia Code', 'Consolas', monospace; }
        pre { background: #0f0f23; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; }
        .conclusions, .recommendations { background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }
        footer { text-align: center; margin-top: 40px; padding: 20px; color: #888; }
        .badge { background: #FF6B35; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Reporte de Pentesting</h1>
            <p>PTAI - Pentesting AI Tool</p>
        </header>
        
        <div class="info-grid">
            <div class="info-box"><strong>Fecha:</strong> {{ date }}</div>
            <div class="info-box"><strong>Target:</strong> {{ target }}</div>
            <div class="info-box"><strong>Tipo:</strong> {{ assessment_type }}</div>
            <div class="info-box"><strong>Herramienta:</strong> PTAI</div>
        </div>
        
        <h2>Resumen Ejecutivo</h2>
        <p>{{ executive_summary }}</p>
        
        <h2>Alcance</h2>
        <p><strong>Objetivos:</strong> {{ scope }}</p>
        <p><strong>Técnicas:</strong> {{ techniques }}</p>
        
        {% if findings %}
        <h2>Hallazgos ({{ findings|length }})</h2>
        {% for finding in findings %}
        <div class="finding {{ finding.severity|lower }}">
            <h3>{{ loop.index }}. {{ finding.title }} <span class="severity {{ finding.severity|lower }}">{{ finding.severity }}</span></h3>
            <p><strong>Descripción:</strong> {{ finding.description }}</p>
            {% if finding.evidence %}
            <p><strong>Evidencia:</strong></p>
            <pre>{{ finding.evidence }}</pre>
            {% endif %}
            {% if finding.remediation %}
            <p><strong>Remediación:</strong> {{ finding.remediation }}</p>
            {% endif %}
            {% if finding.references %}
            <p><strong>Referencias:</strong> {{ finding.references }}</p>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
        
        <h2>Conclusiones</h2>
        <div class="conclusions">{{ conclusions }}</div>
        
        <h2>Recomendaciones</h2>
        <div class="recommendations">{{ recommendations }}</div>
        
        <footer>
            <p>Reporte generado por PTAI - Pentesting AI Tool</p>
        </footer>
    </div>
</body>
</html>"""


def generate_report(
    target: str,
    findings: List[Dict],
    assessment_type: str = "Pentesting",
    scope: str = "",
    techniques: Optional[List[str]] = None,
    executive_summary: str = "",
    conclusions: str = "",
    recommendations: str = "",
    format: str = "markdown"
) -> Path:
    if techniques is None:
        techniques = ["Nmap", "Nikto", "Análisis manual"]
    else:
        techniques = techniques or ["Nmap", "Nikto", "Análisis manual"]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = "html" if format == "html" else "md"
    filename = f"report_{target}_{timestamp}.{ext}"
    filepath = REPORTS_DIR / filename
    
    if format == "html":
        template = Template(HTML_TEMPLATE)
        ext = "html"
    else:
        template = Template(REPORT_TEMPLATE)
        ext = "md"
    
    content = template.render(
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        assessment_type=assessment_type,
        scope=scope,
        techniques=", ".join(techniques),
        findings=findings,
        executive_summary=executive_summary or "Se realizó una evaluación de seguridad en los objetivos especificados.",
        conclusions=conclusions or "La evaluación reveló hallazgos que deben ser atendidos.",
        recommendations=recommendations or "Se recomienda revisar los hallazgos y aplicar las remediaciones sugeridas."
    )
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    
    return filepath


def create_quick_report(target: str, scan_results: Dict, tool_name: str) -> Path:
    findings = []
    
    output = scan_results.get("output", "")
    if "VULNERABLE" in output.upper() or "EXPOSED" in output.upper():
        findings.append({
            "title": f"Posible vulnerabilidad detectada por {tool_name}",
            "severity": "Media",
            "description": f"El escaneo con {tool_name} detectó posibles problemas.",
            "evidence": output[:1000],
            "remediation": "Revisar el resultado completo y validar manualmente.",
            "references": ""
        })
    
    return generate_report(
        target=target,
        findings=findings,
        assessment_type="Escaneo automático",
        scope=target,
        executive_summary=f"Escaneo automático realizado con {tool_name}.",
        conclusions=f"Se encontraron {len(findings)} posibles hallazgos.",
        recommendations="Validar manualmente los hallazgos encontrados."
    )


def generate_pdf_report(
    target: str,
    findings: List[Dict],
    assessment_type: str = "Pentesting",
    scope: str = "",
    techniques: Optional[List[str]] = None,
    executive_summary: str = "",
    conclusions: str = "",
    recommendations: str = ""
) -> Optional[Path]:
    global WEASYPRINT_AVAILABLE
    if not WEASYPRINT_AVAILABLE:
        try:
            import weasyprint
            WEASYPRINT_AVAILABLE = True
        except Exception:
            print("weasyprint no está disponible. Instala GTK3 para Windows o usa PDF en Linux.")
            return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{target}_{timestamp}.pdf"
    filepath = REPORTS_DIR / filename
    
    template = Template(HTML_TEMPLATE)
    
    content = template.render(
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=target,
        assessment_type=assessment_type,
        scope=scope,
        techniques=", ".join(techniques) if techniques else "Nmap, Nikto, Análisis manual",
        findings=findings,
        executive_summary=executive_summary or "Se realizó una evaluación de seguridad en los objetivos especificados.",
        conclusions=conclusions or "La evaluación reveló hallazgos que deben ser atendidos.",
        recommendations=recommendations or "Se recomienda revisar los hallazgos y aplicar las remediaciones sugeridas."
    )
    
    import weasyprint
    html_doc = weasyprint.HTML(string=content)
    html_doc.write_pdf(filepath)
    
    return filepath


def create_pdf_report(target: str, scan_results: Dict, tool_name: str) -> Optional[Path]:
    findings = []
    
    output = scan_results.get("output", "")
    if "VULNERABLE" in output.upper() or "EXPOSED" in output.upper():
        findings.append({
            "title": f"Posible vulnerabilidad detectada por {tool_name}",
            "severity": "Media",
            "description": f"El escaneo con {tool_name} detectó posibles problemas.",
            "evidence": output[:1000],
            "remediation": "Revisar el resultado completo y validar manualmente.",
            "references": ""
        })
    
    return generate_pdf_report(
        target=target,
        findings=findings,
        assessment_type="Escaneo automático",
        scope=target,
        executive_summary=f"Escaneo automático realizado con {tool_name}.",
        conclusions=f"Se encontraron {len(findings)} posibles hallazgos.",
        recommendations="Validar manualmente los hallazgos encontrados."
    )
