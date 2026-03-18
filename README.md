# RETRO-OLLAMA - Pentesting AI Tool

**Autonomous Pentesting AI powered by Local AI Models (Ollama, LM Studio, Llama.cpp)**

```
   ───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄
──▌▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▀▄
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐ ▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▒█
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌
────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀

  [ RETRO-OLLAMA ]   Pentesting AI Tool
============================================================
        +++ Powered by Local AI Models +++
        (Ollama, LM Studio, Llama.cpp)
```

Herramienta CLI de pentesting con IA local y agente autónomo mejorado, con múltiples modos de operación especializados, comandos específicos por modo, capacidades de ejecución automática e investigación web.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-green)

## Características Principales

### 🤖 Agente Autónomo Mejorado

El agente ahora tiene capacidad de pensamiento autónomo y ejecución automática:

```
Usuario: "dime los dispositivos en mi red"
Agente: 
  [*] Red: 10.47.89.0/24
  [+] Host activos encontrados:
     10.47.89.1 - ACTIVE
     10.47.89.170 - ACTIVE (DC-56-7B-FA-42-C1)
```

**Motor de razonamiento:**
- Análisis de intención automático
- Selección de herramientas inteligente
- Workflows predefinidos (recon, vuln_assess, web_assess, full_pentest)
- Pensamiento paso a paso
- Descubrimiento de red automático
- Investigación web automática
- Mejora de código con memoria

**Comandos del Agente:**
```bash
/agent dime los dispositivos en mi red    # Escaneo de red
/agent busca como hacer un reverse shell   # Investigación web
/agent mejora este script                  # Mejora código
/agent que dispositivos tengo en mi red    # Descubrimiento hosts
```

### Sistema de Modos Especializados

17+ modos diferentes para cubrir todas las necesidades de seguridad:

| Comando | Modo | Icono | Descripción |
|---------|------|-------|-------------|
| `/mode autonomous` | Autonomous | 🤖 | Agente autónomo - Investigación, mejora código |
| `/mode pentester` | Pentester | ⚔️ | Ataque, vulnerabilidades, exploits |
| `/mode blue` | Blue Team | 🛡️ | Defensa, malware, hardening, SIEM |
| `/mode osint` | OSINT | 🔍 | Investigación, dorks, emails |
| `/mode forense` | Forense | 🔎 | Análisis forense, memory, disk |
| `/mode bugbounty` | Bug Bounty | 🎯 | Bug hunting, recon, reporting |
| `/mode redteam` | Red Team | 🎭 | APT simulation, pivoting |
| `/mode vulnassessment` | Vuln Assessment | 📊 | CVSS, evaluación, remediación |
| `/mode network` | Network | 🌐 | Firewalls, segmentación |
| `/mode webapp` | Web App | 🌍 | OWASP Top 10, inyecciones |
| `/mode social` | Social Engineering | 🎣 | Phishing, awareness |
| `/mode devsecops` | DevSecOps | ⚙️ | CI/CD security, SAST, DAST |
| `/mode malware` | Malware | 🦠 | Análisis malware, sandbox |
| `/mode iot` | IoT | 📡 | Seguridad IoT, protocolos |
| `/mode cloud` | Cloud | ☁️ | AWS, Azure, GCP security |
| `/mode mobile` | Mobile | 📱 | Android/iOS security |
| `/mode compliance` | Compliance | 📋 | HIPAA, PCI-DSS, ISO27001 |

### IA Autónoma con NLP

La IA detecta automáticamente lo que necesitas:

```
"escanea 192.168.1.1"           → Escaneo automático
"busca vulnerabilidades en X"    → Vuln scan
"haz un pentest a empresa.com"   → Workflow completo
"genera reverse shell python"   → Genera payload
"analiza estos resultados"       → Análisis automático
```

## Instalación

```bash
# Clonar e instalar dependencias
git clone https://github.com/tu-repo/RETRO-Ollama.git
cd RETRO-Ollama
pip install -r requirements.txt

# Configurar API keys (opcional)
export SHODAN_API_KEY="tu_key"
export VIRUSTOTAL_API_KEY="tu_key"
export HUNTER_API_KEY="tu_key"

# Ejecutar
python main.py
```

## Uso

```bash
# Iniciar la herramienta
python main.py

# Seleccionar backend (1=Ollama, 2=LM Studio, 3=Llama.cpp)
# Seleccionar modelo

# Cambiar modo
/mode autonomous

# Ver ayuda
/help
```

## Comandos por Categoría

### Modos
```bash
/mode              # Ver modo actual
/mode autonomous  # Cambiar a modo autónomo
/modes             # Listar todos los modos
/mode pentester   # Cambiar a modo pentester
/mode blue        # Cambiar a modo blue team
# ... y muchos más
```

### Agente Autónomo (Nuevo!)
```bash
/agent <tarea>           # Ejecutar tarea autónoma
/agent dime los dispositivos en mi red    # Descubrir hosts
/agent busca como hacer un reverse shell  # Investigar
/agent mejora este código                # Mejorar código
/workflow <nombre> <target>  # Ejecutar workflow
/status              # Ver estado del agente
/reset               # Resetear memoria
/summary             # Resumen de actividad
```

### Escaneos Automáticos
```bash
/scan <target>       # Escaneo rápido (Nmap)
/full <target>       # Escaneo completo
/vuln <target>      # Vulnerabilidades
/web <target>        # Escaneo web
/dir <target>       # Directorios
/stealth <target>   # Escaneo sigiloso
/os <target>        # Detección SO
/autopwn <target>   # Pentest automático
/fullpentest <target> # Pentest completo
```

### Enumeración
```bash
/enum <target>       # Enumeración completa
/dns <target>        # DNS enumeration
/subdomain <target>  # Subdominios
```

### OSINT APIs
```bash
/shodan <IP>        # Shodan lookup
/virus <domain>     # VirusTotal
/hunter <domain>    # Buscar emails
/crt <domain>       # Certificados SSL
/whois <domain>     # Whois lookup
```

### Compliance & Security
```bash
/compliance <tipo>  # Verificar compliance (cis, owasp, pci, nist)
/ioc <texto>        # Extraer IOCs de texto
/threat <tipo>      # Clasificar amenazas
/headers <domain>  # Verificar security headers
```

### Incident Response
```bash
/incident <tipo>    # Crear incidente de respuesta
/ir-steps <tipo>   # Ver pasos de respuesta
/escalate <severidad> # Info de escalamiento
```

### CVE & Exploits
```bash
/cve <id>           # Buscar CVE
/cve <keyword>      # Buscar por keyword
/recent             # Últimos exploits
/cveupdate          # Actualizar base de datos
/vuln-db            # Ver base de datos de vulnerabilidades
```

### Generación de Código
```bash
/code <tipo>        # Generar código
/shell <tipo>      # Generar shells
/payload <tipo>    # Generar payloads
```

### Sistema
```bash
/run <comando>      # Ejecutar comando
/exec <tool> <args> # Ejecutar herramienta
/search <término>  # Buscar en Exploit-DB
/report <target>    # Generar reporte
/tools              # Listar herramientas
```

### Sesiones & Historial
```bash
/session <nombre>   # Crear sesión
/resume <nombre>   # Continuar sesión
/history            # Ver historial
/files              # Archivos generados
```

### Comandos por Modo

**Pentester:**
```bash
/exploit <target>   # Buscar y ejecutar exploits
/pwn <target>       # Comprometer objetivo
/shell <tipo>       # Generar shells
/lateral <target>   # Movimiento lateral
/pivot <target>    # Pivoting
```

**Blue Team:**
```bash
/detect <target>   # Detectar amenazas
/harden <target>   # Hardening
/siem <dato>       # Integrar SIEM
/incident <tipo>   # Respuesta a incidentes
/hunt              # Threat hunting
```

**OSINT:**
```bash
/dorks <domain>    # Google Dorks
/emails <domain>   # Harvesting emails
/social <target>   # Social media OSINT
/footprints <target> # Huellas digitales
```

**WebApp:**
```bash
/inject <target>   # Testing inyecciones
/xss <target>      # XSS testing
/sql <target>      # SQL Injection
/auth <target>     # Testing autenticación
```

**Forense:**
```bash
/memory <file>     # Análisis de memoria
/disk <file>       # Análisis de disco
/timeline <case>   # Crear timeline
/artefacts <type>  # Analizar artefactos
```

**BugBounty:**
```bash
/reconauto <target> # Recon automatizado
/subdomain <domain> # Subdomain enum
/tech <target>      # Detección tecnologías
/reporting <target> # Generar reporte
```

## Sistema de Skills

El sistema de skills permite cargar y ejecutar skills/plugins personalizados:

```bash
/skills              # Listar todos los skills
/skills <nombre>    # Ver detalle de un skill
```

**Skills disponibles:**
- network_scan - Advanced Nmap scanning
- web_enum - Web enumeration
- vuln_detect - Vulnerability detection
- osint_collect - OSINT collection
- exploit_search - Exploit search
- code_gen - Code generation
- report_gen - Report generation
- cloud_audit - Cloud security auditing
- mobile_audit - Mobile app auditing
- malware_analysis - Malware analysis

## Sistema de Workflows

Los workflows permiten encadenar múltiples herramientas:

```bash
/workflow <nombre>   # Listar workflows
/workflow recon target.com  # Ejecutar workflow
```

**Workflows disponibles:**
- recon - Complete reconnaissance
- quick_recon - Quick reconnaissance
- vuln_assess - Vulnerability assessment
- web_assess - Web application assessment
- full_pentest - Full PTES pentest
- stealth_scan - Evasion scan
- osint - OSINT collection

## Nuevos Módulos

### compliance.py - Compliance & Auditoría
- **CIS Benchmarks**: Verificaciones de seguridad Linux/Windows
- **OWASP Top 10**: Security headers y configuración
- **PCI-DSS**: Requisitos de tarjeta de pago
- **NIST**: Framework de ciberseguridad

### threat_intel.py - Threat Intelligence
- Extracción automática de IOCs (IPs, domains, emails, hashes)
- Clasificación de amenazas
- Reputación de IPs
- Patrones de malware

### incident_response.py - Incident Response
- Workflows de respuesta a incidentes
- Tipos: malware, phishing, ransomware, breach
- Pasos de remediación
- Escalamiento por severidad

### metrics.py - Métricas de Seguridad
- Recopilación de métricas
- Dashboard de hallazgos
- Tracking de escaneos

### vuln_db.py - Vulnerability Database
- Base de datos de vulnerabilidades conocidas
- CVSS scoring
- Referencias y exploits disponibles

## Detección Automática de Intenciones

El sistema detecta automáticamente más de 30 tipos de intenciones:

| Palabras clave | Acción |
|----------------|--------|
| escanea, scan, analiza | scan |
| vuln, vulnerability, exploit | vuln |
| web, http, sitio | web |
| directorio, dir, carpeta | dir |
| completo, full, exhaustivo | full |
| stealth, evasion, sigiloso | stealth |
| whois, registro, dueño | whois |
| subdomain, subdominio | subdomain |
| shodan, dispositivos | shodan |
| virustotal, malware | virustotal |
| email, hunter | hunter |
| genera, create, make, code | generate |
| analiza, analyze | analyze |

## Herramientas de Pentesting

### Reconocimiento
- nmap, whatweb, theHarvester
- dnsenum, sublist3r, amass
- subfinder, assetfinder, findomain

### Scanning
- nikto, sqlmap, dirb
- gobuster, commix, wpscan
- nuclei, XSStrike, feroxbuster

### Explotación
- hydra, searchsploit, msfconsole
- msfvenom, john, hashcat
- responder, impacket, pwntools

### Post-Explotación
- mimikatz, linpeas, winpeas
- pspy, gtfobins, lolbas

## Configuración de API Keys

```bash
# Linux/Mac
export SHODAN_API_KEY="tu_api_key"
export VIRUSTOTAL_API_KEY="tu_api_key"
export HUNTER_API_KEY="tu_api_key"
export CENSYS_API_KEY="tu_api_key"
export SECURITYTRAILS_API_KEY="tu_api_key"

# Windows (PowerShell)
$env:SHODAN_API_KEY="tu_api_key"
```

## Estructura del Proyecto

```
RETRO-OLLAMA/
├── src/
│   ├── ai/
│   │   ├── agent.py          # Agente autónomo mejorado
│   │   ├── backends/        # Multi-backend (Ollama, LM Studio, Llama.cpp)
│   │   ├── prompts.py       # System prompts
│   │   ├── skills.py        # Sistema de skills ★ NEW
│   │   └── workflows.py     # Sistema de workflows ★ NEW
│   ├── cli_app.py           # Main CLI app
│   ├── config/
│   │   ├── settings.py      # Configuración
│   │   └── config.py        # Pydantic config
│   ├── modes/
│   │   ├── mode_manager.py  # Mode manager (17+ modes)
│   │   └── prompts.py       # Mode prompts
│   ├── reports/             # Report generator
│   └── tools/
│       ├── apis.py          # OSINT APIs
│       ├── compliance.py    # Compliance checking
│       ├── cve.py           # CVE lookup
│       ├── incident_response.py # Incident Response
│       ├── metrics.py       # Security metrics
│       ├── pentest.py       # Pentest tools
│       ├── security.py      # Security functions
│       ├── system.py        # System functions
│       ├── threat_intel.py # Threat intelligence
│       ├── vuln_db.py       # Vulnerability database
│       └── ...
├── tests/                   # Test suite
├── .github/workflows/       # CI/CD
├── Dockerfile
├── OBJECTIVES.md           # Plan de desarrollo ★ NEW
└── README.md
└── README.md
```

## Modelos Recomendados

| Modelo | Tamaño | Uso recomendado |
|--------|--------|-----------------|
| pentest_ai | Custom | Pentesting especializado |
| dolphin-mixtral | 24GB | Mejor para código |
| llama3.2 | 4GB | Uso general |
| qwen3-coder | Variable | Generación de código |
| mistral | 4GB | Rápido |

## Docker

```bash
# Build
docker build -t ptai .

# Run
docker run -it -v $(pwd):/app ptai
```

## Testing

```bash
# Ejecutar tests
pytest tests/ -v

# Tests específicos
pytest tests/test_security.py -v
pytest tests/test_compliance.py -v
```

## Interfaz CLI Mejorada

La interfaz ahora tiene un diseño profesional con banner Skull ASCII:

```
   ───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄
──▌▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▀▄
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐ ▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▒█
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌
────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀

  [ Autonomous ]   Agente autónomo - Pensamiento, ejecución automática
============================================================
        +++ Powered by Local AI Models +++
        (Ollama, LM Studio, Llama.cpp)

╭──────────────────────────────────────────────────────── MODO ACTUAL ────────────────────────────────────────────────────────╮
│  Mode: Pentester   |   Model: pentest_ai   |   Output:                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

>> [⚔️ Pentester]: /scan 192.168.1.1
>> [⚔️ Pentester]: /mode autonomous
>> [🤖 Autonomous]: /agent dime los dispositivos en mi red
```

## Changelog v2.0

### Nuevas funcionalidades:
- 🤖 Agente autónomo con investigación web
- 🔍 Descubrimiento automático de red local
- 💾 Mejora de código con memoria
- 🎨 Banner Skull ASCII profesional
- 🎯 17+ modos especializados
- 📦 Sistema de skills
- 🔄 Sistema de workflows
- 🌐 Compatible Windows/Linux/Mac
██████╗ ███████╗████████╗██████╗  ██████╗ 
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗
██████╔╝█████╗     ██║   ██████╔╝██║   ██║
██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║
██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝

        PENTESTING AI TOOL   Powered by Local AI Models

>> Mode: 🤖 Autonomous  |  Model: pentest_ai  |  Output: ./output

>> SCANS                        >> GENERATION
   /scan <target>    Quick nmap      /code <desc>   Generate code
   /vuln <target>    Vuln scan       /shell <type>  Generate shell
   
>> HELP: /help /modes /history /files /session /exit
```

## Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## Licencia

MIT License - Uso educativo y profesional.

---

**Nota**: Esta herramienta es para uso educativo y profesional. Asegúrate de tener permiso antes de realizar cualquier prueba de seguridad en sistemas que no te pertenezcan.

**Autor**: RETRO-Ollama Team
**Versión**: 2.0
