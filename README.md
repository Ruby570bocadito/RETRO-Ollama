# RETRO-OLLAMA - Asistente de Pentesting con IA Local

Herramienta CLI de pentesting con IA local (Ollama) y control autónomo del sistema, con múltiples modos de operación.

## Características Principales

### Sistema de Modos
Cambia entre diferentes modos según tu necesidad:

| Comando | Modo | Descripción |
|---------|------|-------------|
| `/mode pentester` | ⚔️ Pentester | Ataque, vulnerabilidades, exploits |
| `/mode blue` | 🛡️ Blue Team | Defensa, antivirus, hardening |
| `/mode osint` | 🔍 OSINT | Investigación, Whois, subdomains |
| `/mode forense` | 🔎 Forense | Análisis, disk, memory, artifacts |
| `/mode bugbounty` | 🎯 Bug Bounty | Bug hunting, recon, reporting |

### IA Autónoma con Control del Sistema
La IA tiene acceso a funciones reales del sistema y las ejecuta automáticamente:

| Función | Descripción |
|---------|-------------|
| Procesos | Lista procesos en ejecución |
| Carpetas | Explora cualquier directorio |
| Sistema | Información completa del PC |
| Red | Configuración de red e IPs |
| Servicios | Servicios de Windows |
| Disco | Espacio en disco |
| WSL | Ejecuta comandos en Linux |

### Detección Automática
La IA detecta lo que necesitas sin necesidad de comandos explícitos:
- "¿qué procesos hay?" → Ejecuta `get_processes()`
- "¿qué hay en C:/Users?" → Lista el directorio
- "¿qué información del sistema?" → Muestra specs
- "¿está nmap instalado?" → Verifica la herramienta

## Requisitos

- Python 3.8+
- Ollama instalado y ejecutándose
- Windows 10/11 o Linux (WSL recomendado)

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

```bash
# Iniciar la herramienta
python main.py

# Listar modelos disponibles
python main.py --list

# Especificar modelo
python main.py --model llama3.2

# Ejecutar comando directo
python main.py --cmd "nmap -V"
```

## Comandos

### Modos
- `/mode` - Ver modo actual
- `/mode <nombre>` - Cambiar modo (pentester, blue, osint, forense, bugbounty)
- `/modes` - Listar todos los modos

### Chat & IA
- `/help` - Mostrar ayuda
- `/models` - Listar modelos Ollama
- `/setmodel <nombre>` - Cambiar modelo activo

### Escaneos
- `/scan <target>` - Escaneo rápido (Nmap)
- `/full <target>` - Escaneo completo
- `/vuln <target>` - Escaneo de vulnerabilidades
- `/web <target>` - Escaneo web (Nikto, WhatWeb)
- `/dir <target>` - Escaneo de directorios
- `/stealth <target>` - Escaneo sigiloso (evasión)
- `/os <target>` - Detección de SO
- `/autopwn <target>` - Pentest automático
- `/fullpentest <target>` - Pentest completo

### Enumeración
- `/enum <target>` - Enumeración completa
- `/dns <target>` - Enumeración DNS
- `/subdomain <target>` - Buscar subdominios

### APIs OSINT
- `/shodan <IP>` - Consulta Shodan
- `/virus <domain>` - VirusTotal
- `/hunter <domain>` - Buscar emails
- `/crt <domain>` - Certificados SSL
- `/whois <domain>` - Whois lookup

### CVE & Exploits
- `/cve <id>` - Buscar CVE
- `/cve <keyword>` - Buscar por keyword
- `/recent` - Últimos exploits
- `/cveupdate` - Actualizar base de datos

### Archivos & Código
- `/files` - Listar archivos generados
- `/code <tipo>` - Generar código
- `/shell <tipo>` - Generar shells
- `/payload <tipo>` - Generar payloads

### Ejecución
- `/run <comando>` - Ejecutar comando del sistema
- `/exec <tool> <args>` - Ejecutar herramienta
- `/search <término>` - Buscar en Exploit-DB

### Sesiones
- `/session <nombre>` - Crear sesión
- `/resume <nombre>` - Continuar sesión

### Sistema
- `/tools` - Listar herramientas
- `/history` - Ver historial
- `/clear` - Limpiar pantalla
- `/exit` - Salir

## Ejemplo de Uso

```bash
# Iniciar chat
python main.py

# Cambiar modo
/mode osint
/mode blue
/mode pentester

# La IA responde automáticamente - puedes decir:
"hola" - Saludo
"qué procesos hay" - Lista procesos reales
"qué hay en C:/Users" - Explora carpeta
"qué información del sistema" - Specs del PC
"está python instalado" - Verifica herramienta
"escanea 192.168.1.1" - Escaneo automático
"busca exploits de apache" - Searchsploit
"genera reverse shell python" - Genera código

# O usar comandos explícitos
/scan 192.168.1.1
/run nmap -sV 192.168.1.1
/search apache
/files
```

## Funciones del Sistema Disponibles

- `ls_directory(path)` - Lista contenido de carpeta
- `get_processes()` - Lista procesos en ejecución
- `get_network_info()` - Info de red (IP, interfaces)
- `get_services()` - Lista servicios
- `get_disk_info()` - Info disco
- `get_system_info()` - Info del sistema
- `check_tool(name)` - Verifica si herramienta está instalada
- `execute_command(cmd)` - Ejecuta comandos del sistema
- `run_wsl(cmd)` - Ejecuta comando en Linux (WSL)
- `check_pentest_env()` - Verifica entorno de pentesting
- `check_wsl_tools()` - Lista herramientas en WSL

## Estructura de Archivos

```
output/
├── scripts/      # Scripts generados por la IA
├── tools/        # Herramientas de pentesting
├── payloads/     # Payloads y exploits
└── exploits/     # Exploits personalizados

reports/          # Reportes generados
history.json      # Historial de conversación
mode.json         # Modo actual
```

## Modelos Recomendados

- **dolphin-mixtral:latest** - Mejor para código/pentesting (24GB)
- **llama3:8b** - Balanceado (4GB)
- **mistral:latest** - Rápido (4GB)

## WSL Soporte

Si tienes WSL instalado, puedes ejecutar herramientas de Linux:
- `wsl nmap -sV target`
- `wsl python3 script.py`
- `wsl curl ...`

El sistema detecta automáticamente WSL y permite ejecución cruzada.

## Configuración

Edita `src/config/settings.py` para personalizar:
- Host de Ollama
- Modelo por defecto
- Herramientas disponibles
