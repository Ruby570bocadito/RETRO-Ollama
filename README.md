# PTAI - Pentesting AI Tool

Herramienta CLI de pentesting con IA local (Ollama) y control autónomo del sistema.

## Requisitos

- Python 3.8+
- Ollama instalado y ejecutándose
- Herramientas de Kali Linux (opcional, para Windows usar Godot/Nmap)

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

## Características Principales

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
| Herramientas | Verifica si están instaladas |

### Detección Automática
La IA detecta lo que necesitas sin necesidad de comandos explícitos:
- "¿qué procesos hay?" → Ejecuta `get_processes()`
- "¿qué hay en C:/Users?" → Lista el directorio
- "¿qué información del sistema?" → Muestra specs
- "¿está nmap instalado?" → Verifica la herramienta

## Comandos

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

## Estructura de Archivos

```
output/
├── scripts/      # Scripts generados por la IA
├── tools/        # Herramientas de pentesting
├── payloads/     # Payloads y exploits
└── exploits/     # Exploits personalizados

reports/          # Reportes generados
history.json      # Historial de conversación
```

## Modelos Recomendados

- **dolphin-mixtral:latest** - Mejor para código/pentesting (24GB)
- **llama3:8b** - Balanceado (4GB)
- **mistral:latest** - Rápido (4GB)

## Configuración

Edita `src/config/settings.py` para personalizar:
- Host de Ollama
- Modelo por defecto
- Herramientas disponibles
