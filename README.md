# PTAI - Pentesting AI Tool

Herramienta CLI de pentesting con IA local (Ollama) y control del sistema.

## Requisitos

- Python 3.8+
- Ollama instalado y ejecutándose
- Herramientas de Kali Linux (opcional)

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
- `/autopwn <target>` - Pentest automático completo

### Archivos & Código
- `/files [cat]` - Listar archivos generados (scripts, tools, payloads, exploits)
- `/cat <archivo>` - Ver contenido de archivo
- `/edit <archivo>` - Editar archivo
- `/del <archivo>` - Eliminar archivo
- `/output` - Mostrar directorio de salida

### Ejecución
- `/run <comando>` - Ejecutar comando del sistema
- `/exec <script>` - Ejecutar script generado
- `/searchsploit <término>` - Buscar en Exploit-DB

### Sistema
- `/tools` - Listar herramientas disponibles
- `/clear` - Limpiar pantalla
- `/exit` - Salir

## Estructura de Archivos

```
output/
├── scripts/      # Scripts generados por la IA
├── tools/        # Herramientas de pentesting
├── payloads/     # Payloads y exploits
└── exploits/     # Exploits personalizados
```

## Ejemplo de Uso

```bash
# Iniciar chat
python main.py

# El modelo generará código y lo guardará automáticamente
# en la carpeta correspondiente

# Ejecutar un escaneo
/scan 192.168.1.1

# Ejecutar comando del sistema
/run nmap -sV 192.168.1.1

# Buscar exploits
/searchsploit apache

# Ver archivos generados
/files
```

## Configuración

Edita `src/config/settings.py` para personalizar:
- Host de Ollama
- Modelo por defecto
- Herramientas disponibles
