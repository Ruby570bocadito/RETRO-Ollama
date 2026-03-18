# RETRO-OLLAMA - Objetivos del Proyecto

## Vision General

**RETRO-OLLAMA** es una herramienta CLI de pentesting potenciada por IA local (Ollama, LM Studio, Llama.cpp). El objetivo es crear un asistente de seguridad autonomous y completo que pueda ejecutar herramientas, investigar, mejorar codigo y adaptarse al modo de trabajo seleccionado.

---

## Objetivos por Fase

### Fase 1: UI/UX y Modo Visible

#### 1.1 Banner y ASCII
- [ ] Arreglar caracteres ASCII para Windows (evitar `|`, `\`, `/` problematicos)
- [ ] Mostrar MODO ACTUAL en banner principal con color
- [ ] Eliminar duplicacion de banner al iniciar
- [ ] Usar caracteres compatibles: `+`, `-`, `=`, `:`

#### 1.2 Indicador de Modo
- [ ] Modo siempre visible en barra de estado
- [ ] Prompt personalizado: `>> PENTESTING [MODO]: `
- [ ] Colores por modo en la barra de estado
- [ ] Panel de modo visible al cambiar

### Fase 2: Sistema de Modos Mejorado

#### 2.1 Comandos por Modo

**Autonomous:**
- [ ] /research - Investigacion web automatica
- [ ] /improve - Mejorar/optimizar codigo
- [ ] /execute - Ejecutar herramientas
- [ ] /plan - Planificar ataque
- [ ] /iterate - Iterar hasta completar

**Pentester:**
- [ ] /exploit - Buscar y ejecutar exploits
- [ ] /pwn - Comprometer objetivo
- [ ] /shell - Generar shells
- [ ] /lateral - Movimiento lateral
- [ ] /pivot - Pivoting

**Blue Team:**
- [ ] /detect - Detectar amenazas
- [ ] /harden - Hardening de sistemas
- [ ] /siem - Integracion SIEM
- [ ] /incident - Respuesta a incidentes
- [ ] /hunt - Threat hunting

**OSINT:**
- [ ] /dorks - Google Dorks
- [ ] /emails - Harvesting de emails
- [ ] /social - Social media OSINT
- [ ] /footprints - Huellas digitales

**WebApp:**
- [ ] /inject - Inyecciones (SQL, XSS)
- [ ] /xss - XSS testing
- [ ] /sql - SQL Injection
- [ ] /auth - Testing autenticacion

**Forense:**
- [ ] /memory - Analisis de memoria
- [ ] /disk - Analisis de disco
- [ ] /timeline - Crear timelines
- [ ] /artefacts - Analisis de artefactos

**BugBounty:**
- [ ] /reconauto - Recon automatizado
- [ ] /subdomain - Subdomain enum
- [ ] /tech - Deteccion de tecnologias

#### 2.2 Prompts Especializados
- [ ] Prompts unicos por cada modo
- [ ] Comportamiento diferente segun modo
- [ ] Herramientas prioritarias por modo

### Fase 3: Nuevos Modos

- [ ] **devsecops**: CI/CD security, SAST, DAST
- [ ] **malware**: Analisis de malware, sandbox
- [ ] **iot**: Seguridad IoT, protocolos
- [ ] **cloud**: AWS/Azure/GCP security
- [ ] **mobile**: Android/iOS security
- [ ] **compliance**: HIPAA, PCI-DSS, ISO27001

### Fase 4: Skills y MCP

- [ ] Sistema de skills cargables
- [ ] Integracion MCP (Model Context Protocol)
- [ ] Plugins/Extensiones
- [ ] Comandos dinámicos

### Fase 5: Agente Autonomo

- [ ] Web research automatico
- [ ] Mejora de codigo con memoria
- [ ] Auto-ejecucion de herramientas
- [ ] Iteracion inteligente
- [ ] Learning de resultados

### Fase 6: Workflows

- [ ] Workflows por modo
- [ ] Crear workflows personalizados
- [ ] Guardar/cargar workflows
- [ ] Workflows encadenados

### Fase 7: Memoria y Contexto

- [ ] Persistencia de sesion
- [ ] Historial de comandos
- [ ] Memoria de hallazgos
- [ ] Contexto entre comandos

### Fase 8: Reportes

- [ ] Reportes HTML/PDF
- [ ] Exportar a JSON/XML
- [ ] Dashboard de resultados

---

## Roadmap de Implementacion

```
Fase 1 (Semana 1): UI/UX y Modo Visible
    ├── 1.1 Arreglar banner ASCII
    └── 1.2 Indicador de modo visible

Fase 2 (Semana 2): Sistema de Modos
    ├── 2.1 Comandos por modo (todos)
    └── 2.2 Prompts especializados

Fase 3 (Semana 3): Nuevos Modos
    ├── 3.1 devsecops
    ├── 3.2 malware
    ├── 3.3 iot
    ├── 3.4 cloud
    └── 3.5 mobile/compliance

Fase 4-8: Características Avanzadas
    ├── Skills y MCP
    ├── Agente autonomo
    ├── Workflows
    └── Reportes
```

---

## Métricas de Éxito

- [ ] Banner se muestra correctamente en Windows
- [ ] Modo siempre visible en CLI
- [ ] Minimo 15 comandos nuevos funcionando
- [ ] 7+ modos especializados con prompts unicos
- [ ] Agente puede investigar y mejorar codigo
- [ ] Workflows personalizables

---

## Notas de Desarrollo

- Usar caracteres ASCII seguros para Windows: `+`, `-`, `=`, `:`, `[`, `]`
- Evitar: `|`, `\`, `/`, `@`, `#` en banners
- Testing constante despues de cada cambio
- Mantener compatibilidad con LM Studio, Ollama, Llama.cpp

---

*Última actualización: 2026-03-17*
