# ExamNetBy
# README - PIPELINE CI/CD CON SEGURIDAD PARA TREXNEGRO
======================================================

Este proyecto contiene un pipeline funcional de CI/CD con controles de seguridad integrados. Está diseñado para ejecutarse automáticamente en GitLab CI/CD, con soporte para herramientas de análisis estático (SAST), análisis de composición (SCA), escaneo de secretos, generación de SBOM, validación de despliegue y pruebas dinámicas (DAST).

----------------------------------------
REQUISITOS DEL ENTORNO
----------------------------------------

1. GitLab con Runners habilitados.
2. Proyecto en lenguaje Python con archivo `requirements.txt`.
3. Docker instalado en el runner.
4. Acceso a los siguientes CLI/tools:
   - `semgrep`
   - `trivy`
   - `git-leaks`
   - `syft`
   - `curl`
   - `docker`

----------------------------------------
ESTRUCTURA DEL PIPELINE
----------------------------------------

Fase 1: Análisis Estático de Seguridad (SAST)
- Herramienta: Semgrep
- Detecta vulnerabilidades en el código fuente.
- Configurada para Python y buenas prácticas generales.

Fase 2: Análisis de Composición de Software (SCA)
- Herramienta: Trivy
- Analiza dependencias declaradas en `requirements.txt`.
- Reporta vulnerabilidades por CVE y criticidad.

Fase 3: Escaneo de Secretos
- Herramienta: Gitleaks
- Detecta secretos expuestos en el repositorio.

Fase 4: Generación de SBOM (Software Bill of Materials)
- Herramienta: Syft
- Genera un informe completo de componentes de software usados.

Fase 5: Despliegue y Validación de Seguridad
- Construcción y despliegue con Docker.
- Validación automática para evitar despliegue si hay vulnerabilidades críticas.
- Despliegue controlado a producción solo si las fases anteriores no fallan.

Fase 6: Pruebas Dinámicas (DAST)
- Herramienta: curl + script personalizado
- Simula una prueba básica contra endpoints para validaciones.

----------------------------------------
ARCHIVO DE CONFIGURACIÓN
----------------------------------------

El pipeline está contenido en el archivo `.gitlab-ci.yml`, listo para ejecución.

----------------------------------------
EJECUCIÓN
----------------------------------------

1. Haz commit del archivo `.gitlab-ci.yml` y de este README.txt.
2. Asegúrate de que el runner tenga los permisos necesarios.
3. Push al repositorio remoto.
4. GitLab ejecutará el pipeline automáticamente.
5. Puedes ver los reportes de seguridad en el panel CI/CD > Pipelines.

----------------------------------------
NOMBRE DEL PROYECTO / EMPRESA
----------------------------------------

Nombre del proyecto: TREXNEGRO Web App
Responsable DevSecOps: Jeremy Erazo, Senior Security Engineer

----------------------------------------
COMENTARIOS FINALES
----------------------------------------

Este pipeline es modular y puede extenderse con escáneres comerciales o integrarse con servicios de terceros como SonarQube, Snyk, o ZAP si se desea mayor profundidad. Toda la configuración está comentada línea por línea dentro de `.gitlab-ci.yml`.
