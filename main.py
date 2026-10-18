
# =============================================================================
# MÓDULO PRINCIPAL — Aplicación web del Laboratorio de Ciberseguridad
# ID: APP-MAIN-01
#
# Objetivo:
# Crear la aplicación FastAPI y registrar los routers de los módulos
# educativos que componen el laboratorio.
#
# Módulos registrados:
# - XSS: reflejo de entradas del usuario en respuestas HTML.
# - SQL Injection: consultas SQL y manejo de entradas.
# - Passwords: almacenamiento y verificación de contraseñas.
# - IDOR básico: control de acceso a recursos.
# - IDOR autenticación segura: credenciales y validación de JWT.
# - IDOR identidad y roles: identidad del usuario y autorización por rol.
# - IDOR permisos: autorización mediante permisos específicos.
#
# Alcance:
# Este archivo centraliza el registro de rutas. La lógica de autenticación,
# autorización, acceso a datos y mitigación pertenece a cada módulo.
#
# Nota de seguridad:
# El registro de un router no garantiza que sus endpoints sean seguros.
# Las rutas y sus comportamientos deben verificarse individualmente.
# =============================================================================

from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Importación de routers
# ---------------------------------------------------------------------------

# Módulos generales del laboratorio.
from xss import router as xss_router
from sql_injection import router as sqlinjection_router
from password_security import router as password_router

# Módulos IDOR consolidados.
from idor_basico import router as idor_basico_router
from idor_autenticacion_segura import router as idor_autenticacion_segura_router
from idor_identidad_roles import router as idor_identidad_roles_router
from idor_permisos import router as idor_permisos_router


# ---------------------------------------------------------------------------
# Creación de la aplicación
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Laboratorio de Ciberseguridad",
    description=(
        "Laboratorio educativo para estudiar vulnerabilidades web, "
        "autenticación, autorización y mitigaciones de seguridad."
    ),
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Registro de routers
# ---------------------------------------------------------------------------

# Cada router incorpora a la aplicación los endpoints definidos en su módulo.
# Los módulos IDOR consolidados sustituyen el registro de las versiones
# anteriores. Los archivos antiguos se conservan sin modificar.

routers = [
    # Módulos generales.
    xss_router,
    sqlinjection_router,
    password_router,

    # IDOR consolidado.
    idor_basico_router,
    idor_autenticacion_segura_router,
    idor_identidad_roles_router,
    idor_permisos_router,
]

for router in routers:
    app.include_router(router)
