
# =============================================================================
# PRUEBAS DE INTEGRACIÓN — Módulos IDOR
# ID: TEST-IDOR-INTEGRATION-01
#
# Objetivo:
# Verificar el comportamiento de los módulos IDOR registrados en main.py.
#
# Pruebas:
# - Inicio de sesión con credenciales válidas e inválidas.
# - Acceso a cuentas propias y ajenas.
# - Identidad y autorización basada en roles.
# - Autorización basada en permisos específicos.
#
# Alcance:
# Las pruebas utilizan TestClient y la aplicación principal.
# Se emplea la base de datos de laboratorio existente.
#
# Nota:
# El acceso cruzado del endpoint vulnerable es intencional y educativo.
# =============================================================================

import sys
from pathlib import Path

from fastapi.testclient import TestClient

# Agregar la carpeta raíz del proyecto a la ruta de búsqueda de Python.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from main import app


# ---------------------------------------------------------------------------
# Configuración de las pruebas
# ---------------------------------------------------------------------------

client = TestClient(app)

JUAN_CREDENTIALS = {
    "username": "juan",
    "password": "LabUser_2026!",
}

MARIA_CREDENTIALS = {
    "username": "maria",
    "password": "LabAdmin_2026!",
}


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------

def obtener_token(login_path: str, credentials: dict) -> str:
    """Inicia sesión y devuelve el token JWT de la respuesta."""

    response = client.post(login_path, json=credentials)

    assert response.status_code == 200, (
        f"Error al iniciar sesión en {login_path}: "
        f"{response.status_code} - {response.text}"
    )

    data = response.json()

    # Los módulos pueden usar nombres distintos para el campo del token.
    token = (
        data.get("access_token")
        or data.get("token")
    )

    assert token, (
        f"La respuesta de {login_path} no contiene un token: {data}"
    )

    return token


def encabezado_bearer(token: str) -> dict:
    """Construye el encabezado HTTP de autenticación Bearer."""

    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Ejecución de pruebas
# ---------------------------------------------------------------------------

def main() -> None:
    """Ejecuta las comprobaciones de integración de los módulos IDOR."""

    # -----------------------------------------------------------------------
    # 1. IDOR básico
    # -----------------------------------------------------------------------

    token_juan_basico = obtener_token(
        "/login-idor-basic",
        JUAN_CREDENTIALS,
    )

    headers_juan_basico = encabezado_bearer(token_juan_basico)

    # El endpoint vulnerable permite consultar una cuenta ajena.
    vulnerable = client.get(
        "/accounts-vulnerable/2",
        headers=headers_juan_basico,
    )

    assert vulnerable.status_code == 200, (
        f"Se esperaba 200 en el endpoint vulnerable; "
        f"se recibió {vulnerable.status_code}"
    )

    # El endpoint protegido debe impedir el acceso cruzado.
    protegido = client.get(
        "/accounts-protected/2",
        headers=headers_juan_basico,
    )

    assert protegido.status_code == 403, (
        f"Se esperaba 403 en el endpoint protegido; "
        f"se recibió {protegido.status_code}"
    )

    # -----------------------------------------------------------------------
    # 2. Autenticación segura y propiedad de cuentas
    # -----------------------------------------------------------------------

    token_juan_seguro = obtener_token(
        "/login-idor-secure",
        JUAN_CREDENTIALS,
    )

    headers_juan_seguro = encabezado_bearer(token_juan_seguro)

    perfil = client.get(
        "/me-idor-secure",
        headers=headers_juan_seguro,
    )

    assert perfil.status_code == 200, (
        f"Se esperaba 200 al consultar el perfil; "
        f"se recibió {perfil.status_code}"
    )

    cuenta_propia = client.get(
        "/accounts-idor-secure/1",
        headers=headers_juan_seguro,
    )

    assert cuenta_propia.status_code == 200, (
        f"Se esperaba 200 para la cuenta propia; "
        f"se recibió {cuenta_propia.status_code}"
    )

    cuenta_ajena = client.get(
        "/accounts-idor-secure/2",
        headers=headers_juan_seguro,
    )

    assert cuenta_ajena.status_code == 403, (
        f"Se esperaba 403 para una cuenta ajena; "
        f"se recibió {cuenta_ajena.status_code}"
    )

    # -----------------------------------------------------------------------
    # 3. Identidad y autorización basada en roles
    # -----------------------------------------------------------------------

    token_juan_roles = obtener_token(
        "/login-idor-roles",
        JUAN_CREDENTIALS,
    )

    token_maria_roles = obtener_token(
        "/login-idor-roles",
        MARIA_CREDENTIALS,
    )

    area_usuario = client.get(
        "/user-area-idor-roles",
        headers=encabezado_bearer(token_juan_roles),
    )

    assert area_usuario.status_code == 200, (
        f"Se esperaba 200 para el área de usuario; "
        f"se recibió {area_usuario.status_code}"
    )

    area_admin_juan = client.get(
        "/admin-area-idor-roles",
        headers=encabezado_bearer(token_juan_roles),
    )

    assert area_admin_juan.status_code == 403, (
        f"Se esperaba 403 para Juan en el área de administración; "
        f"se recibió {area_admin_juan.status_code}"
    )

    area_admin_maria = client.get(
        "/admin-area-idor-roles",
        headers=encabezado_bearer(token_maria_roles),
    )

    assert area_admin_maria.status_code == 200, (
        f"Se esperaba 200 para María en el área de administración; "
        f"se recibió {area_admin_maria.status_code}"
    )

    # -----------------------------------------------------------------------
    # 4. Autorización basada en permisos específicos
    # -----------------------------------------------------------------------

    token_juan_permisos = obtener_token(
        "/login-idor-permissions",
        JUAN_CREDENTIALS,
    )

    token_maria_permisos = obtener_token(
        "/login-idor-permissions",
        MARIA_CREDENTIALS,
    )

    perfil_juan = client.get(
        "/my-profile-idor-permissions",
        headers=encabezado_bearer(token_juan_permisos),
    )

    assert perfil_juan.status_code == 200, (
        f"Se esperaba 200 para el perfil propio; "
        f"se recibió {perfil_juan.status_code}"
    )

    auditoria_juan = client.get(
        "/audit-logs-idor-permissions",
        headers=encabezado_bearer(token_juan_permisos),
    )

    assert auditoria_juan.status_code == 403, (
        f"Se esperaba 403 para Juan en los registros de auditoría; "
        f"se recibió {auditoria_juan.status_code}"
    )

    usuarios_juan = client.get(
        "/manage-users-idor-permissions",
        headers=encabezado_bearer(token_juan_permisos),
    )

    assert usuarios_juan.status_code == 403, (
        f"Se esperaba 403 para Juan al gestionar usuarios; "
        f"se recibió {usuarios_juan.status_code}"
    )

    auditoria_maria = client.get(
        "/audit-logs-idor-permissions",
        headers=encabezado_bearer(token_maria_permisos),
    )

    assert auditoria_maria.status_code == 200, (
        f"Se esperaba 200 para María en los registros de auditoría; "
        f"se recibió {auditoria_maria.status_code}"
    )

    usuarios_maria = client.get(
        "/manage-users-idor-permissions",
        headers=encabezado_bearer(token_maria_permisos),
    )

    assert usuarios_maria.status_code == 200, (
        f"Se esperaba 200 para María al gestionar usuarios; "
        f"se recibió {usuarios_maria.status_code}"
    )

    # -----------------------------------------------------------------------
    # Resultado
    # -----------------------------------------------------------------------

    print("Todas las pruebas de integración finalizaron correctamente.")
    print("IDOR básico: acceso vulnerable y protección verificados.")
    print("Autenticación segura: perfil y propiedad de cuentas verificados.")
    print("Roles: acceso de usuario y administrador verificado.")
    print("Permisos: accesos permitidos y denegados verificados.")


if __name__ == "__main__":
    main()
