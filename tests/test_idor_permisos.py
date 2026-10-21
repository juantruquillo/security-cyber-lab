# =============================================================================
# PRUEBAS — MÓDULO IDOR: PERMISOS
# Descripción:
#   Verifica autorización basada en permisos asignados a cada rol.
# =============================================================================

# =============================================================================
# IMPORTACIONES
# =============================================================================

from fastapi import FastAPI
from fastapi.testclient import TestClient
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from idor_permisos import router


# =============================================================================
# CONFIGURACIÓN DE PRUEBAS
# =============================================================================

app = FastAPI()
app.include_router(router)

client = TestClient(app)

JUAN_USERNAME = "juan"
JUAN_PASSWORD = "LabUser_2026!"

MARIA_USERNAME = "maria"
MARIA_PASSWORD = "LabAdmin_2026!"


# =============================================================================
# FUNCIÓN AUXILIAR — INICIAR SESIÓN
# =============================================================================

def login(username: str, password: str) -> str:
    response = client.post(
        "/login-idor-permissions",
        json={
            "username": username,
            "password": password,
        },
    )

    assert response.status_code == 200, (
        f"Falló el inicio de sesión de {username}: "
        f"{response.status_code} - {response.text}"
    )

    token = response.json()["access_token"]

    assert token, f"No se recibió un token para {username}."

    return token


# =============================================================================
# PRUEBA 1 — JUAN CONSULTA SU PROPIO PERFIL
# =============================================================================

def test_juan_consulta_su_propio_perfil():
    juan_token = login(JUAN_USERNAME, JUAN_PASSWORD)
    juan_headers = {"Authorization": f"Bearer {juan_token}"}

    response = client.get(
        "/my-profile-idor-permissions",
        headers=juan_headers,
    )

    print("\nPRUEBA 1 — Juan consulta su perfil")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 200, response.text
    assert response.json()["username"] == "juan"
    assert response.json()["account"]["email"] == "juan@example.com"

    print("Resultado: OK — permiso read_own_profile concedido.")


# =============================================================================
# PRUEBA 2 — JUAN INTENTA CONSULTAR AUDITORÍA
# =============================================================================

def test_juan_no_puede_consultar_auditoria():
    juan_token = login(JUAN_USERNAME, JUAN_PASSWORD)
    juan_headers = {"Authorization": f"Bearer {juan_token}"}

    response = client.get(
        "/audit-logs-idor-permissions",
        headers=juan_headers,
    )

    print("\nPRUEBA 2 — Juan intenta consultar auditoría")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 403, (
        f"Se esperaba 403, se recibió {response.status_code}: "
        f"{response.text}"
    )

    print("Resultado: OK — permiso read_audit_logs denegado.")


# =============================================================================
# PRUEBA 3 — JUAN INTENTA GESTIONAR USUARIOS
# =============================================================================

def test_juan_no_puede_gestionar_usuarios():
    juan_token = login(JUAN_USERNAME, JUAN_PASSWORD)
    juan_headers = {"Authorization": f"Bearer {juan_token}"}

    response = client.get(
        "/manage-users-idor-permissions",
        headers=juan_headers,
    )

    print("\nPRUEBA 3 — Juan intenta gestionar usuarios")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 403, (
        f"Se esperaba 403, se recibió {response.status_code}: "
        f"{response.text}"
    )

    print("Resultado: OK — permiso manage_users denegado.")


# =============================================================================
# PRUEBA 4 — MARÍA CONSULTA AUDITORÍA
# =============================================================================

def test_maria_puede_consultar_auditoria():
    maria_token = login(MARIA_USERNAME, MARIA_PASSWORD)
    maria_headers = {"Authorization": f"Bearer {maria_token}"}

    response = client.get(
        "/audit-logs-idor-permissions",
        headers=maria_headers,
    )

    print("\nPRUEBA 4 — María consulta auditoría")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 200, response.text
    assert response.json()["requested_by"] == "maria"

    print("Resultado: OK — permiso read_audit_logs concedido.")


# =============================================================================
# PRUEBA 5 — MARÍA GESTIONA USUARIOS
# =============================================================================

def test_maria_puede_gestionar_usuarios():
    maria_token = login(MARIA_USERNAME, MARIA_PASSWORD)
    maria_headers = {"Authorization": f"Bearer {maria_token}"}

    response = client.get(
        "/manage-users-idor-permissions",
        headers=maria_headers,
    )

    print("\nPRUEBA 5 — María gestiona usuarios")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 200, response.text

    usernames = [
        user["username"]
        for user in response.json()["users"]
    ]

    assert "juan" in usernames
    assert "maria" in usernames

    print("Resultado: OK — permiso manage_users concedido.")


# =============================================================================
# PRUEBA 6 — SOLICITUD SIN TOKEN
# =============================================================================

def test_solicitud_sin_token():
    response = client.get("/my-profile-idor-permissions")

    print("\nPRUEBA 6 — Solicitud sin token")
    print("Estado HTTP:", response.status_code)

    assert response.status_code == 401, (
        f"Se esperaba 401, se recibió {response.status_code}: "
        f"{response.text}"
    )

    print("Resultado: OK — solicitud sin autenticación rechazada.")
