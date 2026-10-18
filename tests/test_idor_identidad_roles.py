
# =============================================================================
# PRUEBAS — MÓDULO IDOR: IDENTIDAD Y ROLES
# Descripción:
#   Comprueba identidad, autenticación y autorización basada en roles.
# =============================================================================

from fastapi import FastAPI
from fastapi.testclient import TestClient
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from idor_identidad_roles import router


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
        "/login-idor-roles",
        json={
            "username": username,
            "password": password,
        },
    )

    assert response.status_code == 200, (
        f"Falló el inicio de sesión de {username}: "
        f"{response.status_code} - {response.text}"
    )

    return response.json()["access_token"]


juan_token = login(JUAN_USERNAME, JUAN_PASSWORD)
maria_token = login(MARIA_USERNAME, MARIA_PASSWORD)


# =============================================================================
# PRUEBA 1 — IDENTIDAD Y ROL DE JUAN
# =============================================================================

response = client.get(
    "/me-idor-roles",
    headers={"Authorization": f"Bearer {juan_token}"},
)

print("\nPRUEBA 1 — Identidad de Juan")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, response.text
assert response.json()["username"] == "juan"
assert response.json()["role"] == "user"

print("Resultado: OK — Juan tiene el rol user.")


# =============================================================================
# PRUEBA 2 — IDENTIDAD Y ROL DE MARÍA
# =============================================================================

response = client.get(
    "/me-idor-roles",
    headers={"Authorization": f"Bearer {maria_token}"},
)

print("\nPRUEBA 2 — Identidad de María")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, response.text
assert response.json()["username"] == "maria"
assert response.json()["role"] == "admin"

print("Resultado: OK — María tiene el rol admin.")


# =============================================================================
# PRUEBA 3 — JUAN ACCEDE AL ÁREA DE USUARIOS
# =============================================================================

response = client.get(
    "/user-area-idor-roles",
    headers={"Authorization": f"Bearer {juan_token}"},
)

print("\nPRUEBA 3 — Juan accede al área de usuarios")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, response.text

print("Resultado: OK — usuario autenticado autorizado.")


# =============================================================================
# PRUEBA 4 — JUAN INTENTA ACCEDER AL ÁREA ADMINISTRATIVA
# =============================================================================

response = client.get(
    "/admin-area-idor-roles",
    headers={"Authorization": f"Bearer {juan_token}"},
)

print("\nPRUEBA 4 — Juan intenta acceder al área administrativa")
print("Estado HTTP:", response.status_code)

assert response.status_code == 403, (
    f"Se esperaba 403, se recibió {response.status_code}: "
    f"{response.text}"
)

print("Resultado: OK — acceso administrativo denegado.")


# =============================================================================
# PRUEBA 5 — MARÍA ACCEDE AL ÁREA ADMINISTRATIVA
# =============================================================================

response = client.get(
    "/admin-area-idor-roles",
    headers={"Authorization": f"Bearer {maria_token}"},
)

print("\nPRUEBA 5 — María accede al área administrativa")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, response.text

print("Resultado: OK — acceso administrativo autorizado.")


# =============================================================================
# PRUEBA 6 — SOLICITUD SIN TOKEN
# =============================================================================

response = client.get("/me-idor-roles")

print("\nPRUEBA 6 — Solicitud sin token")
print("Estado HTTP:", response.status_code)

assert response.status_code == 401, (
    f"Se esperaba 401, se recibió {response.status_code}: "
    f"{response.text}"
)

print("Resultado: OK — solicitud sin autenticación rechazada.")


# =============================================================================
# RESUMEN
# =============================================================================

print("\nTodas las pruebas finalizaron correctamente.")
