
# =============================================================================
# PRUEBAS — MÓDULO IDOR: AUTENTICACIÓN SEGURA
# Descripción:
#   Verifica inicio de sesión, JWT, identidad y autorización de cuentas.
# =============================================================================

from fastapi import FastAPI
from fastapi.testclient import TestClient
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from idor_autenticacion_segura import router


# =============================================================================
# CONFIGURACIÓN DE PRUEBAS
# =============================================================================

app = FastAPI()
app.include_router(router)

client = TestClient(app)

USERNAME = "juan"
PASSWORD = "LabUser_2026!"


# =============================================================================
# PRUEBA 1 — INICIO DE SESIÓN CORRECTO
# =============================================================================

response = client.post(
    "/login-idor-secure",
    json={
        "username": USERNAME,
        "password": PASSWORD,
    },
)

print("\nPRUEBA 1 — Inicio de sesión correcto")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, (
    f"Se esperaba 200, se recibió {response.status_code}: "
    f"{response.text}"
)

token = response.json()["access_token"]

assert token, "La respuesta no contiene un token."

print("Resultado: OK — se recibió un JWT.")


# =============================================================================
# PRUEBA 2 — CONTRASEÑA INCORRECTA
# =============================================================================

response = client.post(
    "/login-idor-secure",
    json={
        "username": USERNAME,
        "password": "ContraseñaIncorrecta",
    },
)

print("\nPRUEBA 2 — Contraseña incorrecta")
print("Estado HTTP:", response.status_code)

assert response.status_code == 401, (
    f"Se esperaba 401, se recibió {response.status_code}: "
    f"{response.text}"
)

print("Resultado: OK — acceso rechazado.")


# =============================================================================
# PRUEBA 3 — PERFIL CON JWT VÁLIDO
# =============================================================================

response = client.get(
    "/me-idor-secure",
    headers={"Authorization": f"Bearer {token}"},
)

print("\nPRUEBA 3 — Perfil con JWT válido")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, (
    f"Se esperaba 200, se recibió {response.status_code}: "
    f"{response.text}"
)

assert response.json()["username"] == USERNAME

print("Resultado: OK — identidad validada.")


# =============================================================================
# PRUEBA 4 — ACCESO A CUENTA PROPIA
# =============================================================================

response = client.get(
    "/accounts-idor-secure/1",
    headers={"Authorization": f"Bearer {token}"},
)

print("\nPRUEBA 4 — Acceso a cuenta propia")
print("Estado HTTP:", response.status_code)

assert response.status_code == 200, (
    f"Se esperaba 200, se recibió {response.status_code}: "
    f"{response.text}"
)

print("Resultado: OK — acceso autorizado.")


# =============================================================================
# PRUEBA 5 — ACCESO A CUENTA AJENA
# =============================================================================

response = client.get(
    "/accounts-idor-secure/2",
    headers={"Authorization": f"Bearer {token}"},
)

print("\nPRUEBA 5 — Acceso a cuenta ajena")
print("Estado HTTP:", response.status_code)

assert response.status_code == 403, (
    f"Se esperaba 403, se recibió {response.status_code}: "
    f"{response.text}"
)

print("Resultado: OK — acceso denegado.")


# =============================================================================
# PRUEBA 6 — AUSENCIA DE TOKEN
# =============================================================================

response = client.get("/me-idor-secure")

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
