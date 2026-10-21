# =============================================================================
# PRUEBAS — Módulo IDOR básico
# ID: TEST-IDOR-BASIC-01
# Descripción:
#   Verifica inicio de sesión, JWT y control de propiedad.
#   Utiliza la base auth_lab.db del laboratorio.
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

from idor_basico import router


# =============================================================================
# CONFIGURACIÓN DE LA APLICACIÓN DE PRUEBA
# =============================================================================

app = FastAPI()
app.include_router(router)

client = TestClient(app)


# =============================================================================
# PRUEBA DE INICIO DE SESIÓN
# =============================================================================

def test_inicio_de_sesion():
    response = client.post(
        "/login-idor-basic",
        json={
            "username": "juan",
            "password": "LabUser_2026!",
        },
    )

    print("\nINICIO DE SESIÓN")
    print("=" * 60)
    print("Estado:", response.status_code)

    assert response.status_code == 200, response.text

    token = response.json()["access_token"]

    print("Token recibido:", bool(token))

    assert token


# =============================================================================
# FUNCIÓN AUXILIAR — OBTENER TOKEN
# =============================================================================

def obtener_token():
    response = client.post(
        "/login-idor-basic",
        json={
            "username": "juan",
            "password": "LabUser_2026!",
        },
    )

    assert response.status_code == 200, response.text

    return response.json()["access_token"]


# =============================================================================
# PRUEBA DE ACCESO A LA CUENTA PROPIA
# =============================================================================

def test_acceso_cuenta_propia():
    token = obtener_token()

    headers = {
        "Authorization": f"Bearer {token}",
    }

    response = client.get(
        "/accounts-protected/1",
        headers=headers,
    )

    print("\nCUENTA PROPIA — RUTA PROTEGIDA")
    print("=" * 60)
    print("Estado:", response.status_code)
    print("Respuesta:", response.json())

    assert response.status_code == 200, response.text


# =============================================================================
# PRUEBA DE IDOR EN LA RUTA VULNERABLE
# =============================================================================

def test_idor_ruta_vulnerable():
    token = obtener_token()

    headers = {
        "Authorization": f"Bearer {token}",
    }

    response = client.get(
        "/accounts-vulnerable/2",
        headers=headers,
    )

    print("\nCUENTA AJENA — RUTA VULNERABLE")
    print("=" * 60)
    print("Estado:", response.status_code)
    print("Respuesta:", response.json())

    # Este 200 es intencional:
    # demuestra la vulnerabilidad IDOR del endpoint educativo.
    assert response.status_code == 200, response.text


# =============================================================================
# PRUEBA DE BLOQUEO DE IDOR EN LA RUTA PROTEGIDA
# =============================================================================

def test_bloqueo_idor_ruta_protegida():
    token = obtener_token()

    headers = {
        "Authorization": f"Bearer {token}",
    }

    response = client.get(
        "/accounts-protected/2",
        headers=headers,
    )

    print("\nCUENTA AJENA — RUTA PROTEGIDA")
    print("=" * 60)
    print("Estado:", response.status_code)
    print("Respuesta:", response.json())

    assert response.status_code == 403, response.text


# =============================================================================
# PRUEBA DE CONTRASEÑA INCORRECTA
# =============================================================================

def test_contrasena_incorrecta():
    response = client.post(
        "/login-idor-basic",
        json={
            "username": "juan",
            "password": "Incorrecta_123!",
        },
    )

    print("\nCONTRASEÑA INCORRECTA")
    print("=" * 60)
    print("Estado:", response.status_code)

    assert response.status_code == 401, response.text