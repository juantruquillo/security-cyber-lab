# =============================================================================
# MÓDULO 03 — Almacenamiento y protección de contraseñas
# =============================================================================
# ID: AUTH-PASSWORD-01
# Objetivo: demostrar los riesgos de almacenar contraseñas en texto plano
# y comparar esa práctica con el almacenamiento de hashes mediante Argon2.
#
# Una contraseña no debe almacenarse directamente en la base de datos.
# Si la base de datos queda expuesta, las contraseñas en texto plano pueden
# utilizarse inmediatamente para acceder a las cuentas afectadas.
#
# Argon2 permite almacenar un hash de la contraseña y verificarla posteriormente
# sin tener que guardar la contraseña original.
# =============================================================================


# ---------------------------------------------------------------------------
# Importación de librerías
# ---------------------------------------------------------------------------

import sqlite3
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, HTTPException


# ---------------------------------------------------------------------------
# Configuración del módulo
# ---------------------------------------------------------------------------

# Creamos el router para registrar las rutas en la aplicación principal.
router = APIRouter()

# Creamos el componente que genera y verifica los hashes mediante Argon2.
password_hasher = PasswordHasher()

# Definimos la ubicación de la base de datos compartida por los módulos
# de SQL Injection, seguridad de contraseñas y otros ejercicios de seguridad.
DB_PATH = Path(__file__).resolve().parent / "security_lab.db"


# ---------------------------------------------------------------------------
# Inicialización de la base de datos
# ---------------------------------------------------------------------------

def init_db():
    """
    Crea las tablas necesarias para comparar el almacenamiento inseguro
    de contraseñas con el almacenamiento de hashes mediante Argon2.
    """

    # Abrimos la conexión y permitimos que el bloque with la cierre.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # -------------------------------------------------------------------
        # Tabla INSEGURA: almacena las contraseñas en texto plano.
        # -------------------------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords_vulnerable_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_plaintext TEXT NOT NULL
            )
        """)

        # Insertamos usuarios ficticios para las pruebas del laboratorio.
        # Estas contraseñas son deliberadamente débiles y solo deben usarse
        # como datos de demostración, nunca en cuentas reales.
        cursor.execute(
            """
            INSERT OR IGNORE INTO passwords_vulnerable_users
                (id, username, password_plaintext)
            VALUES (?, ?, ?)
            """,
            (1, "juan", "123456"),
        )

        cursor.execute(
            """
            INSERT OR IGNORE INTO passwords_vulnerable_users
                (id, username, password_plaintext)
            VALUES (?, ?, ?)
            """,
            (2, "pedro", "password123"),
        )

        # -------------------------------------------------------------------
        # Tabla SEGURA: almacena hashes, no contraseñas originales.
        # -------------------------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords_secure_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


# Inicializamos las tablas cuando se importa este módulo.
init_db()


# ---------------------------------------------------------------------------
# Registro INSEGURO — Contraseña en texto plano
# ---------------------------------------------------------------------------

@router.post("/register")
def register(username: str, password: str):
    """
    Demostración intencionalmente insegura.

    La contraseña se almacena directamente en la base de datos.
    No utilizar este procedimiento en una aplicación real.
    """

    # Abrimos la conexión con la base de datos.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # VULNERABILIDAD:
        # Guardamos la contraseña original sin aplicar un hash.
        cursor.execute(
            """
            INSERT INTO passwords_vulnerable_users
                (username, password_plaintext)
            VALUES (?, ?)
            """,
            (username, password),
        )

    # Informamos que el registro terminó correctamente.
    return {
        "message": "Usuario registrado correctamente",
        "username": username,
    }


# ---------------------------------------------------------------------------
# Inicio de sesión INSEGURO — Comparación de texto plano
# ---------------------------------------------------------------------------

@router.post("/login")
def login(username: str, password: str):
    """
    Demostración intencionalmente insegura.

    Recupera la contraseña almacenada y la compara directamente
    con la contraseña recibida.
    """

    # Buscamos el usuario por su nombre mediante una consulta parametrizada.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username, password_plaintext
            FROM passwords_vulnerable_users
            WHERE username = ?
            """,
            (username,),
        )

        user = cursor.fetchone()

    # Si no existe el usuario, devolvemos un error HTTP 404.
    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado",
        )

    # VULNERABILIDAD:
    # La contraseña se compara directamente con el texto almacenado.
    if password != user[2]:
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas",
        )

    # Devolvemos información básica del usuario autenticado.
    return {
        "message": "Login exitoso",
        "user_id": user[0],
        "username": user[1],
    }


# ---------------------------------------------------------------------------
# Registro SEGURO — Hash de contraseña mediante Argon2
# ---------------------------------------------------------------------------

@router.post("/register-secure")
def register_secure(username: str, password: str):
    """
    Genera un hash de la contraseña antes de almacenarla.

    Argon2 incorpora una sal y parámetros de cálculo al hash generado.
    La contraseña original no se guarda en la tabla segura.
    """

    # Generamos el hash de la contraseña.
    password_hash = password_hasher.hash(password)

    # Guardamos el hash, no la contraseña original.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO passwords_secure_users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash),
        )

    return {
        "message": "Usuario registrado correctamente",
        "username": username,
    }


# ---------------------------------------------------------------------------
# Inicio de sesión SEGURO — Verificación mediante Argon2
# ---------------------------------------------------------------------------

@router.post("/login-secure")
def login_secure(username: str, password: str):
    """
    Busca el hash almacenado y verifica la contraseña mediante Argon2.

    No recupera ni compara una contraseña original almacenada en texto plano.
    """

    # Buscamos el usuario y recuperamos su hash.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username, password_hash
            FROM passwords_secure_users
            WHERE username = ?
            """,
            (username,),
        )

        user = cursor.fetchone()

    # Comprobamos que el usuario exista.
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas",
        )

    # Verificamos la contraseña usando el hash almacenado.
    # VerifyMismatchError indica que la contraseña no coincide.
    try:
        password_hasher.verify(user[2], password)

    except VerifyMismatchError:
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas",
        )

    # Si la verificación termina sin excepción, la contraseña coincide.
    return {
        "message": "Login exitoso",
        "user_id": user[0],
        "username": user[1],
    }