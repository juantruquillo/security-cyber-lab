# =============================================================================
# MÓDULO 02 — SQL Injection
# =============================================================================
# ID: WEB-SQLI-01
# Objetivo: demostrar una vulnerabilidad de inyección SQL y compararla con
# una consulta parametrizada que evita que la entrada se interprete como SQL.
#
# SQL Injection ocurre cuando una aplicación incorpora entradas del usuario
# directamente en una consulta SQL. Una entrada manipulada puede alterar la
# consulta y permitir acceder a información que no debería estar disponible.
#
# IMPORTANTE: la ruta vulnerable se conserva únicamente con fines educativos.
# Utilizar este módulo solo en el laboratorio local y con datos ficticios.
# =============================================================================


# ---------------------------------------------------------------------------
# Importación de librerías
# ---------------------------------------------------------------------------

import sqlite3
from pathlib import Path

from fastapi import APIRouter


# ---------------------------------------------------------------------------
# Configuración del módulo
# ---------------------------------------------------------------------------

# Creamos el router para registrar las rutas de este módulo en la aplicación
# principal, sin crear una instancia independiente de FastAPI.
router = APIRouter()

# Definimos la ruta de la base de datos a partir de la ubicación de este archivo.
# Esto evita depender de la carpeta desde la que se inicia la aplicación.
DB_PATH = Path(__file__).resolve().parent / "security_lab.db"


# ---------------------------------------------------------------------------
# Inicialización de la base de datos
# ---------------------------------------------------------------------------

def init_db():
    """
    Crea la tabla de usuarios para SQL Injection si no existe e inserta
    datos ficticios para realizar las pruebas del laboratorio.
    """

    # El bloque with administra el cierre de la conexión al terminar.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # Creamos una tabla exclusiva para el módulo de SQL Injection.
        #
        # Se utiliza un nombre específico para evitar conflictos con otras
        # tablas de usuarios que pertenecen a otros módulos del laboratorio.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sqli_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL
            )
        """)

        # Definimos los usuarios ficticios que se utilizarán en las pruebas.
        test_users = [
            (1, "juan", "juan@example.com"),
            (2, "pedro", "pedro@example.com"),
            (3, "maria", "maria@example.com"),
        ]

        # Insertamos los usuarios sin duplicar identificadores existentes.
        # Los parámetros ? separan los valores de la instrucción SQL.
        cursor.executemany(
            """
            INSERT OR IGNORE INTO sqli_users (id, username, email)
            VALUES (?, ?, ?)
            """,
            test_users,
        )


# Inicializamos la base de datos cuando se importa este módulo.
init_db()


# ---------------------------------------------------------------------------
# Formato de los resultados
# ---------------------------------------------------------------------------

def format_users(users):
    """
    Convierte las filas devueltas por SQLite en una lista de diccionarios
    que FastAPI puede serializar como una respuesta JSON.
    """

    return [
        {
            "id": user[0],
            "username": user[1],
            "email": user[2],
        }
        for user in users
    ]


# ---------------------------------------------------------------------------
# Ruta vulnerable — SQL Injection
# ---------------------------------------------------------------------------

@router.get("/users-vulnerable/{user_id}")
def get_user_vulnerable(user_id: str):
    """
    Demostración intencionalmente vulnerable.

    La entrada del usuario se incorpora directamente a la consulta SQL.
    Una entrada manipulada puede modificar la lógica de la consulta.
    No utilizar este patrón en aplicaciones reales.
    """

    # Abrimos una conexión con la base de datos del laboratorio.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # VULNERABILIDAD:
        # La interpolación f-string introduce user_id directamente en el SQL.
        # SQLite puede interpretar el contenido recibido como parte del código.
        query = (
            "SELECT id, username, email "
            f"FROM sqli_users WHERE id = {user_id}"
        )

        # Ejecutamos la consulta vulnerable para observar su comportamiento.
        cursor.execute(query)

        # Recuperamos todas las filas que coincidan con la consulta.
        users = cursor.fetchall()

    # Devolvemos los resultados en formato JSON.
    return {"users": format_users(users)}


# ---------------------------------------------------------------------------
# Ruta segura — Consulta parametrizada
# ---------------------------------------------------------------------------

@router.get("/users-safe/{user_id}")
def get_user_safe(user_id: str):
    """
    Versión protegida contra la inyección SQL.

    El valor recibido se transmite por separado de la instrucción SQL,
    por lo que se interpreta como un dato y no como código SQL.
    """

    # Abrimos una conexión con la base de datos del laboratorio.
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # El marcador ? representa el parámetro que se enviará por separado.
        query = (
            "SELECT id, username, email "
            "FROM sqli_users WHERE id = ?"
        )

        # Pasamos user_id como parámetro, no como parte del texto SQL.
        cursor.execute(query, (user_id,))

        # Recuperamos las filas que coincidan con el valor proporcionado.
        users = cursor.fetchall()

    # Devolvemos los resultados en formato JSON.
    return {"users": format_users(users)}