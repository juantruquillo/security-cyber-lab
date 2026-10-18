
# =============================================================================
# MÓDULO DE BASE DE DATOS — Autenticación y autorización centralizadas
# ID: AUTH-DATABASE-01
# Descripción:
#   Crea la base de datos auth_lab.db desde cero.
#   Define usuarios, credenciales, cuentas, roles y permisos.
#   Centraliza las conexiones SQLite utilizadas por los módulos IDOR/JWT.
#   Incluye datos ficticios exclusivamente para el laboratorio.
# =============================================================================

# =============================================================================
# IMPORTACIONES
# =============================================================================

import sqlite3

from pathlib import Path
from argon2 import PasswordHasher


# =============================================================================
# CONFIGURACIÓN GENERAL
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "auth_lab.db"

PASSWORD_HASHER = PasswordHasher()


# =============================================================================
# DATOS FICTICIOS DEL LABORATORIO
# =============================================================================

# Estas contraseñas son exclusivamente para las pruebas locales.
# No deben utilizarse en cuentas reales ni en otros sistemas.

INITIAL_USERS = [
    {
        "username": "juan",
        "password": "LabUser_2026!",
        "role": "user",
        "email": "juan@example.com",
    },
    {
        "username": "maria",
        "password": "LabAdmin_2026!",
        "role": "admin",
        "email": "maria@example.com",
    },
]


# =============================================================================
# DEFINICIÓN DE PERMISOS
# =============================================================================

INITIAL_PERMISSIONS = [
    "read_own_profile",
    "read_audit_logs",
    "manage_users",
]


# =============================================================================
# ASIGNACIÓN EXPLÍCITA DE PERMISOS POR ROL
# =============================================================================

ROLE_PERMISSIONS = {
    "user": [
        "read_own_profile",
    ],
    "admin": [
        "read_own_profile",
        "read_audit_logs",
        "manage_users",
    ],
}


# =============================================================================
# CREACIÓN DE LA ESTRUCTURA DE LA BASE DE DATOS
# =============================================================================

def create_tables(connection: sqlite3.Connection) -> None:
    """
    Crea las seis tablas necesarias para autenticación y autorización.
    """

    connection.executescript(
        """
        CREATE TABLE roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            role_id INTEGER NOT NULL,
            FOREIGN KEY (role_id)
                REFERENCES roles(id)
                ON UPDATE CASCADE
                ON DELETE RESTRICT
        );

        CREATE TABLE credentials (
            user_id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON UPDATE CASCADE
                ON DELETE CASCADE
        );

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON UPDATE CASCADE
                ON DELETE CASCADE
        );

        CREATE TABLE permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,

            PRIMARY KEY (role_id, permission_id),

            FOREIGN KEY (role_id)
                REFERENCES roles(id)
                ON UPDATE CASCADE
                ON DELETE CASCADE,

            FOREIGN KEY (permission_id)
                REFERENCES permissions(id)
                ON UPDATE CASCADE
                ON DELETE CASCADE
        );
        """
    )


# =============================================================================
# INSERCIÓN DE LOS DATOS INICIALES
# =============================================================================

def seed_initial_data(connection: sqlite3.Connection) -> None:
    """
    Inserta los usuarios, sus credenciales, cuentas y permisos iniciales.
    """

    cursor = connection.cursor()

    # -------------------------------------------------------------------------
    # Creación de roles
    # -------------------------------------------------------------------------

    cursor.executemany(
        """
        INSERT INTO roles (name)
        VALUES (?);
        """,
        [
            ("user",),
            ("admin",),
        ],
    )

    roles = {
        row["name"]: row["id"]
        for row in connection.execute(
            "SELECT id, name FROM roles;"
        ).fetchall()
    }

    # -------------------------------------------------------------------------
    # Creación de usuarios, credenciales y cuentas
    # -------------------------------------------------------------------------

    for user in INITIAL_USERS:
        cursor.execute(
            """
            INSERT INTO users (username, role_id)
            VALUES (?, ?);
            """,
            (
                user["username"],
                roles[user["role"]],
            ),
        )

        user_id = cursor.lastrowid

        password_hash = PASSWORD_HASHER.hash(user["password"])

        cursor.execute(
            """
            INSERT INTO credentials (user_id, password_hash)
            VALUES (?, ?);
            """,
            (
                user_id,
                password_hash,
            ),
        )

        cursor.execute(
            """
            INSERT INTO accounts (user_id, email)
            VALUES (?, ?);
            """,
            (
                user_id,
                user["email"],
            ),
        )

    # -------------------------------------------------------------------------
    # Creación de permisos
    # -------------------------------------------------------------------------

    cursor.executemany(
        """
        INSERT INTO permissions (name)
        VALUES (?);
        """,
        [
            (permission,)
            for permission in INITIAL_PERMISSIONS
        ],
    )

    permissions = {
        row["name"]: row["id"]
        for row in connection.execute(
            "SELECT id, name FROM permissions;"
        ).fetchall()
    }

    # -------------------------------------------------------------------------
    # Asignación explícita de permisos a cada rol
    # -------------------------------------------------------------------------

    for role_name, permission_names in ROLE_PERMISSIONS.items():
        role_id = roles[role_name]

        for permission_name in permission_names:
            cursor.execute(
                """
                INSERT INTO role_permissions (
                    role_id,
                    permission_id
                )
                VALUES (?, ?);
                """,
                (
                    role_id,
                    permissions[permission_name],
                ),
            )


# =============================================================================
# INICIALIZACIÓN DE LA BASE DE DATOS
# =============================================================================

def initialize_database() -> None:
    """
    Crea auth_lab.db sin sobrescribir una base de datos existente.

    Si el archivo ya existe, la función se detiene para proteger sus datos.
    """

    if DATABASE_PATH.exists():
        raise FileExistsError(
            f"La base de datos ya existe: {DATABASE_PATH}\n"
            "No se ha modificado ningún archivo. "
            "Verifica la base existente antes de continuar."
        )

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA foreign_keys = ON;")

        with connection:
            create_tables(connection)
            seed_initial_data(connection)

            connection.execute(
                "PRAGMA user_version = 1;"
            )

        print("Base de datos creada correctamente.")
        print(f"Ubicación: {DATABASE_PATH}")
        print("Tablas creadas: 6")
        print("Usuarios ficticios creados: 2")
        print("Cuentas protegidas creadas: 2")

    except Exception:
        connection.rollback()

        # El archivo solo se elimina si fue creado por esta ejecución.
        # Nunca se elimina una base de datos que ya existía previamente.
        connection.close()

        if DATABASE_PATH.exists():
            DATABASE_PATH.unlink()

        raise

    finally:
        if connection:
            connection.close()


# =============================================================================
# CONEXIÓN CENTRALIZADA A LA BASE DE DATOS
# =============================================================================

def get_connection() -> sqlite3.Connection:
    """
    Devuelve una conexión a auth_lab.db con claves foráneas activadas.

    No crea una base vacía si el archivo todavía no existe.
    """

    if not DATABASE_PATH.is_file():
        raise FileNotFoundError(
            "No existe auth_lab.db. "
            "Ejecuta primero auth_database.py para inicializarla."
        )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON;")

    return connection


# =============================================================================
# EJECUCIÓN DIRECTA DEL INICIALIZADOR
# =============================================================================

if __name__ == "__main__":
    initialize_database()
