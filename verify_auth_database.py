
# =============================================================================
# SCRIPT DE VERIFICACIÓN — Base de datos central de autenticación
# ID: AUTH-DATABASE-VERIFY-01
# Descripción:
#   Comprueba las tablas, los datos iniciales y las claves foráneas
#   de auth_lab.db sin modificar su contenido.
# =============================================================================

# =============================================================================
# IMPORTACIONES
# =============================================================================

from auth_database import get_connection


# =============================================================================
# VERIFICACIÓN DE LA BASE DE DATOS
# =============================================================================

def verify_database() -> None:
    connection = get_connection()

    try:
        # ---------------------------------------------------------------------
        # Verificación de las tablas
        # ---------------------------------------------------------------------

        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name;
            """
        ).fetchall()

        print("\nTABLAS")
        print("=" * 60)

        for table in tables:
            print(table["name"])

        print(f"\nTotal de tablas: {len(tables)}")

        # ---------------------------------------------------------------------
        # Verificación de usuarios y roles
        # ---------------------------------------------------------------------

        users = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                roles.name AS role
            FROM users
            JOIN roles ON roles.id = users.role_id
            ORDER BY users.id;
            """
        ).fetchall()

        print("\nUSUARIOS Y ROLES")
        print("=" * 60)

        for user in users:
            print(dict(user))

        # ---------------------------------------------------------------------
        # Verificación de cuentas y propietarios
        # ---------------------------------------------------------------------

        accounts = connection.execute(
            """
            SELECT
                accounts.id,
                accounts.email,
                users.username AS owner
            FROM accounts
            JOIN users ON users.id = accounts.user_id
            ORDER BY accounts.id;
            """
        ).fetchall()

        print("\nCUENTAS Y PROPIETARIOS")
        print("=" * 60)

        for account in accounts:
            print(dict(account))

        # ---------------------------------------------------------------------
        # Verificación de permisos por rol
        # ---------------------------------------------------------------------

        permissions = connection.execute(
            """
            SELECT
                roles.name AS role,
                permissions.name AS permission
            FROM role_permissions
            JOIN roles
                ON roles.id = role_permissions.role_id
            JOIN permissions
                ON permissions.id = role_permissions.permission_id
            ORDER BY roles.name, permissions.name;
            """
        ).fetchall()

        print("\nPERMISOS ASIGNADOS")
        print("=" * 60)

        for permission in permissions:
            print(dict(permission))

        # ---------------------------------------------------------------------
        # Verificación de credenciales
        # ---------------------------------------------------------------------

        credentials = connection.execute(
            """
            SELECT
                users.username,
                credentials.password_hash
            FROM credentials
            JOIN users ON users.id = credentials.user_id
            ORDER BY users.id;
            """
        ).fetchall()

        print("\nCREDENCIALES")
        print("=" * 60)

        for credential in credentials:
            print({
                "username": credential["username"],
                "hash_present": bool(credential["password_hash"]),
                "hash_prefix": (
                    credential["password_hash"].split("$")[1]
                    if credential["password_hash"].startswith("$")
                    else "formato no reconocido"
                ),
            })

        # ---------------------------------------------------------------------
        # Verificación de claves foráneas
        # ---------------------------------------------------------------------

        foreign_key_errors = connection.execute(
            "PRAGMA foreign_key_check;"
        ).fetchall()

        print("\nCLAVES FORÁNEAS")
        print("=" * 60)

        if foreign_key_errors:
            for error in foreign_key_errors:
                print(dict(error))
        else:
            print("No se encontraron errores de integridad referencial.")

        # ---------------------------------------------------------------------
        # Resultado general
        # ---------------------------------------------------------------------

        print("\nRESUMEN")
        print("=" * 60)
        print(f"Tablas: {len(tables)}")
        print(f"Usuarios: {len(users)}")
        print(f"Cuentas: {len(accounts)}")
        print(f"Asignaciones de permisos: {len(permissions)}")
        print(f"Credenciales: {len(credentials)}")
        print(f"Errores de claves foráneas: {len(foreign_key_errors)}")

    finally:
        connection.close()


# =============================================================================
# EJECUCIÓN DEL SCRIPT
# =============================================================================

if __name__ == "__main__":
    verify_database()
