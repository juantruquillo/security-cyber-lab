
# =============================================================================
# MÓDULO IDOR — Permisos y autorización centralizada
# ID: IDOR-PERMISSIONS-01
# Descripción:
#   Controla el acceso mediante permisos asignados a los roles.
#   Centraliza las comprobaciones de autorización y las consultas de datos.
#   Utiliza JWT para identificar al usuario y auth_lab.db como fuente de datos.
# =============================================================================

# =============================================================================
# IMPORTACIONES
# =============================================================================

import os

from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from auth_database import get_connection


# =============================================================================
# CONFIGURACIÓN GENERAL
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 15

if not JWT_SECRET_KEY:
    raise RuntimeError(
        "Falta JWT_SECRET_KEY en el archivo .env. "
        "Configura el secreto antes de iniciar la aplicación."
    )

router = APIRouter(tags=["IDOR - Permisos"])

bearer_scheme = HTTPBearer()
password_hasher = PasswordHasher()


# =============================================================================
# MODELOS DE DATOS
# =============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class CurrentUser(BaseModel):
    user_id: int
    username: str
    role: str


# =============================================================================
# AUTENTICACIÓN DE USUARIOS
# =============================================================================

def authenticate_user(username: str, password: str):
    """
    Verifica las credenciales y recupera la identidad del usuario.
    """

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                roles.name AS role,
                credentials.password_hash
            FROM users
            JOIN roles
                ON roles.id = users.role_id
            JOIN credentials
                ON credentials.user_id = users.id
            WHERE users.username = ?;
            """,
            (username,),
        ).fetchone()

        if user is None:
            return None

        try:
            password_hasher.verify(
                user["password_hash"],
                password,
            )
        except (VerifyMismatchError, VerificationError):
            return None

        return {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }

    finally:
        connection.close()


# =============================================================================
# GENERACIÓN DE JWT
# =============================================================================

def create_access_token(user_id: int) -> str:
    """
    Crea un JWT con identificador de usuario y expiración.
    """

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


# =============================================================================
# IDENTIDAD DEL USUARIO AUTENTICADO
# =============================================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Valida el JWT y obtiene la identidad actual desde la base de datos.
    """

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        subject = payload.get("sub")

        if subject is None:
            raise JWTError("Falta el identificador del usuario.")

        user_id = int(subject)

    except (JWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                roles.name AS role
            FROM users
            JOIN roles
                ON roles.id = users.role_id
            WHERE users.id = ?;
            """,
            (user_id,),
        ).fetchone()

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El usuario del token ya no existe.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return CurrentUser(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
        )

    finally:
        connection.close()


# =============================================================================
# COMPROBACIÓN CENTRALIZADA DE PERMISOS
# =============================================================================

def has_permission(role: str, permission_name: str) -> bool:
    """
    Comprueba si un rol tiene asignado un permiso en la base de datos.
    """

    connection = get_connection()

    try:
        permission = connection.execute(
            """
            SELECT 1
            FROM role_permissions
            JOIN roles
                ON roles.id = role_permissions.role_id
            JOIN permissions
                ON permissions.id = role_permissions.permission_id
            WHERE roles.name = ?
              AND permissions.name = ?;
            """,
            (role, permission_name),
        ).fetchone()

        return permission is not None

    finally:
        connection.close()


def require_permission(permission_name: str):
    """
    Crea una dependencia que exige un permiso específico.
    """

    def permission_checker(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if not has_permission(
            current_user.role,
            permission_name,
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes el permiso necesario para esta acción.",
            )

        return current_user

    return permission_checker


# =============================================================================
# ENDPOINT DE INICIO DE SESIÓN
# =============================================================================

@router.post(
    "/login-idor-permissions",
    response_model=TokenResponse,
)
def login_idor_permissions(request: LoginRequest):
    """
    Autentica al usuario y entrega un JWT.
    """

    user = authenticate_user(
        request.username,
        request.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(
        access_token=create_access_token(user["user_id"]),
        token_type="bearer",
    )


# =============================================================================
# ENDPOINT DE PERFIL PROPIO
# =============================================================================

@router.get("/my-profile-idor-permissions")
def get_my_profile(
    current_user: CurrentUser = Depends(
        require_permission("read_own_profile")
    ),
):
    """
    Devuelve el perfil del usuario que ha superado la autorización.
    """

    connection = get_connection()

    try:
        account = connection.execute(
            """
            SELECT id, email
            FROM accounts
            WHERE user_id = ?;
            """,
            (current_user.user_id,),
        ).fetchone()

        if account is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Perfil no encontrado.",
            )

        return {
            "user_id": current_user.user_id,
            "username": current_user.username,
            "role": current_user.role,
            "account": {
                "id": account["id"],
                "email": account["email"],
            },
        }

    finally:
        connection.close()


# =============================================================================
# ENDPOINT DE AUDITORÍA
# =============================================================================

@router.get("/audit-logs-idor-permissions")
def get_audit_logs(
    current_user: CurrentUser = Depends(
        require_permission("read_audit_logs")
    ),
):
    """
    Demuestra una operación protegida por un permiso específico.

    Los registros son datos ficticios para fines educativos.
    """

    return {
        "message": "Acceso autorizado a los registros de auditoría.",
        "requested_by": current_user.username,
        "records": [
            {
                "event": "login",
                "result": "success",
            },
            {
                "event": "access_denied",
                "result": "forbidden",
            },
        ],
    }


# =============================================================================
# ENDPOINT DE GESTIÓN DE USUARIOS
# =============================================================================

@router.get("/manage-users-idor-permissions")
def manage_users(
    current_user: CurrentUser = Depends(
        require_permission("manage_users")
    ),
):
    """
    Demuestra una operación que exige el permiso manage_users.
    """

    connection = get_connection()

    try:
        users = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                roles.name AS role
            FROM users
            JOIN roles
                ON roles.id = users.role_id
            ORDER BY users.id;
            """
        ).fetchall()

        return {
            "message": "Acceso autorizado a la gestión de usuarios.",
            "requested_by": current_user.username,
            "users": [
                {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"],
                }
                for user in users
            ],
        }

    finally:
        connection.close()


# =============================================================================
# FIN DEL MÓDULO DE PERMISOS
# =============================================================================
