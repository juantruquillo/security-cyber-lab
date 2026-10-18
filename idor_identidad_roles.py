
# =============================================================================
# MÓDULO IDOR — Identidad y roles
# ID: IDOR-IDENTITY-ROLES-01
# Descripción:
#   Representa al usuario autenticado mediante un modelo CurrentUser.
#   Recupera su rol desde auth_lab.db y demuestra autorización por rol.
#   Utiliza JWT para identificar al usuario y SQLite como fuente de datos.
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

router = APIRouter(tags=["IDOR - Identidad y roles"])

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
    Verifica las credenciales y recupera el rol del usuario.
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
    Crea un JWT con el identificador del usuario y su expiración.
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
    Valida el JWT y recupera identidad y rol desde la base de datos.

    El rol no se toma de una entrada enviada por el cliente ni se confía
    en un rol almacenado dentro del token.
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
# AUTORIZACIÓN BASADA EN ROLES
# =============================================================================

def require_role(required_role: str):
    """
    Genera una dependencia que exige un rol específico.
    """

    def role_checker(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tu rol no permite realizar esta acción.",
            )

        return current_user

    return role_checker


# =============================================================================
# ENDPOINT DE INICIO DE SESIÓN
# =============================================================================

@router.post(
    "/login-idor-roles",
    response_model=TokenResponse,
)
def login_idor_roles(request: LoginRequest):
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
# ENDPOINT DE IDENTIDAD Y ROL
# =============================================================================

@router.get("/me-idor-roles")
def get_my_identity(
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Devuelve la identidad y el rol recuperados desde la base de datos.
    """

    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "role": current_user.role,
    }


# =============================================================================
# ENDPOINT DISPONIBLE PARA USUARIOS AUTENTICADOS
# =============================================================================

@router.get("/user-area-idor-roles")
def get_user_area(
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Permite el acceso a cualquier usuario autenticado.
    """

    return {
        "message": "Acceso permitido al área de usuarios.",
        "username": current_user.username,
        "role": current_user.role,
    }


# =============================================================================
# ENDPOINT EXCLUSIVO PARA ADMINISTRADORES
# =============================================================================

@router.get("/admin-area-idor-roles")
def get_admin_area(
    current_user: CurrentUser = Depends(require_role("admin")),
):
    """
    Demuestra una restricción basada en el rol admin.
    """

    return {
        "message": "Acceso permitido al área administrativa.",
        "username": current_user.username,
        "role": current_user.role,
    }


# =============================================================================
# FIN DEL MÓDULO DE IDENTIDAD Y ROLES
# =============================================================================
