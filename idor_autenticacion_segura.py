
# =============================================================================
# MÓDULO IDOR — Autenticación segura
# ID: IDOR-AUTH-SECURE-01
# Descripción:
#   Demuestra autenticación segura mediante contraseñas Argon2 y JWT.
#   Valida la identidad del usuario, la firma y la expiración del token.
#   Utiliza exclusivamente la base de datos central auth_lab.db.
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

router = APIRouter(tags=["IDOR - Autenticación segura"])

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


# =============================================================================
# VERIFICACIÓN DE CREDENCIALES
# =============================================================================

def authenticate_user(username: str, password: str):
    """
    Verifica las credenciales almacenadas en auth_lab.db.
    """

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT
                users.id,
                users.username,
                credentials.password_hash
            FROM users
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
        }

    finally:
        connection.close()


# =============================================================================
# GENERACIÓN DE JWT
# =============================================================================

def create_access_token(user_id: int) -> str:
    """
    Genera un JWT con identificador de usuario y expiración.
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
# VALIDACIÓN DE JWT Y RECUPERACIÓN DEL USUARIO
# =============================================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Valida el JWT y comprueba que el usuario exista en la base de datos.
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
            SELECT id, username
            FROM users
            WHERE id = ?;
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
        )

    finally:
        connection.close()


# =============================================================================
# ENDPOINT DE INICIO DE SESIÓN
# =============================================================================

@router.post(
    "/login-idor-secure",
    response_model=TokenResponse,
)
def login_idor_secure(request: LoginRequest):
    """
    Autentica al usuario y genera un JWT de corta duración.
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
# ENDPOINT DE PERFIL AUTENTICADO
# =============================================================================

@router.get("/me-idor-secure")
def get_my_profile(
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Devuelve la identidad del usuario autenticado.
    """

    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
    }


# =============================================================================
# ENDPOINT DE CONSULTA DE CUENTA PROPIA
# =============================================================================

@router.get("/accounts-idor-secure/{account_id}")
def get_my_account(
    account_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Permite consultar exclusivamente una cuenta de propiedad del usuario.
    """

    connection = get_connection()

    try:
        account = connection.execute(
            """
            SELECT id, user_id, email
            FROM accounts
            WHERE id = ?;
            """,
            (account_id,),
        ).fetchone()

        if account is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cuenta no encontrada.",
            )

        if account["user_id"] != current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permiso para acceder a esta cuenta.",
            )

        return {
            "message": "Acceso autorizado.",
            "account": {
                "id": account["id"],
                "email": account["email"],
            },
        }

    finally:
        connection.close()


# =============================================================================
# FIN DEL MÓDULO DE AUTENTICACIÓN SEGURA
# =============================================================================
