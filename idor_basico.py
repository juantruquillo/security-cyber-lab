
# =============================================================================
# MÓDULO IDOR BÁSICO — Autenticación JWT y control de propiedad
# ID: IDOR-BASIC-01
# Descripción:
#   Demuestra los fundamentos de autenticación mediante JWT.
#   Incluye una ruta vulnerable y otra protegida contra IDOR.
#   Utiliza exclusivamente la base de datos central auth_lab.db.
# =============================================================================

# =============================================================================
# IMPORTACIONES
# =============================================================================

import os

from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

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

router = APIRouter(tags=["IDOR básico"])

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
# AUTENTICACIÓN Y GENERACIÓN DE JWT
# =============================================================================

def authenticate_user(username: str, password: str):
    """
    Comprueba las credenciales del usuario mediante un hash Argon2.
    Devuelve la identidad del usuario si las credenciales son válidas.
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


def create_access_token(user_id: int) -> str:
    """
    Genera un JWT firmado con identificador y fecha de expiración.
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
# DEPENDENCIA DE AUTENTICACIÓN JWT
# =============================================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Valida el JWT y recupera la identidad desde auth_lab.db.
    """

    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        subject = payload.get("sub")

        if subject is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El token no contiene un usuario válido.",
                headers={"WWW-Authenticate": "Bearer"},
            )

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
# CONSULTA DE CUENTAS
# =============================================================================

def find_account(account_id: int):
    """
    Busca una cuenta por su identificador.
    """

    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT id, user_id, email
            FROM accounts
            WHERE id = ?;
            """,
            (account_id,),
        ).fetchone()

    finally:
        connection.close()


# =============================================================================
# RUTA DE INICIO DE SESIÓN
# =============================================================================

@router.post(
    "/login-idor-basic",
    response_model=TokenResponse,
)
def login_idor_basic(request: LoginRequest):
    """
    Autentica al usuario y entrega un JWT de corta duración.
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

    access_token = create_access_token(user["user_id"])

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
    )


# =============================================================================
# RUTA VULNERABLE — DEMOSTRACIÓN EDUCATIVA DE IDOR
# =============================================================================

@router.get("/accounts-vulnerable/{account_id}")
def get_account_vulnerable(
    account_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Demuestra IDOR: autentica al usuario, pero no comprueba la propiedad.

    Esta ruta es intencionalmente vulnerable para pruebas locales.
    """

    account = find_account(account_id)

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cuenta no encontrada.",
        )

    return {
        "message": "Ruta vulnerable: no se comprobó la propiedad.",
        "authenticated_user": current_user.username,
        "account": {
            "id": account["id"],
            "email": account["email"],
        },
    }


# =============================================================================
# RUTA PROTEGIDA — CONTROL DE PROPIEDAD
# =============================================================================

@router.get("/accounts-protected/{account_id}")
def get_account_protected(
    account_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Comprueba que el usuario autenticado sea propietario de la cuenta.
    """

    account = find_account(account_id)

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
        "authenticated_user": current_user.username,
        "account": {
            "id": account["id"],
            "email": account["email"],
        },
    }


# =============================================================================
# FIN DEL MÓDULO IDOR BÁSICO
# =============================================================================
