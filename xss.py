# =============================================================================
# MÓDULO 01 — Cross-Site Scripting (XSS)
# ID: WEB-XSS-01
#
# Objetivo:
# Estudiar cómo una entrada controlada por el usuario puede convertirse en
# contenido HTML ejecutable y cómo mitigar el problema mediante escaping.
#
# Conceptos principales:
# - Parámetros HTTP y validación básica de entradas.
# - Respuestas JSON frente a respuestas HTML.
# - Reflected Cross-Site Scripting (XSS).
# - Escaping del contenido según el contexto de salida.
#
# Endpoints:
# - GET /                 : comprobación básica de la aplicación.
# - GET /hello            : saludo mediante respuesta JSON.
# - GET /hello-html       : saludo HTML con la entrada escapada.
#
# Alcance:
# La demostración vulnerable se conserva como referencia comentada.
# El endpoint HTML activo aplica escaping antes de insertar la entrada.
# =============================================================================


# ---------------------------------------------------------------------------
# Importación de librerías
# ---------------------------------------------------------------------------

from html import escape

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse


# ---------------------------------------------------------------------------
# Configuración del módulo
# ---------------------------------------------------------------------------

# Creamos el router para registrar las rutas en la aplicación principal.
router = APIRouter()


# ---------------------------------------------------------------------------
# Endpoint de comprobación
# ---------------------------------------------------------------------------

@router.get("/")
def home():
    """
    Devuelve un mensaje para comprobar que el módulo está disponible.

    La respuesta se serializa como JSON de forma predeterminada en FastAPI.
    """
    return {"message": "Laboratorio de Ciberseguridad funcionando"}


# ---------------------------------------------------------------------------
# Endpoint de saludo mediante JSON
# ---------------------------------------------------------------------------

@router.get("/hello")
def hello(name: str = Query(min_length=1)):
    """
    Recibe un nombre mediante un parámetro de consulta y devuelve un saludo.

    La longitud mínima evita una cadena vacía, pero no elimina espacios
    ni sustituye una validación específica de negocio.
    """
    return {"message": f"Hola {name}"}


# ---------------------------------------------------------------------------
# Referencia educativa: versión vulnerable a XSS reflejado
# ---------------------------------------------------------------------------
#
# Esta implementación insertaba directamente la entrada del usuario en HTML.
# Si el navegador interpretaba la entrada como marcado o JavaScript, podía
# producirse una vulnerabilidad de Cross-Site Scripting (XSS).
#
# Endpoint de referencia:
# GET /hello-html?name=<entrada>
#
# Ejemplos de prueba en un entorno local controlado:
# - <h1>HACKED</h1>
# - <script>alert(1)</script>
#
# Impacto potencial:
# El navegador puede interpretar contenido controlado por el usuario dentro
# del origen de la aplicación. El impacto real depende del contexto y de las
# protecciones adicionales existentes.
#
# La implementación vulnerable permanece desactivada intencionalmente.
#
# @router.get("/hello-html", response_class=HTMLResponse)
# def hello_html_vulnerable(name: str):
#     return f"<html><body><h1>Hola {name}</h1></body></html>"


# ---------------------------------------------------------------------------
# Endpoint mitigado: respuesta HTML con escaping
# ---------------------------------------------------------------------------

@router.get("/hello-html", response_class=HTMLResponse)
def hello_html(name: str = Query(min_length=1)):
    """
    Devuelve un saludo HTML tratando el nombre recibido como texto.

    escape() transforma caracteres especiales de HTML en entidades, evitando
    que una entrada como '<script>' se interprete como una etiqueta en este
    contexto de texto HTML.

    Importante:
    El escaping debe corresponder al contexto donde se inserta el dato.
    html.escape() no sustituye las medidas específicas necesarias para
    contextos como JavaScript, CSS o URLs.
    """
    safe_name = escape(name)

    return (
        "<html>"
        "<body>"
        f"<h1>Hola {safe_name}</h1>"
        "</body>"
        "</html>"
    )
