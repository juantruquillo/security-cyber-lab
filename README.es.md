# Security Cyber Lab

Laboratorio práctico de **seguridad de aplicaciones** desarrollado con Python y FastAPI para estudiar vulnerabilidades web y de API, comprender sus causas raíz, reproducirlas en un entorno controlado y verificar mecanismos de mitigación.

El proyecto sigue un enfoque progresivo y práctico de seguridad de aplicaciones. Incluye implementaciones intencionalmente vulnerables con fines educativos, alternativas protegidas, pruebas manuales mediante Swagger UI y pruebas automatizadas.

**Idioma:** [English](README.md) | Español

> **Aviso de seguridad:** Este es un laboratorio educativo local. Las implementaciones intencionalmente vulnerables deben utilizarse únicamente en el entorno controlado del laboratorio y nunca deben desplegarse como código de producción.

---

## Tabla de contenidos

- [Objetivos del proyecto](#objetivos-del-proyecto)
- [Tecnologías](#tecnologías)
- [1. Cross-Site Scripting reflejado (XSS)](#1-cross-site-scripting-reflejado-xss)
- [2. Inyección SQL](#2-inyección-sql)
- [3. Almacenamiento inseguro de contraseñas](#3-almacenamiento-inseguro-de-contraseñas)
- [4. IDOR / Control de acceso deficiente](#4-idor--control-de-acceso-deficiente)
  - [4.1. IDOR básico](#41-idor-básico)
  - [4.2. IDOR con autenticación segura y JWT](#42-idor-con-autenticación-segura-y-jwt)
  - [4.3. Autorización basada en roles](#43-autorización-basada-en-roles)
  - [4.4. Autorización basada en permisos](#44-autorización-basada-en-permisos)
- [5. Estructura de pruebas](#5-estructura-de-pruebas)
- [6. Documentación de pruebas manuales](#6-documentación-de-pruebas-manuales)
- [7. Ejecución local](#7-ejecución-local)
- [8. Bases de datos y datos de prueba](#8-bases-de-datos-y-datos-de-prueba)
- [9. Principios de seguridad estudiados](#9-principios-de-seguridad-estudiados)
- [10. Mejoras futuras](#10-mejoras-futuras)
- [Alcance y limitaciones](#alcance-y-limitaciones)

---

## Objetivos del proyecto

- Comprender cómo se originan las vulnerabilidades comunes en aplicaciones web y API.
- Reproducir vulnerabilidades mediante pruebas de concepto controladas.
- Comparar implementaciones vulnerables con sus alternativas protegidas.
- Aplicar controles de autenticación y autorización.
- Comprender JWT, el hashing de contraseñas, los roles y los permisos.
- Validar el comportamiento esperado mediante pruebas automatizadas.
- Construir un portafolio práctico enfocado en seguridad de aplicaciones y, progresivamente, en pruebas de penetración.

## Tecnologías

- **Python:** lenguaje de programación principal.
- **FastAPI:** desarrollo de API y endpoints del laboratorio.
- **Uvicorn:** servidor ASGI utilizado para ejecutar la aplicación.
- **SQLite:** almacenamiento de datos para los laboratorios.
- **JWT:** representación y validación de tokens de autenticación.
- **Argon2id:** hashing de contraseñas.
- **python-jose:** manejo y validación de JWT.
- **argon2-cffi:** implementación de Argon2id.
- **python-dotenv:** carga de variables de entorno.
- **HTTPX:** cliente HTTP utilizado por las pruebas.
- **Swagger UI:** exploración interactiva y ejecución manual de solicitudes.
- **pytest / TestClient:** herramientas para ejecutar y validar pruebas automatizadas.

---

# 1. Cross-Site Scripting reflejado (XSS)

## Descripción

Cross-Site Scripting (XSS) es una vulnerabilidad que puede aparecer cuando una aplicación incorpora datos controlados por el usuario en una página web sin tratarlos adecuadamente según el contexto en el que se utilizan.

Este laboratorio estudia el XSS reflejado mediante un parámetro que se incorpora a una respuesta HTML.

## Endpoint vulnerable de referencia

```http
GET /hello-html
```

Parámetro afectado:

```text
name
```

La implementación vulnerable de referencia inserta directamente el parámetro en el HTML:

```python
return f"<html><body><h1>Hello {name}</h1></body></html>"
```

**Estado actual:** esta implementación vulnerable se conserva comentada en `xss.py`. No es la implementación activa del endpoint.

## Causa raíz

El problema consiste en insertar directamente datos no confiables en una respuesta HTML sin aplicar el tratamiento adecuado para ese contexto.

El navegador interpreta la respuesta como HTML. Por lo tanto, una entrada que contiene marcado puede alterar la estructura de la página y, bajo las condiciones apropiadas, ejecutar JavaScript.

## Prueba de concepto

Payload utilizado:

```html
<script>alert(1)</script>
```

También se probó la interpretación de HTML con:

```html
<h1>HACKED</h1>
```

En las pruebas originales de la implementación vulnerable, el navegador ejecutó el JavaScript y mostró el encabezado HTML.

## Impacto potencial

Dependiendo del contexto de la aplicación y de sus protecciones, una vulnerabilidad XSS puede permitir a un atacante:

- Manipular el contenido visible de una página.
- Ejecutar JavaScript en el contexto del sitio web afectado.
- Realizar acciones en nombre de un usuario bajo determinadas condiciones.
- Acceder a información disponible para los scripts que se ejecutan en ese contexto.

La explotación real depende de factores como las cookies, los privilegios del usuario, la política de seguridad de contenido (CSP) y las restricciones del navegador.

## Mitigación

La implementación activa aplica escaping al contenido antes de incorporarlo al HTML:

```python
from html import escape

safe_name = escape(name)
return f"<html><body><h1>Hello {safe_name}</h1></body></html>"
```

La función `escape()` convierte ciertos caracteres especiales en representaciones que el navegador interpreta como texto, en lugar de interpretarlos como estructura HTML.

Esta solución se aplica al contexto HTML utilizado en el laboratorio. Otros contextos, como JavaScript, CSS o atributos HTML, requieren un tratamiento apropiado para cada contexto.

## Verificación

Los payloads originales se probaron nuevamente después de aplicar la mitigación.

Resultados documentados:

- El payload `<script>alert(1)</script>` apareció como texto.
- `alert(1)` no se ejecutó.
- El payload `<h1>HACKED</h1>` no creó un encabezado HTML; las etiquetas aparecieron como texto.

**Estado documentado:** mitigación implementada en el endpoint activo y verificada mediante las pruebas manuales realizadas.

## Lecciones aprendidas

- Los datos proporcionados por el usuario deben tratarse como no confiables.
- La validación de entradas no sustituye el escaping de salida.
- Reflejar una entrada en una respuesta no significa necesariamente que exista una vulnerabilidad XSS.
- El tratamiento de los datos depende del contexto en el que se utilizan.
- Las mitigaciones deben volver a probarse después de su implementación.

---

# 2. Inyección SQL

## Descripción

La inyección SQL es una vulnerabilidad que ocurre cuando una aplicación construye consultas SQL utilizando entradas no confiables de una forma que permite modificar la estructura de la consulta.

Este laboratorio compara una consulta vulnerable con una consulta parametrizada.

## Endpoint vulnerable

```http
GET /users-vulnerable/{user_id}
```

## Causa raíz

La implementación vulnerable construye la consulta mediante interpolación directa:

```python
query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
```

Cuando una entrada puede alterar la estructura de la consulta, la base de datos puede ejecutar una condición diferente de la prevista por la aplicación.

## Prueba de concepto

Una solicitud normal:

```http
GET /users-vulnerable/1
```

recupera el usuario asociado al identificador `1`.

Después se probó el siguiente valor:

```text
1 OR 1=1
```

La consulta resultante era equivalente a:

```sql
SELECT id, username, email
FROM users
WHERE id = 1 OR 1=1;
```

Como la condición `1=1` siempre es verdadera, la consulta devolvió los tres usuarios presentes en la base de datos de prueba.

Este resultado demuestra la vulnerabilidad del endpoint del laboratorio.

## Impacto potencial

Dependiendo de la consulta, los privilegios de conexión a la base de datos y las operaciones disponibles, una inyección SQL puede permitir a un atacante:

- Acceder a registros que no deberían devolverse.
- Modificar o eliminar datos.
- Evadir determinados controles de la aplicación.
- Comprometer información almacenada en la base de datos.

El impacto real depende de las operaciones SQL disponibles y de los privilegios concedidos a la aplicación.

## Mitigación

La consulta se reemplazó por una consulta parametrizada:

```python
query = "SELECT id, username, email FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

Los parámetros se suministran por separado de la sentencia SQL. Esto permite que las entradas se traten como valores y no como parte de la estructura de la consulta.

## Endpoint protegido

```http
GET /users-safe/{user_id}
```

## Verificación

Se volvió a probar el siguiente valor:

```text
1 OR 1=1
```

En la prueba documentada, el endpoint protegido no devolvió los tres usuarios. La respuesta observada fue:

```json
{
  "users": []
}
```

Esto demuestra que el payload dejó de producir el resultado de explotación original.

La respuesta vacía depende de cómo el endpoint convierte y procesa el parámetro. No debe interpretarse como una respuesta universal de todas las implementaciones seguras.

## Lecciones aprendidas

- Las consultas SQL no deben construirse mediante concatenación o interpolación de entradas no confiables.
- Las consultas parametrizadas separan los valores de la estructura SQL.
- La validación de tipos de datos puede complementar la protección, pero no sustituye la parametrización adecuada.
- Las pruebas de mitigación deben repetir el escenario que permitió reproducir originalmente la vulnerabilidad.

---

# 3. Almacenamiento inseguro de contraseñas

## Descripción

El almacenamiento inseguro de contraseñas ocurre cuando una aplicación guarda las contraseñas de manera inadecuada, por ejemplo, en texto plano.

Las contraseñas no deben almacenarse directamente ni protegerse mediante cifrado reversible como sustituto del hashing de contraseñas. Deben utilizarse algoritmos especializados como Argon2id, bcrypt o scrypt.

Este laboratorio compara dos implementaciones: una versión vulnerable que almacena contraseñas en texto plano y una versión protegida que utiliza Argon2id.

## 3.1. Implementación vulnerable

### Endpoints

```http
POST /register
POST /login
```

La implementación vulnerable almacena directamente la contraseña proporcionada por el usuario:

```python
cursor.execute(
    "INSERT INTO users (username, password_plaintext) VALUES (?, ?)",
    (username, password)
)
```

La consulta utiliza parámetros SQL, pero esto no protege la contraseña almacenada.

La estructura conceptual de la tabla es:

```text
users
├── id
├── username
└── password_plaintext
```

Por ejemplo, una fila podría contener:

```text
username: example
password_plaintext: mypassword123
```

### Causa raíz

La causa raíz es almacenar la contraseña original en lugar de un hash generado mediante un algoritmo especializado para contraseñas.

Una consulta SQL parametrizada puede prevenir determinadas formas de inyección SQL y, aun así, dejar las credenciales expuestas en la base de datos.

### Prueba de concepto

Si se puede acceder a la base de datos del laboratorio, se puede consultar la tabla:

```sql
SELECT id, username, password_plaintext
FROM users;
```

Si las contraseñas originales aparecen en los resultados, esto demuestra que la implementación almacena credenciales en texto plano.

### Impacto potencial

Si una persona no autorizada obtiene una copia de la base de datos, podría leer directamente las contraseñas almacenadas. El impacto también podría extenderse a otros servicios si los usuarios reutilizan sus credenciales.

## 3.2. Implementación segura con Argon2id

### Endpoints

```http
POST /register-secure
POST /login-secure
```

La implementación protegida utiliza `argon2-cffi` y `PasswordHasher`.

Antes de almacenar una contraseña, la aplicación genera su hash:

```python
password_hash = password_hasher.hash(password)
```

La estructura conceptual de la tabla es:

```text
users_secure
├── id
├── username
└── password_hash
```

Un valor almacenado tiene una estructura similar a:

```text
$argon2id$v=19$m=65536,t=3,p=4$...
```

Este es un ejemplo ilustrativo; el hash y los parámetros exactos dependen de la configuración.

Argon2id genera una representación hash que incluye sus parámetros y su salt. La aplicación no necesita almacenar la contraseña original para verificarla posteriormente.

### Verificación de la contraseña

La implementación utiliza el verificador de Argon2id:

```python
password_hasher.verify(user[2], password)
```

Cuando la contraseña no coincide, la excepción correspondiente se gestiona explícitamente:

```python
except VerifyMismatchError:
    return {"error": "Incorrect password"}
```

No debería utilizarse un `except Exception` general para ocultar errores inesperados.

### Verificación documentada

Se probaron escenarios con contraseñas correctas e incorrectas. También se inspeccionó el contenido de `users_secure` para comprobar que se almacenaba un hash Argon2id, en lugar de la contraseña original.

### Comparación

| Característica | Implementación vulnerable | Implementación protegida |
|---|---|---|
| Tabla | `users` | `users_secure` |
| Contraseña almacenada | Texto plano | Hash Argon2id |
| Registro | `/register` | `/register-secure` |
| Inicio de sesión | `/login` | `/login-secure` |
| Verificación | Comparación directa | `PasswordHasher.verify()` |
| Contraseña original en la tabla | Sí | No |
| Salt | No se utiliza | Generado por el mecanismo de hashing |

**Estado documentado:** el laboratorio incluye ambas implementaciones y pruebas manuales para el registro, la autenticación y la inspección del almacenamiento.

## Lecciones aprendidas

- Las contraseñas no deben almacenarse en texto plano.
- El hashing de contraseñas no es lo mismo que el cifrado reversible.
- Argon2id está diseñado para aumentar el costo de los ataques de adivinación de contraseñas.
- Las consultas parametrizadas protegen contra determinados ataques SQL, pero no hacen seguro el almacenamiento de credenciales.
- Los errores de autenticación deben gestionarse sin ocultar fallos inesperados.

---

# 4. IDOR / Control de acceso deficiente

## Descripción

Insecure Direct Object Reference (IDOR) es una vulnerabilidad de control de acceso que puede aparecer cuando una aplicación permite solicitar un recurso mediante su identificador sin verificar si el usuario actual está autorizado para acceder a él.

Los laboratorios IDOR de este proyecto amplían el análisis más allá de la comprobación de propiedad para incluir autenticación JWT, roles y permisos.

Los cuatro módulos establecidos son:

1. IDOR básico.
2. IDOR con autenticación segura.
3. Autorización basada en roles.
4. Autorización basada en permisos.

## 4.1. IDOR básico

### Endpoints

```http
POST /login-idor-basic
GET /accounts-vulnerable/{account_id}
GET /accounts-protected/{account_id}
```

Este módulo compara un endpoint vulnerable con otro que comprueba la propiedad de la cuenta.

### Causa raíz

La implementación vulnerable permite que un usuario autenticado solicite una cuenta mediante su identificador sin comprobar si esa cuenta le pertenece.

En los datos de prueba del laboratorio, Juan corresponde al usuario `1` y María al usuario `2`.

### Prueba de concepto

Juan inicia sesión y obtiene un token de acceso para las pruebas.

Al solicitar la cuenta de María mediante el endpoint vulnerable:

```http
GET /accounts-vulnerable/2
```

la aplicación devuelve la información de la cuenta, aunque Juan no sea su propietario.

La solicitud equivalente al endpoint protegido:

```http
GET /accounts-protected/2
```

devuelve `403 Forbidden` cuando se utiliza el token de Juan.

### Mitigación

El endpoint protegido comprueba si el identificador de la cuenta solicitada corresponde al usuario autenticado.

La identidad utilizada para esta comprobación debe proceder de un mecanismo de autenticación validado por el servidor, no de un identificador que el cliente pueda modificar libremente.

### Resultados observados

| Escenario | Resultado |
|---|---|
| Juan solicita la cuenta de María mediante el endpoint vulnerable | `200 OK` |
| Juan solicita la cuenta de María mediante el endpoint protegido | `403 Forbidden` |
| Juan intenta iniciar sesión con una contraseña incorrecta | `401 Unauthorized` |

Estos resultados corresponden a las pruebas manuales y automatizadas realizadas en el laboratorio.

## 4.2. IDOR con autenticación segura y JWT

### Endpoints

```http
POST /login-idor-secure
GET /me-idor-secure
GET /accounts-idor-secure/{account_id}
```

Este módulo introduce controles adicionales:

- Verificación de contraseñas mediante Argon2id.
- Validación de la firma JWT.
- Validación de la expiración del token.
- Validación del identificador de usuario incluido en el token.
- Comprobación de la existencia del usuario.
- Verificación de la propiedad de la cuenta solicitada.

### Pruebas realizadas

| Escenario | Resultado |
|---|---|
| Inicio de sesión con credenciales válidas | `200 OK` |
| Inicio de sesión con contraseña incorrecta | `401 Unauthorized` |
| Solicitud de perfil con un token válido | `200 OK` |
| Acceso a la cuenta propia | `200 OK` |
| Acceso a la cuenta de otro usuario | `403 Forbidden` |
| Solicitud protegida sin token | `401 Unauthorized` |

Estos escenarios ilustran la diferencia entre autenticar a un usuario y autorizar su acceso a un recurso.

Un JWT válido no concede automáticamente acceso a todas las cuentas. La aplicación también debe verificar los permisos aplicables a cada recurso.

## 4.3. Autorización basada en roles

### Endpoints

```http
POST /login-idor-roles
GET /me-idor-roles
GET /user-area-idor-roles
GET /admin-area-idor-roles
```

Este módulo demuestra el **control de acceso basado en roles (RBAC, por sus siglas en inglés)**.

La identidad autenticada se representa mediante un objeto `CurrentUser` que contiene información como el identificador del usuario, el nombre de usuario y el rol.

La autorización administrativa se aplica mediante una dependencia que comprueba el rol requerido.

### Usuarios de prueba

| Usuario | Rol |
|---|---|
| Juan | `user` |
| María | `admin` |

### Pruebas realizadas

| Escenario | Resultado |
|---|---|
| Juan consulta su identidad y rol | `200 OK` |
| Juan accede al área de usuarios | `200 OK` |
| Juan intenta acceder al área administrativa | `403 Forbidden` |
| María accede al área administrativa | `200 OK` |
| Solicitud protegida sin token | `401 Unauthorized` |

### Lección aprendida

Los roles permiten agrupar permisos y simplificar determinadas decisiones de autorización. Sin embargo, asignar un rol no elimina la necesidad de verificar la identidad y validar el acceso a los recursos correspondientes.

## 4.4. Autorización basada en permisos

### Endpoints

```http
POST /login-idor-permissions
GET /my-profile-idor-permissions
GET /audit-logs-idor-permissions
GET /manage-users-idor-permissions
```

Este módulo amplía el control de acceso basado en roles mediante permisos específicos almacenados en SQLite.

La autorización se determina mediante la relación entre roles y permisos, utilizando las tablas `roles`, `permissions` y `role_permissions`.

Los permisos incluidos en el laboratorio son:

```text
read_own_profile
read_audit_logs
manage_users
```

### Comportamiento esperado

- Juan tiene permiso para consultar su propio perfil.
- Juan no tiene permiso para consultar los registros de auditoría.
- Juan no tiene permiso para administrar usuarios.
- María, con el rol `admin`, puede acceder a los endpoints administrativos probados.

### Pruebas realizadas

| Escenario | Resultado |
|---|---|
| Juan consulta su perfil | `200 OK` |
| Juan solicita los registros de auditoría | `403 Forbidden` |
| Juan intenta administrar usuarios | `403 Forbidden` |
| María consulta los registros de auditoría | `200 OK` |
| María accede a la administración de usuarios | `200 OK` |
| Solicitud protegida sin token | `401 Unauthorized` |

### Lecciones aprendidas sobre IDOR

- La autenticación identifica al usuario; la autorización determina qué puede hacer.
- Conocer un identificador válido no concede permiso para acceder a un recurso.
- Un token válido no sustituye las comprobaciones de propiedad ni los controles de autorización.
- Los roles y los permisos son mecanismos diferentes, pero complementarios.
- Las decisiones de autorización deben aplicarse en el servidor.
- Una respuesta observada `403 Forbidden` demuestra el rechazo de ese escenario específico, no que toda la aplicación esté libre de fallos de autorización.

---

# 5. Estructura de pruebas

Las pruebas automatizadas están separadas de los módulos funcionales en el directorio `tests/`.

```text
tests/
├── test_idor_basico.py
├── test_idor_autenticacion_segura.py
├── test_idor_identidad_roles.py
├── test_idor_permisos.py
└── test_integracion_idor.py
```

## Pruebas individuales

| Archivo | Propósito |
|---|---|
| `test_idor_basico.py` | Verificar la diferencia entre el acceso vulnerable y la aplicación de controles de propiedad. |
| `test_idor_autenticacion_segura.py` | Verificar autenticación, JWT, acceso al perfil y propiedad de las cuentas. |
| `test_idor_identidad_roles.py` | Verificar el acceso basado en roles. |
| `test_idor_permisos.py` | Verificar permisos concedidos y denegados. |
| `test_integracion_idor.py` | Ejecutar una comprobación integrada de los cuatro módulos IDOR. |

Las pruebas utilizan `TestClient` para enviar solicitudes HTTP a la aplicación y verificar las respuestas esperadas.

## Ejecución de las pruebas

Desde la raíz del proyecto, con el entorno virtual activado, ejecuta cada archivo individualmente:

```powershell
python .\tests\test_idor_basico.py
python .\tests\test_idor_autenticacion_segura.py
python .\tests\test_idor_identidad_roles.py
python .\tests\test_idor_permisos.py
python .\tests\test_integracion_idor.py
```

Los cinco archivos finalizaron correctamente durante las ejecuciones documentadas del laboratorio.

**Importante:** estas pruebas validan los escenarios implementados y probados. No sustituyen una auditoría exhaustiva, una revisión de todas las rutas ni pruebas de seguridad completas.

---

# 6. Documentación de pruebas manuales

La guía de pruebas manuales está disponible en:

```text
docs/
└── guia_pruebas_manuales_idor.md
```

Incluye:

- Descripciones de los módulos IDOR.
- Usuarios de prueba del laboratorio.
- Procedimientos para enviar solicitudes mediante Swagger UI.
- Resultados esperados y observados.
- Interpretación de códigos de estado HTTP.
- Conclusiones de las pruebas.

Esta guía complementa las pruebas automatizadas y permite reproducir manualmente los principales escenarios.

---

# 7. Ejecución local

## Requisitos

- Python compatible con las dependencias del proyecto.
- PowerShell o una terminal equivalente.
- Visual Studio Code u otro editor de código.
- Dependencias definidas en `requirements.txt`.

## Crear y activar el entorno virtual

Desde la raíz del proyecto, crea el entorno virtual si todavía no existe:

```powershell
python -m venv .venv
```

Actívalo:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Instalar las dependencias

Con el entorno virtual activado:

```powershell
python -m pip install -r requirements.txt
```

## Iniciar la aplicación

Desde la raíz del proyecto:

```powershell
python -m uvicorn main:app --reload
```

La aplicación normalmente estará disponible en:

```text
http://127.0.0.1:8000
```

La documentación interactiva de FastAPI estará disponible en:

```text
http://127.0.0.1:8000/docs
```

Swagger UI permite seleccionar endpoints, introducir parámetros y enviar solicitudes manuales.

Para detener el servidor, pulsa `Ctrl + C` en la terminal donde se está ejecutando.

---

# 8. Bases de datos y datos de prueba

El proyecto utiliza SQLite para almacenar los datos de los distintos laboratorios.

La base de datos `auth_lab.db` contiene datos de prueba utilizados por los módulos IDOR establecidos, incluidas tablas relacionadas con usuarios, credenciales, cuentas, roles y permisos.

Los usuarios de laboratorio documentados son:

| Usuario | Contraseña del laboratorio | Rol |
|---|---|---|
| Juan | `LabUser_2026!` | `user` |
| María | `LabAdmin_2026!` | `admin` |

Estas credenciales son exclusivamente para el entorno educativo local. No deben reutilizarse en cuentas personales ni en servicios reales.

Las contraseñas se almacenan como hashes Argon2id en la base de datos de autenticación.

**Precaución:** no ejecutes el inicializador de `auth_database.py` sobre una base de datos existente si su implementación impide sobrescribirla. Antes de cualquier operación que pueda modificar o recrear una base de datos, comprueba los archivos actuales y realiza una copia de seguridad cuando corresponda.

---

# 9. Principios de seguridad estudiados

Los laboratorios cubren los siguientes principios:

1. **Validación y tratamiento de entradas:** los datos no confiables deben procesarse de acuerdo con su uso previsto.
2. **Codificación de salida:** los datos insertados en HTML deben tratarse según el contexto de salida.
3. **Consultas parametrizadas:** los valores no confiables deben mantenerse separados de la estructura SQL.
4. **Almacenamiento seguro de contraseñas:** deben utilizarse algoritmos especializados de hashing de contraseñas.
5. **Autenticación segura:** las credenciales y los tokens deben validarse antes de permitir operaciones protegidas.
6. **Control de acceso:** cada solicitud debe verificar si el usuario está autorizado para acceder al recurso solicitado.
7. **Mínimo privilegio:** los usuarios deben recibir únicamente los permisos que necesitan.
8. **Pruebas de seguridad:** las vulnerabilidades y sus mitigaciones deben verificarse mediante escenarios reproducibles.

---

# 10. Mejoras futuras

El proyecto continúa en desarrollo. Entre las áreas de expansión progresiva se encuentran:

- Pruebas automatizadas adicionales para XSS, SQL Injection y almacenamiento de contraseñas.
- Más casos de prueba negativos para autenticación y autorización.
- Validación de entradas y manejo coherente de errores.
- Registro de eventos de seguridad relevantes.
- Seguridad de API y controles de acceso a nivel de objeto.
- Análisis estático de código y análisis de dependencias.
- Integración de pruebas de seguridad en CI/CD.
- Fundamentos de DevSecOps.
- Introducción a la seguridad de aplicaciones blockchain y contratos inteligentes.

La prioridad es ampliar las capacidades del laboratorio mediante módulos y pruebas controlados, conservando los ejemplos vulnerables como material educativo y manteniendo las implementaciones de aprendizaje separadas de las alternativas protegidas.

---

## Alcance y limitaciones

Security Cyber Lab es un proyecto educativo y de portafolio. Las vulnerabilidades reproducidas y las mitigaciones verificadas se limitan a los escenarios descritos y probados.

La existencia de una implementación protegida no demuestra, por sí sola, que una aplicación sea completamente segura. Una evaluación más amplia requiere revisar el código, la configuración, las rutas relevantes, los controles de autorización y los posibles escenarios de abuso.

**Objetivo a largo plazo:** construir una base práctica y verificable en seguridad de aplicaciones, avanzando desde la comprensión de vulnerabilidades individuales hasta la implementación y validación de controles de seguridad.