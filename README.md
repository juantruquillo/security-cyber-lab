# Security Ciber Lab

Laboratorio práctico de **Application Security** desarrollado con Python y FastAPI para estudiar vulnerabilidades web y de API, comprender sus causas raíz, reproducirlas de forma controlada y comprobar mecanismos de mitigación.

El proyecto está orientado al aprendizaje progresivo de seguridad de aplicaciones. Incluye implementaciones vulnerables con fines educativos, versiones protegidas, pruebas manuales mediante Swagger UI y pruebas automatizadas.

> **Aviso:** este proyecto es un laboratorio educativo local. Las implementaciones vulnerables deben utilizarse únicamente en el entorno controlado del laboratorio, nunca como código de producción.

---

## Objetivos del proyecto

- Comprender cómo se originan las vulnerabilidades comunes en aplicaciones web y API.
- Reproducir vulnerabilidades mediante pruebas de concepto controladas.
- Comparar implementaciones vulnerables con sus versiones protegidas.
- Aplicar controles de autenticación y autorización.
- Comprender el funcionamiento de JWT, hashing de contraseñas, roles y permisos.
- Validar comportamientos esperados mediante pruebas automatizadas.
- Construir un portafolio práctico orientado a Application Security y, progresivamente, a pentesting.

## Tecnologías

- **Python:** lenguaje principal.
- **FastAPI:** desarrollo de API y endpoints de laboratorio.
- **Uvicorn:** servidor ASGI para ejecutar la aplicación.
- **SQLite:** almacenamiento de datos de los laboratorios.
- **JWT:** representación y validación de tokens de autenticación.
- **Argon2id:** hashing de contraseñas.
- **python-jose:** manejo y validación de tokens JWT.
- **argon2-cffi:** implementación de Argon2id.
- **python-dotenv:** carga de variables de entorno.
- **HTTPX:** cliente HTTP utilizado por las pruebas.
- **Swagger UI:** exploración y ejecución manual de solicitudes.
- **pytest / TestClient:** herramientas para ejecutar y validar pruebas automatizadas.

---

# 1. Reflected Cross-Site Scripting (XSS)

## Descripción

Cross-Site Scripting (XSS) es una vulnerabilidad que puede aparecer cuando una aplicación incorpora datos controlados por el usuario en una página web sin tratarlos correctamente para el contexto en el que se utilizan.

Este laboratorio estudia una variante de XSS reflejado mediante un parámetro incluido directamente en una respuesta HTML.

## Endpoint vulnerable

```http
GET /hello-html
```

Parámetro afectado:

```text
name
```

## Causa raíz

La implementación vulnerable inserta directamente el parámetro en el HTML:

```python
return f"<html><body><h1>Hola {name}</h1></body></html>"
```

El navegador interpreta el contenido de la respuesta como HTML. Por ello, una entrada que contiene etiquetas puede modificar la estructura de la página y, bajo las condiciones adecuadas, ejecutar JavaScript.

## Prueba de concepto

Payload utilizado:

```html
<script>alert(1)</script>
```

También se probó la interpretación de HTML arbitrario:

```html
<h1>HACKED</h1>
```

Durante las pruebas originales se observó que el navegador ejecutaba el JavaScript y mostraba el encabezado HTML.

## Impacto potencial

Dependiendo del contexto y de las protecciones de la aplicación, una vulnerabilidad XSS puede permitir:

- Manipular el contenido visible de una página.
- Ejecutar JavaScript en el contexto del sitio afectado.
- Realizar acciones en nombre del usuario bajo determinadas condiciones.
- Acceder a información disponible para los scripts de ese contexto.

La explotación real depende de factores como las cookies, los permisos del usuario, la política de seguridad de contenido (CSP) y las restricciones del navegador.

## Mitigación

Se aplicó escaping del contenido antes de incorporarlo al HTML:

```python
from html import escape

safe_name = escape(name)
return f"<html><body><h1>Hola {safe_name}</h1></body></html>"
```

La función `escape()` convierte determinados caracteres especiales en representaciones que el navegador interpreta como texto en lugar de como estructura HTML.

Esta solución corresponde al contexto HTML utilizado por el laboratorio. Otros contextos, como JavaScript, CSS o atributos HTML, requieren un tratamiento adecuado para cada contexto.

## Verificación

Los payloads originales se volvieron a probar después de la mitigación.

Resultados observados:

- El payload `<script>alert(1)</script>` apareció como texto.
- No se ejecutó `alert(1)`.
- El payload `<h1>HACKED</h1>` no creó un encabezado HTML; las etiquetas aparecieron como texto.

**Estado documentado: mitigación aplicada y verificada mediante las pruebas manuales realizadas.**

## Lecciones aprendidas

- Los datos proporcionados por el usuario deben considerarse no confiables.
- La validación de entrada no sustituye el escaping de salida.
- Reflejar una entrada en una respuesta no implica necesariamente que exista XSS.
- El tratamiento de los datos depende del contexto en el que se utilizan.
- Las mitigaciones deben verificarse nuevamente después de implementarse.

---

# 2. SQL Injection

## Descripción

SQL Injection es una vulnerabilidad que ocurre cuando una aplicación construye consultas SQL incorporando entradas no confiables de una forma que permite modificar la estructura de la consulta.

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

Cuando una entrada puede alterar la estructura de la consulta, la base de datos podría ejecutar una condición diferente de la que pretendía la aplicación.

## Prueba de concepto

Una solicitud normal:

```http
GET /users-vulnerable/1
```

permite consultar el usuario correspondiente al identificador `1`.

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

Este resultado demuestra la vulnerabilidad en el endpoint del laboratorio.

## Impacto potencial

Según la consulta, los permisos de la conexión y las funciones disponibles, una vulnerabilidad SQL Injection puede permitir:

- Acceder a registros que no deberían devolverse.
- Modificar o eliminar datos.
- Eludir determinados controles de la aplicación.
- Comprometer información almacenada en la base de datos.

El impacto concreto depende de las operaciones SQL disponibles y de los privilegios concedidos a la aplicación.

## Mitigación

La consulta se reemplazó por una consulta parametrizada:

```python
query = "SELECT id, username, email FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

Los parámetros se suministran por separado de la instrucción SQL. Así, la entrada se trata como un valor y no como parte de la estructura de la consulta.

## Endpoint protegido

```http
GET /users-safe/{user_id}
```

## Verificación

Se volvió a probar el valor:

```text
1 OR 1=1
```

En la prueba documentada, el endpoint protegido no devolvió los tres usuarios. La respuesta observada fue:

```json
{
  "users": []
}
```

Esto demuestra que el payload ya no producía el resultado de la explotación original.

La respuesta vacía depende de cómo el endpoint convierte y procesa el parámetro. No debe interpretarse como una regla universal para todas las implementaciones seguras.

## Lecciones aprendidas

- No se deben construir consultas SQL mediante concatenación o interpolación de entradas no confiables.
- Las consultas parametrizadas separan los valores de la estructura SQL.
- La validación del tipo de dato puede complementar la protección, pero no sustituye una consulta correctamente parametrizada.
- La prueba de mitigación debe repetir el escenario que permitió reproducir la vulnerabilidad.

---

# 3. Insecure Password Storage

## Descripción

Insecure Password Storage ocurre cuando una aplicación almacena contraseñas de manera inadecuada, por ejemplo, en texto plano.

Las contraseñas no deben almacenarse directamente ni mediante cifrado reversible como sustituto del hashing. Se recomienda utilizar algoritmos especializados para contraseñas, como Argon2id, bcrypt o scrypt.

Este laboratorio compara dos implementaciones: una vulnerable, que almacena contraseñas en texto plano, y otra que utiliza Argon2id.

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
username: ejemplo
password_plaintext: mypassword123
```

### Causa raíz

La causa raíz es guardar el valor original de la contraseña en lugar de almacenar un hash especializado para contraseñas.

Una consulta SQL parametrizada puede evitar una forma de SQL Injection y, al mismo tiempo, dejar las credenciales expuestas en la base de datos.

### Prueba de concepto

Si se tiene acceso a la base de datos del laboratorio, se puede consultar la tabla:

```sql
SELECT id, username, password_plaintext
FROM users;
```

Si aparecen las contraseñas originales, queda demostrado que la implementación almacena las credenciales en texto plano.

### Impacto potencial

Si una persona no autorizada obtiene una copia de la base de datos, podría leer directamente las contraseñas almacenadas. El impacto también puede extenderse a otros servicios si los usuarios reutilizan sus credenciales.

## 3.2. Implementación segura con Argon2id

### Endpoints

```http
POST /register-secure
POST /login-secure
```

La versión protegida utiliza `argon2-cffi` y `PasswordHasher`.

Antes de almacenar una contraseña, genera su hash:

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

El valor almacenado tiene una estructura similar a:

```text
$argon2id$v=19$m=65536,t=3,p=4$...
```

Este ejemplo es ilustrativo; los parámetros y el hash exacto dependen de la configuración utilizada.

Argon2id genera un hash con parámetros y salt incluidos en su representación. La aplicación no necesita almacenar la contraseña original para verificarla posteriormente.

### Verificación de la contraseña

La implementación utiliza el verificador de Argon2id:

```python
password_hasher.verify(user[2], password)
```

Cuando la contraseña no coincide, se controla específicamente la excepción correspondiente:

```python
except VerifyMismatchError:
    return {"error": "Contraseña incorrecta"}
```

Es importante no utilizar un `except Exception` demasiado amplio para ocultar errores inesperados.

### Verificación documentada

Se probaron los escenarios de contraseña correcta e incorrecta. También se inspeccionó el contenido de `users_secure` para comprobar que se almacenaba un hash Argon2id en lugar de la contraseña original.

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

**Estado documentado:** el laboratorio incluye ambas implementaciones y pruebas manuales de registro, autenticación e inspección del almacenamiento.

## Lecciones aprendidas

- Las contraseñas no deben almacenarse en texto plano.
- El hashing de contraseñas no es lo mismo que el cifrado reversible.
- Argon2id está diseñado para dificultar ataques de adivinación de contraseñas.
- Las consultas parametrizadas protegen contra ciertos ataques SQL, pero no hacen seguro el almacenamiento de credenciales.
- Los errores de autenticación deben controlarse sin ocultar fallos inesperados.

---

# 4. IDOR / Broken Access Control

## Descripción

Insecure Direct Object Reference (IDOR) es una vulnerabilidad de control de acceso que puede ocurrir cuando una aplicación permite solicitar un recurso mediante su identificador sin comprobar que el usuario actual tiene permiso para acceder a él.

En este proyecto, los laboratorios IDOR se han ampliado para estudiar no solo la comprobación de propiedad, sino también la autenticación mediante JWT, los roles y los permisos.

Los cuatro módulos consolidados son:

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

El módulo compara un endpoint vulnerable con otro que comprueba la propiedad de la cuenta.

### Causa raíz

La implementación vulnerable permite que un usuario autenticado solicite una cuenta mediante su identificador sin comprobar que esa cuenta le pertenece.

Con los datos de prueba del laboratorio, Juan corresponde al usuario `1` y María al usuario `2`.

### Prueba de concepto

Juan inicia sesión y obtiene un token de acceso para las pruebas.

Al solicitar la cuenta de María mediante el endpoint vulnerable:

```http
GET /accounts-vulnerable/2
```

la aplicación devuelve la información de esa cuenta, aunque Juan no sea su propietario.

La solicitud equivalente al endpoint protegido:

```http
GET /accounts-protected/2
```

devuelve `403 Forbidden` cuando se utiliza el token de Juan.

### Mitigación

El endpoint protegido comprueba que el identificador de la cuenta solicitada corresponde al usuario autenticado.

La identidad utilizada para esta comprobación debe proceder de un mecanismo de autenticación validado por el servidor, no de un identificador que el cliente pueda modificar libremente.

### Resultado observado

| Escenario | Resultado |
|---|---|
| Juan consulta la cuenta de María mediante el endpoint vulnerable | `200 OK` |
| Juan consulta la cuenta de María mediante el endpoint protegido | `403 Forbidden` |
| Juan utiliza una contraseña incorrecta al iniciar sesión | `401 Unauthorized` |

Estos resultados corresponden a las pruebas manuales y automatizadas ejecutadas en el laboratorio.

## 4.2. IDOR con autenticación segura y JWT

### Endpoints

```http
POST /login-idor-secure
GET /me-idor-secure
GET /accounts-idor-secure/{account_id}
```

Este módulo incorpora controles adicionales:

- Verificación de contraseñas mediante Argon2id.
- Validación de la firma del JWT.
- Validación de la expiración del token.
- Comprobación del identificador de usuario contenido en el token.
- Comprobación de la existencia del usuario.
- Verificación de la propiedad de la cuenta solicitada.

### Pruebas realizadas

| Escenario | Resultado |
|---|---|
| Inicio de sesión con credenciales válidas | `200 OK` |
| Inicio de sesión con contraseña incorrecta | `401 Unauthorized` |
| Consulta del perfil con token válido | `200 OK` |
| Acceso a la cuenta propia | `200 OK` |
| Acceso a la cuenta de otro usuario | `403 Forbidden` |
| Consulta protegida sin token | `401 Unauthorized` |

Estos escenarios permiten estudiar la diferencia entre autenticar al usuario y autorizar el acceso a un recurso.

Un JWT válido no concede automáticamente acceso a todas las cuentas: la aplicación debe verificar también los permisos aplicables a cada recurso.

## 4.3. Autorización basada en roles

### Endpoints

```http
POST /login-idor-roles
GET /me-idor-roles
GET /user-area-idor-roles
GET /admin-area-idor-roles
```

Este módulo representa la autorización basada en roles, también conocida como **Role-Based Access Control (RBAC)**.

La identidad autenticada se representa mediante un objeto `CurrentUser`, que incluye información como el identificador del usuario, el nombre de usuario y su rol.

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
| Juan accede al área de usuario | `200 OK` |
| Juan intenta acceder al área administrativa | `403 Forbidden` |
| María accede al área administrativa | `200 OK` |
| Solicitud protegida sin token | `401 Unauthorized` |

### Lección

Los roles permiten agrupar permisos y simplificar determinadas decisiones de autorización. Sin embargo, asignar un rol no elimina la necesidad de comprobar la identidad y validar el acceso a los recursos correspondientes.

## 4.4. Autorización basada en permisos

### Endpoints

```http
POST /login-idor-permissions
GET /my-profile-idor-permissions
GET /audit-logs-idor-permissions
GET /manage-users-idor-permissions
```

Este módulo amplía el control basado en roles mediante permisos específicos almacenados en SQLite.

La autorización se determina a partir de la relación entre roles y permisos, utilizando las tablas `roles`, `permissions` y `role_permissions`.

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
| Juan consulta los registros de auditoría | `403 Forbidden` |
| Juan intenta administrar usuarios | `403 Forbidden` |
| María consulta los registros de auditoría | `200 OK` |
| María consulta la administración de usuarios | `200 OK` |
| Solicitud protegida sin token | `401 Unauthorized` |

### Lecciones aprendidas sobre IDOR

- La autenticación identifica al usuario; la autorización determina qué puede hacer.
- Conocer un identificador válido no concede permiso para acceder al recurso.
- Un token válido no sustituye las comprobaciones de propiedad y autorización.
- Los roles y los permisos representan mecanismos distintos y complementarios.
- Las decisiones de autorización deben realizarse en el servidor.
- Un `403 Forbidden` observado en una prueba demuestra el rechazo de ese escenario concreto, no que toda la aplicación esté libre de fallos de autorización.

---

# 5. Estructura de pruebas

Las pruebas automatizadas se encuentran separadas de los módulos funcionales, en la carpeta `tests/`.

```text
tests/
├── test_idor_basico.py
├── test_idor_autenticacion_segura.py
├── test_idor_identidad_roles.py
├── test_idor_permisos.py
└── test_integracion_idor.py
```

## Pruebas individuales

| Archivo | Objetivo |
|---|---|
| `test_idor_basico.py` | Verificar la diferencia entre acceso vulnerable y control de propiedad. |
| `test_idor_autenticacion_segura.py` | Verificar autenticación, JWT, perfil y propiedad de las cuentas. |
| `test_idor_identidad_roles.py` | Verificar el acceso basado en roles. |
| `test_idor_permisos.py` | Verificar los permisos concedidos y denegados. |
| `test_integracion_idor.py` | Ejecutar una comprobación integrada de los cuatro módulos IDOR. |

Las pruebas utilizan `TestClient` para enviar solicitudes HTTP a la aplicación y comprobar las respuestas esperadas.

## Ejecutar las pruebas

Desde la raíz del proyecto y con el entorno virtual activado, ejecutar cada archivo individualmente:

```powershell
python .\tests\test_idor_basico.py
python .\tests\test_idor_autenticacion_segura.py
python .\tests\test_idor_identidad_roles.py
python .\tests\test_idor_permisos.py
python .\tests\test_integracion_idor.py
```

Los cinco archivos finalizaron correctamente durante las ejecuciones documentadas del laboratorio.

**Importante:** estas pruebas validan los escenarios implementados y comprobados. No sustituyen una auditoría integral, una revisión de todas las rutas ni pruebas de seguridad exhaustivas.

---

# 6. Documentación de pruebas manuales

La guía de pruebas manuales está disponible en:

```text
docs/
└── guia_pruebas_manuales_idor.md
```

Incluye:

- Descripción de los módulos IDOR.
- Usuarios de prueba del laboratorio.
- Procedimientos para ejecutar solicitudes desde Swagger UI.
- Resultados esperados y observados.
- Interpretación de los códigos HTTP.
- Conclusiones de las pruebas.

Esta guía complementa las pruebas automatizadas y permite reproducir manualmente los escenarios principales.

---

# 7. Ejecución local

## Requisitos

- Python compatible con las dependencias del proyecto.
- PowerShell o una terminal equivalente.
- Visual Studio Code u otro editor.
- Dependencias definidas en `requirements.txt`.

## Activar el entorno virtual

Desde la raíz del proyecto:

```powershell
.\.venv\Scripts\Activate.ps1
```

Si el entorno virtual todavía no existe, se puede crear con:

```powershell
python -m venv .venv
```

Después de crearlo, se activa mediante el primer comando.

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

La aplicación se ejecuta normalmente en:

```text
http://127.0.0.1:8000
```

La documentación interactiva de FastAPI está disponible en:

```text
http://127.0.0.1:8000/docs
```

Swagger UI permite seleccionar endpoints, introducir parámetros y enviar solicitudes manuales.

Para finalizar el servidor, utiliza `Ctrl + C` en la terminal donde se está ejecutando.

---

# 8. Bases de datos y datos de prueba

El proyecto utiliza SQLite para almacenar datos de los distintos laboratorios.

La base de datos `auth_lab.db` contiene los datos de prueba utilizados por los módulos IDOR consolidados, incluidas las tablas relacionadas con usuarios, credenciales, cuentas, roles y permisos.

Los usuarios de laboratorio documentados son:

| Usuario | Contraseña de laboratorio | Rol |
|---|---|---|
| Juan | `LabUser_2026!` | `user` |
| María | `LabAdmin_2026!` | `admin` |

Estas credenciales son exclusivamente para el entorno educativo local. No deben reutilizarse en cuentas personales ni en servicios reales.

Las contraseñas se almacenan mediante hashes Argon2id en la base de datos de autenticación.

**Precaución:** el inicializador de `auth_database.py` no debe ejecutarse de nuevo sobre una base de datos existente si su implementación rechaza sobrescribirla. Antes de cualquier operación que pueda modificar o recrear una base de datos, debe verificarse el estado de los archivos y realizarse una copia de seguridad cuando corresponda.

---

# 9. Principios de seguridad estudiados

A través de los laboratorios se estudian los siguientes principios:

1. **Validación y tratamiento de entradas:** las entradas no confiables deben procesarse según su uso.
2. **Output encoding:** los datos insertados en HTML deben tratarse según el contexto de salida.
3. **Consultas parametrizadas:** los valores no confiables deben separarse de la estructura SQL.
4. **Almacenamiento seguro de contraseñas:** deben utilizarse algoritmos especializados de hashing.
5. **Autenticación segura:** las credenciales y los tokens deben validarse antes de permitir operaciones protegidas.
6. **Control de acceso:** cada solicitud debe verificar si el usuario tiene permiso para acceder al recurso solicitado.
7. **Mínimo privilegio:** los usuarios deben recibir solamente los permisos necesarios.
8. **Pruebas de seguridad:** las vulnerabilidades y sus mitigaciones deben comprobarse con escenarios reproducibles.

---

# 10. Próximos pasos

El proyecto se encuentra en desarrollo. Entre las áreas que pueden ampliarse progresivamente están:

- Pruebas automatizadas adicionales para XSS, SQL Injection y almacenamiento de contraseñas.
- Casos negativos adicionales para autenticación y autorización.
- Validación de entradas y manejo consistente de errores.
- Registro de eventos relevantes de seguridad.
- Seguridad de APIs y controles de acceso a nivel de objeto.
- Análisis estático de código y análisis de dependencias.
- Integración de pruebas de seguridad en CI/CD.
- Fundamentos de DevSecOps.
- Introducción a seguridad de aplicaciones blockchain y contratos inteligentes.

La prioridad será ampliar las capacidades del laboratorio mediante módulos y pruebas controladas, conservando los ejemplos vulnerables como material educativo y manteniendo separadas las implementaciones de aprendizaje de las versiones protegidas.

---

## Alcance y limitaciones

Security Ciber Lab es un proyecto educativo y de portafolio. Las vulnerabilidades reproducidas y las mitigaciones verificadas se limitan a los escenarios descritos y probados.

La existencia de una versión protegida no demuestra por sí sola que una aplicación sea completamente segura. Una evaluación más amplia requiere revisar el código, la configuración, todas las rutas relevantes, los controles de autorización y los posibles escenarios de abuso.

**Objetivo final:** construir una base práctica y verificable en seguridad de aplicaciones, desde la comprensión de vulnerabilidades individuales hasta la implementación y validación de controles de seguridad.