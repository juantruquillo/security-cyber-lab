# Security Cyber Lab

**Security Cyber Lab** es un laboratorio práctico de aprendizaje en ciberseguridad desarrollado con Python, FastAPI y SQLite.

El proyecto está diseñado para estudiar vulnerabilidades comunes de aplicaciones web mediante endpoints intencionalmente vulnerables, implementaciones seguras, pruebas automatizadas y ejercicios de pruebas manuales.

El laboratorio forma parte de un portafolio personal de ciberseguridad enfocado en comprender las vulnerabilidades desde las perspectivas del **atacante y el defensor**.

[English](README.md)

---

## Tabla de contenidos

- [Objetivos del proyecto](#objetivos-del-proyecto)
- [Tecnologías](#tecnologías)
- [Módulos de seguridad](#módulos-de-seguridad)
  - [Reflected XSS](#1-reflected-xss)
  - [SQL Injection](#2-sql-injection)
  - [Almacenamiento inseguro de contraseñas](#3-almacenamiento-inseguro-de-contraseñas)
  - [IDOR y Broken Access Control](#4-idor-y-broken-access-control)
- [Pruebas automatizadas](#pruebas-automatizadas)
- [Pruebas manuales](#pruebas-manuales)
- [Ejecución local con Python](#ejecución-local-con-python)
- [Ejecución con Docker](#ejecución-con-docker)
- [Bases de datos y datos de prueba](#bases-de-datos-y-datos-de-prueba)
- [Conceptos de seguridad estudiados](#conceptos-de-seguridad-estudiados)
- [Mejoras futuras](#mejoras-futuras)
- [Alcance y limitaciones](#alcance-y-limitaciones)
- [Aviso de seguridad](#aviso-de-seguridad)

---

## Objetivos del proyecto

Los principales objetivos de Security Cyber Lab son:

- Desarrollar conocimientos prácticos de ciberseguridad mediante la experimentación.
- Comprender el funcionamiento de vulnerabilidades web comunes.
- Comparar implementaciones vulnerables con alternativas seguras.
- Practicar la identificación y explotación de vulnerabilidades en un entorno controlado.
- Desarrollar pruebas automatizadas orientadas a la seguridad.
- Documentar conceptos y procedimientos de pruebas de seguridad.
- Construir un portafolio práctico de ciberseguridad.

El proyecto avanza progresivamente desde vulnerabilidades fundamentales hacia escenarios más estructurados de autenticación y autorización.

---

## Tecnologías

- **Python**
- **FastAPI**
- **SQLite**
- **JWT**
- **Argon2id**
- **Pytest**
- **HTTPX2**, para las pruebas mediante el cliente de pruebas utilizado por el proyecto
- **PowerShell**, para la ejecución y las pruebas locales
- **Docker**
- **Docker Compose**

---

# Módulos de seguridad

## 1. Reflected XSS

El módulo de XSS demuestra una vulnerabilidad de **Cross-Site Scripting reflejado (Reflected XSS)**.

El endpoint vulnerable refleja directamente información controlada por el usuario dentro de una respuesta HTML.

### Endpoint vulnerable

```text
GET /hello-html
```

El módulo demuestra por qué los datos no confiables no deben insertarse directamente en una respuesta HTML.

La alternativa segura utiliza *HTML escaping* para codificar los datos controlados por el usuario antes de incluirlos en la respuesta.

### Conceptos de seguridad

- Reflected XSS
- Datos no confiables
- Codificación de salida
- HTML escaping
- Inyección de código del lado del cliente

---

## 2. SQL Injection

El módulo de SQL Injection demuestra la diferencia entre construir consultas SQL dinámicamente y utilizar consultas parametrizadas.

### Endpoint vulnerable

```text
GET /users-vulnerable/{user_id}
```

La implementación vulnerable permite que la entrada del usuario forme parte de la sentencia SQL.

Por ejemplo, una entrada como:

```text
1 OR 1=1
```

puede modificar la lógica prevista de la consulta SQL.

### Endpoint seguro

```text
GET /users-safe/{user_id}
```

La implementación segura utiliza una consulta SQLite parametrizada, haciendo que la entrada del usuario sea tratada como datos y no como sintaxis SQL ejecutable.

### Conceptos de seguridad

- SQL Injection
- Manipulación de consultas SQL
- Consultas parametrizadas
- Validación y manejo de entradas
- Acceso seguro a bases de datos

---

## 3. Almacenamiento inseguro de contraseñas

Este módulo demuestra los riesgos de almacenar contraseñas directamente y compara ese enfoque con el almacenamiento mediante funciones de *hashing*.

### Endpoints vulnerables

```text
POST /register
POST /login
```

La implementación vulnerable almacena las contraseñas en texto plano.

### Endpoints seguros

```text
POST /register-secure
POST /login-secure
```

La implementación segura utiliza **Argon2id** para generar hashes de contraseñas.

El objetivo es demostrar por qué las contraseñas nunca deben almacenarse en texto plano y por qué deben utilizarse algoritmos de hashing diseñados específicamente para proteger credenciales.

### Conceptos de seguridad

- Almacenamiento de contraseñas en texto plano
- Password hashing
- Argon2id
- Autenticación
- Protección de credenciales

---

## 4. IDOR y Broken Access Control

La sección de IDOR amplía el laboratorio hacia escenarios de autenticación y autorización.

Contiene varias implementaciones progresivamente más seguras que cubren:

- IDOR básico
- Autenticación mediante JWT
- Validación de identidad y roles
- Autorización basada en permisos

Los módulos permiten observar la diferencia entre:

1. Identificar a un usuario.
2. Autenticar a un usuario.
3. Determinar la identidad del usuario a partir de una solicitud autenticada.
4. Determinar qué recursos está autorizado a consultar o utilizar ese usuario.

### Conceptos de seguridad

- IDOR (*Insecure Direct Object Reference*)
- Broken Access Control
- Autenticación
- Autorización
- JWT
- Roles
- Permisos
- Propiedad de recursos

---

# Pruebas automatizadas

El proyecto incluye pruebas automatizadas que verifican el comportamiento de los módulos de IDOR y sus diferentes implementaciones de seguridad.

Los scripts disponibles son:

```text
tests/
├── test_idor_basico.py
├── test_idor_autenticacion_segura.py
├── test_idor_identidad_roles.py
├── test_idor_permisos.py
└── test_integracion_idor.py
```

### Ejecutar las pruebas localmente

Desde PowerShell, con el entorno virtual activado, ejecuta:

```powershell
python -m pytest tests/ -v
```

También puedes ejecutar cada script individualmente:

```powershell
python .\tests\test_idor_basico.py
python .\tests\test_idor_autenticacion_segura.py
python .\tests\test_idor_identidad_roles.py
python .\tests\test_idor_permisos.py
python .\tests\test_integracion_idor.py
```

### Ejecutar las pruebas dentro de Docker

Con el contenedor en ejecución:

```powershell
docker compose exec cyber-lab python -m pytest tests/ -v
```

Durante la validación del entorno Docker, la suite automatizada ejecutó correctamente **24 pruebas: 24 aprobadas**.

Este resultado corresponde a esa ejecución de validación; puedes volver a ejecutar las pruebas después de realizar cambios para comprobar que el comportamiento esperado se mantiene.

---

# Pruebas manuales

El repositorio incluye una guía para realizar pruebas manuales sobre los módulos de IDOR:

```text
docs/guia_pruebas_manuales_idor.md
```

La guía proporciona una forma estructurada de interactuar con los endpoints y observar las diferencias entre las implementaciones vulnerables y protegidas.

Las pruebas manuales son importantes porque permiten observar directamente el comportamiento de seguridad y no depender exclusivamente de las pruebas automatizadas.

---

# Ejecución local con Python

Esta alternativa permite ejecutar la aplicación directamente desde el entorno Python del proyecto.

## 1. Clonar el repositorio

```powershell
git clone https://github.com/juantruquillo/security-cyber-lab.git
cd security-cyber-lab
```

## 2. Activar el entorno virtual

Si el entorno virtual ya existe:

```powershell
.\.venv\Scripts\Activate.ps1
```

## 3. Instalar las dependencias

```powershell
pip install -r requirements.txt
```

## 4. Configurar las variables de entorno

El proyecto utiliza un archivo `.env` para configurar variables de entorno, incluida la clave utilizada para firmar los tokens JWT.

Asegúrate de tener configurada la variable `JWT_SECRET_KEY` con un valor secreto y adecuado para el entorno local. No publiques la clave real en el repositorio.

## 5. Iniciar la aplicación FastAPI

```powershell
python -m uvicorn main:app --reload
```

La aplicación estará disponible en:

```text
http://127.0.0.1:8000/
```

La documentación interactiva de la API estará disponible en:

```text
http://127.0.0.1:8000/docs
```

---

# Ejecución con Docker

Security Cyber Lab también puede ejecutarse dentro de un contenedor Docker. Esta alternativa ayuda a mantener un entorno de ejecución consistente y facilita la puesta en marcha del laboratorio.

## Requisitos previos

- Windows, Linux o macOS compatible con Docker.
- Docker Desktop instalado y en ejecución en Windows o macOS, o Docker Engine en Linux.
- Docker Compose disponible.
- Los archivos del proyecto y la configuración local necesarios para iniciar la aplicación.

En Windows, Docker Desktop puede utilizar el backend de WSL 2.

## 1. Configurar las variables de entorno

El archivo `.env` debe encontrarse en la raíz del proyecto, junto a `compose.yaml`.

Debe incluir la variable `JWT_SECRET_KEY` con una clave secreta local. Por ejemplo, la siguiente línea representa únicamente un marcador de posición:

```dotenv
JWT_SECRET_KEY=replace_with_a_local_secret_key
```

Sustituye el valor de ejemplo por una clave propia antes de iniciar la aplicación. No compartas la clave real ni la incluyas en el repositorio.

Docker Compose lee este archivo para proporcionar las variables de entorno al contenedor. El archivo `.env` está excluido del contexto de construcción mediante `.dockerignore`, por lo que no se copia dentro de la imagen.

## 2. Construir la imagen e iniciar el contenedor

Desde la carpeta raíz del proyecto, ejecuta:

```powershell
docker compose up -d --build
```

Este comando construye la imagen cuando es necesario e inicia el servicio en segundo plano.

## 3. Comprobar el estado del contenedor

```powershell
docker compose ps
```

Para consultar los registros de la aplicación:

```powershell
docker compose logs -f cyber-lab
```

Para dejar de seguir los registros, utiliza `Ctrl + C`. Esto no detiene el contenedor.

## 4. Acceder a la aplicación

La aplicación estará disponible en:

```text
http://127.0.0.1:8000/
```

La documentación interactiva de FastAPI estará disponible en:

```text
http://127.0.0.1:8000/docs
```

El servicio está configurado para escuchar únicamente en la interfaz local del equipo mediante el mapeo de puertos de Docker Compose. Esta configuración ayuda a evitar que los endpoints deliberadamente vulnerables queden expuestos directamente a otras interfaces de red.

## 5. Ejecutar las pruebas dentro del contenedor

```powershell
docker compose exec cyber-lab python -m pytest tests/ -v
```

Este comando ejecuta la suite de pruebas dentro del contenedor en ejecución.

## 6. Detener el laboratorio

```powershell
docker compose down
```

Este comando detiene y elimina el contenedor del servicio. No elimina los archivos SQLite locales que están montados en el contenedor.

Para volver a iniciar el laboratorio:

```powershell
docker compose up -d
```

Si modificas el código o las dependencias que se copian a la imagen, vuelve a construirla:

```powershell
docker compose up -d --build
```

---

# Bases de datos y datos de prueba

El laboratorio utiliza bases de datos SQLite para sus escenarios educativos.

Entre los archivos utilizados por la configuración Docker se encuentran:

```text
auth_lab.db
security_lab.db
```

Estas bases de datos contienen datos de prueba destinados exclusivamente a la experimentación local.

La configuración de Docker Compose monta los archivos SQLite locales dentro del contenedor. Por tanto, los datos almacenados en esos archivos permanecen en el equipo anfitrión y no dependen del ciclo de vida del contenedor.

Esto permite detener, eliminar o recrear el contenedor sin eliminar los archivos de base de datos locales montados.

Los archivos de bases de datos están excluidos del control de versiones y del contexto de construcción de Docker.

**Importante:** utiliza únicamente datos ficticios en el laboratorio. No almacenes información personal real, credenciales de producción ni información sensible en estas bases de datos.

---

# Conceptos de seguridad estudiados

Actualmente, Security Cyber Lab aborda conceptos como:

- Cross-Site Scripting reflejado (XSS)
- SQL Injection
- Consultas SQL parametrizadas
- Password hashing
- Argon2id
- Autenticación
- JWT
- IDOR
- Broken Access Control
- Identidad del usuario
- Autorización basada en roles
- Autorización basada en permisos
- Propiedad de recursos
- Pruebas automatizadas de seguridad
- Pruebas manuales de API
- Ejecución de aplicaciones con Docker
- Gestión de variables de entorno
- Persistencia de datos mediante volúmenes y montajes de Docker

El laboratorio está diseñado para relacionar cada vulnerabilidad con su correspondiente enfoque defensivo.

---

# Mejoras futuras

Entre las posibles incorporaciones futuras se encuentran:

- Nuevas pruebas automatizadas de seguridad.
- Validación de entradas.
- Registro de eventos orientado a la seguridad (*security logging*).
- Nuevos escenarios de seguridad para APIs.
- Integración de SAST (*Static Application Security Testing*).
- Análisis de vulnerabilidades de dependencias.
- Experimentación con DAST (*Dynamic Application Security Testing*).
- Controles de seguridad en CI/CD.
- Prácticas de DevSecOps.
- Nuevos escenarios de autenticación y autorización.
- Ejercicios de seguridad relacionados con blockchain y contratos inteligentes (*smart contracts*).

Estas mejoras se incorporarán progresivamente sin reemplazar innecesariamente los módulos educativos existentes.

---

# Alcance y limitaciones

Security Cyber Lab es un proyecto educativo y de portafolio personal. Su propósito es demostrar conceptos de seguridad mediante escenarios controlados, implementaciones vulnerables y alternativas defensivas.

La inclusión de Docker facilita la ejecución del laboratorio, pero **no convierte automáticamente las implementaciones vulnerables en seguras ni hace que el proyecto sea apropiado para producción**.

Las pruebas automatizadas verifican comportamientos específicos de los módulos implementados; no constituyen una auditoría completa ni garantizan que la aplicación esté libre de vulnerabilidades.

Las futuras mejoras permitirán ampliar progresivamente la cobertura de pruebas y los escenarios de seguridad estudiados.

---

# Aviso de seguridad

Security Cyber Lab contiene implementaciones vulnerables de manera intencional con fines educativos.

Los endpoints vulnerables deben ejecutarse y probarse únicamente en un entorno controlado en el que se tenga autorización para realizar pruebas de seguridad.

No despliegues las implementaciones deliberadamente vulnerables en producción ni las expongas a usuarios o redes no confiables.

La configuración Docker actual limita el puerto publicado a la interfaz local del equipo. Mantén esa restricción cuando ejecutes el laboratorio y evita modificarla para exponerlo a redes externas.

El proyecto está destinado a la **educación en ciberseguridad, la experimentación controlada y el desarrollo de un portafolio profesional**.