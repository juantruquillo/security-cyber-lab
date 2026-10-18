# Guía de pruebas manuales: vulnerabilidad IDOR

## 1. Objetivo

Esta guía explica cómo comprobar, mediante Swagger UI, distintos escenarios de control de acceso relacionados con la vulnerabilidad **IDOR (Insecure Direct Object Reference)**.

El laboratorio permite comparar una ruta vulnerable con una protegida y estudiar diferentes mecanismos de seguridad: autenticación, propiedad de recursos, roles y permisos.

**Entorno:** laboratorio local de ciberseguridad.

**Herramienta principal:** Swagger UI.

**URL local:** `http://127.0.0.1:8000/docs`

## 2. Conceptos fundamentales

### IDOR

IDOR ocurre cuando una aplicación permite acceder a un recurso utilizando un identificador manipulable sin verificar correctamente si el usuario tiene autorización para acceder a ese recurso.

Por ejemplo, Juan está autenticado y consulta la cuenta con identificador `1`, que le pertenece. Si cambia el identificador a `2` y la aplicación le devuelve la cuenta de María sin comprobar la propiedad, existe un fallo de autorización.

### Autenticación

Es el proceso mediante el cual la aplicación verifica la identidad del usuario.

### Autorización

Determina qué recursos y operaciones puede utilizar un usuario después de autenticarse.

### Códigos HTTP relevantes

- `200 OK`: la solicitud se procesó correctamente.
- `401 Unauthorized`: falta una autenticación válida o las credenciales no son válidas.
- `403 Forbidden`: el servidor rechaza la acción por falta de autorización.
- `422 Unprocessable Entity`: los datos enviados no cumplen la validación esperada.

## 3. Preparación del laboratorio

1. Inicia la aplicación FastAPI.
2. Abre `http://127.0.0.1:8000/docs`.
3. Localiza los endpoints del módulo que deseas probar.
4. Utiliza las credenciales de laboratorio indicadas para cada escenario.
5. Cuando un endpoint requiera autenticación, envía el token correspondiente al usuario de la prueba.

### Usuarios de laboratorio

**Juan — usuario normal**

- Usuario: `juan`
- Contraseña: `LabUser_2026!`
- Rol: `user`

**María — administradora**

- Usuario: `maria`
- Contraseña: `LabAdmin_2026!`
- Rol: `admin`

Estas credenciales son exclusivamente para el entorno educativo local. No deben reutilizarse en servicios reales.

## 4. Módulo 1: IDOR básico

### Objetivo

Comparar una ruta que no comprueba la propiedad del recurso con otra que sí aplica ese control.

### Prueba A: acceso vulnerable

1. Ejecuta `POST /login-idor-basic` con las credenciales de Juan.
2. Comprueba que el inicio de sesión devuelva `200 OK`.
3. Conserva el token obtenido.
4. Ejecuta `GET /accounts-vulnerable/{account_id}` con `account_id = 2`.
5. Utiliza el token de Juan.

**Resultado observado en el laboratorio:** `200 OK`. La respuesta indicó que el usuario autenticado era Juan y devolvió la cuenta `2`, cuyo correo era `maria@example.com`.

**Interpretación:** la ruta permitió consultar la cuenta de María sin comprobar su propiedad.

### Prueba B: acceso protegido

1. Ejecuta `GET /accounts-protected/{account_id}`.
2. Introduce `account_id = 2`.
3. Utiliza el mismo token de Juan.

**Resultado observado:** `403 Forbidden`.

Respuesta:

```json
{
  "detail": "No tienes permiso para acceder a esta cuenta."
}
```

**Interpretación:** el servidor rechazó el acceso a una cuenta que no pertenece al usuario autenticado.

## 5. Módulo 2: autenticación segura

### Objetivo

Comprobar la autenticación mediante token y el control de propiedad de las cuentas.

### Pruebas

1. Inicia sesión mediante `POST /login-idor-secure`.
2. Consulta `GET /me-idor-secure` utilizando el token obtenido.
3. Consulta `GET /accounts-idor-secure/1` como Juan.
4. Consulta `GET /accounts-idor-secure/2` con el mismo token.

### Resultados observados

| Prueba | Resultado |
|---|---|
| Inicio de sesión | `200 OK` |
| Perfil autenticado | `200 OK` |
| Cuenta propia, ID 1 | `200 OK` |
| Cuenta ajena, ID 2 | `403 Forbidden` |

**Interpretación:** la aplicación permitió el acceso a la cuenta propia y rechazó el acceso a la cuenta de María.

## 6. Módulo 3: identidad y roles

### Objetivo

Comprobar que las operaciones se habiliten o rechacen según el rol del usuario autenticado.

### Pruebas con Juan

1. Inicia sesión en `POST /login-idor-roles`.
2. Consulta `GET /me-idor-roles`.
3. Ejecuta `GET /user-area-idor-roles`.
4. Ejecuta `GET /admin-area-idor-roles`.

Resultados observados:

| Endpoint | Resultado |
|---|---|
| Perfil de Juan | `200 OK` |
| Área de usuarios | `200 OK` |
| Área administrativa | `403 Forbidden` |

La respuesta del área de usuarios identificó a Juan con el rol `user`.

### Pruebas con María

1. Inicia sesión en `POST /login-idor-roles` con las credenciales de María.
2. Utiliza el nuevo token de María.
3. Consulta `GET /admin-area-idor-roles`.
4. Consulta `GET /user-area-idor-roles`.

**Resultados observados:** ambos endpoints respondieron `200 OK`.

**Interpretación:** Juan no pudo acceder al área administrativa, mientras que María pudo acceder tanto al área administrativa como al área de usuarios.

## 7. Módulo 4: permisos

### Objetivo

Comprobar la autorización basada en permisos específicos, en lugar de depender exclusivamente del nombre del rol.

### Pruebas con Juan

1. Inicia sesión en `POST /login-idor-permissions`.
2. Consulta `GET /my-profile-idor-permissions`.
3. Consulta `GET /audit-logs-idor-permissions`.
4. Consulta `GET /manage-users-idor-permissions`.

Resultados observados:

| Endpoint | Permiso | Resultado |
|---|---|---|
| Perfil propio | `read_own_profile` | `200 OK` |
| Registros de auditoría | `read_audit_logs` | `403 Forbidden` |
| Gestión de usuarios | `manage_users` | `403 Forbidden` |

### Pruebas con María

1. Inicia sesión en `POST /login-idor-permissions`.
2. Utiliza el token de María.
3. Consulta `GET /audit-logs-idor-permissions`.
4. Consulta `GET /manage-users-idor-permissions`.

**Resultados observados:** ambos endpoints respondieron `200 OK`.

La respuesta de auditoría mostró dos eventos de ejemplo: un inicio de sesión exitoso y un acceso denegado. La respuesta de gestión mostró los usuarios Juan y María con sus respectivos roles.

Estos datos corresponden a las respuestas del módulo educativo y no deben interpretarse como un registro completo de todas las acciones realizadas en el laboratorio.

## 8. Conclusiones

Las pruebas permiten observar cuatro enfoques relacionados con el control de acceso:

1. **IDOR básico:** demuestra el riesgo de no comprobar la propiedad del recurso.
2. **Autenticación segura:** combina la identidad autenticada con la comprobación de propiedad.
3. **Control por roles:** permite o deniega operaciones según el rol del usuario.
4. **Control por permisos:** verifica autorizaciones específicas para cada acción.

Los resultados obtenidos coinciden con los comportamientos esperados para los escenarios probados. Esto valida los endpoints examinados, pero no constituye una auditoría exhaustiva de toda la aplicación.

## 9. Recomendaciones para estudiantes

- Realiza estas pruebas únicamente en el laboratorio autorizado.
- Cambia un parámetro a la vez para identificar su efecto.
- Conserva el token del usuario correcto para cada escenario.
- Compara las respuestas HTTP y el contenido de los cuerpos JSON.
- No confundas autenticación con autorización.
- Comprueba tanto los accesos permitidos como los denegados.
- Repite las pruebas después de modificar el código para verificar que los controles de seguridad continúen funcionando.
