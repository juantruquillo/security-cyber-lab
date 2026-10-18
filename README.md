# Security Cyber Lab

A hands-on **Application Security** laboratory built with Python and FastAPI to study web and API vulnerabilities, understand their root causes, reproduce them in a controlled environment, and verify mitigation mechanisms.

The project follows a progressive, practical approach to application security. It includes intentionally vulnerable implementations for educational purposes, protected alternatives, manual testing through Swagger UI, and automated tests.

**Language:** English | [Español](README.es.md)

> **Security notice:** This is a local educational laboratory. Intentionally vulnerable implementations must only be used in the controlled lab environment and must never be deployed as production code.

---

## Table of Contents

- [Project Goals](#project-goals)
- [Technologies](#technologies)
- [1. Reflected Cross-Site Scripting (XSS)](#1-reflected-cross-site-scripting-xss)
- [2. SQL Injection](#2-sql-injection)
- [3. Insecure Password Storage](#3-insecure-password-storage)
- [4. IDOR / Broken Access Control](#4-idor--broken-access-control)
  - [4.1. Basic IDOR](#41-basic-idor)
  - [4.2. IDOR with Secure Authentication and JWT](#42-idor-with-secure-authentication-and-jwt)
  - [4.3. Role-Based Authorization](#43-role-based-authorization)
  - [4.4. Permission-Based Authorization](#44-permission-based-authorization)
- [5. Test Structure](#5-test-structure)
- [6. Manual Testing Documentation](#6-manual-testing-documentation)
- [7. Running Locally](#7-running-locally)
- [8. Databases and Test Data](#8-databases-and-test-data)
- [9. Security Principles Studied](#9-security-principles-studied)
- [10. Future Improvements](#10-future-improvements)
- [Scope and Limitations](#scope-and-limitations)

---

## Project Goals

- Understand how common web application and API vulnerabilities originate.
- Reproduce vulnerabilities through controlled proof-of-concept tests.
- Compare vulnerable implementations with their protected alternatives.
- Apply authentication and authorization controls.
- Understand JWT, password hashing, roles, and permissions.
- Validate expected behavior through automated tests.
- Build a practical portfolio focused on Application Security and, progressively, penetration testing.

## Technologies

- **Python:** Main programming language.
- **FastAPI:** API development and laboratory endpoints.
- **Uvicorn:** ASGI server used to run the application.
- **SQLite:** Data storage for the laboratories.
- **JWT:** Authentication token representation and validation.
- **Argon2id:** Password hashing.
- **python-jose:** JWT handling and validation.
- **argon2-cffi:** Argon2id implementation.
- **python-dotenv:** Environment variable loading.
- **HTTPX:** HTTP client used by the tests.
- **Swagger UI:** Interactive exploration and manual request execution.
- **pytest / TestClient:** Tools for running and validating automated tests.

---

# 1. Reflected Cross-Site Scripting (XSS)

## Description

Cross-Site Scripting (XSS) is a vulnerability that can occur when an application incorporates user-controlled data into a web page without properly handling it for the context in which it is used.

This laboratory studies reflected XSS through a parameter that is incorporated into an HTML response.

## Vulnerable endpoint

```http
GET /hello-html
```

Affected parameter:

```text
name
```

## Root cause

The vulnerable implementation directly inserts the parameter into the HTML:

```python
return f"<html><body><h1>Hello {name}</h1></body></html>"
```

The browser interprets the response as HTML. Therefore, an input containing markup can alter the page structure and, under the appropriate conditions, execute JavaScript.

## Proof of concept

Payload used:

```html
<script>alert(1)</script>
```

HTML interpretation was also tested with:

```html
<h1>HACKED</h1>
```

During the original tests, the browser executed the JavaScript and displayed the HTML heading.

## Potential impact

Depending on the application context and its protections, an XSS vulnerability may allow an attacker to:

- Manipulate the visible content of a page.
- Execute JavaScript in the context of the affected website.
- Perform actions on behalf of a user under certain conditions.
- Access information available to scripts running in that context.

Actual exploitation depends on factors such as cookies, user privileges, Content Security Policy (CSP), and browser restrictions.

## Mitigation

The content was escaped before being incorporated into the HTML:

```python
from html import escape

safe_name = escape(name)
return f"<html><body><h1>Hello {safe_name}</h1></body></html>"
```

The `escape()` function converts certain special characters into representations that the browser interprets as text rather than HTML structure.

This solution applies to the HTML context used in this laboratory. Other contexts, such as JavaScript, CSS, or HTML attributes, require context-appropriate handling.

## Verification

The original payloads were tested again after the mitigation.

Observed results:

- The `<script>alert(1)</script>` payload appeared as text.
- `alert(1)` was not executed.
- The `<h1>HACKED</h1>` payload did not create an HTML heading; the tags appeared as text.

**Documented status:** Mitigation implemented and verified through the manual tests performed.

## Lessons learned

- User-provided data must be treated as untrusted.
- Input validation does not replace output escaping.
- Reflecting input in a response does not necessarily mean that XSS exists.
- Data handling depends on the context in which the data is used.
- Mitigations must be retested after implementation.

---

# 2. SQL Injection

## Description

SQL Injection is a vulnerability that occurs when an application constructs SQL queries using untrusted input in a way that allows the query structure to be modified.

This laboratory compares a vulnerable query with a parameterized query.

## Vulnerable endpoint

```http
GET /users-vulnerable/{user_id}
```

## Root cause

The vulnerable implementation constructs the query through direct interpolation:

```python
query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
```

When input can alter the query structure, the database may execute a condition different from the one intended by the application.

## Proof of concept

A normal request:

```http
GET /users-vulnerable/1
```

retrieves the user associated with identifier `1`.

The following value was then tested:

```text
1 OR 1=1
```

The resulting query was equivalent to:

```sql
SELECT id, username, email
FROM users
WHERE id = 1 OR 1=1;
```

Because the condition `1=1` is always true, the query returned all three users present in the test database.

This result demonstrates the vulnerability in the laboratory endpoint.

## Potential impact

Depending on the query, database connection privileges, and available operations, SQL Injection may allow an attacker to:

- Access records that should not be returned.
- Modify or delete data.
- Bypass certain application controls.
- Compromise information stored in the database.

The actual impact depends on the available SQL operations and the privileges granted to the application.

## Mitigation

The query was replaced with a parameterized query:

```python
query = "SELECT id, username, email FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

Parameters are supplied separately from the SQL statement. This allows input to be treated as a value rather than part of the query structure.

## Protected endpoint

```http
GET /users-safe/{user_id}
```

## Verification

The following value was tested again:

```text
1 OR 1=1
```

In the documented test, the protected endpoint did not return all three users. The observed response was:

```json
{
  "users": []
}
```

This demonstrates that the payload no longer produced the original exploitation result.

The empty response depends on how the endpoint converts and processes the parameter. It should not be interpreted as a universal response for every secure implementation.

## Lessons learned

- SQL queries must not be constructed through concatenation or interpolation of untrusted input.
- Parameterized queries separate values from SQL structure.
- Data type validation can complement protection but does not replace properly parameterized queries.
- Mitigation testing should repeat the scenario that originally reproduced the vulnerability.

---

# 3. Insecure Password Storage

## Description

Insecure Password Storage occurs when an application stores passwords improperly, for example, in plaintext.

Passwords must not be stored directly or protected with reversible encryption as a substitute for password hashing. Specialized password-hashing algorithms such as Argon2id, bcrypt, or scrypt should be used.

This laboratory compares two implementations: a vulnerable version that stores plaintext passwords and a protected version that uses Argon2id.

## 3.1. Vulnerable implementation

### Endpoints

```http
POST /register
POST /login
```

The vulnerable implementation stores the password supplied by the user directly:

```python
cursor.execute(
    "INSERT INTO users (username, password_plaintext) VALUES (?, ?)",
    (username, password)
)
```

The query uses SQL parameters, but this does not protect the stored password.

The conceptual table structure is:

```text
users
├── id
├── username
└── password_plaintext
```

For example, a row might contain:

```text
username: example
password_plaintext: mypassword123
```

### Root cause

The root cause is storing the original password instead of a specialized password hash.

A parameterized SQL query can prevent a form of SQL Injection while still leaving credentials exposed in the database.

### Proof of concept

If the laboratory database is accessible, the table can be queried:

```sql
SELECT id, username, password_plaintext
FROM users;
```

If the original passwords appear in the results, this demonstrates that the implementation stores credentials in plaintext.

### Potential impact

If an unauthorized person obtains a copy of the database, they may be able to read the stored passwords directly. The impact may also extend to other services if users reuse their credentials.

## 3.2. Secure implementation with Argon2id

### Endpoints

```http
POST /register-secure
POST /login-secure
```

The protected implementation uses `argon2-cffi` and `PasswordHasher`.

Before storing a password, the application generates its hash:

```python
password_hash = password_hasher.hash(password)
```

The conceptual table structure is:

```text
users_secure
├── id
├── username
└── password_hash
```

A stored value has a structure similar to:

```text
$argon2id$v=19$m=65536,t=3,p=4$...
```

This is an illustrative example; the exact hash and parameters depend on the configuration.

Argon2id generates a hash representation that includes its parameters and salt. The application does not need to store the original password to verify it later.

### Password verification

The implementation uses the Argon2id verifier:

```python
password_hasher.verify(user[2], password)
```

When the password does not match, the corresponding exception is handled explicitly:

```python
except VerifyMismatchError:
    return {"error": "Incorrect password"}
```

A broad `except Exception` should not be used to conceal unexpected errors.

### Documented verification

Correct and incorrect password scenarios were tested. The contents of `users_secure` were also inspected to verify that an Argon2id hash, rather than the original password, was stored.

### Comparison

| Feature | Vulnerable implementation | Protected implementation |
|---|---|---|
| Table | `users` | `users_secure` |
| Stored password | Plaintext | Argon2id hash |
| Registration | `/register` | `/register-secure` |
| Login | `/login` | `/login-secure` |
| Verification | Direct comparison | `PasswordHasher.verify()` |
| Original password in the table | Yes | No |
| Salt | Not used | Generated by the hashing mechanism |

**Documented status:** The laboratory includes both implementations and manual tests for registration, authentication, and storage inspection.

## Lessons learned

- Passwords must not be stored in plaintext.
- Password hashing is not the same as reversible encryption.
- Argon2id is designed to make password-guessing attacks more expensive.
- Parameterized queries protect against certain SQL attacks but do not make credential storage secure.
- Authentication errors should be handled without concealing unexpected failures.

---

# 4. IDOR / Broken Access Control

## Description

Insecure Direct Object Reference (IDOR) is an access-control vulnerability that can occur when an application allows a resource to be requested through its identifier without verifying that the current user is authorized to access it.

The IDOR laboratories in this project have expanded beyond ownership checks to cover JWT authentication, roles, and permissions.

The four established modules are:

1. Basic IDOR.
2. IDOR with secure authentication.
3. Role-based authorization.
4. Permission-based authorization.

## 4.1. Basic IDOR

### Endpoints

```http
POST /login-idor-basic
GET /accounts-vulnerable/{account_id}
GET /accounts-protected/{account_id}
```

This module compares a vulnerable endpoint with another endpoint that checks account ownership.

### Root cause

The vulnerable implementation allows an authenticated user to request an account by its identifier without checking whether that account belongs to the user.

In the laboratory test data, Juan corresponds to user `1` and María to user `2`.

### Proof of concept

Juan logs in and obtains an access token for testing.

When requesting María's account through the vulnerable endpoint:

```http
GET /accounts-vulnerable/2
```

the application returns the account information, even though Juan is not its owner.

The equivalent request to the protected endpoint:

```http
GET /accounts-protected/2
```

returns `403 Forbidden` when Juan's token is used.

### Mitigation

The protected endpoint checks whether the requested account identifier corresponds to the authenticated user.

The identity used for this check must come from a server-validated authentication mechanism, not from an identifier that the client can freely modify.

### Observed results

| Scenario | Result |
|---|---|
| Juan requests María's account through the vulnerable endpoint | `200 OK` |
| Juan requests María's account through the protected endpoint | `403 Forbidden` |
| Juan attempts to log in with an incorrect password | `401 Unauthorized` |

These results correspond to the manual and automated tests performed in the laboratory.

## 4.2. IDOR with Secure Authentication and JWT

### Endpoints

```http
POST /login-idor-secure
GET /me-idor-secure
GET /accounts-idor-secure/{account_id}
```

This module introduces additional controls:

- Password verification using Argon2id.
- JWT signature validation.
- Token expiration validation.
- Validation of the user identifier contained in the token.
- Verification that the user exists.
- Ownership checks for the requested account.

### Tests performed

| Scenario | Result |
|---|---|
| Login with valid credentials | `200 OK` |
| Login with an incorrect password | `401 Unauthorized` |
| Profile request with a valid token | `200 OK` |
| Access to the user's own account | `200 OK` |
| Access to another user's account | `403 Forbidden` |
| Protected request without a token | `401 Unauthorized` |

These scenarios illustrate the difference between authenticating a user and authorizing access to a resource.

A valid JWT does not automatically grant access to every account. The application must also verify the permissions applicable to each resource.

## 4.3. Role-Based Authorization

### Endpoints

```http
POST /login-idor-roles
GET /me-idor-roles
GET /user-area-idor-roles
GET /admin-area-idor-roles
```

This module demonstrates **Role-Based Access Control (RBAC)**.

The authenticated identity is represented by a `CurrentUser` object containing information such as the user identifier, username, and role.

Administrative authorization is enforced through a dependency that checks the required role.

### Test users

| User | Role |
|---|---|
| Juan | `user` |
| María | `admin` |

### Tests performed

| Scenario | Result |
|---|---|
| Juan retrieves his identity and role | `200 OK` |
| Juan accesses the user area | `200 OK` |
| Juan attempts to access the administrative area | `403 Forbidden` |
| María accesses the administrative area | `200 OK` |
| Protected request without a token | `401 Unauthorized` |

### Lesson learned

Roles allow permissions to be grouped and simplify certain authorization decisions. However, assigning a role does not eliminate the need to verify identity and validate access to the relevant resources.

## 4.4. Permission-Based Authorization

### Endpoints

```http
POST /login-idor-permissions
GET /my-profile-idor-permissions
GET /audit-logs-idor-permissions
GET /manage-users-idor-permissions
```

This module extends role-based access control through specific permissions stored in SQLite.

Authorization is determined by the relationship between roles and permissions, using the `roles`, `permissions`, and `role_permissions` tables.

The permissions included in the laboratory are:

```text
read_own_profile
read_audit_logs
manage_users
```

### Expected behavior

- Juan has permission to view his own profile.
- Juan does not have permission to view audit logs.
- Juan does not have permission to manage users.
- María, with the `admin` role, can access the tested administrative endpoints.

### Tests performed

| Scenario | Result |
|---|---|
| Juan retrieves his profile | `200 OK` |
| Juan requests audit logs | `403 Forbidden` |
| Juan attempts to manage users | `403 Forbidden` |
| María retrieves audit logs | `200 OK` |
| María accesses user management | `200 OK` |
| Protected request without a token | `401 Unauthorized` |

### Lessons learned about IDOR

- Authentication identifies the user; authorization determines what the user can do.
- Knowing a valid identifier does not grant permission to access a resource.
- A valid token does not replace ownership checks or authorization controls.
- Roles and permissions are distinct but complementary mechanisms.
- Authorization decisions must be enforced on the server.
- An observed `403 Forbidden` response demonstrates rejection of that specific scenario, not that the entire application is free from authorization flaws.

---

# 5. Test Structure

Automated tests are separated from the functional modules in the `tests/` directory.

```text
tests/
├── test_idor_basico.py
├── test_idor_autenticacion_segura.py
├── test_idor_identidad_roles.py
├── test_idor_permisos.py
└── test_integracion_idor.py
```

## Individual tests

| File | Purpose |
|---|---|
| `test_idor_basico.py` | Verify the difference between vulnerable access and ownership enforcement. |
| `test_idor_autenticacion_segura.py` | Verify authentication, JWT, profile access, and account ownership. |
| `test_idor_identidad_roles.py` | Verify role-based access. |
| `test_idor_permisos.py` | Verify granted and denied permissions. |
| `test_integracion_idor.py` | Run an integrated check of the four IDOR modules. |

The tests use `TestClient` to send HTTP requests to the application and verify the expected responses.

## Running the tests

From the project root, with the virtual environment activated, run each file individually:

```powershell
python .\tests\test_idor_basico.py
python .\tests\test_idor_autenticacion_segura.py
python .\tests\test_idor_identidad_roles.py
python .\tests\test_idor_permisos.py
python .\tests\test_integracion_idor.py
```

All five files completed successfully during the documented laboratory runs.

**Important:** These tests validate the implemented and tested scenarios. They do not replace a comprehensive audit, a review of every route, or exhaustive security testing.

---

# 6. Manual Testing Documentation

The manual testing guide is available at:

```text
docs/
└── guia_pruebas_manuales_idor.md
```

It includes:

- Descriptions of the IDOR modules.
- Laboratory test users.
- Procedures for sending requests through Swagger UI.
- Expected and observed results.
- Interpretation of HTTP status codes.
- Test conclusions.

This guide complements the automated tests and allows the main scenarios to be reproduced manually.

---

# 7. Running Locally

## Requirements

- Python compatible with the project's dependencies.
- PowerShell or an equivalent terminal.
- Visual Studio Code or another code editor.
- Dependencies defined in `requirements.txt`.

## Creating and activating the virtual environment

From the project root, create the virtual environment if it does not already exist:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Installing dependencies

With the virtual environment activated:

```powershell
python -m pip install -r requirements.txt
```

## Starting the application

From the project root:

```powershell
python -m uvicorn main:app --reload
```

The application normally runs at:

```text
http://127.0.0.1:8000
```

FastAPI's interactive documentation is available at:

```text
http://127.0.0.1:8000/docs
```

Swagger UI allows you to select endpoints, enter parameters, and send manual requests.

To stop the server, press `Ctrl + C` in the terminal where it is running.

---

# 8. Databases and Test Data

The project uses SQLite to store data for the different laboratories.

The `auth_lab.db` database contains test data used by the established IDOR modules, including tables related to users, credentials, accounts, roles, and permissions.

The documented laboratory users are:

| User | Laboratory password | Role |
|---|---|---|
| Juan | `LabUser_2026!` | `user` |
| María | `LabAdmin_2026!` | `admin` |

These credentials are exclusively for the local educational environment. They must not be reused for personal accounts or real services.

Passwords are stored as Argon2id hashes in the authentication database.

**Caution:** Do not run the initializer in `auth_database.py` against an existing database if its implementation refuses to overwrite it. Before any operation that may modify or recreate a database, check the current files and make a backup when appropriate.

---

# 9. Security Principles Studied

The laboratories cover the following principles:

1. **Input validation and handling:** Untrusted input must be processed according to its intended use.
2. **Output encoding:** Data inserted into HTML must be handled according to the output context.
3. **Parameterized queries:** Untrusted values must be separated from SQL structure.
4. **Secure password storage:** Specialized password-hashing algorithms must be used.
5. **Secure authentication:** Credentials and tokens must be validated before protected operations are allowed.
6. **Access control:** Each request must verify whether the user is authorized to access the requested resource.
7. **Least privilege:** Users should receive only the permissions they need.
8. **Security testing:** Vulnerabilities and their mitigations should be verified through reproducible scenarios.

---

# 10. Future Improvements

The project is under active development. Areas for progressive expansion include:

- Additional automated tests for XSS, SQL Injection, and password storage.
- More negative test cases for authentication and authorization.
- Input validation and consistent error handling.
- Logging of relevant security events.
- API security and object-level access controls.
- Static code analysis and dependency analysis.
- Integration of security tests into CI/CD.
- DevSecOps fundamentals.
- Introduction to blockchain application security and smart contracts.

The priority is to expand the laboratory's capabilities through controlled modules and tests, preserving vulnerable examples as educational material and keeping learning implementations separate from protected alternatives.

---

## Scope and Limitations

Security Cyber Lab is an educational and portfolio project. The reproduced vulnerabilities and verified mitigations are limited to the scenarios described and tested.

The existence of a protected implementation does not, by itself, prove that an application is completely secure. A broader assessment requires reviewing the code, configuration, relevant routes, authorization controls, and potential abuse scenarios.

**Long-term goal:** Build a practical and verifiable foundation in application security, progressing from understanding individual vulnerabilities to implementing and validating security controls.
