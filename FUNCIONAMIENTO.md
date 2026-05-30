# SecureSign — Documentación Técnica de Funcionamiento

Sistema educativo de emisión y verificación criptográfica de documentos PDF, implementado con Java 17 y Spring Boot.
Demuestra el uso práctico de ECDSA (P-256) y Ed25519 para garantizar integridad documental, autenticación y no repudio.

---

## Índice

1. [Arquitectura general](#1-arquitectura-general)
2. [Estructura del proyecto](#2-estructura-del-proyecto)
3. [Tecnologías utilizadas](#3-tecnologías-utilizadas)
4. [Flujo completo: emisión de certificado](#4-flujo-completo-emisión-de-certificado)
5. [Flujo completo: verificación de certificado](#5-flujo-completo-verificación-de-certificado)
6. [Criptografía: ECDSA vs Ed25519](#6-criptografía-ecdsa-vs-ed25519)
7. [Almacenamiento de claves: KeyStore PKCS12](#7-almacenamiento-de-claves-keystore-pkcs12)
8. [Certificado X.509 autofirmado](#8-certificado-x509-autofirmado)
9. [Generación de documentos PDF](#9-generación-de-documentos-pdf)
10. [API REST](#10-api-rest)
11. [Frontend](#11-frontend)
12. [Logging criptográfico](#12-logging-criptográfico)
13. [Manejo de errores](#13-manejo-de-errores)
14. [Configuración y ejecución](#14-configuración-y-ejecución)
15. [Propiedades garantizadas](#15-propiedades-garantizadas)

---

## 1. Arquitectura general

El sistema sigue una separación de responsabilidades entre frontend e infraestructura criptográfica:

```
┌─────────────────────────────┐
│  Frontend (index.html)      │
│  Solicita emisión y         │
│  sube PDF para verificar    │
└────────────┬────────────────┘
             │  HTTP / JSON + multipart
             ▼
┌─────────────────────────────┐
│  Backend (Spring Boot)      │
│  ├── Genera documentos PDF  │
│  ├── Gestiona claves PKCS12 │
│  ├── Firma con ECDSA/Ed25519│
│  └── Verifica firmas        │
└─────────────────────────────┘
```

**Principio de seguridad central:** la clave privada nunca sale del backend. El cliente recibe únicamente el PDF
generado y un `keyId` UUID que referencia el par de claves en el servidor.

---

## 2. Estructura del proyecto

```
src/main/
├── java/es/faustino/securesign/
│   ├── SecureSignApplication.java        ← punto de entrada Spring Boot
│   ├── config/
│   │   └── WebConfig.java                ← CORS para el frontend
│   ├── controller/
│   │   ├── CertificateController.java    ← endpoints /api/certificates/*
│   │   └── SignatureController.java      ← endpoints /api/keys/*, /api/sign, /api/verify
│   ├── service/
│   │   ├── CertificateService.java       ← genera PDF, coordina firma, guarda firma
│   │   └── SignatureService.java         ← gestión de claves, PKCS12, firma, verificación
│   ├── model/
│   │   ├── CertificateRequest.java       ← record: nombre, dni, tipo, fecha, algorithm
│   │   ├── KeyInfoResponse.java          ← record: keyId, algorithm, publicKey
│   │   ├── SignRequest.java              ← record: keyId, algorithm, data (Base64)
│   │   ├── SignResponse.java             ← record: keyId, algorithm, signature (Base64)
│   │   └── VerifyRequest.java            ← record: keyId, algorithm, data, signature
│   └── exception/
│       ├── KeyNotFoundException.java     ← lanzada cuando keyId no existe
│       └── GlobalExceptionHandler.java   ← mapea excepciones a respuestas HTTP
└── resources/
    ├── application.yaml                  ← configuración del servidor y contraseña KS
    └── static/
        └── index.html                    ← frontend completo (HTML + CSS + JS)
```

---

## 3. Tecnologías utilizadas

| Capa                  | Tecnología                      | Versión |
|-----------------------|---------------------------------|---------|
| Lenguaje              | Java                            | 17      |
| Framework             | Spring Boot (WebMVC)            | 4.0.6   |
| Criptografía          | `java.security` (JCA/JCE)       | —       |
| Certificados X.509    | BouncyCastle (`bcpkix-jdk18on`) | 1.78.1  |
| Generación PDF        | Apache PDFBox                   | 3.0.1   |
| Frontend              | HTML + CSS + JavaScript vanilla | —       |
| Almacenamiento claves | Java KeyStore PKCS12 (RFC 7292) | —       |

---

## 4. Flujo completo: emisión de certificado

### 4.1 Secuencia

```
Frontend
  │  POST /api/certificates/generate
  │  Body: { nombre, dni, tipo, fecha, algorithm }
  ▼
CertificateController.generate()
  │
  ▼
CertificateService.emitirCertificado()
  │
  ├─→ generarCertificadoPDF()          [PDFBox]
  │      └─ Devuelve byte[] con el PDF
  │
  ├─→ SignatureService.generateKeyPair()
  │      ├─ Genera KeyPair (ECDSA P-256 o Ed25519)
  │      ├─ Genera certificado X.509 autofirmado  [BouncyCastle]
  │      ├─ Guarda clave privada + cert en securesign.p12  [PKCS12]
  │      └─ Guarda clave pública en Map<keyId, PublicKey>
  │
  ├─→ SignatureService.sign()
  │      ├─ Carga securesign.p12, extrae PrivateKey
  │      ├─ Calcula SHA-256 del PDF (para log)
  │      ├─ Firma bytes del PDF con SHA256withECDSA o Ed25519
  │      └─ Devuelve byte[] con la firma
  │
  └─ signatureStore.put(keyId, firma)   [Map en memoria]

  Respuesta HTTP 200:
    Content-Type: application/pdf
    Header X-Key-Id: <uuid>
    Header X-Algorithm: ECDSA | Ed25519
    Body: bytes del PDF
```

### 4.2 Código clave — `CertificateService.emitirCertificado()`

```java
byte[] pdfBytes = generarCertificadoPDF(nombre, dni, tipo, fecha);
String keyId    = signatureService.generateKeyPair(algorithm);
byte[] firma    = signatureService.sign(keyId, algorithm, pdfBytes);
signatureStore.put(keyId, firma);
```

### 4.3 Lo que ocurre criptográficamente

1. Se genera un par de claves efímero específico para este documento.
2. La firma se calcula sobre los **bytes completos del PDF** — cualquier modificación posterior, incluso de un solo
   byte, invalidará la firma.
3. `SHA256withECDSA` calcula SHA-256 internamente antes de firmar. `Ed25519` usa SHA-512 internamente. Ninguno requiere
   pre-hashing externo.
4. La clave privada queda cifrada en `securesign.p12` y nunca se transmite al cliente.

---

## 5. Flujo completo: verificación de certificado

### 5.1 Secuencia

```
Frontend
  │  POST /api/certificates/verify
  │  Params: keyId, algorithm
  │  Body multipart: archivo PDF
  ▼
CertificateController.verify()
  │
  ▼
CertificateService.verificarCertificado()
  │
  ├─ Recupera firma original: signatureStore.get(keyId)
  │
  └─→ SignatureService.verify()
         ├─ Carga securesign.p12
         ├─ Extrae certificado X.509: ks.getCertificate(keyId)
         ├─ Obtiene PublicKey del certificado X.509
         ├─ Calcula SHA-256 del PDF recibido (para log)
         ├─ Verifica: sig.verify(firma)
         └─ Devuelve boolean

  Respuesta HTTP 200:
    { "valid": true | false, "keyId": "...", "algorithm": "..." }
```

### 5.2 Por qué la verificación detecta alteraciones

La firma digital es una función matemática de los bytes del documento y la clave privada. Al verificar:

```
PDF original  →  hash A  →  verificación: ✔ (hash A == hash contenido en la firma)
PDF alterado  →  hash B  →  verificación: ✘ (hash B ≠ hash contenido en la firma)
```

Cualquier modificación al PDF — añadir un espacio, cambiar un carácter, modificar metadatos — produce un hash SHA-256
completamente diferente, haciendo que la verificación falle de forma determinista.

---

## 6. Criptografía: ECDSA vs Ed25519

Ambos algoritmos están disponibles en la JVM a través de `java.security` sin dependencias externas.

### ECDSA (P-256 / secp256r1)

- Curva recomendada por NIST, ampliamente usada en TLS/HTTPS.
- La firma requiere un número aleatorio interno en cada operación. Si ese número se repite o es predecible, la clave
  privada queda expuesta.
- Produce firmas de tamaño variable (~70–72 bytes en DER).
- Algoritmo de firma utilizado: `SHA256withECDSA`.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
```

### Ed25519

- Basado en EdDSA sobre la curva Edwards25519.
- **Firma determinista:** el mismo documento y la misma clave siempre producen la misma firma — sin aleatoriedad
  externa.
- Más rápido que ECDSA. Produce firmas de exactamente 64 bytes.
- Algoritmo de firma utilizado: `Ed25519`.

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
```

### Comparativa observable en el sistema

| Propiedad          | ECDSA                | Ed25519         |
|--------------------|----------------------|-----------------|
| Tamaño clave       | 256 bits             | 256 bits        |
| Tamaño firma       | ~72 bytes (variable) | 64 bytes (fijo) |
| Firma determinista | No                   | Sí              |
| Velocidad          | Rápida               | Muy rápida      |

> **Demostración del determinismo:** emitir el mismo certificado dos veces con Ed25519 produce firmas idénticas en
> Base64. Con ECDSA, las firmas son diferentes en cada emisión.

---

## 7. Almacenamiento de claves: KeyStore PKCS12

### El problema que resuelve

La alternativa anterior (`ConcurrentHashMap<String, KeyPair>`) perdía todas las claves al reiniciar el servidor y no
ofrecía ninguna protección en disco. Con PKCS12:

| Característica        | Map en memoria | PKCS12 KeyStore          |
|-----------------------|----------------|--------------------------|
| Persiste al reiniciar | ✘ No           | ✔ Sí                     |
| Protección en disco   | ✘ No           | ✔ AES-256 por contraseña |
| Estándar reconocido   | ✘ No           | ✔ RFC 7292               |

### Operaciones implementadas

**Carga (`cargarKeyStore`):**

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
if (archivo.exists()) {
    ks.load(new FileInputStream(archivo), password);
} else {
    ks.load(null, password);  // nuevo vacío
}
```

**Guardado (`guardarKeyStore`):** sincronizado para evitar escrituras concurrentes.

**Inserción de clave privada:**

```java
ks.setKeyEntry(keyId, privateKey, password, new Certificate[]{ cert });
```

PKCS12 exige una cadena de certificados adjunta a cada clave privada — de ahí la necesidad del certificado X.509
autofirmado.

**Recuperación:**

```java
PrivateKey pk  = (PrivateKey) ks.getKey(keyId, password);
X509Certificate cert = (X509Certificate) ks.getCertificate(keyId);
```

### Archivo generado

`securesign.p12` se crea en el directorio raíz del proyecto al emitir el primer certificado. Su contenido es ilegible
sin la contraseña, independientemente de quién acceda al sistema de archivos.

---

## 8. Certificado X.509 autofirmado

PKCS12 prohíbe guardar una clave privada sin una cadena de certificados. Como el sistema no dispone de una CA real, se
genera un certificado autofirmado de vida larga (10 años) exclusivamente para satisfacer ese requisito estructural.

### Campos del certificado

| Campo              | Valor generado                            | Propósito                                |
|--------------------|-------------------------------------------|------------------------------------------|
| Subject            | `CN=SecureSign-ECDSA, O=SecureSign, C=ES` | Identificador del titular                |
| Issuer             | Idéntico al Subject                       | Define el certificado como autofirmado   |
| Número de serie    | `System.currentTimeMillis()`              | Unicidad dentro del KeyStore             |
| Not Before         | Fecha actual                              | Inicio de validez                        |
| Not After          | Fecha actual + 10 años                    | Sin restricción práctica (uso educativo) |
| Clave pública      | La del par generado (EC P-256 o Ed25519)  | Dato criptográfico real                  |
| Algoritmo de firma | `SHA256withECDSA` o `Ed25519`             | Compatible con el tipo de clave          |

### Lo que el certificado no hace

No firma los documentos PDF — eso lo realiza `sign()` con la `PrivateKey`. No tiene extensiones X.509 (usos de clave,
SAN). No forma parte de ninguna cadena de confianza ni PKI real.

### Código de generación (BouncyCastle)

```java
X500Name subject = new X500Name("CN=SecureSign-" + algo + ",O=SecureSign,C=ES");
X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
    subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
);
ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).build(keyPair.getPrivate());
return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
```

### Uso en verificación

Al verificar, la clave pública **se extrae del certificado X.509 almacenado en el KeyStore**, no del Map en memoria:

```java
X509Certificate cert = (X509Certificate) ks.getCertificate(keyId);
PublicKey publicKey  = cert.getPublicKey();
```

Esto demuestra el flujo real de PKI: el verificador obtiene la clave pública desde el certificado, no como un dato
suelto.

---

## 9. Generación de documentos PDF

Implementada en `CertificateService.generarCertificadoPDF()` usando Apache PDFBox 3.0.

```java
PDDocument document = new PDDocument();
PDPage page = new PDPage(PDRectangle.A4);
document.addPage(page);

PDPageContentStream content = new PDPageContentStream(document, page);
content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
content.showText("CERTIFICADO INSTITUCIONAL");
// ... campos: tipo, nombre, DNI, fecha
```

El PDF se genera en memoria como `byte[]` y nunca se escribe a disco. Esos mismos bytes son los que se firman
criptográficamente, garantizando que la firma cubre el documento exacto que recibe el cliente.

### Tipos de certificado disponibles

- Constancia Académica
- Antecedentes Penales
- Certificado Laboral
- Certificado de Residencia

---

## 10. API REST

### `POST /api/certificates/generate`

Genera un PDF institucional, lo firma y lo devuelve.

**Request:**

```json
{
  "nombre":    "Ana García López",
  "dni":       "12345678",
  "tipo":      "Constancia Academica",
  "fecha":     "2025-05-30",
  "algorithm": "Ed25519"
}
```

**Response `200 OK`:**

```
Content-Type: application/pdf
X-Key-Id: 3f8a1c2d-0b4e-4f1a-9c2d-7e3f1a2b4c5d
X-Algorithm: Ed25519
Body: <bytes del PDF>
```

---

### `POST /api/certificates/verify`

Verifica la firma de un PDF previamente emitido.

**Request (`multipart/form-data`):**

```
keyId=3f8a1c2d-...
algorithm=Ed25519
file=<archivo PDF>
```

**Response `200 OK`:**

```json
{
  "valid":     true,
  "keyId":     "3f8a1c2d-...",
  "algorithm": "Ed25519"
}
```

---

### Endpoints adicionales (`SignatureController`)

| Método | Ruta                            | Descripción                        |
|--------|---------------------------------|------------------------------------|
| `POST` | `/api/keys/generate?algorithm=` | Genera par de claves standalone    |
| `GET`  | `/api/keys/{keyId}`             | Devuelve clave pública y algoritmo |
| `POST` | `/api/sign`                     | Firma datos arbitrarios en Base64  |
| `POST` | `/api/verify`                   | Verifica firma de datos en Base64  |

---

## 11. Frontend

Archivo único `src/main/resources/static/index.html`, servido directamente por Spring Boot en `http://localhost:8080`.

### Panel 01 — Emisión

1. El usuario completa nombre, DNI, tipo de certificado y fecha.
2. Selecciona algoritmo: ECDSA o Ed25519.
3. Clic en **Emitir certificado** → `POST /api/certificates/generate`.
4. El Key ID y el algoritmo se autocompletan en el panel de verificación.
5. El botón **Descargar PDF firmado** crea un blob URL y dispara la descarga.

### Panel 02 — Verificación

1. El Key ID se autocompleta tras emitir (o se introduce manualmente).
2. El usuario arrastra el PDF o lo selecciona desde el explorador.
3. Clic en **Verificar integridad** → `POST /api/certificates/verify`.
4. Se muestra el resultado: `✔ FIRMA VÁLIDA` (verde) o `✗ FIRMA INVÁLIDA` (rojo).

### CORS

`WebConfig` permite peticiones desde `http://localhost:5173` y `http://localhost:5500`, y expone los headers `X-Key-Id`
y `X-Algorithm` al navegador.

---

## 12. Logging criptográfico

Cada operación de firma y verificación imprime en consola un bloque estructurado con todos los datos relevantes.

### Al emitir

```
╔══════════════════════════════════════════════════════════════╗
║                     EMISIÓN  —  FIRMA PDF                   ║
╠══════════════════════════════════════════════════════════════╣
║  Key ID          : 3f8a1c2d-...
║  Algoritmo       : ECDSA
║  Tamaño PDF      : 4821 bytes
╠══════════════════════════════════════════════════════════════╣
║  [DOCUMENTO]
║  SHA-256         : a3f9c2e1...   ← huella del PDF
╠══════════════════════════════════════════════════════════════╣
║  [CERTIFICADO X.509]
║  Subject         : CN=SecureSign-ECDSA,O=SecureSign,C=ES
║  Alg. firma cert : SHA256WITHECDSA
║  Clave pública   : MFkwEwYH...   ← extraída del cert en el KS
╠══════════════════════════════════════════════════════════════╣
║  [FIRMA DIGITAL]
║  Tamaño firma    : 71 bytes
║  Firma (Base64)  : MEUCIQDk...
╚══════════════════════════════════════════════════════════════╝
```

### Al verificar

El bloque de verificación añade los campos del certificado X.509 extraídos directamente del KeyStore: Subject, Issuer (
idéntico al Subject, confirmando que es autofirmado), número de serie, fecha de expiración y clave pública. Finaliza con
el resultado `✔ FIRMA VÁLIDA` o `✘ FIRMA INVÁLIDA`.

### Sobre el SHA-256 mostrado

El hash que aparece en el log se calcula explícitamente con `MessageDigest.getInstance("SHA-256")` sobre el array de
bytes del PDF. `SHA256withECDSA` recalcula su propio hash internamente — ambos operan sobre los mismos bytes, por lo que
el valor impreso es exactamente la huella que el algoritmo utilizó.

---

## 13. Manejo de errores

`GlobalExceptionHandler` intercepta todas las excepciones y las convierte en respuestas JSON estructuradas:

| Excepción                  | HTTP                        | Respuesta                                                         |
|----------------------------|-----------------------------|-------------------------------------------------------------------|
| `KeyNotFoundException`     | `404 Not Found`             | `{ "error": "Clave no encontrada: <keyId>" }`                     |
| `IllegalArgumentException` | `400 Bad Request`           | `{ "error": "<mensaje>" }` — algoritmo no soportado, campos nulos |
| `Exception` (general)      | `500 Internal Server Error` | `{ "error": "Error interno: <mensaje>" }`                         |

---

## 14. Configuración y ejecución

### Variable de entorno

```bash
# Linux / macOS
export SECURESIGN_KEYSTORE_PASSWORD=mi-contrasena

# Windows PowerShell
$env:SECURESIGN_KEYSTORE_PASSWORD="mi-contrasena"
```

Si no se define, el fallback de desarrollo definido en `application.yaml` se aplica automáticamente:

```yaml
securesign:
  keystore-password: ${SECURESIGN_KEYSTORE_PASSWORD:securesign-dev-password}
```

### Ejecutar el backend

```bash
cd securesign-backend
./mvnw spring-boot:run
# Disponible en http://localhost:8080
```

El archivo `securesign.p12` se crea automáticamente en el directorio raíz del proyecto al emitir el primer certificado.

### Acceder al frontend

Abrir directamente `http://localhost:8080` en el navegador — Spring Boot sirve `index.html` como recurso estático.

---

## 15. Propiedades garantizadas

### Integridad

La firma se calcula sobre los bytes completos del PDF. Cualquier modificación posterior al documento — aunque sea de un
solo bit — produce un hash SHA-256 diferente y la verificación falla de forma determinista.

### Autenticación

Solo quien posee la clave privada (el backend) pudo haber generado la firma. El cliente puede verificar la autenticidad
con la clave pública sin necesidad de conocer la privada.

### No repudio

El emisor no puede negar haber firmado el documento, ya que la firma solo pudo haberse producido con la clave privada
almacenada en el KeyStore del servidor.

### Protección en reposo

Las claves privadas se almacenan cifradas con AES-256 en `securesign.p12`, protegido por contraseña. El archivo es
ilegible sin la contraseña, independientemente de quién acceda al sistema de archivos. La clave privada en texto plano
solo existe en memoria durante los milisegundos que dura la operación de firma.

---

> **Alcance educativo.** Este sistema implementa una infraestructura simplificada de firma digital basada en claves
> públicas. No constituye una PKI completa: no implementa certificados X.509 con jerarquía de CA, ni revocación (
> CRL/OCSP), ni cumplimiento de estándares como eIDAS o PAdES. Para un sistema de producción real se requeriría un HSM y
> una arquitectura PKI completa.
