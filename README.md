# SecureSign

API REST para la emisión y verificación de documentos PDF con firma digital embebida siguiendo el estándar **PAdES-Baseline-B** (PDF Advanced Electronic Signatures), implementado con **DSS 6.4** (Digital Signature Services de la UE) + **PDFBox 3.x** + **Bouncy Castle** sobre Spring Boot 4.x.

---

## Requisitos

- Java 17+
- Maven 3.9+ (o usar el wrapper `./mvnw` incluido)
- IntelliJ IDEA (recomendado) u otro IDE con soporte para variables de entorno en configuraciones de ejecución

---

## Configuración inicial

### 1. Crear el archivo `.env`

En la raíz del proyecto crea un archivo llamado `.env` con el siguiente contenido:

```
SECURESIGN_KEYSTORE_PASSWORD=tu_contraseña_segura
```

Este valor protege el KeyStore PKCS#12 (`securesign.p12`) donde se almacenan los pares de claves generados. Usa una
cadena aleatoria larga; puedes generar una con:

```bash
openssl rand -base64 32
```

> El archivo `.env` ya está en `.gitignore`. No lo subas al repositorio.

### 2. Cargar la variable en IntelliJ IDEA

La aplicación lee `SECURESIGN_KEYSTORE_PASSWORD` como variable de entorno al arrancar. Para inyectarla desde el `.env`:

1. Abre **Run > Edit Configurations…**
2. Selecciona la configuración de `SecureSignApplication`
3. En el campo **Environment variables**, haz clic en el icono de carpeta a la derecha
4. Haz clic en **Load variables** (icono de archivo) y selecciona tu `.env`
5. Confirma con **OK** y guarda la configuración

Alternativamente, puedes instalar el plugin **[EnvFile](https://plugins.jetbrains.com/plugin/7861-envfile)** para cargar
el `.env` automáticamente en cada ejecución.

### 3. Ejecutar

Con Maven wrapper:

```bash
./mvnw spring-boot:run
```

O directamente desde IntelliJ ejecutando `SecureSignApplication`.

La aplicación arranca en `http://localhost:8080`. La interfaz web está disponible en esa misma URL (servida como
contenido estático desde `resources/static`).

---

## Endpoints

| Método | Ruta                      | Descripción                                  |
|--------|---------------------------|----------------------------------------------|
| POST   | `/api/documents/generate` | Genera y devuelve un PDF firmado (PAdES)     |
| POST   | `/api/documents/verify`   | Verifica la firma embebida en un PDF firmado |

### POST `/api/documents/generate`

Body JSON:

```json
{
  "nombre": "Juan Pérez",
  "dni": "12345678",
  "tipo": "CONTRATO",
  "fecha": "2026-05-30",
  "algorithm": "EC"
}
```

El campo `algorithm` acepta `EC` (ECDSA sobre secp256r1 con SHA-256) o `Ed25519` (EdDSA con SHA-512). Devuelve el PDF firmado como `application/pdf` con cabecera `Content-Disposition: attachment; filename="documento_<dni>.pdf"`.

### POST `/api/documents/verify`

Body `multipart/form-data` con el campo `file` conteniendo el PDF firmado. Devuelve JSON con diagnóstico granular:

```json
{
  "valid": true,
  "firmaExtraible": true,
  "byteRangeValido": true,
  "cmsParseable": true,
  "certificadoExtraible": true,
  "firmaValida": true,
  "certificadoVigente": true,
  "subject": "CN=SecureSign Institucional, O=Universidad, C=PE",
  "validoDesde": "2026-05-30T00:00:00Z",
  "validoHasta": "2027-05-30T00:00:00Z",
  "algoritmoFirma": "SHA256withECDSA",
  "razon": null
}
```

El campo `valid` es `true` únicamente si **tanto** `firmaValida` como `certificadoVigente` son verdaderos. Ante cualquier error, `razon` describe el punto de fallo exacto.

---

## Arquitectura y fundamentos criptográficos

### Generación de claves — ECDSA y Ed25519

Cada documento se firma con un par de claves efímero generado en tiempo de ejecución mediante `KeyManagementService`. El proyecto soporta dos familias de algoritmos de curva elíptica:

**EC (ECDSA sobre secp256r1)**

`secp256r1` (también llamada `P-256`) es la curva recomendada por NIST SP 800-186 y es ampliamente utilizada en TLS 1.3, JWT (ES256) y documentos eIDAS. Produce claves de 256 bits con seguridad equivalente a RSA-3072. La firma usa el algoritmo de digest **SHA-256**.

**Ed25519 (EdDSA)**

Ed25519 está definido en RFC 8032 y es parte del estándar FIPS 186-5. Su diseño evita por construcción ataques de canal lateral relacionados con la aleatoriedad del nonce (un punto débil histórico de ECDSA). Es el algoritmo preferido en sistemas modernos como SSH, Signal y WireGuard. La firma usa el algoritmo de digest **SHA-512**.

### Certificados X.509 autofirmados

Para cada firma se genera un certificado X.509 v3 autofirmado (issuer == subject) a través de `CertificateX509Service`, vinculando la clave pública con la identidad institucional:

```
CN=SecureSign Institucional, O=Universidad, C=PE
```

El certificado tiene un período de validez de 365 días. Aunque en producción estos certificados deberían estar firmados por una CA de confianza (jerarquía PKI), el modelo autofirmado es suficiente para demostrar la estructura PAdES: el certificado viaja embebido en el propio PDF y la verificación no depende de una cadena de confianza externa.

### Almacenamiento de claves — PKCS#12 + DSS Token

Las claves privadas y los certificados se persisten en un KeyStore de tipo PKCS#12 (`securesign.p12`) gestionado por `KeyStoreService`. El acceso al KeyStore desde DSS se realiza mediante `KeyStoreSignatureTokenConnection`, que expone la clave privada como `KSPrivateKeyEntry` para la firma delegada a `PAdESService`.

El archivo se cifra simétricamente con la contraseña inyectada via variable de entorno. Cada par de claves recibe un UUID como alias, lo que permite gestionar múltiples identidades en el mismo almacén sin colisiones.

### Firma PAdES con DSS — PAdES-Baseline-B

La firma sigue el perfil **PAdES-Baseline-B** (ETSI EN 319 132), delegando todo el proceso de firma incremental, gestión del `ByteRange` y serialización CMS a la librería DSS de la Comisión Europea:

```java
PAdESSignatureParameters parametros = new PAdESSignatureParameters();
parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);

ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametros);
SignatureValue valorFirma = conexionToken.sign(datosAFirmar, DigestAlgorithm.SHA256, entradaClave);
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametros, valorFirma);
```

El uso de PDFBox 3.x es **obligatorio** con DSS 6.x: PDFBox 2.x calculaba los offsets del `ByteRange` antes de serializar el objeto xref, produciendo una desalineación de 1-4 bytes en `/Contents` que Adobe Acrobat rechaza con "ByteRange invalid".

### Verificación independiente — ByteRange + CMS directo

La verificación en `VerificationService` opera directamente sobre la estructura binaria del PDF sin depender del estado del servidor, en dos fases:

1. **`ByteRangeExtractor`** parsea el PDF, extrae el rango `/ByteRange`, los bytes firmados y el bloque CMS DER de `/Contents`, y valida que el ByteRange sea coherente con el tamaño real del fichero.

2. **Verificación CMS con Bouncy Castle**: reconstruye el `CMSSignedData` con los bytes firmados y verifica la firma mediante `JcaSimpleSignerInfoVerifierBuilder`. El certificado X.509 se extrae del propio CMS embebido.

La respuesta incluye diagnóstico granular (`firmaExtraible`, `byteRangeValido`, `cmsParseable`, `certificadoExtraible`, `firmaValida`, `certificadoVigente`) para identificar exactamente en qué paso falla la verificación. El algoritmo de firma se resuelve desde los OIDs del `SignerInfo` con soporte para ECDSA, Ed25519 y RSA.

---

## Estructura del proyecto

```
src/main/
├── java/es/faustino/securesign/
│   ├── controller/
│   │   └── DocumentController.java        # Endpoints REST: /generate y /verify
│   ├── dto/
│   │   ├── internal/
│   │   │   └── ResultadoExtraccion.java   # DTO interno: ByteRange + bytes CMS
│   │   ├── request/
│   │   │   └── DocumentRequest.java       # DTO de entrada (record)
│   │   └── response/
│   │       └── VerificationResultResponse.java  # DTO de respuesta con diagnóstico granular
│   ├── keys/
│   │   ├── KeyManagementService.java      # Generación de pares de claves (EC / Ed25519)
│   │   └── KeyStoreService.java           # Carga y persistencia del KeyStore PKCS#12
│   ├── services/
│   │   ├── certificate/
│   │   │   └── CertificateX509Service.java  # Generación de certificados X.509 autofirmados
│   │   ├── document/
│   │   │   └── DocumentService.java         # Orquestación: generación PDF + firma
│   │   ├── signature/
│   │   │   └── SignatureService.java         # Firma PAdES-B via DSS + KeyStoreSignatureTokenConnection
│   │   └── verification/
│   │       └── VerificationService.java      # Verificación CMS con Bouncy Castle
│   ├── shared/
│   │   ├── config/
│   │   │   ├── BouncyCastleConfig.java    # Registro del provider BC
│   │   │   └── WebConfig.java            # Configuración CORS
│   │   ├── exception/
│   │   │   ├── GlobalExceptionHandler.java
│   │   │   └── KeyNotFoundException.java
│   │   └── util/
│   │       └── ByteRangeExtractor.java   # Parser binario del ByteRange PDF
│   └── SecureSignApplication.java
└── resources/
    ├── application.yaml
    └── static/                            # Interfaz web
        ├── index.html
        ├── css/styles.css
        └── js/
            ├── api.js                     # Llamadas fetch a los endpoints
            ├── ui.js                      # Manipulación del DOM
            └── app.js                     # Lógica y eventos
```

---

## Dependencias principales

| Librería                              | Versión | Rol                                                   |
|---------------------------------------|---------|-------------------------------------------------------|
| Spring Boot Web MVC                   | 4.0.6   | Framework HTTP y servidor embebido                    |
| DSS `dss-pades`                       | 6.4     | Parámetros y servicio PAdES-Baseline-B                |
| DSS `dss-pades-pdfbox`                | 6.4     | Bridge DSS ↔ PDFBox 3.x para firma incremental        |
| DSS `dss-token`                       | 6.4     | `KeyStoreSignatureTokenConnection` (PKCS#12 → DSS)    |
| DSS `dss-cades`                       | 6.4     | Validación offline de firmas CMS                      |
| DSS `dss-cms-object`                  | 6.4     | Modelo de objetos CMS/PKCS#7                          |
| Apache PDFBox                         | 3.0.3   | Generación de PDF antes del firmado                   |
| Bouncy Castle (`bcpkix-jdk18on`)      | (BOM)   | ECDSA, Ed25519, CMS, X.509 — versión gestionada por DSS BOM |
| Spring Security Crypto                | (BOM)   | Utilidades de cifrado para el KeyStore                |
