# SecureSign

API REST para la emisión y verificación de documentos PDF con firma digital embebida siguiendo el estándar **PAdES** (
PDF Advanced Electronic Signatures), implementado con Bouncy Castle sobre Spring Boot.

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

El campo `algorithm` acepta `EC` o `Ed25519`. Devuelve el PDF firmado como `application/pdf`.

### POST `/api/documents/verify`

Body `multipart/form-data` con el campo `file` conteniendo el PDF firmado. Devuelve JSON:

```json
{
  "valid": true,
  "firmaValida": true,
  "certificadoVigente": true,
  "subject": "CN=SecureSign Institucional, O=Universidad, C=PE",
  "validoDesde": "Fri May 30 ...",
  "validoHasta": "Sat May 30 ..."
}
```

---

## Arquitectura y fundamentos criptográficos

### Generación de claves — ECDSA y Ed25519

Cada documento se firma con un par de claves efímero generado en tiempo de ejecución. El proyecto soporta dos familias
de algoritmos de curva elíptica:

**EC (ECDSA sobre secp256r1)**

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair keyPair = kpg.generateKeyPair();
```

`secp256r1` (también llamada `P-256`) es la curva recomendada por NIST SP 800-186 y es ampliamente utilizada en TLS 1.3,
JWT (ES256) y documentos eIDAS. Produce claves de 256 bits con seguridad equivalente a RSA-3072.

**Ed25519 (EdDSA)**

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
KeyPair keyPair = kpg.generateKeyPair();
```

Ed25519 está definido en RFC 8032 y es parte del estándar FIPS 186-5. Su diseño evita por construcción ataques de canal
lateral relacionados con la aleatoriedad del nonce (un punto débil histórico de ECDSA). Es el algoritmo preferido en
sistemas modernos como SSH, Signal y WireGuard.

### Certificados X.509 autofirmados

Para cada firma se genera un certificado X.509 v3 que vincula la clave pública con la identidad institucional:

```java
X500Name subject = new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");
JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
    subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
);
```

El certificado tiene un período de validez de 365 días y es autofirmado (issuer == subject). Aunque en producción estos
certificados deberían estar firmados por una CA de confianza (jerarquía PKI), el modelo autofirmado es suficiente para
demostrar la estructura PAdES porque el certificado viaja embebido en el propio PDF y la verificación no depende de una
cadena de confianza externa.

### Almacenamiento de claves — PKCS#12

Las claves privadas y los certificados se persisten en un KeyStore de tipo PKCS#12 (`.p12`), el formato interoperable
definido en RFC 7292:

```java
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.setKeyEntry(keyId, privateKey, password, new Certificate[]{ cert });
```

El archivo se cifra simétricamente con la contraseña inyectada via variable de entorno. Cada par de claves recibe un
UUID como alias (`keyId`), lo que permite gestionar múltiples identidades en el mismo almacén sin colisiones.

### Firma PAdES — estructura CMS/PKCS#7

La firma sobre el PDF sigue el perfil **PAdES-BES** (ETSI EN 319 132), que embebe una estructura CMS SignedData
directamente en el stream del documento PDF:

```java
ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(privateKey);
CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
gen.addSignerInfoGenerator(
    new JcaSignerInfoGeneratorBuilder(digestProvider).build(signer, cert)
);
gen.addCertificates(new JcaCertStore(List.of(cert)));
CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(content), false);
```

El último argumento `false` en `gen.generate()` indica firma *detached*: los bytes firmados no se duplican dentro del
CMS, sino que la firma referencia el contenido original del PDF. PDFBox embebe esta firma en un rango de bytes
reservado (`/ByteRange`) del documento, produciendo un PDF autocontenible verificable independientemente.

### Verificación independiente del servidor

La verificación no requiere ningún estado del servidor ni el `keyId` original. El PDF contiene todo lo necesario:

```java
// Extraer firma embebida
byte[] signatureBytes = signature.getContents(pdfBytes);   // estructura CMS
byte[] signedContent  = signature.getSignedContent(pdfBytes); // bytes cubiertos por la firma

// Reconstruir y verificar
CMSSignedData cmsSignedData = new CMSSignedData(
    new CMSProcessableByteArray(signedContent), signatureBytes
);
X509Certificate cert = extraerCertificadoDelCMS(cmsSignedData);
boolean firmaValida = signerInfo.verify(
    new JcaSimpleSignerInfoVerifierBuilder().build(cert)
);
```

Este es el principio central de PAdES: el documento es autocontenible. La firma cubre el contenido del PDF (no su hash
en una base de datos externa), y el certificado X.509 del firmante viaja embebido en el mismo CMS. Cualquier
modificación posterior al PDF invalida la firma criptográficamente.

---

## Estructura del proyecto

```
src/main/
├── java/es/faustino/securesign/
│   ├── certificate/
│   │   └── CertificateX509Service.java   # Generación de certificados X.509
│   ├── config/
│   │   └── WebConfig.java                # CORS
│   ├── controller/
│   │   └── DocumentController.java       # Endpoints REST
│   ├── document/
│   │   └── DocumentService.java          # Orquestación del flujo completo
│   ├── exception/
│   │   ├── GlobalExceptionHandler.java
│   │   └── KeyNotFoundException.java
│   ├── model/
│   │   ├── DocumentRequest.java          # DTO de entrada
│   │   └── VerifyRequest.java
│   ├── signature/
│   │   └── SignatureService.java         # KeyStore PKCS#12 + firma PAdES
│   └── verification/
│       └── VerificationService.java      # Verificación CMS independiente
└── resources/
    ├── application.yaml
    └── static/                           # Interfaz web
        ├── index.html
        ├── css/styles.css
        └── js/
            ├── api.js                    # Llamadas fetch a los endpoints
            ├── ui.js                     # Manipulación del DOM
            └── app.js                    # Lógica y eventos
```

---

## Dependencias principales

| Librería                         | Versión | Rol                                      |
|----------------------------------|---------|------------------------------------------|
| Spring Boot Web MVC              | 4.0.6   | Framework HTTP y servidor embebido       |
| Apache PDFBox                    | 3.0.1   | Generación y firma de documentos PDF     |
| Bouncy Castle (`bcpkix-jdk18on`) | 1.84    | Criptografía: ECDSA, Ed25519, CMS, X.509 |
| Spring Security Crypto           | (BOM)   | Utilidades de cifrado para el KeyStore   |
