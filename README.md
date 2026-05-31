# SecureSign

API REST para firma digital y verificación de documentos PDF con **firma PAdES embebida**. Desarrollado con Spring Boot
4 y Java 17, usando DSS (Digital Signature Services) de la UE y BouncyCastle.

---

## Tecnologías

| Tecnología             | Versión           |
|------------------------|-------------------|
| Java                   | 17                |
| Spring Boot            | 4.0.6             |
| EU DSS (PAdES)         | 6.4               |
| Apache PDFBox          | 3.0.3             |
| BouncyCastle           | (BOM DSS 6.4)     |
| Spring Security Crypto | (BOM Spring Boot) |
| Maven                  | Wrapper incluido  |

---

## Estructura del proyecto

```
src/main/java/es/faustino/securesign/
├── SecureSignApplication.java
├── controller/
│   └── DocumentController.java           # POST /api/documents/generate y /verify
├── dto/
│   ├── internal/
│   │   └── ResultadoExtraccion.java
│   └── response/
│       └── VerificationResultResponse.java
├── keys/
│   ├── KeyManagementService.java         # Generación y búsqueda de pares de claves
│   └── KeyStoreService.java              # Persistencia PKCS#12 en disco
├── services/
│   ├── certificate/
│   │   └── CertificateX509Service.java   # Emisión de certificados X.509 autofirmados
│   ├── document/
│   │   └── DocumentService.java          # Orquestación: generar clave → firmar
│   ├── signature/
│   │   └── SignatureService.java         # Firma PAdES con DSS
│   └── verification/
│       └── VerificationService.java      # Verificación CMS/PAdES con BouncyCastle
└── shared/
    ├── config/
    │   ├── BouncyCastleConfig.java
    │   └── WebConfig.java
    ├── exception/
    │   ├── GlobalExceptionHandler.java
    │   └── KeyNotFoundException.java
    └── util/
        └── ByteRangeExtractor.java       # Extracción del bloque /Contents y ByteRange
```

---

## Ejecución

```bash
./mvnw spring-boot:run       # Linux / macOS
mvnw.cmd spring-boot:run     # Windows
```

El servidor escucha en `http://localhost:8080`.

La interfaz web está disponible en `http://localhost:8080/index.html`.

### Variables de entorno

| Variable                       | Valor por defecto         | Descripción                     |
|--------------------------------|---------------------------|---------------------------------|
| `SECURESIGN_KEYSTORE_PASSWORD` | `securesign-dev-password` | Contraseña del KeyStore PKCS#12 |

El archivo del KeyStore se guarda como `securesign.p12` en el directorio de trabajo (configurable con
`securesign.keystore-path`).

---

## API Reference

### `POST /api/documents/sign`

Firma un PDF con PAdES Baseline-B y devuelve el PDF firmado como descarga.

**Parámetros (multipart/form-data):**

| Campo       | Tipo    | Requerido | Descripción                    |
|-------------|---------|-----------|--------------------------------|
| `file`      | Archivo | Sí        | PDF a firmar                   |
| `algorithm` | String  | No        | `EC` (por defecto) o `Ed25519` |

**Respuesta:** `application/pdf` — el PDF original con la firma PAdES embebida.

El nombre del archivo descargado será `<nombre-original>_firmado.pdf`.

---

### `POST /api/documents/verify`

Verifica la firma PAdES de un PDF firmado.

**Parámetros (multipart/form-data):**

| Campo  | Tipo    | Requerido | Descripción             |
|--------|---------|-----------|-------------------------|
| `file` | Archivo | Sí        | PDF firmado a verificar |

**Respuesta:** `application/json`

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
  "validoDesde": "2026-05-30T12:00:00Z",
  "validoHasta": "2027-05-30T12:00:00Z",
  "algoritmoFirma": "SHA256withECDSA",
  "razon": null
}
```

El campo `razon` contiene el motivo del fallo cuando `valid` es `false`.

---

## Algoritmos soportados

| Valor en API | Curva / Estándar  | Algoritmo de firma | Hash            |
|--------------|-------------------|--------------------|-----------------|
| `EC`         | secp256r1 (P-256) | SHA256withECDSA    | SHA-256 externo |
| `Ed25519`    | Curve25519        | EdDSA              | SHA-512 interno |

---

## Arquitectura y flujo

### Firma (`/generate`)

```
HTTP multipart/form-data (PDF + algorithm)
  └─► DocumentController.generate()  →  POST /api/documents/signed
        └─► DocumentService.firmarDocumento()
              ├─► KeyManagementService.generarYAlmacenarParDeClaves()
              │     ├─► KeyPairGenerator (EC secp256r1 o Ed25519)
              │     ├─► CertificateX509Service.generarCertificadoX509()   ← cert autofirmado X.509v3
              │     └─► KeyStoreService.guardar()                         ← persiste en PKCS#12
              └─► SignatureService.firmarPdf()
                    └─► DSS PAdESService.signDocument()                   ← firma PAdES Baseline-B
                          └─► PDFBox 3.x saveIncremental()                ← ByteRange correcto
```

Cada operación de firma genera un nuevo par de claves con su propio certificado X.509 autofirmado. El par se persiste en
el KeyStore PKCS#12 en disco y sobrevive a reinicios.

### Verificación (`/verify`)

```
HTTP multipart/form-data (PDF firmado)
  └─► DocumentController.verify()
        └─► VerificationService.verificarDocumentoFirmado()
              ├─► ByteRangeExtractor.extraer()          ← parsea /ByteRange y /Contents del PDF
              ├─► CMSSignedData (BouncyCastle)           ← parsea el bloque CMS DER
              ├─► JcaX509CertificateConverter            ← extrae el cert X.509 embebido
              └─► SignerInformation.verify()             ← verifica la firma criptográfica
```

La verificación es completamente **offline**: no contacta ninguna CA ni servicio de revocación externo.

### Descripción detallada de campos en `VerificationResultResponse`

| Campo                  | Significado                                                                       |
|------------------------|-----------------------------------------------------------------------------------|
| `valid`                | Resultado global: `true` solo si `firmaValida && certificadoVigente`              |
| `firmaExtraible`       | Se encontró y extrajo el bloque `/Contents` del PDF                               |
| `byteRangeValido`      | El `/ByteRange` cubre exactamente los bytes fuera del bloque de firma             |
| `cmsParseable`         | El bloque DER en `/Contents` es un `CMSSignedData` válido                         |
| `certificadoExtraible` | El CMS contiene al menos un certificado X.509                                     |
| `firmaValida`          | El hash del documento coincide con el valor de firma (verificación criptográfica) |
| `certificadoVigente`   | El certificado no ha expirado en el momento de la verificación                    |
| `algoritmoFirma`       | OID resuelto al nombre legible (ej. `SHA256withECDSA`, `Ed25519`)                 |

---

## Notas técnicas

**PDFBox 3.x es obligatorio.** PDFBox 2.x calcula los offsets del `ByteRange` antes de serializar el xref, lo que
provoca desalineación de 1–4 bytes en el bloque `/Contents`. Resultado: `ByteRange invalid` en Adobe Acrobat. DSS 6.x
usa exclusivamente la API de PDFBox 3.x.

**BOM de DSS antes de BouncyCastle.** El BOM `dss-bom` gestiona la versión de `bcprov-jdk18on`. Mezclar `bcprov-jdk15on`
y `bcprov-jdk18on` en el classpath causa `ClassNotFoundException` en runtime.

**`CommonCertificateVerifier` sin revocación.** La firma se realiza sin consultar OCSP ni CRL, adecuado para
certificados autofirmados en entornos de desarrollo y universitarios.

---

## Tests de integración

`FirmaVerificacionTest` cubre cuatro escenarios sin contexto Spring:

| Test      | Descripción                                                          |
|-----------|----------------------------------------------------------------------|
| Estado 0  | PDF firmado → verificación válida (EC secp256r1)                     |
| Estado 1  | PDF modificado post-firma → `firmaValida: false`, estructura intacta |
| Sin firma | PDF sin firma → detectado como `firmaExtraible: false`               |
| Ed25519   | PDF firmado con Ed25519 → verificación válida                        |

```bash
./mvnw test
```
