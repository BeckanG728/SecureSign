# SecureSign

API REST para firma digital y verificación de documentos PDF con **firma PAdES embebida**. Desarrollado con Spring Boot
4 y Java 17, usando DSS (Digital Signature Services) de la UE y BouncyCastle.

---

## Tecnologías

| Tecnología     | Versión          |
|----------------|------------------|
| Java           | 17               |
| Spring Boot    | 4.0.6            |
| EU DSS (PAdES) | 6.4              |
| Apache PDFBox  | 3.0.3            |
| BouncyCastle   | (BOM DSS 6.4)    |
| Maven          | Wrapper incluido |

---

## Estructura del proyecto

```
src/main/java/es/faustino/securesign/
├── SecureSignApplication.java
├── controller/
│   └── DocumentController.java             # POST /api/documents/sign y /verify
├── dto/
│   ├── internal/
│   │   ├── ResultadoExtraccion.java        # ByteRange + bytes cubiertos + CMS DER (record)
│   │   └── DatosCertificado.java           # Par (certHolder, cert) para verificación (record)
│   └── response/
│       └── VerificationResultResponse.java # JSON de salida con builder interno
├── keys/
│   ├── KeyManagementService.java           # Generación y búsqueda de pares de claves
│   └── KeyStoreService.java                # Persistencia PKCS#12 en disco
├── services/
│   ├── certificate/
│   │   └── CertificateX509Service.java     # Emisión de certificados X.509v3 autofirmados
│   ├── document/
│   │   └── DocumentService.java            # Orquestación: generar clave → firmar
│   ├── signature/
│   │   └── SignatureService.java           # Firma PAdES con DSS
│   └── verification/
│       └── VerificationService.java        # Pipeline de verificación CMS/PAdES
└── shared/
    ├── config/
    │   ├── BouncyCastleConfig.java
    │   └── WebConfig.java
    ├── enums/
    │   └── SignatureAlgorithm.java          # OIDs, nombres JCA y DigestAlgorithm
    ├── exception/
    │   ├── GlobalExceptionHandler.java
    │   └── KeyNotFoundException.java
    └── util/
        ├── ByteRangeExtractor.java          # Extracción de ByteRange y bloque CMS del PDF
        ├── CmsUtils.java                    # Parseo de CMSSignedData y búsqueda de SignerInfo
        └── CertificadoUtils.java            # Extracción y conversión de certificados X.509
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
  "valido": true,
  "firmaExtraible": true,
  "estructuraValida": true,
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

El campo `razon` es `null` cuando `valido` es `true`. En caso de fallo contiene el motivo exacto
(p. ej. `"El documento fue modificado después de ser firmado"`).

---

## Algoritmos soportados

| Valor en API | Curva / Estándar  | Algoritmo de firma | Hash    |
|--------------|-------------------|--------------------|---------|
| `EC`         | secp256r1 (P-256) | SHA256withECDSA    | SHA-256 |
| `Ed25519`    | Curve25519        | EdDSA              | SHA-512 |

La resolución de OID ↔ nombre JCA ↔ DigestAlgorithm está centralizada en `SignatureAlgorithm.java`.

---

## Arquitectura y flujo

### Firma (`/sign`)

```
POST /api/documents/sign  (multipart: file + algorithm)
  └─► DocumentController.generate()
        └─► DocumentService.firmarDocumento()
              ├─► KeyManagementService.generarYAlmacenarParDeClaves()
              │     ├─► KeyPairGenerator  (EC secp256r1 o Ed25519)
              │     ├─► CertificateX509Service.generarCertificadoX509()
              │     │     └─► JcaX509v3CertificateBuilder + JcaContentSignerBuilder (BouncyCastle)
              │     └─► KeyStoreService.guardar()  ← persiste clave + cert en securesign.p12
              └─► SignatureService.firmarPdf()
                    └─► DSS PAdESService  (getDataToSign → sign → signDocument)
                          └─► PDFBox 3.x  ← escribe ByteRange y bloque /Contents en el PDF
```

Cada operación genera un par de claves nuevo con su certificado X.509v3 autofirmado, persiste ambos en el
KeyStore PKCS#12 bajo un alias UUID y devuelve el PDF con la firma embebida.

### Verificación (`/verify`)

```
POST /api/documents/verify  (multipart: file)
  └─► DocumentController.verify()
        └─► VerificationService.verificarDocumentoFirmado()
              ├─► ByteRangeExtractor.extraer()
              │     └─► PDFBox 3.x  ← lee /ByteRange y extrae /Contents como DER
              │           └─► ResultadoExtraccion (dto/internal)
              ├─► CmsUtils.parsearCMS()
              │     └─► BouncyCastle ASN1InputStream + CMSSignedData
              ├─► CertificadoUtils.extraerCertHolder() + convertirCertificado()
              │     └─► DatosCertificado (dto/internal)
              ├─► CmsUtils.buscarSignerParaCertificado()
              └─► SignerInformation.verify()  ← recalcula hash y compara (BouncyCastle)
                    └─► VerificationResultResponse  (builder interno)
```

La verificación es completamente **offline**: todo lo necesario (firma, certificado, ByteRange) viaja
dentro del propio PDF.

### Campos de `VerificationResultResponse`

| Campo                  | Significado                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `valido`               | Resultado global: `true` solo si `firmaValida && certificadoVigente`        |
| `firmaExtraible`       | Se encontró el diccionario `/Sig` con `/Contents` en el PDF                 |
| `estructuraValida`     | `offset2 + longitud2 == tamañoPDF` (el ByteRange cubre el archivo completo) |
| `cmsParseable`         | El DER en `/Contents` es un `CMSSignedData` válido                          |
| `certificadoExtraible` | El CMS contiene al menos un certificado X.509 convertible                   |
| `firmaValida`          | El hash recalculado coincide con el valor de firma                          |
| `certificadoVigente`   | El certificado no ha expirado en el momento de la verificación              |
| `algoritmoFirma`       | OID resuelto al nombre legible (`SHA256withECDSA`, `Ed25519`, etc.)         |
| `razon`                | Descripción del primer fallo encontrado; `null` si `valido` es `true`       |

---

## Notas técnicas

**PDFBox 3.x es obligatorio.** PDFBox 2.x calcula los offsets del `ByteRange` antes de serializar el xref,
provocando desalineación de bytes en `/Contents`. DSS 6.x usa exclusivamente la API de PDFBox 3.x.

**El bloque CMS se extrae del PDF original, no del recortado.** PDFBox necesita la estructura completa del
PDF para indexar los diccionarios de firma. El recorte (`recortarPdfAlTamanoOriginal`) solo se aplica para
ensamblar los bytes cubiertos por la firma.

**BOM de DSS antes de BouncyCastle.** El BOM `dss-bom` fija la versión de `bcprov-jdk18on` compatible con
las firmas PAdES. Declararlo antes del BOM de Spring Boot evita que este último inyecte una versión más
antigua de BC.

**`CommonCertificateVerifier` sin revocación.** La firma se realiza sin consultar OCSP ni CRL, adecuado
para certificados autofirmados en entornos de desarrollo y universitarios.

**Builder interno en `VerificationResultResponse`.** Los factory methods (`sinFirma`, `firmaInvalida`, etc.)
usan un builder privado en lugar de constructores posicionales de 13 argumentos, lo que hace más segura la
adición de nuevos campos al record.

---