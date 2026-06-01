# SecureSign

API REST para firma digital y verificación de documentos PDF con **firma PAdES CAdES-detached embebida**.
Desarrollado con Spring Boot 4 y Java 17, usando DSS (Digital Signature Services) de la UE y BouncyCastle.

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
├── crypto/
│   ├── CryptoIdentityService.java          # Inicialización y obtención de identidades (alias → cert)
│   ├── KeyStoreAccessService.java          # Acceso y persistencia del KeyStore PKCS#12
│   └── CertificateX509Service.java         # Emisión de certificados X.509v3 autofirmados
├── dto/
│   ├── internal/
│   │   ├── ResultadoExtraccion.java        # ByteRange + bytes cubiertos + CMS DER (record)
│   │   └── DatosCertificado.java           # Par (certHolder, cert) para verificación (record)
│   └── response/
│       └── VerificationResultResponse.java # JSON de salida con factory methods internos
├── services/
│   ├── SignatureService.java               # Firma PAdES con DSS
│   └── VerificationService.java            # Pipeline de verificación CMS/PAdES
└── shared/
    ├── config/
    │   ├── BouncyCastleConfig.java         # Registro del provider BC
    │   └── WebConfig.java
    ├── enums/
    │   └── SignatureAlgorithm.java          # OIDs, nombres JCA, DigestAlgorithm y generación de claves
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

### Variables de entorno / properties

| Property                      | Variable de entorno            | Valor por defecto         | Descripción                          |
|-------------------------------|--------------------------------|---------------------------|--------------------------------------|
| `securesign.keystore-path`    | —                              | `securesign.p12`          | Ruta del archivo KeyStore PKCS#12    |
| `securesign.keystore-password`| `SECURESIGN_KEYSTORE_PASSWORD` | —                         | Contraseña del KeyStore              |
| `securesign.alias-ecdsa`      | —                              | —                         | Alias de la clave ECDSA en el store  |
| `securesign.alias-ed25519`    | —                              | —                         | Alias de la clave Ed25519 en el store|

Al arrancar, `CryptoIdentityService` inicializa automáticamente los dos alias si no existen en el KeyStore.

---

## API Reference

### `POST /api/documents/sign`

Firma un PDF con PAdES Baseline-B y devuelve el PDF firmado como descarga.

**Parámetros (multipart/form-data):**

| Campo       | Tipo    | Requerido | Descripción                              |
|-------------|---------|-----------|------------------------------------------|
| `file`      | Archivo | Sí        | PDF a firmar                             |
| `algorithm` | String  | Sí        | `SHA256withECDSA` o `Ed25519`            |

**Respuesta:** `application/pdf` — el PDF con la firma PAdES embebida.
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
  "subject": "CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE",
  "validoDesde": "2026-06-01T19:32:36Z",
  "validoHasta": "2027-06-01T19:33:36Z",
  "algoritmoFirma": "SHA256withECDSA",
  "razon": null
}
```

`razon` es `null` cuando `valido` es `true`. En caso de fallo contiene el motivo exacto,
por ejemplo `"El documento fue modificado después de ser firmado"`.

#### Campos de la respuesta

| Campo                  | Significado                                                                              |
|------------------------|------------------------------------------------------------------------------------------|
| `valido`               | `true` solo si `firmaValida && certificadoVigente`                                       |
| `firmaExtraible`       | Se encontró el diccionario `/Sig` con `/Contents` en el PDF                              |
| `estructuraValida`     | `offset2 + longitud2 == tamañoPDF` — el ByteRange cubre el archivo completo              |
| `cmsParseable`         | El DER en `/Contents` es un `CMSSignedData` válido                                       |
| `certificadoExtraible` | El CMS contiene al menos un certificado X.509 convertible                                |
| `firmaValida`          | El hash recalculado de los bytes firmados coincide con el valor de firma del `SignerInfo` |
| `certificadoVigente`   | El certificado no ha expirado al momento de la verificación                              |
| `algoritmoFirma`       | OID resuelto a nombre legible (`SHA256withECDSA`, `Ed25519`, etc.)                       |
| `razon`                | Descripción del primer fallo; `null` si `valido` es `true`                               |

---

## Algoritmos soportados

| `algorithm` en API   | Curva / Estándar  | JCA Name         | Hash    |
|----------------------|-------------------|------------------|---------|
| `SHA256withECDSA`    | secp256r1 (P-256) | SHA256withECDSA  | SHA-256 |
| `Ed25519`            | Curve25519        | Ed25519          | SHA-512 |

RSA (`SHA256withRSA`, `SHA512withRSA`) está definido en el enum `SignatureAlgorithm` para
resolución de OIDs en verificación, pero no genera claves propias en este sistema.

La resolución OID ↔ JCA Name ↔ DigestAlgorithm está centralizada en `SignatureAlgorithm.java`.

---

## Arquitectura y flujo

### Firma (`/sign`)

```
POST /api/documents/sign  (multipart: file + algorithm)
  └─► DocumentController.sign()
        └─► SignatureService.firmarDocumento(bytesPdf, "SHA256withECDSA")
              ├─► SignatureAlgorithm.fromJcaName()       → SHA256_WITH_ECDSA
              ├─► CryptoIdentityService.obtenerCertificado()
              │     └─► KeyStoreAccessService.cargar()   → cert del alias "ecdsa-key"
              └─► firmarPdf(bytesPdf, certificado, algoritmo)
                    ├─► buscarAliasPorCertificado()      → "ecdsa-key"
                    ├─► abrirConexionToken()             → KeyStoreSignatureTokenConnection
                    ├─► conexionToken.getKey(alias)      → KSPrivateKeyEntry
                    ├─► construirParametrosFirma()
                    │     ├─► PAdES_BASELINE_B + ENVELOPED
                    │     └─► DigestAlgorithm = SHA-256
                    ├─► PAdESService.getDataToSign()     → seg1 + seg2 (ToBeSigned)
                    ├─► conexionToken.sign()             → SHA-256(seg1+seg2) → ECDSA_sign → SignatureValue
                    └─► PAdESService.signDocument()      → empaqueta CMS DER en /Contents + escribe ByteRange
```

### Inicialización de identidades (al arrancar)

```
CryptoIdentityService.inicializarIdentidades()
  ├─► ¿Existe alias "ecdsa-key"?
  │     NO → KeyPairGenerator(EC, secp256r1) → par de claves
  │           CertificateX509Service.generarCertificadoX509()
  │             └─► X509v3 autofirmado, CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE
  │                 KeyUsage: digitalSignature + nonRepudiation | BasicConstraints: CA=false
  │           KeyStoreAccessService.guardar() → securesign.p12
  └─► ¿Existe alias "ed25519-key"?
        NO → KeyPairGenerator(Ed25519) → mismo proceso
```

### Verificación (`/verify`)

```
POST /api/documents/verify  (multipart: file)
  └─► DocumentController.verify()
        └─► VerificationService.verificarDocumentoFirmado(bytesPdf)
              ├─► ByteRangeExtractor.extraer()
              │     ├─► PDFBox: AcroForm → Fields[0] → dict /Sig → PDSignature
              │     ├─► new ByteRange([0, b, c, d])
              │     ├─► validarByteRange()
              │     │     ├─► byteRange.validate()       → coherencia interna del array
              │     │     └─► c + d == pdf.length?       → cobertura total del archivo
              │     ├─► ensamblarContenidoFirmado()      → seg1 + seg2 del PDF actual
              │     └─► extraerBloqueCmsDer()            → /Contents como bytes DER
              │           └─► ResultadoExtraccion
              ├─► CmsUtils.parsearCMS(bytesCMS, bytesPdfCubiertos)
              │     └─► ASN1InputStream → ContentInfo → CMSSignedData(bytesPdfCubiertos)
              ├─► CertificadoUtils.extraerCertHolder()
              │     └─► X509CertificateHolder → X509Certificate → DatosCertificado
              ├─► CmsUtils.buscarSignerParaCertificado() → SignerInfo por SID (issuer+serial)
              └─► signerInfo.verify(certHolder)
                    ├─► digest(bytesPdfCubiertos) == messageDigest en signedAttrs?
                    └─► firma sobre signedAttrs DER válida con clave pública del cert?
                          └─► VerificationResultResponse
```

La verificación es completamente **offline**: todo lo necesario (firma, certificado, ByteRange)
viaja dentro del propio PDF.

---

## Notas técnicas

**PDFBox 3.x es obligatorio.** PDFBox 2.x calcula los offsets del `ByteRange` antes de serializar
el xref, provocando desalineación de bytes en `/Contents`. DSS 6.x usa exclusivamente la API de PDFBox 3.x.

**BOM de DSS antes de BouncyCastle.** El BOM `dss-bom` fija la versión de `bcprov-jdk18on` compatible
con las firmas PAdES. Declararlo antes del BOM de Spring Boot evita que este último inyecte una versión
incompatible de BC.

**`CommonCertificateVerifier` sin revocación.** La firma se realiza sin consultar OCSP ni CRL,
adecuado para certificados autofirmados en entornos de desarrollo y universitarios.

**`estructuraValida` y `firmaValida` son verificaciones independientes.** `estructuraValida` detecta
bytes añadidos fuera del ByteRange (Incremental Updates no autorizados). `firmaValida` detecta
modificaciones dentro del rango firmado. Ninguna sustituye a la otra.

**La firma no se verifica directamente sobre el hash del PDF.** BouncyCastle verifica la firma sobre
los `signedAttrs` serializados en DER — que incluyen el hash del contenido más atributos como
`ContentType` y `SigningTime`. Es parte de la spec CAdES.

---