# SecureSign — Flujo de Firma de Documentos PDF

Documentación técnica del proceso de firma digital PAdES CAdES-detached,
basada en el análisis de `SignatureService`, `CryptoIdentityService`, `KeyStoreAccessService`,
`CertificateX509Service` y `SignatureAlgorithm`.

---

## 1. Entrada al sistema

El flujo comienza en `DocumentController`:

```
POST /api/documents/sign
  @RequestParam file      → PDF como MultipartFile
  @RequestParam algorithm → "SHA256withECDSA" | "Ed25519" | "SHA256withRSA" | "SHA512withRSA"
```

El controller extrae los bytes del PDF y delega:

```java
byte[] pdfFirmado = signatureService.firmarDocumento(file.getBytes(), algoritmo);
```

El PDF firmado se retorna como descarga con nombre `{original}_firmado.pdf`.

---

## 2. Algoritmos soportados

`SignatureAlgorithm` es el enum central que unifica los distintos algoritmos disponibles:

| Enum | JCA Name | OID | Digest (DSS) | Curva / Tipo |
|------|----------|-----|--------------|--------------|
| `SHA256_WITH_ECDSA` | `SHA256withECDSA` | `1.2.840.10045.4.3.2` | SHA-256 | secp256r1 (P-256) |
| `ED25519` | `Ed25519` | `1.3.101.112` | SHA-512 | Curve25519 |
| `SHA256_WITH_RSA` | `SHA256withRSA` | `1.2.840.113549.1.1.11` | SHA-256 | RSA |
| `SHA512_WITH_RSA` | `SHA512withRSA` | `1.2.840.113549.1.1.13` | SHA-512 | RSA |

Solo `SHA256_WITH_ECDSA` y `ED25519` tienen implementación de `generarParDeClaves()` —
son los únicos algoritmos para los que el sistema puede crear identidades propias.
RSA existe en el enum para resolución/verificación pero no genera claves.

---

## 3. KeyStore — almacén de identidades

El sistema usa un archivo `securesign.p12` (PKCS12) como KeyStore persistente.
`KeyStoreAccessService` gestiona todo acceso a él:

```
securesign.p12
├── alias: "ecdsa-key"   → clave privada ECDSA + certificado X.509
└── alias: "ed25519-key" → clave privada Ed25519 + certificado X.509
```

Los alias se configuran vía properties:
```
securesign.alias-ecdsa    = ecdsa-key
securesign.alias-ed25519  = ed25519-key
securesign.keystore-path  = securesign.p12
securesign.keystore-password = <contraseña>
```

`guardar()` es `synchronized` para evitar escrituras concurrentes al archivo `.p12`.

---

## 4. Inicialización de identidades

`CryptoIdentityService.inicializarIdentidades()` se ejecuta al arrancar la aplicación.
Para cada algoritmo firmante (ECDSA y Ed25519), verifica si el alias ya existe en el KeyStore:

```
¿Existe alias en KeyStore?
    SÍ → log "ya existe", no hace nada
    NO → genera par de claves + certificado X.509 → guarda en KeyStore
```

### 4.1 Generación del par de claves

```java
// ECDSA — curva P-256
KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
gen.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair parDeClaves = gen.generateKeyPair();

// Ed25519
KeyPair parDeClaves = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
```

### 4.2 Generación del certificado X.509 (`CertificateX509Service`)

Con el par de claves se genera un certificado X.509 autofirmado usando BouncyCastle:

```
Subject / Issuer: CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE
Serial:           128 bits aleatorios (SecureRandom)
Validez:          desde: ahora - 1 minuto
                  hasta: ahora + 365 días
Clave pública:    la recién generada
```

Extensiones X.509 añadidas:

| Extensión | Crítica | Valor |
|-----------|---------|-------|
| `SubjectKeyIdentifier` | No | hash de la clave pública |
| `AuthorityKeyIdentifier` | No | hash de la clave pública (autofirmado) |
| `KeyUsage` | Sí | `digitalSignature` + `nonRepudiation` |
| `BasicConstraints` | Sí | `CA=false` (no es CA) |

El certificado se firma con la propia clave privada recién generada — es autofirmado.
Esto corresponde al certificado `CN=Equipo-01 SecureSign` que aparece embebido en el `/Contents`
del PDF firmado.

---

## 5. SignatureService — proceso de firma paso a paso

### 5.1 `firmarDocumento()`

```java
SignatureAlgorithm algoritmo = SignatureAlgorithm.fromJcaName(jcaName);
X509Certificate certificado  = cryptoIdentityService.obtenerCertificado(algoritmo);
```

Resuelve el algoritmo desde el string recibido (`"SHA256withECDSA"`) y obtiene el certificado
correspondiente del KeyStore.

### 5.2 Buscar alias

```java
String alias = keyStoreService.buscarAliasPorCertificado(certificado);
```

Recorre todos los aliases del KeyStore comparando certificados por `equals()` hasta encontrar
el que corresponde al certificado dado. Retorna el alias (ej. `"ecdsa-key"`).

### 5.3 Abrir conexión al token DSS

```java
KeyStoreSignatureTokenConnection conexionToken = keyStoreService.abrirConexionToken();
KSPrivateKeyEntry identidadFirmante = conexionToken.getKey(alias);
```

DSS abstrae el acceso al KeyStore PKCS12 como si fuera un token criptográfico HSM.
`KSPrivateKeyEntry` agrupa la clave privada + certificado + cadena de certificados.

### 5.4 Construir parámetros PAdES

```java
PAdESSignatureParameters parametros = new PAdESSignatureParameters();
parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);
parametros.setSigningCertificate(identidadFirmante.getCertificate());
parametros.setCertificateChain(identidadFirmante.getCertificateChain());
parametros.setDigestAlgorithm(SignatureAlgorithm.resolverDigestDss(algoritmo));
```

| Parámetro | Valor | Significado |
|-----------|-------|-------------|
| `SignatureLevel` | `PAdES_BASELINE_B` | Nivel básico — sin timestamp TSA ni revocación |
| `SignaturePackaging` | `ENVELOPED` | La firma va dentro del propio PDF (no separada) |
| `DigestAlgorithm` | SHA-256 o SHA-512 | Según el algoritmo elegido |

`ENVELOPED` es lo que produce el `ByteRange` que estudiamos — la firma queda en el campo
`/Contents` dentro del PDF, excluyéndose a sí misma mediante el ByteRange.

### 5.5 `getDataToSign()` — obtener bytes a firmar

```java
ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
```

DSS prepara internamente el PDF dejando el espacio para el `/Contents`, calcula el ByteRange,
y retorna los bytes que corresponden a `seg1 + seg2` — exactamente lo que luego se llamará
`bytesPdfCubiertos` en la verificación.

### 5.6 `conexionToken.sign()` — firma criptográfica

```java
SignatureValue valorFirma = conexionToken.sign(
    datosAFirmar,
    parametrosFirma.getDigestAlgorithm(),
    identidadFirmante
);
```

Aquí ocurre la operación criptográfica real con la clave privada:

```
ECDSA:
  hash = SHA-256(datosAFirmar)
  firma = ECDSA_sign(hash, clavePrivadaECDSA)  → par (r, s) codificado en DER

Ed25519:
  firma = Ed25519_sign(datosAFirmar, clavePrivadaEd25519)
  (Ed25519 no necesita hash previo separado — lo hace internamente)
```

### 5.7 `signDocument()` — ensamblar PDF firmado

```java
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);
```

DSS toma el valor de firma calculado y lo empaqueta en un bloque CMS/PKCS#7 DER que incluye:

```
SignedData
├── digestAlgorithms        → SHA-256 o SHA-512
├── encapContentInfo        → vacío (detached — el contenido está en el PDF)
├── certificates            → certificado X.509 del firmante embebido
└── signerInfos
    └── SignerInfo
        ├── sid             → issuer + serial del certificado
        ├── signedAttrs     → { contentType, messageDigest(hash del pdf) }
        ├── signatureAlg    → OID del algoritmo (ECDSA/Ed25519/RSA)
        └── signature       → el valor de firma calculado en 5.6
```

Este bloque DER se escribe como hex en el campo `/Contents` del PDF, y el `ByteRange`
queda registrado en el diccionario `/Sig` apuntando exactamente a los bytes que lo rodean.

---

## 6. Estructura del PDF resultante

```
┌──────────────────────────┬──────────────────────────────┬────────────────┐
│   Segmento 1             │  /Contents <bloque CMS DER>  │   Segmento 2   │
│   (cabecera, páginas,    │  (firma + certificado)        │   (xref,       │
│    AcroForm, dict /Sig)  │                               │    trailer)    │
└──────────────────────────┴──────────────────────────────┴────────────────┘
 ←————————————ByteRange[0,b]————————————→               ←——ByteRange[c,d]——→
```

El diccionario `/Sig` (dict V) quedará poblado exactamente como el que analizamos:

```
V (dict)
├── Type      = /Sig
├── Filter    = /Adobe.PPKLite
├── SubFilter = /ETSI.CAdES.detached
├── M         = "D:YYYYMMDDHHMMSS±HH'MM'"   ← timestamp local
├── Contents  = <bloque CMS DER en binario>
└── ByteRange = [0, b, c, d]
```

---

## 7. Diagrama del flujo completo

```
POST /api/documents/sign (file, algorithm)
    │
    ▼
SignatureService.firmarDocumento(bytesPdf, "SHA256withECDSA")
    │
    ├── SignatureAlgorithm.fromJcaName()    → SHA256_WITH_ECDSA
    ├── CryptoIdentityService
    │       └── obtenerCertificado()        → X509Certificate (CN=Equipo-01 SecureSign)
    │
    └── firmarPdf(bytesPdf, certificado, algoritmo)
            │
            ├── buscarAliasPorCertificado() → "ecdsa-key"
            ├── abrirConexionToken()        → KeyStoreSignatureTokenConnection (securesign.p12)
            ├── conexionToken.getKey()      → KSPrivateKeyEntry (clavePrivada + cert + cadena)
            │
            ├── construirParametrosFirma()
            │       ├── PAdES_BASELINE_B
            │       ├── ENVELOPED
            │       └── DigestAlgorithm = SHA-256
            │
            ├── construirServicioPades()    → PAdESService (sin verificación de revocación)
            │
            ├── getDataToSign()             → seg1 + seg2 (ToBeSigned)
            │       └── DSS reserva espacio para /Contents y calcula ByteRange
            │
            ├── conexionToken.sign()        → SignatureValue
            │       └── SHA-256(seg1+seg2) → ECDSA_sign(hash, clavePrivada) → (r,s) DER
            │
            └── signDocument()             → PDF firmado
                    └── empaqueta SignatureValue en bloque CMS DER
                        escribe en /Contents, registra ByteRange en /Sig
    │
    ▼
byte[] pdfFirmado → ResponseEntity (attachment: documento_firmado.pdf)
```

---

## 8. Relación con el flujo de verificación

Lo que produce `SignatureService` es exactamente lo que consume `VerificationService`:

| Producido en firma | Consumido en verificación |
|---|---|
| `ByteRange = [0, b, c, d]` en `/Sig` | `ByteRangeExtractor` lo lee para extraer seg1 + seg2 |
| Bloque CMS DER en `/Contents` | `extraerBloqueCmsDer()` lo extrae como `bytesCMS` |
| Certificado X.509 embebido en CMS | `CertificadoUtils.extraerCertHolder()` lo recupera |
| `SignerInfo` con hash + firma | `signerInfo.verify()` recalcula el hash y verifica la firma |
| Clave privada (nunca sale del KeyStore) | Su par público en el certificado verifica la firma |
