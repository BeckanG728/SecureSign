# SecureSign — Flujo de Verificación de Firma PDF

Documentación técnica del proceso de verificación de firmas digitales en PDFs firmados con CAdES detached,
basada en el análisis de `ByteRangeExtractor` y `VerificationService`.

---

## 1. Estructura del PDF firmado

Un PDF firmado contiene un `AcroForm` con un campo de tipo `/Sig`. En el PDF analizado:

```
AcroForm
└── Fields[0]  (id: 160)
    ├── FT        = /Sig              ← campo de firma
    ├── T         = "Signature1"      ← nombre del campo
    └── V  (id: 161)                  ← diccionario de la firma
        ├── Type      = /Sig
        ├── Filter    = /Adobe.PPKLite
        ├── SubFilter = /ETSI.CAdES.detached   ← firma CMS externa al contenido
        ├── M         = "D:20260601162433-05'00'"
        ├── Contents  = <bloque CMS binario DER>
        └── ByteRange = [0, 504125, 523071, 1192]
```

El campo `Contents` contiene el bloque CMS/PKCS#7 DER en binario (representado como string en el dump).
El campo `ByteRange` define exactamente qué bytes del archivo fueron firmados.

---

## 2. ¿Qué significa el ByteRange?

```
ByteRange = [0, 504125, 523071, 1192]
             a    b       c       d
```

| Valor | Significado |
|-------|-------------|
| `a = 0` | El segmento 1 empieza al inicio del archivo |
| `b = 504125` | El segmento 1 tiene 504.125 bytes de longitud |
| `c = 523071` | El segmento 2 empieza en el byte 523.071 |
| `d = 1192` | El segmento 2 tiene 1.192 bytes de longitud |

El hueco entre `b` y `c` (bytes 504.125 → 523.070) es donde vive el campo `/Contents` en el archivo binario.
Ese bloque no se firma a sí mismo — de ahí la necesidad del ByteRange.

Representación del PDF en disco:

```
┌──────────────────────────┬──────────────────────────────┬────────────────┐
│   Segmento 1 (504125 b)  │  /Contents <CMS en hex>      │  Seg2 (1192 b) │
│   byte 0 → 504124        │  byte 504125 → 523070        │  523071→524262 │
└──────────────────────────┴──────────────────────────────┴────────────────┘
```

Tamaño total del PDF: `523071 + 1192 = 524263 bytes`

---

## 3. ByteRangeExtractor — paso a paso

### 3.1 `obtenerPrimeraFirma()`

PDFBox recorre el `AcroForm → Fields[0]` y localiza el widget con `FT = /Sig`.
Retorna el objeto `PDSignature` que apunta al diccionario `V` (id: 161).

### 3.2 Construcción del `ByteRange`

```java
ByteRange byteRange = new ByteRange(firma.getByteRange());
// byteRange internamente = [0, 504125, 523071, 1192]
```

### 3.3 `validarByteRange()`

Se ejecutan dos niveles de validación independientes:

**Nivel 1 — validación interna de DSS** (`byteRange.validate()`):

| Regla | Verificación | Resultado con el PDF analizado |
|-------|-------------|-------------------------------|
| Array de 4 elementos | `byteRangeArray.length == 4` | ✅ |
| Empieza en 0 | `a == 0` | ✅ |
| Segmento 1 cubre algo | `b >= 0` | ✅ `504125` |
| Segmento 2 empieza después | `c >= a + b` | ✅ `523071 >= 504125` |
| Segmento 2 cubre algo | `d >= 0` | ✅ `1192` |

`validate()` de DSS **no verifica** si el ByteRange cubre el PDF completo porque no recibe el tamaño del archivo.

**Nivel 2 — validación de cobertura total** (check propio):

```java
// validate() comprueba: array[4], a==0, b>=0, c>=a+b, d>=0
// No verifica cobertura total del PDF, eso lo hacemos nosotros abajo
try {
    byteRange.validate();
} catch (Exception e) {
    log.warn("[VALIDACION] ByteRange inválido según DSS: {}", e.getMessage());
    byteRange.setValid(false);
    return false;
}

// Verificacion extra: el ByteRange debe cubrir exactamente hasta el fin del PDF
long finDelPdf = byteRange.getSecondPartStart() + (long) byteRange.getSecondPartEnd();
boolean cubreTotalPdf = finDelPdf == longitudTotalPdf;
if (!cubreTotalPdf) {
    log.warn("[VALIDACION] ByteRange no cubre el PDF completo: fin calculado={} != longitudTotalPdf={}",
            finDelPdf, longitudTotalPdf);
}
byteRange.setValid(cubreTotalPdf);
return cubreTotalPdf;
```

Con los valores reales: `523071 + 1192 = 524263 == bytesPdf.length` → válido.
Si el PDF tiene más bytes → alguien añadió contenido después de firmar → `setValid(false)`.

Un `setValid()` único al final — no hay ramas intermedias de retorno para el segundo check.

### 3.4 `ensamblarContenidoFirmado()`

Construye los bytes que el algoritmo de firma procesó originalmente, leyendo del PDF **actual**
en las posiciones exactas del ByteRange:

```java
// Extrae seg1 y seg2 del PDF actual, saltando el /Contents
System.arraycopy(bytesPdf, 0,      resultado, 0,      504125); // seg1
System.arraycopy(bytesPdf, 523071, resultado, 504125, 1192);   // seg2
```

El resultado (`bytesPdfCubiertos`) son 505.317 bytes que representan el contenido del documento
tal como existía al momento de firmar. No es el PDF completo — le falta el hueco del `/Contents` —
pero contiene todo el contenido relevante: páginas, texto, imágenes, metadatos, etc.

**Importante:** si el PDF fue modificado (bytes cambiados dentro del rango), `bytesPdfCubiertos`
contendrá los bytes ya alterados. El hash resultante diferirá del original y la verificación fallará.
Los bytes añadidos **fuera** del ByteRange (al final del archivo) sí se ignoran — solo se detectan
mediante `estructuraValida`.

### 3.5 `extraerBloqueCmsDer()`

```java
COSString bloqueContents = firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
return bloqueContents.getBytes();
```

Extrae el campo `Contents` del diccionario `V`. Ese string binario (`"0\u0004T\u0006\t*H÷..."`)
es el bloque CMS/PKCS#7 DER que contiene la firma criptográfica y el certificado del firmante.

### 3.6 `ResultadoExtraccion`

Al final del extractor se tiene:

| Campo | Valor |
|-------|-------|
| `bytesPdfCubiertos` | seg1 + seg2 concatenados (505.317 bytes) |
| `bytesCMS` | bloque DER del `/Contents` |
| `estructuraValida` | true/false según `validarByteRange` |
| offsets/longitudes | los 4 valores del ByteRange |

---

## 4. VerificationService — paso a paso

### 4.1 `extraerDatosPdf()`

Llama a `ByteRangeExtractor.extraer()`. Si el PDF no tiene firma lanza `PdfNoFirmadoException` y retorna `null`.
Si `estructuraValida == false`, continúa la verificación pero lo registra como advertencia — la firma
puede ser criptográficamente válida aunque el ByteRange no cubra el PDF completo.

### 4.2 `parsearBloquesCMS()`

```java
CMSSignedData parsearCMS(bytesCMS, bytesPdfCubiertos)
```

Dentro de `CmsUtils` ocurren dos cosas:

**Parseo ASN.1:** Los bytes del `Contents` se leen como estructura DER. El bloque tiene este árbol interno:

```
ContentInfo
└── SignedData
    ├── digestAlgorithms     ← OID del hash usado al firmar (leído dinámicamente)
    ├── encapContentInfo     (vacío — firma detached)
    ├── certificates
    │   └── X509Certificate  ← "Equipo-01 SecureSign / Criptografia II / SecureSign / PE"
    └── signerInfos
        └── SignerInfo
            ├── sid          ← identifica al firmante por issuer+serial
            ├── digestAlgorithm  ← algoritmo de hash del firmante
            ├── signedAttrs  ← { contentType, messageDigest(hash del contenido) }
            ├── signatureAlg ← OID del algoritmo de firma (ECDSA, Ed25519, RSA...)
            └── signature    ← el valor de firma calculado con la clave privada
```

**Asociación con el contenido:** Se construye `CMSSignedData` con `CMSProcessableByteArray(bytesPdfCubiertos)`.
Esto le dice a BouncyCastle que el contenido firmado son esos bytes.
Es necesario porque `SubFilter = /ETSI.CAdES.detached` significa que el contenido **no está embebido** en el CMS.

### 4.3 `extraerCertificado()`

```java
private DatosCertificado extraerCertificado(CMSSignedData cms) { ... }
```

Del `SignedData.certificates` se extrae el primer certificado X.509 embebido.
Del dump se puede leer su subject:

```
CN = Equipo-01 SecureSign
OU = Criptografia II
O  = SecureSign
C  = PE
Válido: 2026-06-01 → 2027-06-01
```

Se convierte de `X509CertificateHolder` (BouncyCastle) a `X509Certificate` (Java estándar)
y se almacena en `DatosCertificado` porque luego se necesitan ambos formatos.

> El parámetro `ResultadoExtraccion` fue eliminado de esta firma — no se usaba internamente.

### 4.4 `verificarFirma()`

#### Vigencia del certificado

```java
boolean certVigente = ahora.isAfter(validoDesde) && ahora.isBefore(validoHasta);
```

Verifica si el certificado está vigente **al momento de verificar**, no al momento de firmar.
Para verificar la vigencia en el momento exacto de la firma se necesitaría un timestamp TSA.

#### Buscar el `SignerInfo` correspondiente

Un CMS puede contener múltiples `SignerInfo`. Se busca el que tiene el `SID`
(issuer + serial number) que corresponde al certificado extraído:

```java
signers.stream()
    .filter(s -> s.getSID().match(certHolder))
    .findFirst()
```

#### Resolver algoritmo

```java
String algoritmo = SignatureAlgorithm.resolve(signerInfo.getEncryptionAlgOID());
```

Lee el OID del `SignerInfo` y lo traduce a nombre legible (`"SHA256withECDSA"`, `"Ed25519"`, etc.).
No está hardcodeado — usa el algoritmo que el propio CMS declara.

#### Verificación criptográfica

```java
firmaValida = signerInfo.verify(
    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)
);
```

`bytesPdfCubiertos` ya está asociado al `CMSSignedData` desde el paso 4.2 — BouncyCastle
los recupera internamente. El proceso completo:

```
1. Lee digestAlgorithm del SignerInfo  → el algoritmo usado al firmar (SHA-256, SHA-512, etc.)
2. Calcula digest(bytesPdfCubiertos) con ese algoritmo → hashCalculado
3. Extrae el messageDigest de los signedAttrs → hashOriginal
4. Compara hashCalculado == hashOriginal
5. Serializa los signedAttrs en DER
6. Lee signatureAlgorithm del SignerInfo → ECDSA, Ed25519, RSA... (según clave pública del cert)
7. Verifica la firma sobre los signedAttrs DER con la clave pública del certHolder
→ true si todo coincide, CMSException si algo difiere
```

El paso 5 es importante: **no se firma directamente el hash del PDF**, sino los `signedAttrs`
serializados — que incluyen ese hash más atributos como `ContentType` y `SigningTime`.
Es parte de la spec CAdES.

La clave pública se extrae del `certHolder` — si es `ECPublicKey` usará ECDSA, si es otra
usará el algoritmo correspondiente. Si no coincide con el OID declarado en el `SignerInfo`, falla.

---

## 5. Escenarios de modificación del PDF

| Escenario | `estructuraValida` | `firmaValida` |
|-----------|-------------------|---------------|
| PDF sin modificar | ✅ | ✅ |
| Byte cambiado dentro del rango (mismo tamaño) | ✅ | ❌ hash distinto |
| Bytes añadidos al final (fuera del ByteRange) | ❌ | ✅ pasa* |
| Segunda firma legítima (Incremental Update) | ❌ | ✅ pasa* |

`*` La firma original sigue siendo criptográficamente válida sobre los bytes que cubrió.
`estructuraValida = false` indica que el documento fue extendido después de la firma,
lo que puede ser legítimo (segunda firma) o malicioso (datos añadidos).

Ambas verificaciones son independientes y complementarias — ninguna sustituye a la otra.

---

## 6. Diagrama del flujo completo

```
PDF (bytes)
    │
    ▼
ByteRangeExtractor.extraer()
    ├── obtenerPrimeraFirma()          → PDSignature (dict V, id:161)
    ├── new ByteRange([0,504125,523071,1192])
    ├── validarByteRange()
    │       ├── byteRange.validate()   → coherencia interna [a==0, b>=0, c>=a+b, d>=0]
    │       ├── c+d == pdf.length?     → cobertura total del archivo
    │       └── byteRange.setValid()   → un único set al final
    ├── ensamblarContenidoFirmado()    → seg1 + seg2 del PDF actual (bytesPdfCubiertos)
    └── extraerBloqueCmsDer()          → bytesCMS (bloque DER de /Contents)
    │
    ▼
ResultadoExtraccion { bytesPdfCubiertos, bytesCMS, estructuraValida, offsets }
    │
    ▼
VerificationService.verificarDocumentoFirmado()
    ├── parsearBloquesCMS()
    │       ├── ASN1: bytesCMS → ContentInfo → SignedData
    │       └── CMSSignedData(bytesPdfCubiertos, contentInfo)
    ├── extraerCertificado(cms)                        ← sin ResultadoExtraccion
    │       └── X509: CN=Equipo-01 SecureSign, OU=Criptografia II
    └── verificarFirma()
            ├── certVigente = ahora in [notBefore, notAfter]
            ├── buscarSignerParaCertificado() → SignerInfo por SID (issuer+serial)
            ├── SignatureAlgorithm.resolve(OID) → algoritmo leído del SignerInfo
            └── signerInfo.verify(certHolder)
                    ├── digest(bytesPdfCubiertos) == messageDigest en signedAttrs?
                    └── firma sobre signedAttrs DER válida con clave pública del cert?
    │
    ▼
VerificationResultResponse
    { firmaValida, estructuraValida, certVigente, subject, algoritmo, validoDesde, validoHasta }
```
