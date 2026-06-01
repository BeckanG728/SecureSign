# SecureSign — Procesos internos: certificado, claves, firma y verificación

---

## Estructura del proyecto (referencia rápida)

```
src/main/java/es/faustino/securesign/
├── controller/
│   └── DocumentController.java          ← endpoints HTTP
├── services/
│   ├── document/DocumentService.java    ← orquestador de firma
│   ├── signature/SignatureService.java  ← firma PAdES via DSS
│   ├── certificate/CertificateX509Service.java  ← emisión de certs X.509
│   └── verification/VerificationService.java    ← pipeline de verificación
├── keys/
│   ├── KeyManagementService.java        ← ciclo de vida del par de claves
│   └── KeyStoreService.java             ← I/O sobre el archivo .p12
├── shared/
│   ├── util/
│   │   ├── ByteRangeExtractor.java      ← extracción de ByteRange y CMS del PDF
│   │   ├── CmsUtils.java                ← parseo y búsqueda en CMSSignedData
│   │   └── CertificadoUtils.java        ← extracción y conversión de certificados
│   └── enums/SignatureAlgorithm.java    ← OIDs, nombres JCA y DigestAlgorithm
└── dto/
    ├── internal/
    │   ├── ResultadoExtraccion.java     ← datos extraídos del PDF (record)
    │   └── DatosCertificado.java        ← par (certHolder, cert) (record)
    └── response/
        └── VerificationResultResponse.java  ← JSON de salida con builder interno
```

---

## Proceso I — Creación del certificado X.509

**Archivo:** `services/certificate/CertificateX509Service.java`  
**Método:** `generarCertificadoX509(KeyPair keyPair, String algoritmo)`  
**Librería:** BouncyCastle (`bcpkix-jdk18on`)

Este proceso ocurre una vez por cada firma, justo después de generar el par de claves y antes de persistirlo.

### ¿Qué es un certificado X.509v3?

Un certificado X.509v3 es una estructura ASN.1 firmada (TBSCertificate + firma del emisor) que vincula una clave pública con una identidad. En SecureSign el certificado es **autofirmado**: el emisor y el sujeto son la misma entidad, y la clave privada del par recién generado firma el propio certificado.

```
TBSCertificate {
  version: v3 (2)
  serialNumber: 128 bits aleatorios
  issuer: CN=SecureSign Institucional, O=Universidad, C=PE
  validity: [ notBefore = ahora - 1 min,  notAfter = ahora + 365 días ]
  subject: CN=SecureSign Institucional, O=Universidad, C=PE
  subjectPublicKeyInfo: la clave pública del par generado
  extensions: KeyUsage, BasicConstraints, SKI, AKI
}
signature: firmado con la clave privada del mismo par
```

### Pasos internos dentro de BouncyCastle

#### 1. Construcción del TBSCertificate

`JcaX509v3CertificateBuilder` acepta sujeto, número de serie, rango de fechas e issuer. Internamente construye el bloque `TBSCertificate` en ASN.1 sin firmarlo todavía. El subject es una constante estática del servicio:

```java
private static final X500Name SUBJECT =
        new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");
```

El número de serie se genera con `new BigInteger(128, new SecureRandom())`, suficientemente grande para ser globalmente único sin necesidad de un contador centralizado.

#### 2. Adición de extensiones X.509v3

```java
JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

builder.addExtension(Extension.subjectKeyIdentifier, false,
        extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

builder.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

builder.addExtension(Extension.keyUsage, true,
        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

builder.addExtension(Extension.basicConstraints, true,
        new BasicConstraints(false));
```

| Extensión | Crítica | Valor | Propósito |
|---|---|---|---|
| `SubjectKeyIdentifier` | No | hash SHA-1 de la clave pública | Identifica la clave en cadenas de certificados |
| `AuthorityKeyIdentifier` | No | mismo hash (autofirmado) | Enlaza con el emisor |
| `KeyUsage` | Sí | `digitalSignature \| nonRepudiation` | Limita el uso legítimo del certificado |
| `BasicConstraints` | Sí | `false` (no es CA) | Impide que se use para firmar otros certificados |

#### 3. Firma del TBSCertificate

```java
String sigAlg = SignatureAlgorithm.resolverNombreJca(algoritmo);
// "Ed25519" → "Ed25519"  |  "EC" o cualquier otro → "SHA256withECDSA"

builder.build(new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate()))
```

`JcaContentSignerBuilder` crea un `ContentSigner` que envuelve la operación JCA de firma. Cuando se llama a `build()`, BouncyCastle:
1. Serializa el `TBSCertificate` a DER.
2. Lo firma con la clave privada usando el algoritmo indicado.
3. Empaqueta `TBSCertificate + algorithmIdentifier + signatureValue` en la estructura `Certificate` ASN.1 final.

`JcaX509CertificateConverter` convierte esa estructura en un `java.security.cert.X509Certificate` estándar JCA.

> **Nota sobre `resolverNombreJca`:** El método en `SignatureAlgorithm` resuelve el nombre JCA canónico a partir del nombre de algoritmo del dominio, centralizando la lógica que antes era un literal `"Ed25519".equals(algorithm) ? "Ed25519" : "SHA256withECDSA"` directamente en el servicio.

---

## Proceso II — Persistencia de claves en el archivo .p12

**Archivos:** `keys/KeyManagementService.java`, `keys/KeyStoreService.java`  
**Librería:** JDK estándar (`java.security.KeyStore` con tipo `"PKCS12"`)

### ¿Qué es un archivo PKCS#12?

PKCS#12 (RFC 7292) es un formato de contenedor binario protegido por contraseña que almacena una o varias **claves privadas** junto con sus **certificados X.509** asociados. Internamente es una estructura ASN.1 con `SafeBags` (bolsas de contenido cifradas con PBE — Password-Based Encryption) y una MAC de integridad sobre todo el contenido. La extensión habitual es `.p12` o `.pfx`.

Desde Java 9, `KeyStore.getInstance("PKCS12")` usa la implementación nativa del JDK, sin necesidad de BouncyCastle.

### Pasos del proceso

#### 1. Carga del KeyStore existente (o creación si no existe)

```java
public KeyStore cargar() throws Exception {
    KeyStore keyStore = KeyStore.getInstance(PKCS12);
    File archivo = new File(rutaArchivo);
    if (archivo.exists()) {
        try (FileInputStream flujoEntrada = new FileInputStream(archivo)) {
            keyStore.load(flujoEntrada, claveAcceso.toCharArray());
        }
    } else {
        keyStore.load(null, claveAcceso.toCharArray());  // crea vacío
    }
    return keyStore;
}
```

`keyStore.load(null, password)` inicializa un KeyStore en memoria vacío sin leer ningún archivo. La contraseña se asocia al contenedor para cuando se guarde a disco.

#### 2. Inserción de la entrada (clave privada + certificado)

```java
String alias = UUID.randomUUID().toString();

keyStore.setKeyEntry(
        alias,
        parDeClaves.getPrivate(),
        keyStoreService.getClaveAccesoComoChars(),
        new Certificate[]{certificado}
);
```

`setKeyEntry` registra en memoria una entrada `KeyBag` que asocia:
- La **clave privada** (cifrada internamente con la contraseña).
- El **certificado X.509** (en `CertBag`).
- Un **alias** UUID único que sirve de clave de búsqueda.

El array `Certificate[]` puede contener toda la cadena; aquí solo hay un certificado (autofirmado, sin CA intermedias).

#### 3. Persistencia a disco

```java
public synchronized void guardar(KeyStore keyStore) throws Exception {
    try (FileOutputStream flujoSalida = new FileOutputStream(rutaArchivo)) {
        keyStore.store(flujoSalida, claveAcceso.toCharArray());
    }
}
```

`keyStore.store()` serializa el KeyStore completo en formato PKCS#12 DER:
1. Cifra cada `KeyBag` (clave privada) con PBE usando la contraseña.
2. Opcionalmente cifra los `CertBag` también.
3. Calcula una MAC HMAC-SHA1 sobre el contenido completo.
4. Escribe el resultado al `FileOutputStream`.

El método es `synchronized` para garantizar que dos peticiones concurrentes de firma no corrompan el archivo al escribir simultáneamente.

#### 4. Recuperación posterior del alias

Cuando `SignatureService` necesita la clave privada para firmar, busca el alias en el KeyStore:

```java
public String buscarAliasPorCertificado(X509Certificate certificado) throws Exception {
    KeyStore keyStore = cargar();
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (certificado.equals(keyStore.getCertificate(alias))) {
            return alias;
        }
    }
    throw new IllegalStateException("No se encontró el alias...");
}
```

`KeyStoreSignatureTokenConnection` de DSS usa ese alias para abrir la entrada y obtener la `KSPrivateKeyEntry` que contiene la clave privada en la forma que DSS espera para firmar.

---

## Proceso III — Firma del PDF (PAdES)

**Archivo:** `services/signature/SignatureService.java`  
**Método:** `firmarPdf(byte[] bytesPdf, X509Certificate certificado, String algoritmo)`  
**Librerías:** EU DSS 6.4 (`dss-pades`, `dss-token`), PDFBox 3.x (interno en DSS)

### ¿Qué hace DSS internamente?

EU DSS (Digital Signature Services) es la librería de la Comisión Europea para firmas conformes con eIDAS. Para firmas PAdES usa PDFBox 3.x como backend PDF. El proceso de firma se divide en tres fases explícitas que DSS expone como API, permitiendo que la firma criptográfica ocurra en un token separado (HSM, smartcard, PKCS#12):

#### Fase 1 — `getDataToSign`: preparar el PDF y calcular los bytes a firmar

```java
ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
```

Internamente DSS + PDFBox:
1. Parsean el PDF de entrada con PDFBox.
2. Calculan el tamaño del bloque CMS que se va a embeber (estimación del tamaño de la firma).
3. Añaden al PDF el diccionario `/Sig` con un `/Contents` de longitud fija relleno de ceros como placeholder.
4. Calculan el `/ByteRange`: `[0, offsetAntesDeFirma, offsetDespuesDeFirma, longitudFinal]`.
5. Escriben ese ByteRange en el diccionario.
6. Devuelven como `ToBeSigned` los bytes del PDF **excluyendo** el placeholder de `/Contents`, que son exactamente los bytes que se van a hashear y firmar.

#### Fase 2 — `conexionToken.sign`: firmar criptográficamente

```java
SignatureValue valorFirma = conexionToken.sign(
        datosAFirmar,
        parametrosFirma.getDigestAlgorithm(),
        entradaClave
);
```

`KeyStoreSignatureTokenConnection` (también de DSS) lee la clave privada del PKCS#12 usando el alias. Internamente llama a `java.security.Signature` del JDK con la clave privada y el algoritmo configurado. El resultado es el valor de firma criptográfico (`SignatureValue`): los bytes del hash cifrado con la clave privada.

El algoritmo de digest se resuelve desde el enum:

```java
parametros.setDigestAlgorithm(SignatureAlgorithm.resolverDigestDss(algoritmo));
// EC → DigestAlgorithm.SHA256  |  Ed25519 → DigestAlgorithm.SHA512
```

#### Fase 3 — `signDocument`: ensamblar el PDF final

```java
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);
```

DSS construye el bloque CMS (`SignedData`) real que contiene:
- El `SignerInfo` con el valor de firma producido en la fase 2.
- Los atributos firmados (`signingCertificate`, `contentType`, `messageDigest`).
- El certificado X.509 del firmante embebido en `certificates`.

Luego llama a PDFBox para escribir ese bloque en el placeholder `/Contents` del PDF, reemplazando los ceros por el DER real. El PDF resultante tiene una firma PAdES Baseline-B completamente embebida.

### Parámetros de firma configurados

```java
parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);
parametros.setSigningCertificate(entradaClave.getCertificate());
parametros.setCertificateChain(entradaClave.getCertificateChain());
```

| Parámetro | Valor | Significado |
|---|---|---|
| `SignatureLevel` | `PAdES_BASELINE_B` | Firma básica sin sello de tiempo (ETSI EN 319 132) |
| `SignaturePackaging` | `ENVELOPED` | La firma se embebe dentro del PDF, no como adjunto externo |
| `SigningCertificate` | cert generado en el paso anterior | El certificado que identifica al firmante |
| `CertificateChain` | solo el cert (autofirmado, sin cadena) | Cadena completa embebida en el CMS |

---

## Proceso IV — Verificación de la firma

**Archivo:** `services/verification/VerificationService.java`  
**Método:** `verificarDocumentoFirmado(byte[] pdf)`  
**Librerías:** PDFBox 3.x, BouncyCastle (`bcpkix-jdk18on`)

La verificación es completamente offline: todo lo necesario (firma, certificado, ByteRange) viaja dentro del propio PDF.

### Pipeline de verificación

```
extraerDatosPdf()
    └── ByteRangeExtractor.extraer()
            ↓ ResultadoExtraccion
parsearBloquesCMS()
    └── CmsUtils.parsearCMS()
            ↓ CMSSignedData
extraerCertificado()
    └── CertificadoUtils.extraerCertHolder() + convertirCertificado()
            ↓ DatosCertificado (record en dto/internal)
verificarFirma()
    └── CmsUtils.buscarSignerParaCertificado() + signerInfo.verify()
            ↓ VerificationResultResponse (con builder interno)
```

---

### Paso 1 — Extraer datos del PDF

**Archivo:** `shared/util/ByteRangeExtractor.java`

Un PDF firmado con PAdES tiene esta estructura binaria:

```
[ tramo1 ][ /Contents: bloque CMS en hex DER ][ tramo2 ]
    ↑                                                ↑
 bytes cubiertos por la firma ──────────── bytes cubiertos por la firma
```

El `ByteRange` almacenado en el diccionario `/Sig` del PDF define las 4 coordenadas:
`[offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2]`

#### 1a. Lectura del ByteRange con PDFBox

```java
try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
    List<PDSignature> firmas = documento.getSignatureDictionaries();
    if (firmas == null || firmas.isEmpty()) {
        throw new PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
    }
    int[] byteRangeRaw = firmas.get(0).getByteRange();
    ...
}
```

PDFBox parsea la tabla xref del PDF y navega el árbol COS hasta el diccionario `/Sig`. Si no existe ningún campo de firma, se lanza `PdfNoFirmadoException`, que `VerificationService` captura y traduce a `firmaExtraible = false`.

> **Importante:** el bloque CMS se extrae del **PDF original** (no del recortado), porque PDFBox necesita la estructura completa del PDF para indexar los diccionarios de firma. El recorte solo se aplica antes de ensamblar los bytes firmados.

#### 1b. Validación del ByteRange

`validarByteRange` comprueba que:
- `offsetTramo1 == 0` (el primer tramo empieza al inicio del archivo).
- Los tramos no se solapan.
- `offsetTramo2 + longitudTramo2 == longitudTotalPdf`. Si esta condición falla, el archivo fue extendido después de firmarse → `estructuraValida = false`.

#### 1c. Ensamblado del contenido firmado

```java
byte[] bytesPdfCubiertos = new byte[(int)(longitudTramo1 + longitudTramo2)];
ByteBuffer ensamblador = ByteBuffer.wrap(bytesPdfCubiertos);
ensamblador.put(bytesPdf, (int) offsetTramo1, (int) longitudTramo1);
ensamblador.put(bytesPdf, (int) offsetTramo2, (int) longitudTramo2);
```

Se concatenan los dos tramos excluyendo `/Contents`. Estos son exactamente los bytes que fueron hasheados y firmados durante la emisión. Cualquier modificación posterior al PDF producirá un hash diferente al verificar.

#### 1d. Extracción del bloque CMS DER

```java
COSString bloqueContents = (COSString) firma.getCOSObject()
        .getDictionaryObject(COSName.CONTENTS);
return bloqueContents.getBytes();
```

PDFBox accede al árbol COS del PDF y extrae el valor de `/Contents` como `COSString` (una cadena de bytes). Esos bytes son el bloque CMS en formato DER: la firma criptográfica, el certificado del firmante y los atributos firmados.

El resultado de todo este paso se empaqueta en `ResultadoExtraccion` (record en `dto/internal`).

---

### Paso 2 — Parsear el CMS con BouncyCastle

**Archivo:** `shared/util/CmsUtils.java`

```java
public static CMSSignedData parsearCMS(byte[] bytesCMS, byte[] bytesPdfCubiertos) throws Exception {
    ContentInfo contentInfo;
    try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(bytesCMS))) {
        contentInfo = ContentInfo.getInstance(asn1.readObject());
    }
    return new CMSSignedData(new CMSProcessableByteArray(bytesPdfCubiertos), contentInfo);
}
```

#### ¿Qué hace BouncyCastle aquí?

1. `ASN1InputStream` lee los bytes DER de `/Contents` y los deserializa en el árbol ASN.1 de objetos BouncyCastle.
2. `ContentInfo.getInstance()` identifica la estructura como `SignedData` (OID `1.2.840.113549.1.7.2`).
3. `new CMSSignedData(CMSProcessableByteArray(...), contentInfo)` combina la estructura CMS con el contenido firmado. Esto es lo que permite a BouncyCastle recalcular el hash de los bytes firmados al verificar, comparándolo con el `messageDigest` declarado en los atributos firmados del CMS.

Si el DER está corrupto o truncado, falla aquí y se devuelve `cmsParseable = false`.

---

### Paso 3 — Extraer el certificado

**Archivo:** `shared/util/CertificadoUtils.java`

```java
public static X509CertificateHolder extraerCertHolder(CMSSignedData cms) throws Exception {
    Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
    if (certs.isEmpty()) return null;
    return certs.iterator().next();
}

public static X509Certificate convertirCertificado(X509CertificateHolder certHolder) throws Exception {
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
}
```

`cms.getCertificates()` devuelve el store de certificados embebidos en el bloque CMS. `getMatches(null)` sin filtro devuelve todos; se toma el primero (hay exactamente uno en firmas de un solo firmante).

`JcaX509CertificateConverter` convierte el `X509CertificateHolder` de BouncyCastle (que trabaja con ASN.1 nativo) a la interfaz estándar `java.security.cert.X509Certificate` del JDK, necesaria para acceder a `getSubjectX500Principal()`, `getNotBefore()`, `getNotAfter()`.

El par resultante se empaqueta en `DatosCertificado` (record en `dto/internal`):

```java
// dto/internal/DatosCertificado.java
public record DatosCertificado(X509CertificateHolder certHolder, X509Certificate cert) {}
```

> Este record existía como clase privada interna dentro de `VerificationService` y fue trasladado a `dto/internal` para mantener consistencia con `ResultadoExtraccion`.

---

### Paso 4 — Verificación criptográfica

**Archivos:** `shared/util/CmsUtils.java`, `services/verification/VerificationService.java`

#### 4a. Asociar SignerInfo con el certificado

```java
public static SignerInformation buscarSignerParaCertificado(
        Collection<SignerInformation> signers, X509CertificateHolder certHolder) {
    return signers.stream()
            .filter(s -> s.getSID().match(certHolder))
            .findFirst()
            .orElse(null);
}
```

`getSID()` devuelve el `SignerIdentifier`, que en PAdES/CAdES puede ser `IssuerAndSerialNumber` (issuer DN + número de serie del certificado) o `SubjectKeyIdentifier`. `match(certHolder)` compara el identificador del `SignerInfo` contra el certificado extraído.

#### 4b. Resolver el algoritmo de firma

```java
String algoritmo = SignatureAlgorithm.resolve(signerInfo.getEncryptionAlgOID());
```

`getEncryptionAlgOID()` devuelve el OID del algoritmo de cifrado declarado en el `SignerInfo` (por ejemplo `1.3.101.112` para Ed25519). `SignatureAlgorithm.resolve()` lo mapea al nombre JCA legible (`"Ed25519"`). Si el OID no está registrado en el enum, se devuelve el OID crudo como fallback.

#### 4c. Verificación criptográfica con BouncyCastle

```java
firmaValida = signerInfo.verify(
        new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider("BC")
                .build(certHolder)
);
```

Internamente BouncyCastle ejecuta:
1. Toma el `messageDigest` de los atributos firmados del `SignerInfo`.
2. Recalcula el hash de `bytesPdfCubiertos` con el algoritmo declarado en el `SignerInfo`.
3. Compara ambos hashes. Si difieren → falla aquí con `CMSException: message-digest attribute value does not match`.
4. Si son iguales, descifra el valor de firma con la clave pública del certificado.
5. Compara el resultado descifrado con el hash calculado. Si coinciden → `firmaValida = true`.

Este es el paso que detecta cualquier modificación del documento: cambiar un solo byte en los tramos cubiertos produce un hash completamente diferente.

---

### Paso 5 — Resultado final

**Archivo:** `dto/response/VerificationResultResponse.java`

La respuesta se construye mediante el **builder interno** del record. Cada factory method setea solo los campos que le corresponden según en qué fase del pipeline se encuentra:

```java
// Ejemplo: firma criptográficamente inválida (documento modificado)
return builder()
    .firmaExtraible(true).estructuraValida(estructuraValida).cmsParseable(true).certificadoExtraible(true)
    .certificadoVigente(certVigente)
    .subject(subject).validoDesde(validoDesde).validoHasta(validoHasta).algoritmoFirma(algoritmo)
    .razon("El documento fue modificado después de ser firmado")
    .build();
```

> El builder reemplaza los constructores posicionales de 13 argumentos que tenía la versión anterior. Si se añade un campo al record, solo hay que actualizar el builder y su `build()`, no los 7 factory methods.

El campo `valido` es `true` únicamente si `firmaValida && certificadoVigente`:

| Flag | `true` cuando… | `false` indica… |
|---|---|---|
| `firmaExtraible` | El PDF contiene `/Sig` con `/Contents` | PDF sin firmar o estructura rota |
| `estructuraValida` | `offset2 + longitud2 == tamañoPDF` | El archivo fue extendido tras la firma |
| `cmsParseable` | El DER en `/Contents` es un `SignedData` válido | `/Contents` corrupto o truncado |
| `certificadoExtraible` | El CMS contiene un certificado X.509 convertible | CMS sin certificado embebido |
| `firmaValida` | El hash recalculado coincide con la firma | El documento fue modificado |
| `certificadoVigente` | La fecha actual está dentro de `[notBefore, notAfter]` | El certificado expiró |
| `valido` | `firmaValida && certificadoVigente` | Cualquiera de los dos anteriores |

