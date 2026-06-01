# SecureSign — Procesos internos: identidad criptográfica, firma y verificación

---

## Estructura del proyecto (referencia rápida)

```
src/main/java/es/faustino/securesign/
├── controller/
│   └── DocumentController.java               ← endpoints HTTP
├── crypto/
│   ├── CertificateX509Service.java           ← construcción de certificados X.509 autofirmados
│   ├── CryptoIdentityService.java            ← aprovisionamiento de identidades (keypair + cert)
│   └── KeyStoreAccessService.java            ← I/O sobre el archivo .p12
├── services/
│   ├── SignatureService.java                 ← orquestación y firma PAdES via DSS
│   └── VerificationService.java              ← pipeline de verificación
├── shared/
│   ├── util/
│   │   ├── ByteRangeExtractor.java           ← extracción de ByteRange y CMS del PDF
│   │   ├── CmsUtils.java                     ← parseo y búsqueda en CMSSignedData
│   │   └── CertificadoUtils.java             ← extracción y conversión de certificados
│   └── enums/SignatureAlgorithm.java         ← OIDs, nombres JCA, DigestAlgorithm y generación de claves
└── dto/
    ├── internal/
    │   ├── ResultadoExtraccion.java          ← datos extraídos del PDF (record)
    │   └── DatosCertificado.java             ← par (certHolder, cert) (record)
    └── response/
        └── VerificationResultResponse.java   ← JSON de salida con factory methods
```

---

## Proceso I — Construcción del certificado X.509

**Archivo:** `crypto/CertificateX509Service.java`  
**Método:** `generarCertificadoX509(KeyPair keyPair, String algoritmo)`  
**Librería:** BouncyCastle (`bcpkix-jdk18on`)

Este proceso ocurre **una sola vez por algoritmo** al arrancar la aplicación, siempre que el alias correspondiente no
exista ya en el `.p12`. No se vuelve a ejecutar mientras el archivo persista en disco.

### ¿Qué es un certificado X.509v3?

Un certificado X.509v3 es una estructura ASN.1 firmada (`TBSCertificate` + firma del emisor) que vincula una clave
pública con una identidad. En SecureSign el certificado es **autofirmado**: el emisor y el sujeto son la misma entidad,
y la clave privada del par recién generado firma el propio certificado.

```
TBSCertificate {
  version:        v3 (2)
  serialNumber:   128 bits aleatorios
  issuer:         CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE
  validity:       [ notBefore = ahora - 1 min,  notAfter = ahora + 365 días ]
  subject:        CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE
  subjectPublicKeyInfo: la clave pública del par generado
  extensions:     KeyUsage, BasicConstraints, SKI, AKI
}
signature: firmado con la clave privada del mismo par
```

### Pasos internos dentro de BouncyCastle

#### 1. Construcción del TBSCertificate

`JcaX509v3CertificateBuilder` acepta sujeto, número de serie, rango de fechas e issuer. Construye el bloque
`TBSCertificate` en ASN.1 sin firmarlo todavía. El subject es una constante estática del servicio:

```java
private static final X500Name SUBJECT =
        new X500Name("CN=Equipo-01 SecureSign, OU=Criptografia II, O=SecureSign, C=PE");
```

El número de serie se genera con `new BigInteger(128, new SecureRandom())`, suficientemente grande para ser globalmente
único sin un contador centralizado.

#### 2. Adición de extensiones X.509v3

```java
JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

builder.

addExtension(Extension.subjectKeyIdentifier, false,
             extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.

addExtension(Extension.authorityKeyIdentifier, false,
             extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));
        builder.

addExtension(Extension.keyUsage, true,
        new KeyUsage(KeyUsage.digitalSignature|KeyUsage.nonRepudiation));
        builder.

addExtension(Extension.basicConstraints, true,
        new BasicConstraints(false));
```

| Extensión                | Crítica | Valor                                | Propósito                                        |
|--------------------------|---------|--------------------------------------|--------------------------------------------------|
| `SubjectKeyIdentifier`   | No      | hash SHA-1 de la clave pública       | Identifica la clave en cadenas de certificados   |
| `AuthorityKeyIdentifier` | No      | mismo hash (autofirmado)             | Enlaza con el emisor                             |
| `KeyUsage`               | Sí      | `digitalSignature \| nonRepudiation` | Limita el uso legítimo del certificado           |
| `BasicConstraints`       | Sí      | `false` (no es CA)                   | Impide que se use para firmar otros certificados |

#### 3. Firma del TBSCertificate

```java
String sigAlg = SignatureAlgorithm.fromJcaName(algoritmo).getJcaName();

return new

JcaX509CertificateConverter().

getCertificate(
        builder.build(new JcaContentSignerBuilder(sigAlg).

build(keyPair.getPrivate()))
        );
```

`JcaContentSignerBuilder` crea un `ContentSigner` que envuelve la operación JCA de firma. Cuando se llama a `build()`,
BouncyCastle:

1. Serializa el `TBSCertificate` a DER.
2. Lo firma con la clave privada usando el algoritmo indicado.
3. Empaqueta `TBSCertificate + algorithmIdentifier + signatureValue` en la estructura `Certificate` ASN.1 final.

`JcaX509CertificateConverter` convierte esa estructura en un `java.security.cert.X509Certificate` estándar JCA.

---

## Proceso II — Aprovisionamiento de identidades (KeyStore PKCS#12)

**Archivos:** `crypto/CryptoIdentityService.java`, `crypto/KeyStoreAccessService.java`  
**Librería:** JDK estándar (`java.security.KeyStore` con tipo `"PKCS12"`)

### ¿Qué es un archivo PKCS#12?

PKCS#12 (RFC 7292) es un contenedor binario protegido por contraseña que almacena claves privadas junto con sus
certificados X.509 asociados. Internamente es una estructura ASN.1 con `SafeBags` cifrados con PBE (Password-Based
Encryption) y una MAC de integridad sobre todo el contenido. La extensión habitual es `.p12`.

### CryptoIdentityService — ciclo de vida de identidades

Al arrancar la aplicación, `SecureSignApplication` invoca `inicializarIdentidades()`. Este método gestiona dos
identidades, una por algoritmo de firma soportado:

```java
public void inicializarIdentidades() throws Exception {
    KeyStore keyStore = keyStoreAccessService.cargar();
    inicializarSiAusente(keyStore, aliasEcdsa, SignatureAlgorithm.SHA256_WITH_ECDSA);
    inicializarSiAusente(keyStore, aliasEd25519, SignatureAlgorithm.ED25519);
    keyStoreAccessService.guardar(keyStore);
}
```

Si el alias ya existe en el `.p12`, se omite. Si no existe, se genera el par de claves, se construye el certificado
X.509 y se inserta la entrada en el KeyStore:

```java
KeyPair parDeClaves = algoritmo.generarParDeClaves();
X509Certificate certificado = certificateX509Service.generarCertificadoX509(parDeClaves, algoritmo.getJcaName());

keyStore.

setKeyEntry(alias, parDeClaves.getPrivate(),
        keyStoreAccessService.

getClaveAccesoComoChars(), new Certificate[]{certificado});
```

`setKeyEntry` registra en memoria una entrada `KeyBag` que asocia la clave privada (cifrada con la contraseña), el
certificado X.509 y el alias definido en la configuración (`${securesign.alias-ecdsa}`, `${securesign.alias-ed25519}`).

`CryptoIdentityService` también expone `obtenerCertificado(SignatureAlgorithm)` y `resolverAlias(SignatureAlgorithm)`,
usados por `SignatureService` para obtener el certificado correcto antes de firmar.

### KeyStoreAccessService — I/O sobre el archivo .p12

#### Carga

```java
public KeyStore cargar() throws Exception {
    KeyStore keyStore = KeyStore.getInstance(PKCS12);
    File archivo = new File(rutaArchivo);
    if (archivo.exists()) {
        try (FileInputStream flujoEntrada = new FileInputStream(archivo)) {
            keyStore.load(flujoEntrada, claveAcceso.toCharArray());
        }
    } else {
        keyStore.load(null, claveAcceso.toCharArray());  // crea vacío en memoria
    }
    return keyStore;
}
```

`keyStore.load(null, password)` inicializa un KeyStore vacío en memoria; la contraseña se usará al persistir a disco.

#### Persistencia

```java
public synchronized void guardar(KeyStore keyStore) throws Exception {
    try (FileOutputStream flujoSalida = new FileOutputStream(rutaArchivo)) {
        keyStore.store(flujoSalida, claveAcceso.toCharArray());
    }
}
```

`keyStore.store()` serializa el KeyStore completo en PKCS#12 DER: cifra cada `KeyBag` con PBE, opcionalmente los
`CertBag`, y calcula una MAC HMAC-SHA1 sobre el contenido. El método es `synchronized` para evitar escrituras
concurrentes.

#### Búsqueda de alias por certificado

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
    throw new IllegalStateException("No se encontró el alias en el KeyStore para el certificado proporcionado.");
}
```

`SignatureService` usa este método para resolver el alias antes de abrir la conexión de token DSS. También expone
`abrirConexionToken()` que retorna un `KeyStoreSignatureTokenConnection` para que DSS acceda a la clave privada.

---

## Proceso III — Firma del PDF (PAdES)

**Archivo:** `services/signature/SignatureService.java`  
**Método público:** `firmarDocumento(byte[] bytesPdf, String jcaName)`  
**Librerías:** EU DSS 6.4 (`dss-pades`, `dss-token`), PDFBox 3.x (interno en DSS)

`SignatureService` concentra tanto la orquestación de la identidad criptográfica como la firma PAdES. El método público
`firmarDocumento` resuelve el algoritmo, obtiene el certificado mediante `CryptoIdentityService` y delega en el método
privado `firmarPdf`.

### Flujo general

```
SignatureService.firmarDocumento()
    ├── SignatureAlgorithm.fromJcaName()
    ├── CryptoIdentityService.obtenerCertificado(algoritmo)
    └── firmarPdf(bytesPdf, certificado, jcaName)
            ├── KeyStoreAccessService.buscarAliasPorCertificado()
            ├── KeyStoreAccessService.abrirConexionToken()
            ├── [Fase 1] servicioPades.getDataToSign()
            ├── [Fase 2] conexionToken.sign()
            └── [Fase 3] servicioPades.signDocument()
```

### Fase 1 — `getDataToSign`: preparar el PDF

```java
ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
```

DSS + PDFBox internamente:

1. Parsean el PDF de entrada.
2. Estiman el tamaño del bloque CMS que se va a embeber.
3. Añaden al PDF el diccionario `/Sig` con un `/Contents` de longitud fija relleno de ceros como placeholder.
4. Calculan el `/ByteRange`: `[0, offsetAntesDeFirma, offsetDespuesDeFirma, longitudFinal]`.
5. Devuelven como `ToBeSigned` los bytes del PDF **excluyendo** el placeholder de `/Contents`, que son exactamente los
   bytes que se van a hashear y firmar.

### Fase 2 — `conexionToken.sign`: firma criptográfica

```java
SignatureValue valorFirma = conexionToken.sign(
        datosAFirmar,
        parametrosFirma.getDigestAlgorithm(),
        entradaClave
);
```

`KeyStoreSignatureTokenConnection` lee la clave privada del PKCS#12 usando el alias y llama a `java.security.Signature`
del JDK. El algoritmo de digest se resuelve desde el enum:

```java
parametros.setDigestAlgorithm(SignatureAlgorithm.resolverDigestDss(algoritmo));
// SHA256_WITH_ECDSA → DigestAlgorithm.SHA256  |  ED25519 → DigestAlgorithm.SHA512
```

### Fase 3 — `signDocument`: ensamblado final

```java
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);
```

DSS construye el bloque CMS (`SignedData`) real con el `SignerInfo`, los atributos firmados (`signingCertificate`,
`contentType`, `messageDigest`) y el certificado X.509 embebido. PDFBox escribe ese bloque en el placeholder `/Contents`
del PDF. El resultado es un PDF con firma PAdES Baseline-B completamente embebida.

### Parámetros de firma configurados

```java
parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
parametros.

setSignaturePackaging(SignaturePackaging.ENVELOPED);
parametros.

setSigningCertificate(entradaClave.getCertificate());
        parametros.

setCertificateChain(entradaClave.getCertificateChain());
```

| Parámetro            | Valor                              | Significado                                        |
|----------------------|------------------------------------|----------------------------------------------------|
| `SignatureLevel`     | `PAdES_BASELINE_B`                 | Firma básica sin sello de tiempo (ETSI EN 319 132) |
| `SignaturePackaging` | `ENVELOPED`                        | La firma se embebe dentro del PDF                  |
| `SigningCertificate` | cert de `CryptoIdentityService`    | El certificado que identifica al firmante          |
| `CertificateChain`   | solo el cert (autofirmado, sin CA) | Cadena embebida en el CMS                          |

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
            ↓ DatosCertificado
verificarFirma()
    └── CmsUtils.buscarSignerParaCertificado() + signerInfo.verify()
            ↓ VerificationResultResponse
```

Cada paso devuelve `null` en caso de fallo, y `VerificationService` cortocircuita el pipeline retornando el factory
method apropiado de `VerificationResultResponse`.

---

### Paso 1 — Extraer datos del PDF

**Archivo:** `shared/util/ByteRangeExtractor.java`

Un PDF firmado con PAdES tiene esta estructura binaria:

```
[ tramo1 ][ /Contents: bloque CMS en hex DER ][ tramo2 ]
    ↑                                                ↑
    └──────── bytes cubiertos por la firma ──────────┘
```

El `ByteRange` en el diccionario `/Sig` define las 4 coordenadas:
`[offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2]`

#### 1a. Lectura del ByteRange con PDFBox

```java
try(PDDocument documento = Loader.loadPDF(bytesPdf)){
List<PDSignature> firmas = documento.getSignatureDictionaries();
    if(firmas ==null||firmas.

isEmpty()){
        throw new

PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
    }
int[] byteRangeRaw = firmas.get(0).getByteRange();
    ...
            }
```

PDFBox parsea la tabla xref del PDF y navega el árbol COS hasta el diccionario `/Sig`. Si no existe ningún campo de
firma, se lanza `PdfNoFirmadoException`, que `VerificationService` captura y traduce a `firmaExtraible = false`.

#### 1b. Validación del ByteRange

`validarByteRange` comprueba que:

- `offsetTramo1 == 0` (el primer tramo empieza al inicio del archivo).
- Los tramos no se solapan.
- `offsetTramo2 + longitudTramo2 == longitudTotalPdf`. Si falla → `estructuraValida = false` (el archivo fue extendido
  después de firmarse).

#### 1c. Ensamblado del contenido firmado

```java
byte[] bytesPdfCubiertos = new byte[(int) (longitudTramo1 + longitudTramo2)];
ByteBuffer ensamblador = ByteBuffer.wrap(bytesPdfCubiertos);
ensamblador.

put(bytesPdf, (int) offsetTramo1, (int)longitudTramo1);
        ensamblador.

put(bytesPdf, (int) offsetTramo2, (int)longitudTramo2);
```

Los dos tramos se concatenan excluyendo `/Contents`. Cualquier modificación posterior al PDF producirá un hash diferente
al verificar.

#### 1d. Extracción del bloque CMS

```java
COSString bloqueContents = (COSString) firma.getCOSObject()
        .getDictionaryObject(COSName.CONTENTS);
return bloqueContents.

getBytes();
```

PDFBox extrae el valor de `/Contents` como `COSString`. Esos bytes son el bloque CMS en DER: firma criptográfica,
certificado del firmante y atributos firmados.

El resultado se empaqueta en `ResultadoExtraccion` (record en `dto/internal`).

---

### Paso 2 — Parsear el CMS

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

`ASN1InputStream` deserializa los bytes DER del `/Contents`. `ContentInfo.getInstance()` identifica la estructura como
`SignedData` (OID `1.2.840.113549.1.7.2`). `new CMSSignedData(...)` combina la estructura CMS con el contenido firmado,
permitiendo a BouncyCastle recalcular el hash de los bytes firmados al verificar. Si el DER está corrupto →
`cmsParseable = false`.

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

`cms.getCertificates().getMatches(null)` devuelve todos los certificados embebidos en el CMS; se toma el primero (hay
uno en firmas de un solo firmante). `JcaX509CertificateConverter` convierte el `X509CertificateHolder` de BouncyCastle a
`java.security.cert.X509Certificate` del JDK.

El resultado se empaqueta en `DatosCertificado` (record en `dto/internal`):

```java
public record DatosCertificado(X509CertificateHolder certHolder, X509Certificate cert) {
}
```

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

`getSID().match(certHolder)` compara el `SignerIdentifier` del `SignerInfo` (por `IssuerAndSerialNumber` o
`SubjectKeyIdentifier`) contra el certificado extraído.

#### 4b. Resolver el algoritmo de firma

```java
String algoritmo = SignatureAlgorithm.resolve(signerInfo.getEncryptionAlgOID());
```

`getEncryptionAlgOID()` devuelve el OID declarado en el `SignerInfo` (p.ej. `1.3.101.112` para Ed25519).
`SignatureAlgorithm.resolve()` lo mapea al nombre legible; si el OID no está en el enum, se devuelve el OID crudo como
fallback.

#### 4c. Verificación con BouncyCastle

```java
firmaValida =signerInfo.

verify(
        new JcaSimpleSignerInfoVerifierBuilder()
                .

setProvider("BC")
                .

build(datosCert.certHolder())
        );
```

BouncyCastle ejecuta internamente:

1. Recalcula el hash de `bytesPdfCubiertos` con el algoritmo declarado en el `SignerInfo`.
2. Compara ese hash con el `messageDigest` en los atributos firmados. Si difieren → `CMSException`.
3. Descifra el valor de firma con la clave pública del certificado.
4. Compara el resultado descifrado con el hash calculado. Si coinciden → `firmaValida = true`.

Las excepciones se tratan por separado: `CMSException` indica firma inválida (documento modificado);
`OperatorCreationException` o `CertificateException` indican un error interno al construir el verificador y se traducen
al factory method `errorVerificacion`.

---

### Paso 5 — Resultado final

**Archivo:** `dto/response/VerificationResultResponse.java`

La respuesta se construye mediante factory methods estáticos del record. Cada método refleja el punto del pipeline donde
se detuvo la verificación:

| Factory method      | Condición                                              |
|---------------------|--------------------------------------------------------|
| `sinFirma`          | PDF sin campo `/Sig`                                   |
| `cmsCorrupto`       | `/Contents` no parseable                               |
| `sinCertificado`    | CMS sin certificado embebido                           |
| `sinFirmante`       | CMS sin `SignerInfo` o sin correspondencia con el cert |
| `firmaInvalida`     | Hash o firma criptográfica no coinciden                |
| `firmaVerificada`   | Firma y certificado correctos                          |
| `errorVerificacion` | Error interno al preparar el verificador               |

El campo `valido` es `true` únicamente si `firmaValida && certificadoVigente`.

| Flag                   | `true` cuando…                                         | `false` indica…                        |
|------------------------|--------------------------------------------------------|----------------------------------------|
| `firmaExtraible`       | El PDF contiene `/Sig` con `/Contents`                 | PDF sin firmar o estructura rota       |
| `estructuraValida`     | `offset2 + longitud2 == tamañoPDF`                     | El archivo fue extendido tras la firma |
| `cmsParseable`         | El DER en `/Contents` es un `SignedData` válido        | `/Contents` corrupto o truncado        |
| `certificadoExtraible` | El CMS contiene un certificado X.509 convertible       | CMS sin certificado embebido           |
| `firmaValida`          | El hash recalculado coincide con la firma              | El documento fue modificado            |
| `certificadoVigente`   | La fecha actual está dentro de `[notBefore, notAfter]` | El certificado expiró                  |
| `valido`               | `firmaValida && certificadoVigente`                    | Cualquiera de los dos anteriores       |
