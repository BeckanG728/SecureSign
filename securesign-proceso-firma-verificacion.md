# SecureSign — Proceso de firma y verificación

---

## Proceso de firma

### 1. Generación del par de claves

**Archivo:** `keys/KeyManagementService.java`
**Método:** `generarParDeClaves(String algoritmo)`

```java
if ("Ed25519".equals(algoritmo)) {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
}
KeyPairGenerator generadorEC = KeyPairGenerator.getInstance("EC");
generadorEC.initialize(new ECGenParameterSpec("secp256r1"));
return generadorEC.generateKeyPair();
```

Se genera un par de claves asimétricas. Según el algoritmo elegido en el frontend:
- **EC / ECDSA** → curva `secp256r1`
- **Ed25519** → curva `Curve25519`

---

### 2. Generación del certificado X.509

**Archivo:** `services/certificate/CertificateX509Service.java`
**Método:** `generarCertificadoX509(KeyPair keyPair, String algorithm)`

```java
JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        subject, serialNumber,
        Date.from(now.minus(1, ChronoUnit.MINUTES)),
        Date.from(now.plus(365, ChronoUnit.DAYS)),
        subject,
        keyPair.getPublic()
);
```

Se construye un certificado X.509 autofirmado que contiene:
- La clave pública del par generado en el paso anterior.
- El período de validez (1 año desde la emisión).
- Las extensiones `KeyUsage` con `digitalSignature` y `nonRepudiation`.

```java
String sigAlg = "Ed25519".equals(algorithm) ? "Ed25519" : "SHA256withECDSA";
```

El propio certificado se firma con la clave privada usando el algoritmo correspondiente.

---

### 3. Almacenamiento en el KeyStore PKCS12

**Archivo:** `keys/KeyManagementService.java`
**Método:** `generarYAlmacenarParDeClaves(String algoritmo)`

```java
String alias = UUID.randomUUID().toString();
KeyStore keyStore = keyStoreService.cargar();
keyStore.setKeyEntry(
        alias,
        parDeClaves.getPrivate(),
        keyStoreService.getClaveAccesoComoChars(),
        new Certificate[]{certificado}
);
keyStoreService.guardar(keyStore);
```

La clave privada y el certificado se almacenan juntos en el archivo `securesign.p12` bajo un alias UUID único. Este alias es lo que permite recuperarlos después para firmar.

---

### 4. Construcción del PDF sin firmar

**Archivo:** `services/document/DocumentService.java`
**Método:** `construirPdf(...)`

```java
try (PDDocument documento = new PDDocument()) {
    ...
    documento.save(flujoSalida);
}
return flujoSalida.toByteArray();
```

PDFBox genera el PDF con el contenido institucional. El `try-with-resources` garantiza que `close()` se ejecuta antes de capturar los bytes — obligatorio para que PDFBox termine de escribir la tabla xref antes de que DSS lo procese.

---

### 5. Firma PAdES del PDF

**Archivo:** `services/signature/SignatureService.java`
**Método:** `firmarPdf(byte[] bytesPdf, X509Certificate certificado, String algoritmo)`

#### 5a. Localizar el alias en el KeyStore

```java
private String buscarAliasPorCertificado(X509Certificate certificado) throws Exception {
    ...
    if (certificado.equals(keyStore.getCertificate(alias))) {
        return alias;
    }
    ...
}
```

Se recorre el KeyStore para encontrar el alias que corresponde al certificado, ya que DSS necesita el alias para acceder a la clave privada.

#### 5b. Configurar los parámetros PAdES

```java
private PAdESSignatureParameters construirParametrosFirma(KSPrivateKeyEntry entradaClave, String algoritmo) {
    PAdESSignatureParameters parametros = new PAdESSignatureParameters();
    parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
    parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);
    parametros.setSigningCertificate(entradaClave.getCertificate());
    parametros.setCertificateChain(entradaClave.getCertificateChain());
    if ("Ed25519".equals(algoritmo)) {
        parametros.setDigestAlgorithm(DigestAlgorithm.SHA512);
    } else {
        parametros.setDigestAlgorithm(DigestAlgorithm.SHA256);
    }
    return parametros;
}
```

- `PAdES_BASELINE_B` → nivel de firma (firma básica sin marca de tiempo).
- `ENVELOPED` → la firma se embebe dentro del propio PDF.
- El digest depende del algoritmo: `SHA-256` para ECDSA, `SHA-512` para Ed25519.

#### 5c. Proceso de firma en dos fases

```java
ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
SignatureValue valorFirma = conexionToken.sign(datosAFirmar, parametrosFirma.getDigestAlgorithm(), entradaClave);
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);
```

**Fase 1 — `getDataToSign`:** DSS calcula el ByteRange, reserva el espacio para el bloque `/Contents` dentro del PDF y devuelve los bytes exactos que se deben firmar (el contenido cubierto por el ByteRange).

**Fase 2 — `conexionToken.sign`:** La clave privada del KeyStore firma esos bytes con el algoritmo configurado, produciendo el valor de firma criptográfico.

**Fase 3 — `signDocument`:** DSS ensambla el PDF final: escribe el bloque CMS con la firma real en el espacio reservado. El resultado es el PDF con la firma PAdES embebida.

---

## Proceso de verificación

### 1. Separar firma del contenido firmado

**Archivo:** `shared/util/ByteRangeExtractor.java`
**Método:** `extraer(byte[] bytesPdf)`

Un PDF firmado con PAdES tiene esta estructura:

```
[ tramo1 ][ /Contents: bloque CMS con la firma ][ tramo2 ]
    ↑                                                  ↑
 bytes firmados ──────────────────────────────── bytes firmados
```

#### 1a. Leer el ByteRange

```java
private static long[] leerByteRangeDelPdf(byte[] bytesPdf) throws Exception {
    try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
        int[] byteRangeRaw = firmas.get(0).getByteRange();
        return new long[]{
                Integer.toUnsignedLong(byteRangeRaw[0]), // offsetTramo1
                Integer.toUnsignedLong(byteRangeRaw[1]), // longitudTramo1
                Integer.toUnsignedLong(byteRangeRaw[2]), // offsetTramo2
                Integer.toUnsignedLong(byteRangeRaw[3])  // longitudTramo2
        };
    }
}
```

Se leen las 4 coordenadas del ByteRange que DSS escribió al firmar. Si el archivo fue modificado después de firmarlo, `validarByteRange` detecta que `offsetTramo2 + longitudTramo2 != longitudTotalPdf`.

#### 1b. Ensamblar el contenido firmado

```java
private static byte[] ensamblarContenidoFirmado(...) {
    byte[] contenidoFirmado = new byte[(int) (longitudTramo1 + longitudTramo2)];
    ByteBuffer ensamblador = ByteBuffer.wrap(contenidoFirmado);
    ensamblador.put(bytesPdf, (int) offsetTramo1, (int) longitudTramo1);
    ensamblador.put(bytesPdf, (int) offsetTramo2, (int) longitudTramo2);
    return contenidoFirmado;
}
```

Se concatenan los dos tramos del PDF que estaban cubiertos por la firma, excluyendo el bloque `/Contents`.

#### 1c. Extraer el bloque CMS

```java
private static byte[] extraerBloqueCmsDer(byte[] bytesPdf) throws Exception {
    COSString bloqueContents = (COSString) firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
    return bloqueContents.getBytes();
}
```

Se extrae el bloque CMS en formato DER desde la entrada `/Contents` del diccionario de firma. Este bloque contiene la firma criptográfica, el certificado del firmante y los atributos firmados.

---

### 2. Recalcular el hash del contenido firmado

**Archivo:** `services/verification/VerificationService.java`
**Método:** `parsearCMS(byte[] cmsDerBytes, byte[] contenidoFirmado)`

```java
private CMSSignedData parsearCMS(byte[] cmsDerBytes, byte[] contenidoFirmado) throws Exception {
    ContentInfo contentInfo;
    try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(cmsDerBytes))) {
        contentInfo = ContentInfo.getInstance(asn1.readObject());
    }
    return new CMSSignedData(new CMSProcessableByteArray(contenidoFirmado), contentInfo);
}
```

Al construir `CMSSignedData` con `CMSProcessableByteArray(contenidoFirmado)`, Bouncy Castle recalcula internamente el hash del contenido usando el algoritmo declarado dentro del CMS. Si el archivo fue modificado, los bytes en las posiciones del ByteRange ya no son los originales, y el hash resultante no coincidirá con el que se firmó.

---

### 3. Verificar la firma criptográfica

**Archivo:** `services/verification/VerificationService.java`
**Método:** `verificarDocumentoFirmado(byte[] pdf)`

```java
firmaValida = signerInfo.verify(
        new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)
);
```

Bouncy Castle toma la clave pública del certificado, descifra el valor de firma almacenado en el CMS y lo compara contra el hash recalculado en el paso anterior.

Si el documento fue modificado, esta verificación falla con:

```
CMSException: message-digest attribute value does not match calculated value
```

Que es capturado por:

```java
} catch (CMSException e) {
    log.warn("[VERIFY] Firma inválida (CMSException): {}", e.getMessage());
    firmaValida = false;
}
```

---

### 4. Verificar el certificado del firmante

**Archivo:** `services/verification/VerificationService.java`
**Método:** `verificarDocumentoFirmado(byte[] pdf)`

#### 4a. Extraer el certificado embebido en el CMS

```java
Collection<X509CertificateHolder> certs = cmsSignedData.getCertificates().getMatches(null);
certHolder = certs.iterator().next();
cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
```

El certificado X.509 del firmante viaja embebido dentro del propio bloque CMS. Se extrae y convierte a un objeto `X509Certificate` de Java.

#### 4b. Verificar vigencia

```java
Instant validoDesde = cert.getNotBefore().toInstant();
Instant validoHasta = cert.getNotAfter().toInstant();
boolean certVigente = ahora.isAfter(validoDesde) && ahora.isBefore(validoHasta);
```

Se comprueba que la fecha actual cae dentro del período de validez declarado en el certificado.

#### 4c. Verificar que el certificado corresponde al firmante

```java
private SignerInformation buscarSignerParaCertificado(
        Collection<SignerInformation> signers, X509CertificateHolder certHolder) {
    for (SignerInformation signer : signers) {
        if (signer.getSID().match(certHolder)) {
            return signer;
        }
    }
    return null;
}
```

Se cruza el `SignerIdentifier` (SID) del `SignerInfo` con el certificado extraído para confirmar que el certificado embebido es efectivamente el del firmante declarado en el CMS.

---

### Resultado final

```java
boolean valido = firmaValida && certVigente;
```

La verificación es exitosa únicamente si ambas condiciones se cumplen: la firma criptográfica es válida **y** el certificado está vigente.

| Condición | Qué detecta |
|---|---|
| `firmaValida = false` | El documento fue modificado después de firmarlo |
| `certVigente = false` | El certificado expiró |
| `byteRangeValido = false` | El archivo creció después de firmarse (modificación estructural) |
