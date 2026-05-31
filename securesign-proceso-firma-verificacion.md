# SecureSign — Proceso de firma y verificación

---

## Proceso de firma

El proceso de firma se activa cuando el usuario sube un PDF existente al endpoint `POST /api/documents/generate` junto con el parámetro `algorithm`. El controller delega directamente en `DocumentService.firmarDocumento(byte[], String)`, que orquesta los pasos siguientes.

---

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

Se genera un par de claves asimétricas efímero para cada documento. Según el algoritmo elegido en el frontend:
- **EC / ECDSA** → curva `secp256r1` (P-256)
- **Ed25519** → curva `Curve25519`

---

### 2. Generación del certificado X.509

**Archivo:** `services/certificate/CertificateX509Service.java`
**Método:** `generarCertificadoX509(KeyPair keyPair, String algorithm)`

```java
JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        subject,
        serialNumber,
        Date.from(now.minus(1, ChronoUnit.MINUTES)),
        Date.from(now.plus(365, ChronoUnit.DAYS)),
        subject,
        keyPair.getPublic()
);
```

Se construye un certificado X.509 v3 autofirmado (issuer == subject) que contiene:
- La clave pública del par generado en el paso anterior.
- El período de validez: 1 año desde la emisión (con 1 minuto de holgura hacia atrás para cubrir desfases de reloj).
- Número de serie aleatorio de 128 bits (`SecureRandom`).
- Extensiones críticas: `KeyUsage` con `digitalSignature | nonRepudiation`, `BasicConstraints(false)`.
- Extensiones no críticas: `SubjectKeyIdentifier` y `AuthorityKeyIdentifier`.

```java
String sigAlg = "Ed25519".equals(algorithm) ? "Ed25519" : "SHA256withECDSA";
```

El propio certificado se autofirma con la clave privada usando el algoritmo correspondiente al tipo de clave.

---

### 3. Almacenamiento en el KeyStore PKCS#12

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

La clave privada y el certificado se almacenan juntos en el archivo `securesign.p12` bajo un alias UUID único. La contraseña de acceso se inyecta desde la variable de entorno `SECURESIGN_KEYSTORE_PASSWORD`. El alias se devuelve a `DocumentService` para ser usado en el paso siguiente.

---

### 4. Firma PAdES del PDF

**Archivo:** `services/signature/SignatureService.java`
**Método:** `firmarPdf(byte[] bytesPdf, X509Certificate certificado, String algoritmo)`

El PDF recibido directamente del usuario se firma sin ninguna transformación previa.

#### 4a. Localizar el alias en el KeyStore

```java
private String buscarAliasPorCertificado(X509Certificate certificado) throws Exception {
    ...
    if (certificado.equals(keyStore.getCertificate(alias))) {
        return alias;
    }
    ...
}
```

Se recorre el KeyStore para encontrar el alias que corresponde al certificado recién generado. DSS necesita el alias para obtener la `KSPrivateKeyEntry` y acceder a la clave privada.

#### 4b. Configurar los parámetros PAdES

```java
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
```

- `PAdES_BASELINE_B` → nivel de firma básica sin marca de tiempo (ETSI EN 319 132).
- `ENVELOPED` → la firma se embebe dentro del propio PDF (no como archivo adjunto externo).
- El digest depende del algoritmo: `SHA-256` para ECDSA, `SHA-512` para Ed25519.

#### 4c. Proceso de firma en tres fases

```java
ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
SignatureValue valorFirma = conexionToken.sign(datosAFirmar, parametrosFirma.getDigestAlgorithm(), entradaClave);
DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);
```

**Fase 1 — `getDataToSign`:** DSS calcula el ByteRange, reserva el espacio para el bloque `/Contents` dentro del PDF y devuelve los bytes exactos que se deben firmar (el contenido cubierto por el ByteRange, excluyendo el espacio reservado para la firma).

**Fase 2 — `conexionToken.sign`:** La clave privada del KeyStore PKCS#12 firma esos bytes con el algoritmo configurado, produciendo el valor de firma criptográfico (`SignatureValue`).

**Fase 3 — `signDocument`:** DSS ensambla el PDF final: construye el bloque CMS/PKCS#7 con la firma real y lo escribe en el espacio reservado dentro del PDF. El resultado es el PDF original con la firma PAdES embebida de forma incremental (sin reescribir el contenido original).

El PDF firmado se devuelve al usuario como `application/pdf` con el nombre `<nombre_original>_firmado.pdf`.

---

## Proceso de verificación

El proceso de verificación se activa cuando el usuario sube un PDF firmado al endpoint `POST /api/documents/verify`. No requiere ningún estado del servidor: el PDF es autocontenible. La respuesta incluye diagnóstico granular con flags individuales para cada fase.

---

### 1. Separar firma del contenido firmado

**Archivo:** `shared/util/ByteRangeExtractor.java`
**Método:** `extraer(byte[] bytesPdf)`

Un PDF firmado con PAdES tiene esta estructura binaria:

```
[ tramo1 ][ /Contents: bloque CMS con la firma ][ tramo2 ]
    ↑                                                  ↑
 bytes firmados ──────────────────────────────── bytes firmados
```

El resultado se devuelve en un `ResultadoExtraccion` (record interno) con: las 4 coordenadas del ByteRange, el contenido firmado ensamblado, el bloque CMS DER, y el flag `byteRangeValido`.

#### 1a. Leer el ByteRange

```java
try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
    List<PDSignature> firmas = documento.getSignatureDictionaries();
    if (firmas == null || firmas.isEmpty()) {
        throw new PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
    }
    int[] byteRangeRaw = firmas.get(0).getByteRange();
    return new long[]{
            Integer.toUnsignedLong(byteRangeRaw[0]), // offsetTramo1
            Integer.toUnsignedLong(byteRangeRaw[1]), // longitudTramo1
            Integer.toUnsignedLong(byteRangeRaw[2]), // offsetTramo2
            Integer.toUnsignedLong(byteRangeRaw[3])  // longitudTramo2
    };
}
```

Se leen las 4 coordenadas del ByteRange que DSS escribió al firmar. Si no existe ningún diccionario `/Sig`, se lanza `PdfNoFirmadoException`, que el servicio de verificación captura y traduce al flag `firmaExtraible = false`.

#### 1b. Validar coherencia del ByteRange

`validarByteRange` comprueba que `offsetTramo1 == 0`, que los tramos no se solapan, y especialmente que `offsetTramo2 + longitudTramo2 == longitudTotalPdf`. Si esta última condición falla, significa que el archivo fue extendido después de firmarse, lo que se refleja en `byteRangeValido = false`.

Adicionalmente, si el archivo tiene bytes extra al final (e.g. appended por algún editor), `recortarPdfAlTamanoOriginal` lo trunca al tamaño esperado antes de continuar la extracción.

#### 1c. Ensamblar el contenido firmado

```java
byte[] contenidoFirmado = new byte[(int) (longitudTramo1 + longitudTramo2)];
ByteBuffer ensamblador = ByteBuffer.wrap(contenidoFirmado);
ensamblador.put(bytesPdf, (int) offsetTramo1, (int) longitudTramo1);
ensamblador.put(bytesPdf, (int) offsetTramo2, (int) longitudTramo2);
return contenidoFirmado;
```

Se concatenan los dos tramos del PDF cubiertos por la firma, excluyendo el bloque `/Contents`. Estos son exactamente los bytes que fueron hasheados y firmados durante la emisión.

#### 1d. Extraer el bloque CMS

```java
COSString bloqueContents = (COSString) firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
return bloqueContents.getBytes();
```

Se extrae el bloque CMS en formato DER desde la entrada `/Contents` del diccionario de firma. Este bloque contiene la estructura `SignedData` con: la firma criptográfica, el certificado X.509 del firmante y los atributos firmados (`SignerInfo`).

---

### 2. Reconstruir y parsear el CMS

**Archivo:** `services/verification/VerificationService.java`
**Método:** `parsearCMS(byte[] cmsDerBytes, byte[] contenidoFirmado)`

```java
ContentInfo contentInfo;
try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(cmsDerBytes))) {
    contentInfo = ContentInfo.getInstance(asn1.readObject());
}
return new CMSSignedData(new CMSProcessableByteArray(contenidoFirmado), contentInfo);
```

Al construir `CMSSignedData` con `CMSProcessableByteArray(contenidoFirmado)`, Bouncy Castle asocia el contenido firmado con la estructura CMS. El flag `cmsParseable` se establece en `true` si este paso tiene éxito. Si el bloque `/Contents` está corrupto o truncado, se lanza una excepción y la verificación se detiene aquí.

---

### 3. Extraer el certificado del CMS

**Archivo:** `services/verification/VerificationService.java`

```java
Collection<X509CertificateHolder> certs = cmsSignedData.getCertificates().getMatches(null);
certHolder = certs.iterator().next();
cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
```

El certificado X.509 del firmante viaja embebido dentro del bloque CMS. Se extrae directamente sin necesidad de consultar ningún almacén externo. El flag `certificadoExtraible` se establece en `true` si el CMS contiene al menos un certificado y puede convertirse a `X509Certificate`.

Con el certificado ya disponible se calculan los datos de vigencia:

```java
Instant validoDesde = cert.getNotBefore().toInstant();
Instant validoHasta  = cert.getNotAfter().toInstant();
boolean certVigente  = ahora.isAfter(validoDesde) && ahora.isBefore(validoHasta);
```

---

### 4. Verificar la firma criptográfica

**Archivo:** `services/verification/VerificationService.java`

#### 4a. Asociar el SignerInfo con el certificado

```java
for (SignerInformation signer : signers) {
    if (signer.getSID().match(certHolder)) {
        return signer;
    }
}
```

Se busca el `SignerInfo` cuyo `SignerIdentifier` (SID) corresponde al certificado extraído. Esto garantiza que se verifica contra el firmante declarado en el CMS, no contra un certificado arbitrario.

#### 4b. Resolver el algoritmo de firma

```java
private static final Map<String, String> ALGORITMOS = Map.of(
    "1.2.840.10045.4.3.2", "SHA256withECDSA",
    "1.2.840.10045.4.3.4", "SHA512withECDSA",
    "1.3.101.112",         "Ed25519",
    "1.2.840.113549.1.1.11", "SHA256withRSA",
    ...
);
```

El algoritmo de firma se resuelve a partir del OID de cifrado del `SignerInfo`. Si el OID no está en el mapa, se construye el nombre compuesto combinando el OID del hash con el OID de cifrado. El nombre resuelto se incluye en la respuesta como `algoritmoFirma`.

#### 4c. Verificación criptográfica

```java
firmaValida = signerInfo.verify(
        new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)
);
```

Bouncy Castle recalcula el hash del contenido firmado usando el algoritmo declarado en el `SignerInfo`, descifra el valor de firma con la clave pública del certificado, y los compara. Si el documento fue modificado después de firmarse, el hash recalculado difiere del original y la verificación falla:

```
CMSException: message-digest attribute value does not match calculated value
```

Este error es capturado y se traduce a `firmaValida = false` sin propagar la excepción.

---

### 5. Resultado final

```java
boolean valido = firmaValida && certVigente;
```

La verificación es exitosa únicamente si ambas condiciones se cumplen: la firma criptográfica es válida **y** el certificado está vigente. La respuesta completa incluye diagnóstico granular para identificar exactamente en qué fase falló:

| Flag | `true` si… | `false` indica… |
|---|---|---|
| `firmaExtraible` | El PDF contiene un diccionario `/Sig` con `/Contents` | PDF sin firmar o estructura rota |
| `byteRangeValido` | `offsetTramo2 + longitudTramo2 == tamañoPDF` | El archivo fue extendido tras la firma |
| `cmsParseable` | El bloque DER en `/Contents` es un `SignedData` válido | `/Contents` corrupto o truncado |
| `certificadoExtraible` | El CMS contiene un certificado X.509 convertible | CMS sin certificado embebido |
| `firmaValida` | El hash recalculado coincide con la firma | El documento fue modificado |
| `certificadoVigente` | La fecha actual está dentro de `[notBefore, notAfter]` | El certificado expiró |
| `valid` | `firmaValida && certificadoVigente` | Cualquiera de los dos anteriores |
