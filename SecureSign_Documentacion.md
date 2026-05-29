# SecureSign — Guía de Implementación
### Sistema de Firma Digital Embebida en PDF (PAdES) con Certificados X.509

> **Objetivo:** Implementar un sistema educativo para emitir y validar **documentos PDF firmados digitalmente** usando algoritmos modernos: ECDSA y Ed25519. El sistema simula una entidad institucional que genera documentos como antecedentes penales, constancias académicas y certificados laborales, demostrando integridad documental, autenticación y no repudio de forma práctica. La firma digital se embebe directamente en el PDF (modelo PAdES), generando un documento **autocontenible, portable y verificable de forma independiente** sin depender del servidor emisor.

---

## 1. Introducción conceptual

### Separación de conceptos fundamentales

Este sistema opera con tres conceptos distintos que deben entenderse por separado:

**Documento PDF institucional**
Archivo generado por el sistema que representa el contenido institucional: constancia académica, antecedente penal, certificado laboral, etc. Es el objeto que se firma.

**Firma digital**
Resultado criptográfico obtenido al firmar el hash del PDF con la clave privada del emisor. Garantiza que el documento no fue modificado y que proviene de quien dice haberlo emitido.

**Certificado digital X.509**
Estructura criptográfica estándar que vincula una identidad con una clave pública. Contiene:
- Clave pública del firmante
- Subject e Issuer (identidad)
- Número de serie y fechas de validez
- Algoritmo utilizado
- Firma del propio certificado

> **Regla de redacción:** Este sistema **no emite "certificados digitales"** en el sentido criptográfico. Genera **documentos PDF institucionales firmados digitalmente**, que llevan embebido un **certificado X.509 autofirmado** junto con la firma. Evitar frases como "emitir certificados digitales" o "el PDF es el certificado digital".

> **Aclaración importante:** El proyecto **no implementa una PKI completa** ni certificados emitidos por una CA reconocida públicamente. Utiliza certificados X.509 autofirmados con fines educativos.

---

### ¿Qué garantiza una firma digital sobre un PDF?

Una firma digital aplicada a un documento PDF garantiza tres propiedades fundamentales:

- **Integridad:** el documento no fue modificado desde que fue firmado.
- **Autenticación:** fue emitido por quien dice haberlo emitido.
- **No repudio:** el emisor no puede negar haber firmado el documento.

A diferencia de firmar texto plano, en este sistema la firma se aplica sobre los **bytes completos del documento PDF**. Cualquier modificación posterior al PDF —aunque sea de un solo byte— invalida la firma por completo.

### Flujo criptográfico sobre PDF (modelo PAdES)

```
Documento PDF (bytes completos)
          ↓
SHA-256 interno (calculado por el algoritmo de firma)
          ↓
Firma con clave privada (ECDSA o Ed25519)
          ↓
Firma digital + Certificado X.509
          ↓
Incrustación en el PDF (estructura PAdES)
          ↓
   documento_firmado.pdf  ← archivo único autocontenible
          ↓
Verificación independiente con PublicKey extraída del certificado
→ ✅ válida / ❌ inválida
```

> **Nota técnica importante:** cuando se usa `SHA256withECDSA`, el algoritmo calcula **internamente** el hash SHA-256 del documento antes de firmar. No se realiza un hashing separado previo — el proceso está encapsulado en una sola operación. Ed25519 hace lo mismo con su función hash interna (SHA-512).

El hash actúa como huella digital del documento. Si el PDF se modifica —incluso cambiando un solo carácter invisible— el hash resultante será completamente diferente y la verificación fallará. Esto es lo que hace posible la detección de alteraciones.

---

## 2. Modelo institucional

El sistema está diseñado con una arquitectura que imita la separación de responsabilidades de sistemas reales:

- **El frontend representa una institución emisora** (universidad, municipalidad u organismo público). Es quien solicita la emisión de documentos y los entrega al ciudadano.
- **El backend actúa como infraestructura criptográfica**, responsable de generar claves y certificados X.509, firmar documentos y embeber la firma en el PDF.

La verificación posterior **no requiere al backend**: cualquier persona con el PDF firmado puede verificarlo de forma completamente independiente, offline, sin contactar al servidor emisor.

```
  ┌────────────────────────────┐
  │  Frontend (Institución)    │
  │  Universidad / Municipio   │
  │  Solicita emisión de docs  │
  └────────────┬───────────────┘
               │  REST / JSON
               ▼
  ┌────────────────────────────┐
  │  Backend (Infraestructura  │
  │  Criptográfica)            │
  │  - Genera KeyPair          │
  │  - Genera cert. X.509      │
  │  - Firma el PDF            │
  │  - Embebe firma (PAdES)    │
  │  - Devuelve PDF firmado    │
  └────────────────────────────┘
               │
               ▼
  ┌────────────────────────────┐
  │  documento_firmado.pdf     │
  │  (autocontenible)          │
  │  - Firma digital embebida  │
  │  - Certificado X.509       │
  │  - Metadatos criptográficos│
  └────────────────────────────┘
               │
               ▼
  ┌────────────────────────────┐
  │  Verificación independiente│
  │  No requiere servidor      │
  │  Verificación offline ✅   │
  └────────────────────────────┘
```

---

## 3. Certificados X.509 autofirmados

### ¿Qué es X.509?

X.509 es el estándar internacional para certificados digitales. Un certificado X.509 **vincula una identidad con una clave pública**, junto con metadatos que permiten validar esa asociación.

**Diferencia clave entre PublicKey y certificado X.509:**

| Concepto | Contenido |
|---|---|
| `PublicKey` | Solo el valor criptográfico de la clave pública |
| Certificado X.509 | `PublicKey` + identidad (subject) + issuer + número de serie + fechas de validez + algoritmo + firma del certificado |

### Rol del certificado X.509 en SecureSign

El certificado X.509 autofirmado cumple tres funciones dentro del documento PDF firmado:

1. **Asociar identidad al firmante:** permite saber quién firmó el documento (subject).
2. **Proveer la clave pública para verificación:** la clave pública extraída del certificado se usa para validar la firma.
3. **Validar estructura criptográfica:** las fechas de validez y el algoritmo son verificables.

### Estructura del certificado autofirmado

```
Certificado X.509 autofirmado
├── Subject: CN=SecureSign Institucional, O=Universidad, C=PE
├── Issuer: (mismo que Subject, por ser autofirmado)
├── Serial Number: (UUID o número aleatorio)
├── Not Before: (fecha de generación)
├── Not After:  (fecha de expiración)
├── Public Key: (clave pública ECDSA o Ed25519)
└── Signature:  (firmado con la misma clave privada)
```

### Generación del certificado X.509 con Bouncy Castle

```xml
<!-- pom.xml: dependencia para generación de certificados X.509 -->
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
```

```java
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public X509Certificate generarCertificadoX509(KeyPair keyPair, String algorithm) throws Exception {
    X500Name subject = new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");

    // El certificado es autofirmado: subject == issuer
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        subject,                                          // issuer
        BigInteger.valueOf(System.currentTimeMillis()),  // serial number
        Date.from(Instant.now()),                        // not before
        Date.from(Instant.now().plus(365, ChronoUnit.DAYS)), // not after (1 año)
        subject,                                          // subject
        keyPair.getPublic()
    );

    // Algoritmo de firma del certificado
    String sigAlg = algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA";

    return new JcaX509CertificateConverter()
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate())
            )
        );
}
```

### Almacenamiento en PKCS12

El certificado X.509 se almacena junto con la clave privada dentro del archivo PKCS12:

```
PKCS12 (securesign.p12)
└── PrivateKeyEntry
    ├── PrivateKey   ← clave privada (cifrada con AES-256)
    └── Certificate  ← certificado X.509 asociado
```

```java
// Almacenar PrivateKey + Certificado X.509 en PKCS12
KeyStore ks = cargarKeyStore();
ks.setKeyEntry(
    keyId,
    keyPair.getPrivate(),
    keystorePassword.toCharArray(),
    new Certificate[]{ certificadoX509 }  // Certificado X.509, no null
);
guardarKeyStore(ks);
```

---

## 4. Contexto histórico

### ¿Por qué evolucionar desde RSA?

RSA fue durante décadas el estándar de firmas digitales. Sin embargo, presenta limitaciones importantes:

- Requiere **claves muy grandes** (2048–4096 bits) para ser seguro.
- Produce **firmas de mayor tamaño**.
- Tiene **mayor costo computacional**, especialmente en dispositivos con recursos limitados.

La criptografía de curva elíptica surgió como respuesta a estas limitaciones:

- **ECDSA** reduce drásticamente el tamaño de claves y firmas manteniendo el mismo nivel de seguridad.
- **Ed25519** va más lejos: es más rápido, determinista y más simple de implementar correctamente.

> RSA fue fundamental históricamente, pero hoy existen alternativas más eficientes para prácticamente todos los casos de uso. Este proyecto lo incluye únicamente como punto de comparación conceptual, sin implementarlo.

---

## 5. Algoritmos implementados

### 5.1 ECDSA (P-256 / secp256r1)

Basado en curvas elípticas tradicionales. La curva utilizada, **P-256 (secp256r1)**, es una de las curvas recomendadas por el **NIST (National Institute of Standards and Technology)** para firmas digitales modernas y es ampliamente utilizada en TLS/HTTPS, certificados web y protocolos de red.

**Característica clave:** la firma requiere un número aleatorio por cada operación. Si ese número se repite o es predecible, la clave privada queda expuesta. Esta es una de sus principales diferencias con Ed25519.

**Implementación en Java:**

```java
// Generación de claves
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1")); // Curva P-256, recomendada por NIST
KeyPair keyPair = kpg.generateKeyPair();

// Firma sobre bytes del PDF
// SHA256withECDSA calcula internamente SHA-256 y luego firma el hash con la clave privada
byte[] pdfBytes = Files.readAllBytes(path);
Signature sig = Signature.getInstance("SHA256withECDSA");
sig.initSign(keyPair.getPrivate());
sig.update(pdfBytes);
byte[] firma = sig.sign();
```

---

### 5.2 Ed25519

Algoritmo moderno basado en EdDSA sobre la curva Edwards25519.

**Ventajas sobre ECDSA:**

- **Firma determinista:** no necesita aleatoriedad externa. Dado el mismo documento y clave, siempre produce la misma firma.
- **Más rápido** en generación y verificación.
- **Implementación más segura:** elimina toda una clase de vulnerabilidades relacionadas con la aleatoriedad.
- **Ampliamente adoptado:** SSH moderno, blockchain, sistemas de autenticación.

**Implementación en Java:**

```java
// Generación de claves
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
KeyPair keyPair = kpg.generateKeyPair();

// Firma sobre bytes del PDF
// Ed25519 usa internamente SHA-512 como parte del proceso de firma
byte[] pdfBytes = Files.readAllBytes(path);
Signature sig = Signature.getInstance("Ed25519");
sig.initSign(keyPair.getPrivate());
sig.update(pdfBytes);
byte[] firma = sig.sign();
```

**Verificación** (igual para ambos algoritmos):

```java
// La PublicKey se extrae del certificado X.509 embebido en el PDF
PublicKey publicKey = certificadoX509.getPublicKey();
sig.initVerify(publicKey);
sig.update(pdfBytes);
boolean valida = sig.verify(firma);
```

---

## 6. Aplicaciones reales de ECDSA y Ed25519

Estos algoritmos no son solo conceptos académicos: son la base criptográfica de tecnologías que se usan diariamente en internet y en sistemas de seguridad modernos.

| Tecnología | Algoritmo | Uso |
|---|---|---|
| HTTPS / TLS | ECDSA (P-256) | Certificados de servidores web (candado del navegador) |
| OpenSSH | Ed25519 | Autenticación de servidores y usuarios sin contraseña |
| Blockchain (Ethereum) | ECDSA | Firma de transacciones |
| Blockchain (Solana, Monero) | Ed25519 | Firma de transacciones y billeteras |
| Documentos electrónicos | ECDSA | Firmas en documentos legales con PAdES/CAdES |
| Signal / WhatsApp | Ed25519 | Autenticación de claves en mensajería cifrada |

En todos estos casos, el principio es el mismo que en SecureSign: una clave privada que nunca debe exponerse firma datos, y cualquiera con la clave pública puede verificar esa firma sin necesidad de conocer la privada.

---

## 7. Comparación educativa

| Característica | RSA-2048 *(referencia histórica)* | ECDSA (P-256) | Ed25519 |
|---|---|---|---|
| Tamaño de clave | 2048 bits | 256 bits | 256 bits |
| Tamaño de firma | 256 bytes | ~72 bytes | 64 bytes |
| Velocidad relativa | Lenta | Rápida | Muy rápida |
| Firma determinista | No | No | Sí |
| Recomendado por NIST | Sí (legacy) | Sí (P-256) | Sí (Ed448 familia) |
| Uso moderno | Legacy | TLS, Web PKI | SSH, Blockchain |

> RSA aparece aquí solo como punto de comparación histórica. Este proyecto no lo implementa.

---

## 8. Arquitectura del proyecto

### Tecnologías utilizadas

| Capa | Tecnología |
|---|---|
| Backend | Java 17, Spring Boot |
| Criptografía | `java.security` (ECDSA, Ed25519) + Bouncy Castle (X.509, PAdES) |
| Generación PDF | Apache PDFBox 3.x |
| Firma PAdES | PDFBox `PDSignature` + Bouncy Castle CMS |
| Frontend | HTML + CSS + JavaScript (vanilla) |
| API | REST / JSON + multipart para archivos |

### Flujo general (modelo PAdES)

```
Cliente (frontend)
       ↓  envía formulario (nombre, DNI, tipo, fecha, algoritmo)
   Backend (Java)
       ↓  genera documento PDF institucional
       ↓  genera KeyPair (ECDSA o Ed25519)
       ↓  genera certificado X.509 autofirmado
       ↓  almacena PrivateKey + Certificate en PKCS12 (.p12 cifrado)
       ↓  firma el PDF (hash calculado internamente)
       ↓  embebe firma + certificado X.509 dentro del PDF (PAdES)
       ↓  devuelve documento_firmado.pdf al cliente
   Cliente
       ↓  descarga el PDF firmado (único archivo, autocontenible)
       ↓  puede subir el PDF posteriormente para verificarlo
   Verificación (independiente del backend)
       ↓  extrae firma embebida del PDF (PAdES)
       ↓  extrae certificado X.509 del PDF
       ↓  obtiene PublicKey desde el certificado
       ↓  verifica firma contra el hash del PDF
       ↓  valida fechas del certificado
       ↓  responde: válida / inválida
```

### Principio de portabilidad criptográfica

> **El documento PDF firmado es autocontenible.** Contiene internamente la firma digital, el certificado X.509 y los metadatos criptográficos necesarios para su verificación. No se requiere contactar al servidor emisor ni conservar archivos adicionales. La verificación puede realizarse completamente offline.

---

## 9. Protección de claves privadas mediante PKCS12 KeyStore

El sistema protege las claves privadas usando **Java KeyStore en formato PKCS12**, el estándar internacional para proteger claves criptográficas en software.

### ¿Qué es PKCS12?

PKCS12 (RFC 7292) es un formato estándar internacional para almacenar claves privadas y certificados en un archivo protegido por contraseña. No es exclusivo de Java: es el mismo formato que usan OpenSSL, los navegadores web, Windows y macOS.

Desde Java 9, PKCS12 es el formato por defecto de `java.security.KeyStore`.

El archivo generado tiene extensión `.p12` y su contenido es **ilegible sin la contraseña**, independientemente de quién acceda al sistema de archivos.

### Estructura correcta del PKCS12 en SecureSign

```
PKCS12 KeyStore (securesign.p12)
└── PrivateKeyEntry  [alias = keyId]
    ├── PrivateKey   ← clave privada cifrada (AES-256)
    └── Certificate  ← certificado X.509 autofirmado asociado
```

Esta estructura permite recuperar la clave privada para firmar nuevos documentos y el certificado para adjuntarlo en la firma PAdES.

### Implementación del servicio de firma con PKCS12

```java
@Service
public class SignatureService {

    private static final String KEYSTORE_PATH = "securesign.p12";
    private static final String KEYSTORE_TYPE = "PKCS12";

    @Value("${securesign.keystore-password}")
    private String keystorePassword;

    private KeyStore cargarKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        File archivo = new File(KEYSTORE_PATH);
        if (archivo.exists()) {
            try (FileInputStream fis = new FileInputStream(archivo)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
        } else {
            ks.load(null, keystorePassword.toCharArray());
        }
        return ks;
    }

    private synchronized void guardarKeyStore(KeyStore ks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            ks.store(fos, keystorePassword.toCharArray());
        }
    }

    /**
     * Genera KeyPair, certificado X.509 autofirmado,
     * y los almacena juntos en PKCS12.
     */
    public String generateKeyPairWithCertificate(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "EC"
        );
        if (!algorithm.equals("Ed25519")) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        KeyPair keyPair = kpg.generateKeyPair();

        // Generar certificado X.509 autofirmado
        X509Certificate cert = certificateService.generarCertificadoX509(keyPair, algorithm);

        String keyId = UUID.randomUUID().toString();

        // Almacenar PrivateKey + Certificado X.509 en PKCS12
        KeyStore ks = cargarKeyStore();
        ks.setKeyEntry(
            keyId,
            keyPair.getPrivate(),
            keystorePassword.toCharArray(),
            new Certificate[]{ cert }
        );
        guardarKeyStore(ks);

        return keyId;
    }

    public PrivateKey getPrivateKey(String keyId) throws Exception {
        KeyStore ks = cargarKeyStore();
        return (PrivateKey) ks.getKey(keyId, keystorePassword.toCharArray());
    }

    public X509Certificate getCertificate(String keyId) throws Exception {
        KeyStore ks = cargarKeyStore();
        return (X509Certificate) ks.getCertificate(keyId);
    }
}
```

### ¿Por qué no se usa un HSM en este proyecto?

Un HSM (Hardware Security Module) es un dispositivo físico especializado que almacena y opera con claves privadas en hardware aislado. Las claves **nunca salen del dispositivo**, ni siquiera como bytes cifrados.

Para este proyecto educativo, PKCS12 es la alternativa de software más sólida y reconocida internacionalmente.

| Característica | HSM real | Este proyecto (PKCS12) |
|---|---|---|
| Claves salen del dispositivo | Nunca | Solo en memoria al firmar |
| Protección en disco | Hardware dedicado | AES-256 por contraseña |
| Persiste entre reinicios | Sí | ✅ Sí |
| Estándar reconocido | FIPS 140 | ✅ RFC 7292 |
| Viable en entorno educativo | No | ✅ Sí |

---

## 10. Firma embebida en PDF (PAdES)

### ¿Qué es PAdES?

PAdES (PDF Advanced Electronic Signatures) es el estándar para incrustar firmas digitales dentro de documentos PDF. La firma queda embebida en la estructura interna del PDF — no es un archivo separado, sino parte integral del documento.

**Consecuencia directa:** el documento PDF firmado es autocontenible. Contiene internamente:

- La firma digital
- El certificado X.509 del firmante
- Los metadatos del algoritmo utilizado

No existe ningún archivo adicional. No se genera ningún paquete externo.

> **Modelo de transporte:** un único archivo `documento_firmado.pdf` es todo lo que se necesita. No se utilizan estructuras como `secure-document.zip` con múltiples artefactos separados (firma, certificado, metadata). Todo está embebido en el PDF.

### Implementación de firma PAdES con PDFBox + Bouncy Castle

```xml
<!-- pom.xml: dependencias para firma PAdES -->
<dependency>
    <groupId>org.apache.pdfbox</groupId>
    <artifactId>pdfbox</artifactId>
    <version>3.0.1</version>
</dependency>
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
```

```java
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;

/**
 * Firma el PDF y embebe la firma + certificado X.509 dentro del documento (PAdES).
 * Devuelve el PDF firmado como bytes — un único archivo autocontenible.
 */
public byte[] firmarPDF(byte[] pdfBytes, PrivateKey privateKey,
                         X509Certificate cert, String algorithm) throws Exception {

    try (PDDocument document = PDDocument.load(pdfBytes)) {

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("SecureSign Institucional");
        signature.setSignDate(Calendar.getInstance());

        // Reservar espacio para la firma embebida en el PDF
        SignatureOptions options = new SignatureOptions();
        options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

        document.addSignature(signature, signedContent -> {
            // Leer bytes del PDF a firmar (el rango excluye el espacio reservado)
            byte[] content = signedContent.readAllBytes();

            // Construir estructura CMS (PKCS#7) con firma + certificado
            ContentSigner signer = new JcaContentSignerBuilder(
                algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA"
            ).build(privateKey);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().build()
                ).build(signer, cert)
            );
            gen.addCertificates(new JcaCertStore(List.of(cert)));

            CMSSignedData signedData = gen.generate(
                new CMSProcessableByteArray(content), false
            );
            return signedData.getEncoded(); // Bytes CMS embebidos en el PDF
        }, options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        document.saveIncremental(out);
        return out.toByteArray();
    }
}
```

---

## 11. Generación del documento PDF institucional

El backend genera automáticamente documentos PDF institucionales a partir de los datos del formulario usando **Apache PDFBox**.

### Ejemplo básico de generación con PDFBox

```java
public byte[] generarDocumentoPDF(String nombre, String dni,
                                   String tipoCertificado, String fecha) throws IOException {
    try (PDDocument document = new PDDocument()) {
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);

        try (PDPageContentStream content = new PDPageContentStream(document, page)) {
            content.beginText();
            content.setFont(PDType1Font.HELVETICA_BOLD, 20);
            content.newLineAtOffset(100, 750);
            content.showText("DOCUMENTO INSTITUCIONAL");

            content.setFont(PDType1Font.HELVETICA, 12);
            content.newLineAtOffset(0, -40);
            content.showText("Tipo: " + tipoCertificado);
            content.newLineAtOffset(0, -20);
            content.showText("Nombre: " + nombre);
            content.newLineAtOffset(0, -20);
            content.showText("DNI: " + dni);
            content.newLineAtOffset(0, -20);
            content.showText("Fecha de emisión: " + fecha);
            content.endText();
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        document.save(out);
        return out.toByteArray();
    }
}
```

El documento PDF generado se utiliza directamente como entrada para el proceso de firma PAdES.

---

## 12. Implementación del backend

### 12.1 Configuración del proyecto

Crear un proyecto Spring Boot con Java 17. En `pom.xml` se requieren PDFBox para la generación de documentos y Bouncy Castle para X.509 y PAdES. La criptografía base usa `java.security` nativo.

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.apache.pdfbox</groupId>
        <artifactId>pdfbox</artifactId>
        <version>3.0.1</version>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcpkix-jdk18on</artifactId>
        <version>1.78.1</version>
    </dependency>
</dependencies>
```

### 12.2 Estructura de paquetes recomendada

```
src/main/java/com/securesign/
├── controller/
│   └── DocumentController.java      ← endpoints REST
├── service/
│   ├── DocumentService.java         ← generación de PDF y coordinación
│   ├── SignatureService.java        ← firma PAdES, KeyStore PKCS12
│   ├── CertificateX509Service.java  ← generación de certificados X.509
│   └── VerificationService.java     ← verificación independiente
├── model/
│   └── DocumentRequest.java
└── SecureSignApplication.java
```

### 12.3 Servicio de documentos (coordinación)

```java
@Service
public class DocumentService {

    @Autowired private SignatureService signatureService;
    @Autowired private CertificateX509Service certificateX509Service;

    /**
     * Flujo completo de emisión:
     * 1. Generar PDF
     * 2. Generar KeyPair
     * 3. Generar certificado X.509 autofirmado
     * 4. Firmar PDF
     * 5. Embeber firma en PDF (PAdES)
     * 6. Devolver PDF firmado (autocontenible)
     */
    public byte[] emitirDocumentoFirmado(String nombre, String dni,
                                          String tipo, String fecha,
                                          String algorithm) throws Exception {
        // 1. Generar documento PDF
        byte[] pdfBytes = generarDocumentoPDF(nombre, dni, tipo, fecha);

        // 2. Generar KeyPair + certificado X.509 → almacenar en PKCS12
        String keyId = signatureService.generateKeyPairWithCertificate(algorithm);

        // 3. Recuperar claves y certificado desde PKCS12
        PrivateKey privateKey = signatureService.getPrivateKey(keyId);
        X509Certificate cert = signatureService.getCertificate(keyId);

        // 4 y 5. Firmar y embeber en PDF (PAdES) → PDF autocontenible
        return signatureService.firmarPDF(pdfBytes, privateKey, cert, algorithm);
    }
}
```

### 12.4 Servicio de verificación (independiente del backend emisor)

```java
@Service
public class VerificationService {

    /**
     * Verificación completamente independiente del servidor emisor.
     * Extrae la firma y el certificado X.509 directamente del PDF firmado.
     * No requiere keyId, no requiere estado del servidor.
     */
    public Map<String, Object> verificarDocumentoFirmado(byte[] pdfFirmadoBytes) throws Exception {
        try (PDDocument document = PDDocument.load(pdfFirmadoBytes)) {

            // 1. Extraer firma embebida (PAdES)
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                return Map.of("valid", false, "reason", "El PDF no contiene firma digital");
            }

            PDSignature signature = signatures.get(0);
            byte[] signatureBytes = signature.getContents(pdfFirmadoBytes);
            byte[] signedContent   = signature.getSignedContent(pdfFirmadoBytes);

            // 2. Extraer certificado X.509 desde la estructura CMS del PDF
            CMSSignedData cmsSignedData = new CMSSignedData(
                new CMSProcessableByteArray(signedContent), signatureBytes
            );
            Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
            X509CertificateHolder certHolder = certStore.getMatches(null).iterator().next();
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

            // 3. Obtener PublicKey desde el certificado X.509
            PublicKey publicKey = cert.getPublicKey();

            // 4. Verificar la firma contra el hash del PDF
            SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
            SignerInformation signerInfo = signerInfoStore.getSigners().iterator().next();
            boolean firmaValida = signerInfo.verify(
                new JcaSimpleSignerInfoVerifierBuilder().build(cert)
            );

            // 5. Validar fechas del certificado
            boolean certVigente;
            try {
                cert.checkValidity();
                certVigente = true;
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                certVigente = false;
            }

            return Map.of(
                "valid", firmaValida && certVigente,
                "firmaValida", firmaValida,
                "certificadoVigente", certVigente,
                "subject", cert.getSubjectX500Principal().getName(),
                "validoDesde", cert.getNotBefore().toString(),
                "validoHasta", cert.getNotAfter().toString()
            );
        }
    }
}
```

### 12.5 Controlador REST

```java
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    @Autowired private DocumentService documentService;
    @Autowired private VerificationService verificationService;

    /**
     * Emite un documento PDF firmado digitalmente (PAdES).
     * Devuelve un único PDF autocontenible con firma y certificado X.509 embebidos.
     */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generate(@RequestBody DocumentRequest request) throws Exception {
        byte[] pdfFirmado = documentService.emitirDocumentoFirmado(
            request.getNombre(), request.getDni(),
            request.getTipo(), request.getFecha(),
            request.getAlgorithm()
        );

        return ResponseEntity.ok()
            .header("Content-Type", "application/pdf")
            .header("Content-Disposition", "attachment; filename=documento_firmado.pdf")
            .body(pdfFirmado);
    }

    /**
     * Verifica la firma de un PDF firmado (PAdES).
     * La verificación es completamente independiente: extrae firma y certificado del propio PDF.
     * No requiere keyId ni ningún dato externo.
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfFirmadoBytes = file.getBytes();
        Map<String, Object> resultado = verificationService.verificarDocumentoFirmado(pdfFirmadoBytes);

        return ResponseEntity.ok(resultado);
    }
}
```

---

## 13. Endpoints de la API

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/documents/generate` | Genera PDF, firma y embebe la firma (PAdES). Devuelve PDF autocontenible. |
| POST | `/api/documents/verify` | Verifica el PDF firmado. Extrae firma y certificado del propio PDF. |

**Ejemplo de solicitud de emisión:**

```json
{
  "nombre": "Ana García López",
  "dni": "12345678",
  "tipo": "Constancia Académica",
  "fecha": "2024-01-15",
  "algorithm": "Ed25519"
}
```

La respuesta devuelve directamente el PDF firmado como `application/pdf`. No se devuelve `keyId` — el documento es autocontenible.

**Solicitud de verificación:**

```
POST /api/documents/verify
Content-Type: multipart/form-data

file=<archivo PDF firmado>
```

**Respuesta:**

```json
{
  "valid": true,
  "firmaValida": true,
  "certificadoVigente": true,
  "subject": "CN=SecureSign Institucional, O=Universidad, C=PE",
  "validoDesde": "Thu Jan 15 00:00:00 PET 2025",
  "validoHasta": "Fri Jan 15 00:00:00 PET 2026"
}
```

> **Diferencia clave respecto al modelo anterior:** la verificación ya no requiere `keyId` ni `algorithm` como parámetros externos. Toda la información necesaria para verificar está embebida en el PDF firmado.

---

## 14. Implementación del frontend

El frontend es un único archivo HTML autocontenido (`index.html`) sin dependencias externas ni framework. Incluye CSS embebido y JavaScript vanilla.

### 14.1 Estructura de archivos

```
securesign-frontend/
└── index.html    ← aplicación completa (HTML + CSS + JS)
```

### 14.2 Estructura HTML

El archivo se divide en dos paneles principales dentro de un `<main>` con layout CSS Grid:

- **Panel 01 — Emisión:** formulario, selector de algoritmo, botón de emisión y área de descarga.
- **Panel 02 — Verificación:** drop zone para subir el PDF firmado y resultado.

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SecureSign</title>
  <style>/* ... estilos embebidos ... */</style>
</head>
<body>
  <header><!-- logo y título --></header>
  <main>
    <div class="panel" id="panel-emit"><!-- Panel 01 --></div>
    <div class="panel" id="panel-verify"><!-- Panel 02 --></div>
  </main>
  <footer><!-- etiquetas informativas --></footer>
  <script>/* ... lógica JS ... */</script>
</body>
</html>
```

### 14.3 CSS: variables y layout

```css
:root {
  --bg:      #0d0e12;
  --surface: #14151c;
  --border:  #252630;
  --text:    #e8e9f0;
  --subtle:  #7b7d96;
  --accent:  #c8f060;   /* verde lima — emisión */
  --accent2: #60d4f0;   /* azul cielo — verificación */
  --success: #60f0a8;
  --danger:  #f06060;
}

main {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 2.5rem;
  max-width: 1200px;
  margin: 0 auto;
  padding: 3rem 2.5rem;
}
```

### 14.4 Selector de algoritmo

```javascript
let selectedAlgo = 'ECDSA';

function selectAlgo(algo) {
  selectedAlgo = algo;
  document.getElementById('btn-ecdsa').classList.toggle('active',    algo === 'ECDSA');
  document.getElementById('btn-ed25519').classList.toggle('active',  algo === 'Ed25519');
}
```

### 14.5 Emisión del documento firmado

```javascript
async function emitirDocumento() {
  const nombre = document.getElementById('inp-nombre').value.trim();
  const dni    = document.getElementById('inp-dni').value.trim();
  const tipo   = document.getElementById('inp-tipo').value;
  const fecha  = document.getElementById('inp-fecha').value;

  if (!nombre || !dni || !tipo || !fecha) {
    showResult('emit-error', 'error', 'Completa todos los campos.');
    return;
  }

  const res = await fetch('http://localhost:8080/api/documents/generate', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ nombre, dni, tipo, fecha, algorithm: selectedAlgo }),
  });

  // El PDF devuelto ya contiene firma y certificado X.509 embebidos (PAdES)
  const pdfBlob = await res.blob();
  lastEmission = { pdfBlob, nombre };

  // No se maneja keyId — el documento es autocontenible
}
```

### 14.6 Descarga del PDF firmado

```javascript
function descargarPDF() {
  const url = URL.createObjectURL(lastEmission.pdfBlob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = `documento_firmado_${lastEmission.nombre.replace(/\s+/g, '_').toLowerCase()}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}
```

### 14.7 Drop zone para verificación

```javascript
const dz = document.getElementById('dropzone');

dz.addEventListener('dragover',  e => { e.preventDefault(); dz.classList.add('dragover'); });
dz.addEventListener('dragleave', ()  => dz.classList.remove('dragover'));
dz.addEventListener('drop', e => {
  e.preventDefault();
  dz.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file && file.type === 'application/pdf') {
    document.getElementById('ver-file').files = e.dataTransfer.files;
    showFileName(file.name);
  }
});
```

### 14.8 Verificación del documento firmado

```javascript
async function verificarDocumento() {
  const file = document.getElementById('ver-file').files[0];

  // Solo se envía el PDF — no se necesita keyId ni algorithm
  const formData = new FormData();
  formData.append('file', file);

  const res  = await fetch('http://localhost:8080/api/documents/verify', {
    method: 'POST',
    body:   formData,
  });
  const data = await res.json();

  if (data.valid) {
    showResult('verify-result', 'success',
      `✓ Firma válida — El documento es auténtico e íntegro.\nFirmante: ${data.subject}`);
  } else {
    showResult('verify-result', 'error',
      '✗ Firma inválida — El documento fue alterado o los datos no coinciden.');
  }
}
```

### 14.9 Flujo de uso en el sistema

1. El usuario completa el formulario: nombre, DNI, tipo de documento, fecha.
2. Selecciona el algoritmo de firma (ECDSA o Ed25519).
3. Hace clic en **"Emitir documento"** → el backend genera el PDF, lo firma y embebe la firma (PAdES).
4. El usuario descarga el PDF firmado. **No se necesita ningún código adicional** (no hay `keyId`).
5. En el módulo de verificación, el usuario sube el PDF firmado (clic o drag & drop).
6. El sistema extrae la firma y el certificado X.509 directamente del PDF y verifica la autenticidad.

---

## 15. Evaluación comparativa

Esta sección permite observar empíricamente las diferencias entre ECDSA y Ed25519 al operar sobre documentos PDF reales.

### Métricas a medir

- **Tiempo de firma** y **tiempo de verificación**
- **Tamaño de la firma embebida resultante**
- **Comportamiento determinista**

### Ejemplo con `System.nanoTime()`

```java
long inicio = System.nanoTime();
byte[] pdfFirmado = documentService.emitirDocumentoFirmado(nombre, dni, tipo, fecha, algorithm);
long tiempoFirma = System.nanoTime() - inicio;

long inicioVerif = System.nanoTime();
Map<String, Object> resultado = verificationService.verificarDocumentoFirmado(pdfFirmado);
long tiempoVerif = System.nanoTime() - inicioVerif;

System.out.printf("Algoritmo: %s%n", algorithm);
System.out.printf("Tiempo de firma (PAdES): %d ns%n", tiempoFirma);
System.out.printf("Tiempo de verificación: %d ns%n", tiempoVerif);
System.out.printf("Firma válida: %s%n", resultado.get("valid"));
```

### Comportamiento determinista

- **Ed25519** produce siempre la misma firma para el mismo documento y la misma clave privada. Firmar el PDF dos veces genera bytes idénticos en la firma embebida.
- **ECDSA** produce una firma diferente en cada ejecución, incluso para el mismo documento, debido al número aleatorio interno.

Esto es visible al comparar el contenido binario de las firmas embebidas en distintas emisiones del mismo documento.

---

## 16. Escenarios de demostración

### Escenario 1: Documento original → firma válida

1. Emitir un documento PDF firmado con Ed25519.
2. Subir el mismo PDF sin modificaciones al módulo de verificación.
3. Resultado esperado: `"valid": true`.

Esto demuestra que el documento es auténtico e íntegro desde su emisión.

### Escenario 2: PDF modificado manualmente → firma inválida

1. Emitir un documento PDF firmado.
2. Abrir el PDF con un editor de texto o hexadecimal y modificar cualquier byte.
3. Subir el PDF alterado al módulo de verificación.
4. Resultado esperado: `"valid": false`.

Este escenario demuestra la integridad criptográfica: cualquier cambio en el documento —por mínimo que sea— produce un hash SHA-256 completamente diferente, haciendo que la verificación falle de forma determinista.

### Escenario 3: Verificación offline

1. Emitir y descargar un documento PDF firmado.
2. Desconectar el servidor backend completamente.
3. Cargar el PDF en cualquier herramienta compatible con PAdES (Adobe Acrobat Reader, etc.).
4. Resultado esperado: la firma se verifica correctamente sin servidor.

Este escenario demuestra la **portabilidad criptográfica** del modelo PAdES: el documento es autocontenible y verificable de forma independiente.

### Escenario 4: Determinismo de Ed25519 vs ECDSA

1. Emitir el mismo documento dos veces con Ed25519. Las firmas embebidas en el PDF deben ser **idénticas** (bytes iguales en el bloque de firma).
2. Repetir con ECDSA. Las firmas serán **diferentes** aunque el documento sea el mismo.

Esto demuestra de forma observable la diferencia conceptual entre firma determinista (Ed25519) y firma con aleatoriedad (ECDSA).

---

## 17. Seguridad

### La clave privada nunca sale del backend

El principio central del sistema es que la clave privada nunca es transmitida al cliente ni almacenada fuera del servidor. El cliente únicamente recibe el documento PDF firmado, que contiene la clave **pública** (dentro del certificado X.509), nunca la privada.

### Protección en reposo mediante PKCS12 KeyStore

Las claves privadas se almacenan en un archivo `securesign.p12` en disco, protegido por contraseña usando el estándar PKCS12 (RFC 7292). La clave privada en texto plano solo existe en memoria durante los milisegundos que dura la operación de firma.

### Limitación del sistema educativo

La contraseña del KeyStore se carga desde una variable de entorno. En un sistema de producción real se gestionaría mediante un secrets manager (AWS KMS, HashiCorp Vault, etc.) con rotación y revocación de claves.

---

## 18. Alcance del proyecto y limitaciones respecto a una PKI real

Este sistema es un laboratorio educativo que implementa **firma digital embebida en PDF (PAdES) con certificados X.509 autofirmados**. No constituye una PKI completa.

### Lo que el proyecto NO implementa

| Componente | Justificación |
|---|---|
| Root CA / Intermediate CA | Requiere infraestructura PKI real |
| Cadenas de confianza verificables externamente | Los certificados son autofirmados |
| Revocación (CRL / OCSP) | Fuera del alcance educativo |
| Timestamping (TSA) | Requiere servicio externo de sellado de tiempo |
| HSM (Hardware Security Module) | Reemplazado por PKCS12 para entorno educativo |
| eIDAS / normativa legal | Fuera del alcance académico |

### Lo que el proyecto SÍ demuestra

Aun así, el sistema implementa conceptos criptográficos reales:

- Firmas digitales reales sobre documentos PDF (ECDSA / Ed25519)
- Certificados X.509 autofirmados con subject, issuer, serial number y fechas de validez
- Protección de claves privadas mediante PKCS12 (RFC 7292)
- Verificación criptográfica completa e independiente del servidor emisor
- Firma embebida en PDF (PAdES) — modelo estándar de documentos firmados
- Diferencia práctica entre identidad (certificado X.509) y clave pública
- Verificación offline: el documento es autocontenible

El objetivo no es construir una PKI industrial. Se prioriza la claridad conceptual, la simplicidad arquitectónica y la demostrabilidad en exposición, manteniendo implementaciones criptográficas reales.

---

## 19. Pasos para ejecutar el proyecto

### Configuración de la contraseña del KeyStore

Antes de ejecutar, definir la variable de entorno que protege el archivo PKCS12:

```bash
# Linux / macOS
export SECURESIGN_KEYSTORE_PASSWORD=mi-contrasena-educativa

# Windows (PowerShell)
$env:SECURESIGN_KEYSTORE_PASSWORD="mi-contrasena-educativa"
```

En `application.properties`:

```properties
securesign.keystore-password=${SECURESIGN_KEYSTORE_PASSWORD}
```

El archivo `securesign.p12` se crea automáticamente en el directorio raíz del proyecto al emitir el primer documento firmado.

### Backend

```bash
cd securesign-backend

./mvnw spring-boot:run

# El servidor queda disponible en:
# http://localhost:8080
```

### Frontend

No requiere instalación ni build. Abrir directamente el archivo en el navegador:

```bash
# Opción 1: abrir el archivo directamente
open securesign-frontend/index.html

# Opción 2: servir con cualquier servidor estático para evitar restricciones CORS
npx serve securesign-frontend/
# o
python3 -m http.server 5173 --directory securesign-frontend/

# La interfaz queda disponible en:
# http://localhost:5173
```

---

## 20. Conclusión

RSA fue un pilar histórico de la criptografía, pero sus limitaciones en tamaño de claves, tamaño de firmas y costo computacional impulsaron el desarrollo de alternativas más eficientes.

**ECDSA** y, especialmente, **Ed25519** representan la evolución moderna de las firmas digitales: claves más pequeñas, firmas más compactas, mayor velocidad y —en el caso de Ed25519— una implementación intrínsecamente más segura gracias a la firma determinista. Ambos algoritmos son la base de tecnologías críticas como HTTPS, SSH y blockchain.

Este proyecto evolucionó desde una arquitectura centralizada dependiente del backend hacia un **modelo de documento criptográficamente autónomo**. El sistema demuestra cómo una firma digital protege la integridad de un documento institucional, cómo el certificado X.509 vincula identidad con clave pública, y cómo el modelo PAdES elimina la dependencia del servidor emisor: el documento PDF firmado es portable, autocontenible y verificable por cualquier sistema compatible con el estándar, incluso offline.

La evolución desde RSA hacia ECDSA y Ed25519 no es solo un dato técnico. Con este sistema, es algo que se puede ver, medir y comprobar — sobre documentos reales, con firmas reales, y con verificación independiente.
