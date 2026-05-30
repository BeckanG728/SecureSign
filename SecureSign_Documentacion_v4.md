# SecureSign — Guía de Implementación
### Sistema de Firma y Validación Criptográfica de Documentos PDF

> **Objetivo:** Implementar un sistema educativo para emitir y validar documentos PDF firmados digitalmente usando algoritmos modernos: ECDSA y Ed25519. El sistema simula una entidad institucional que genera documentos como antecedentes penales, constancias académicas y certificados laborales, demostrando integridad documental, autenticación y no repudio de forma práctica.

---

## 1. Introducción conceptual

### ¿Qué garantiza una firma digital sobre un PDF?

Una firma digital aplicada a un documento PDF garantiza tres propiedades fundamentales:

- **Integridad:** el documento no fue modificado desde que fue firmado.
- **Autenticación:** fue emitido por quien dice haberlo emitido.
- **No repudio:** el emisor no puede negar haber firmado el documento.

A diferencia de firmar texto plano, en este sistema la firma se aplica sobre los **bytes completos del documento PDF**. Cualquier modificación posterior al PDF —aunque sea de un solo byte— invalida la firma por completo.

### Flujo criptográfico sobre PDF

```
Documento PDF (bytes completos)
          ↓
SHA-256 interno (calculado por el algoritmo de firma)
          ↓
Firma con clave privada (ECDSA o Ed25519)
          ↓
   Firma digital  (bytes que acompañan al documento)
          ↓
Verificación con clave pública  → ✅ válida / ❌ inválida
```

> **Nota técnica importante:** cuando se usa `SHA256withECDSA`, el algoritmo calcula **internamente** el hash SHA-256 del documento antes de firmar. No se realiza un hashing separado previo — el proceso está encapsulado en una sola operación. Esto significa que no se firman "bytes crudos", sino el hash resultante, todo dentro del mismo llamado criptográfico. Ed25519 hace lo mismo con su función hash interna (SHA-512).

El hash actúa como huella digital del documento. Si el PDF se modifica —incluso cambiando un solo carácter invisible— el hash resultante será completamente diferente y la verificación fallará. Esto es lo que hace posible la detección de alteraciones.

---

## 2. Modelo institucional

El sistema está diseñado con una arquitectura que imita la separación de responsabilidades de sistemas reales:

- **El frontend representa una institución emisora** (universidad, municipalidad u organismo público). Es quien solicita la emisión de documentos y los entrega al ciudadano.
- **El backend actúa como infraestructura criptográfica centralizada**, responsable de generar claves, firmar documentos y verificar su autenticidad.

Esta separación tiene implicaciones de seguridad directas: la institución no gestiona las claves privadas. Esa responsabilidad recae exclusivamente en el backend, reduciendo la superficie de ataque.

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
  │  Criptográfica Central)    │
  │  - Genera claves           │
  │  - Cifra y protege claves  │
  │  - Firma documentos PDF    │
  │  - Verifica firmas         │
  └────────────────────────────┘
```

---

## 3. Contexto histórico

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

## 4. Algoritmos implementados

### 4.1 ECDSA (P-256 / secp256r1)

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

### 4.2 Ed25519

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
sig.initVerify(keyPair.getPublic());
sig.update(pdfBytes);
boolean valida = sig.verify(firma);
```

---

## 5. Aplicaciones reales de ECDSA y Ed25519

Estos algoritmos no son solo conceptos académicos: son la base criptográfica de tecnologías que se usan diariamente en internet y en sistemas de seguridad modernos.

| Tecnología | Algoritmo | Uso |
|---|---|---|
| HTTPS / TLS | ECDSA (P-256) | Certificados de servidores web (candado del navegador) |
| OpenSSH | Ed25519 | Autenticación de servidores y usuarios sin contraseña |
| Blockchain (Ethereum) | ECDSA | Firma de transacciones |
| Blockchain (Solana, Monero) | Ed25519 | Firma de transacciones y billeteras |
| Certificados digitales | ECDSA | Firmas en documentos legales electrónicos |
| Signal / WhatsApp | Ed25519 | Autenticación de claves en mensajería cifrada |

En todos estos casos, el principio es el mismo que en SecureSign: una clave privada que nunca debe exponerse firma datos, y cualquiera con la clave pública puede verificar esa firma sin necesidad de conocer la privada.

---

## 6. Comparación educativa

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

## 7. Arquitectura del proyecto

### Tecnologías utilizadas

| Capa | Tecnología |
|---|---|
| Backend | Java 17, Spring Boot |
| Criptografía | `java.security` (ECDSA, Ed25519) |
| Generación PDF | Apache PDFBox o iText |
| Frontend | HTML + CSS + JavaScript (vanilla) |
| API | REST / JSON + multipart para archivos |

### Flujo general

```
Cliente (frontend)
       ↓  envía formulario (nombre, DNI, tipo, fecha, algoritmo)
   Backend (Java)
       ↓  genera documento PDF institucional
       ↓  genera clave privada → la almacena en KeyStore PKCS12 (archivo .p12 cifrado)
       ↓  firma los bytes con clave privada (ECDSA o Ed25519)
       ↓  almacena: firma + clave pública en memoria + keyId
       ↓  devuelve PDF al cliente para descarga
   Cliente
       ↓  descarga el certificado PDF
       ↓  puede subir el PDF posteriormente para verificarlo
   Backend
       ↓  recibe el PDF subido
       ↓  recupera clave privada del KeyStore PKCS12 con contraseña
       ↓  verifica firma con la clave pública asociada al keyId
       ↓  responde: válida / inválida
```

### Principio de seguridad central

> **La clave privada nunca sale del backend, y en reposo está protegida en un archivo PKCS12.**
> El cliente solo recibe el PDF generado y un identificador (`keyId`). Las claves privadas se almacenan en un KeyStore PKCS12 (formato estándar RFC 7292) cifrado con contraseña en disco, persistiendo entre reinicios del servidor.

---

## 8. Protección de claves privadas mediante PKCS12 KeyStore

El docente requiere proteger las claves privadas. Al no disponer de un HSM (Hardware Security Module), se implementa almacenamiento con **Java KeyStore en formato PKCS12**, que es el estándar internacional para proteger claves criptográficas en software.

### ¿Qué es PKCS12?

PKCS12 (RFC 7292) es un formato estándar internacional para almacenar claves privadas y certificados en un archivo protegido por contraseña. No es exclusivo de Java: es el mismo formato que usan OpenSSL, los navegadores web, Windows y macOS para gestionar sus certificados y claves.

Desde Java 9, PKCS12 es el formato por defecto de `java.security.KeyStore`, reemplazando al antiguo JCEKS que era propietario de Sun/Oracle y usaba el cifrado débil DES.

El archivo generado tiene extensión `.p12` y su contenido es **ilegible sin la contraseña**, independientemente de quién acceda al sistema de archivos.

### ¿Por qué es mejor que un Map en memoria?

| Almacenamiento | Persiste al reiniciar | Protegido en disco | Estándar reconocido |
|---|---|---|---|
| `ConcurrentHashMap` (anterior) | ❌ No | ❌ No | ❌ No |
| PKCS12 KeyStore (actual) | ✅ Sí | ✅ Sí (AES-256) | ✅ Sí (RFC 7292) |

Con el `ConcurrentHashMap` anterior, las claves solo existían mientras el servidor estuviese en ejecución y no había protección real en reposo. Con PKCS12, las claves persisten en disco cifradas y sobreviven reinicios del servidor.

### Esquema de almacenamiento

```
Clave privada generada
          ↓
java.security.KeyStore (PKCS12)
protegido con contraseña (variable de entorno)
          ↓
Archivo securesign.p12 en disco
(bytes cifrados con AES-256, ilegibles sin contraseña)
          ↓
Para usar: cargar KeyStore con contraseña → extraer clave → firmar
```

### Implementación del servicio de firma con PKCS12

```java
@Service
public class SignatureService {

    private static final String KEYSTORE_PATH = "securesign.p12";
    private static final String KEYSTORE_TYPE = "PKCS12"; // Estándar RFC 7292, default en Java 9+

    @Value("${securesign.keystore-password}")
    private String keystorePassword;

    /**
     * Carga el KeyStore desde disco si existe, o crea uno nuevo vacío.
     * El archivo .p12 está protegido por contraseña con AES-256.
     */
    private KeyStore cargarKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        File archivo = new File(KEYSTORE_PATH);

        if (archivo.exists()) {
            // Cargar KeyStore existente desde disco
            try (FileInputStream fis = new FileInputStream(archivo)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
        } else {
            // Inicializar KeyStore vacío (primera ejecución)
            ks.load(null, keystorePassword.toCharArray());
        }
        return ks;
    }

    /**
     * Persiste el KeyStore a disco.
     * Sincronizado para evitar escrituras concurrentes.
     */
    private synchronized void guardarKeyStore(KeyStore ks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            ks.store(fos, keystorePassword.toCharArray());
        }
    }

    /**
     * Genera un par de claves, almacena la clave privada en el KeyStore PKCS12
     * y persiste el archivo cifrado en disco.
     */
    public String generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "EC"
        );
        if (!algorithm.equals("Ed25519")) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        KeyPair keyPair = kpg.generateKeyPair();
        String keyId = UUID.randomUUID().toString();

        // Almacenar clave privada en KeyStore PKCS12
        // setKeyEntry requiere un array de Certificate; para este sistema
        // educativo se pasa null (no se emiten certificados X.509 reales)
        KeyStore ks = cargarKeyStore();
        ks.setKeyEntry(
            keyId,
            keyPair.getPrivate(),
            keystorePassword.toCharArray(),
            null
        );
        guardarKeyStore(ks); // Persiste en disco cifrado

        // La clave pública se almacena en memoria (no requiere protección)
        publicKeyStore.put(keyId, keyPair.getPublic());

        return keyId;
    }

    // Map solo para claves PÚBLICAS (no requieren protección especial)
    private final Map<String, PublicKey> publicKeyStore = new ConcurrentHashMap<>();

    public byte[] sign(String keyId, String algorithm, byte[] pdfBytes) throws Exception {
        // Recuperar clave privada del KeyStore en disco
        KeyStore ks = cargarKeyStore();
        PrivateKey privateKey = (PrivateKey) ks.getKey(keyId, keystorePassword.toCharArray());

        Signature sig = Signature.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA"
        );
        sig.initSign(privateKey);
        sig.update(pdfBytes);
        return sig.sign();
    }

    public boolean verify(String keyId, String algorithm, byte[] pdfBytes, byte[] firma) throws Exception {
        // Verificación usa clave pública (no requiere KeyStore)
        PublicKey publicKey = publicKeyStore.get(keyId);
        if (publicKey == null) return false;

        Signature sig = Signature.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA"
        );
        sig.initVerify(publicKey);
        sig.update(pdfBytes);
        return sig.verify(firma);
    }
}
```

### ¿Por qué no se usa un HSM en este proyecto?

Un HSM (Hardware Security Module) es un dispositivo físico especializado que almacena y opera con claves privadas en hardware aislado. Las claves **nunca salen del dispositivo**, ni siquiera como bytes cifrados. Es el estándar para sistemas bancarios, autoridades certificadoras y gobiernos.

Para este proyecto educativo, PKCS12 es la alternativa de software más sólida y reconocida internacionalmente: las claves privadas se almacenan cifradas en disco en un formato estándar, protegidas por contraseña, y nunca se transmiten fuera del servidor.

| Característica | HSM real | Este proyecto (PKCS12) |
|---|---|---|
| Claves salen del dispositivo | Nunca | Solo en memoria al firmar |
| Protección en disco | Hardware dedicado | AES-256 por contraseña |
| Persiste entre reinicios | Sí | ✅ Sí |
| Estándar reconocido | FIPS 140 | ✅ RFC 7292 |
| Viable en entorno educativo | No | ✅ Sí |

---

## 9. Generación de certificados PDF

El backend genera automáticamente documentos PDF institucionales a partir de los datos del formulario. Se puede usar **Apache PDFBox** o **iText** para esta tarea.

### Dependencia Maven (PDFBox)

```xml
<dependency>
    <groupId>org.apache.pdfbox</groupId>
    <artifactId>pdfbox</artifactId>
    <version>3.0.1</version>
</dependency>
```

### Ejemplo básico de generación con PDFBox

```java
public byte[] generarCertificadoPDF(String nombre, String dni,
                                     String tipoCertificado, String fecha) throws IOException {
    try (PDDocument document = new PDDocument()) {
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);

        try (PDPageContentStream content = new PDPageContentStream(document, page)) {
            content.beginText();
            content.setFont(PDType1Font.HELVETICA_BOLD, 20);
            content.newLineAtOffset(100, 750);
            content.showText("CERTIFICADO INSTITUCIONAL");

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

El PDF generado se devuelve como arreglo de bytes, que luego se utiliza directamente para la firma criptográfica.

---

## 10. Implementación del backend

### 10.1 Configuración del proyecto

Crear un proyecto Spring Boot con Java 17. En `pom.xml` se requiere PDFBox (o iText) para la generación de documentos. La criptografía usa `java.security` nativo.

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
</dependencies>
```

### 10.2 Estructura de paquetes recomendada

```
src/main/java/com/securesign/
├── controller/
│   └── CertificateController.java   ← endpoints REST
├── service/
│   ├── CertificateService.java      ← generación de PDF y coordinación
│   └── SignatureService.java        ← firma, verificación y gestión del KeyStore PKCS12
├── model/
│   ├── CertificateRequest.java
│   └── CertificateRecord.java       ← almacena PDF + firma + keyId
└── SecureSignApplication.java
```

### 10.3 Servicio de certificados

```java
@Service
public class CertificateService {

    @Autowired
    private SignatureService signatureService;

    // Almacén temporal: keyId → firma del PDF emitido
    private final Map<String, byte[]> signatureStore = new ConcurrentHashMap<>();

    public Map<String, Object> emitirCertificado(String nombre, String dni,
                                                   String tipo, String fecha,
                                                   String algorithm) throws Exception {
        // 1. Generar el PDF
        byte[] pdfBytes = generarCertificadoPDF(nombre, dni, tipo, fecha);

        // 2. Generar par de claves (clave privada se cifra internamente) y firmar
        String keyId = signatureService.generateKeyPair(algorithm);
        byte[] firma = signatureService.sign(keyId, algorithm, pdfBytes);

        // 3. Almacenar firma para verificación posterior
        signatureStore.put(keyId, firma);

        return Map.of(
            "keyId", keyId,
            "algorithm", algorithm,
            "pdf", pdfBytes,
            "signature", Base64.getEncoder().encodeToString(firma)
        );
    }

    public boolean verificarCertificado(String keyId, String algorithm,
                                         byte[] pdfBytes) throws Exception {
        byte[] firmaOriginal = signatureStore.get(keyId);
        if (firmaOriginal == null) return false;
        return signatureService.verify(keyId, algorithm, pdfBytes, firmaOriginal);
    }

    private byte[] generarCertificadoPDF(String nombre, String dni,
                                          String tipo, String fecha) throws IOException {
        // (ver sección 9 para implementación completa)
        // ...
    }
}
```

### 10.4 Controlador REST

```java
@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    @Autowired
    private CertificateService certificateService;

    @PostMapping("/generate")
    public ResponseEntity<byte[]> generate(@RequestBody CertificateRequest request) throws Exception {
        Map<String, Object> result = certificateService.emitirCertificado(
            request.getNombre(), request.getDni(),
            request.getTipo(), request.getFecha(),
            request.getAlgorithm()
        );

        byte[] pdf = (byte[]) result.get("pdf");
        String keyId = (String) result.get("keyId");

        return ResponseEntity.ok()
            .header("Content-Type", "application/pdf")
            .header("X-Key-Id", keyId)
            .header("X-Algorithm", request.getAlgorithm())
            .body(pdf);
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(
            @RequestParam String keyId,
            @RequestParam String algorithm,
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfBytes = file.getBytes();
        boolean valida = certificateService.verificarCertificado(keyId, algorithm, pdfBytes);

        return ResponseEntity.ok(Map.of(
            "valid", valida,
            "keyId", keyId,
            "algorithm", algorithm
        ));
    }
}
```

---

## 11. Endpoints de la API

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/certificates/generate` | Genera PDF, lo firma y devuelve el archivo |
| POST | `/api/certificates/verify` | Verifica integridad y autenticidad de un PDF |

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

La respuesta devuelve el PDF como `application/pdf` con los headers `X-Key-Id` y `X-Algorithm` para la verificación posterior.

**Solicitud de verificación:**

```
POST /api/certificates/verify
Content-Type: multipart/form-data

keyId=<uuid>
algorithm=Ed25519
file=<archivo PDF>
```

**Respuesta:**

```json
{
  "valid": true,
  "keyId": "abc123",
  "algorithm": "Ed25519"
}
```

---

## 12. Implementación del frontend

El frontend es un único archivo HTML autocontenido (`index.html`) sin dependencias externas ni framework. Incluye CSS embebido y JavaScript vanilla.

### 12.1 Estructura de archivos

```
securesign-frontend/
└── index.html    ← aplicación completa (HTML + CSS + JS)
```

### 12.2 Estructura HTML

El archivo se divide en dos paneles principales dentro de un `<main>` con layout CSS Grid:

- **Panel 01 — Emisión:** formulario, selector de algoritmo, botón de emisión y área de descarga.
- **Panel 02 — Verificación:** campo Key ID, selector de algoritmo, drop zone para subir PDF y resultado.

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

### 12.3 CSS: variables y layout

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

### 12.4 Selector de algoritmo

```javascript
let selectedAlgo = 'ECDSA';

function selectAlgo(algo) {
  selectedAlgo = algo;
  document.getElementById('btn-ecdsa').classList.toggle('active',    algo === 'ECDSA');
  document.getElementById('btn-ed25519').classList.toggle('active',  algo === 'Ed25519');
}
```

### 12.5 Emisión de certificado

```javascript
async function emitirCertificado() {
  const nombre = document.getElementById('inp-nombre').value.trim();
  const dni    = document.getElementById('inp-dni').value.trim();
  const tipo   = document.getElementById('inp-tipo').value;
  const fecha  = document.getElementById('inp-fecha').value;

  if (!nombre || !dni || !tipo || !fecha) {
    showResult('emit-error', 'error', 'Completa todos los campos.');
    return;
  }

  const res = await fetch('http://localhost:8080/api/certificates/generate', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ nombre, dni, tipo, fecha, algorithm: selectedAlgo }),
  });

  const keyId   = res.headers.get('X-Key-Id');
  const algo    = res.headers.get('X-Algorithm');
  const pdfBlob = await res.blob();

  lastEmission = { keyId, algorithm: algo, pdfBlob, nombre };

  // Autocompletar verificación
  document.getElementById('ver-keyid').value = keyId;
  document.getElementById('ver-algo').value  = algo;
}
```

### 12.6 Descarga del PDF

```javascript
function descargarPDF() {
  const url = URL.createObjectURL(lastEmission.pdfBlob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = `certificado_${lastEmission.nombre.replace(/\s+/g, '_').toLowerCase()}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}
```

### 12.7 Drop zone para verificación

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

### 12.8 Verificación del certificado

```javascript
async function verificarCertificado() {
  const keyId = document.getElementById('ver-keyid').value.trim();
  const algo  = document.getElementById('ver-algo').value;
  const file  = document.getElementById('ver-file').files[0];

  const formData = new FormData();
  formData.append('keyId',     keyId);
  formData.append('algorithm', algo);
  formData.append('file',      file);

  const res  = await fetch('http://localhost:8080/api/certificates/verify', {
    method: 'POST',
    body:   formData,
  });
  const data = await res.json();

  if (data.valid) {
    showResult('verify-result', 'success',
      '✓ Firma válida — El documento es auténtico e íntegro.');
  } else {
    showResult('verify-result', 'error',
      '✗ Firma inválida — El documento fue alterado o los datos no coinciden.');
  }
}
```

### 12.9 Flujo de uso en el sistema

1. El usuario completa el formulario: nombre, DNI, tipo de certificado, fecha.
2. Selecciona el algoritmo de firma (ECDSA o Ed25519).
3. Hace clic en **"Emitir certificado"** → el backend genera el PDF, lo firma y lo devuelve.
4. El usuario descarga el PDF firmado; el Key ID y algoritmo se autocompletan en el panel de verificación.
5. En el módulo de verificación, el usuario sube el PDF (clic o drag & drop).
6. El sistema responde si la firma es válida o si el documento fue alterado.

---

## 13. Evaluación comparativa

Esta sección permite observar empíricamente las diferencias entre ECDSA y Ed25519 al operar sobre documentos PDF reales.

### Métricas a medir

- **Tiempo de firma** y **tiempo de verificación**
- **Tamaño de la firma resultante**
- **Comportamiento determinista**

### Ejemplo con `System.nanoTime()`

```java
long inicio = System.nanoTime();
byte[] firma = signatureService.sign(keyId, algorithm, pdfBytes);
long tiempoFirma = System.nanoTime() - inicio;

long inicioVerif = System.nanoTime();
boolean valida = signatureService.verify(keyId, algorithm, pdfBytes, firma);
long tiempoVerif = System.nanoTime() - inicioVerif;

System.out.printf("Algoritmo: %s%n", algorithm);
System.out.printf("Tiempo de firma: %d ns%n", tiempoFirma);
System.out.printf("Tiempo de verificación: %d ns%n", tiempoVerif);
System.out.printf("Tamaño de firma: %d bytes%n", firma.length);
```

### Comportamiento determinista

- **Ed25519** produce siempre la misma firma para el mismo documento y la misma clave privada. Firmar el PDF dos veces genera bytes idénticos.
- **ECDSA** produce una firma diferente en cada ejecución, incluso para el mismo documento, debido al número aleatorio interno.

Esto es visible directamente en el frontend al comparar las firmas generadas en distintas emisiones.

---

## 14. Escenarios de demostración

### Escenario 1: Documento original → firma válida

1. Emitir un certificado PDF firmado con Ed25519.
2. Subir el mismo PDF sin modificaciones al módulo de verificación.
3. Resultado esperado: `"valid": true`.

Esto demuestra que el documento es auténtico e íntegro desde su emisión.

### Escenario 2: PDF modificado manualmente → firma inválida

1. Emitir un certificado PDF firmado.
2. Abrir el PDF con un editor de texto o hexadecimal y modificar cualquier byte.
3. Subir el PDF alterado al módulo de verificación.
4. Resultado esperado: `"valid": false`.

Este escenario demuestra la integridad criptográfica: cualquier cambio en el documento —por mínimo que sea— produce un hash SHA-256 completamente diferente, haciendo que la verificación falle de forma determinista.

### Escenario 3: Determinismo de Ed25519 vs ECDSA

1. Emitir el mismo certificado dos veces con Ed25519. Las firmas en Base64 devueltas deben ser **idénticas**.
2. Repetir con ECDSA. Las firmas serán **diferentes** aunque el documento sea el mismo.

Esto demuestra de forma observable la diferencia conceptual entre firma determinista (Ed25519) y firma con aleatoriedad (ECDSA).

---

## 15. Seguridad

### La clave privada nunca sale del backend

El principio central del sistema es que la clave privada nunca es transmitida al cliente ni almacenada fuera del servidor. El cliente únicamente recibe:

- El PDF firmado para su descarga.
- Un `keyId` que actúa como referencia temporal al par de claves en el servidor.

### Protección en reposo mediante PKCS12 KeyStore

Las claves privadas se almacenan en un archivo `securesign.p12` en disco, protegido por contraseña usando el estándar PKCS12 (RFC 7292). Este archivo es ilegible sin la contraseña, independientemente de quién acceda al sistema de archivos. La clave privada en texto plano solo existe en memoria durante los milisegundos que dura la operación de firma.

A diferencia del esquema anterior basado en `ConcurrentHashMap`, las claves **persisten entre reinicios del servidor**: un `keyId` emitido sigue siendo válido mientras el archivo `.p12` y la contraseña estén disponibles.

### Limitación del sistema educativo

La contraseña del KeyStore se carga desde una variable de entorno. En un sistema de producción real se gestionaría mediante un secrets manager (AWS KMS, HashiCorp Vault, etc.) y las políticas incluirían rotación y revocación de claves.

---

## 16. Alcance del proyecto

Este sistema es un laboratorio educativo que implementa una **infraestructura simplificada de firma digital basada en claves públicas**, sin constituir una PKI completa ni implementar certificados X.509 reales.

No implementa:

- **PKI real** ni jerarquía de certificación (Root CA → Intermediate CA → End entities).
- **Certificados X.509** ni cadenas de confianza verificables externamente.
- **Autoridades certificadoras** (CA) con capacidad de emitir certificados reconocidos.
- **Revocación de certificados** (CRL / OCSP).

El objetivo es estrictamente educativo y se centra en:

- Demostrar cómo funcionan las firmas digitales modernas sobre documentos reales.
- Comparar ECDSA y Ed25519 de forma práctica y observable.
- Ilustrar los principios de integridad documental y no repudio.
- Implementar protección de claves privadas mediante Java KeyStore PKCS12 (estándar RFC 7292) como alternativa a un HSM.

Para un sistema de producción real se requeriría una arquitectura PKI completa, un HSM, almacenamiento persistente de claves cifradas, y cumplimiento de estándares como eIDAS o PAdES para firmas PDF.

---

## 17. Pasos para ejecutar el proyecto

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

El archivo `securesign.p12` se crea automáticamente en el directorio raíz del proyecto al emitir el primer certificado.

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

## 18. Conclusión

RSA fue un pilar histórico de la criptografía, pero sus limitaciones en tamaño de claves, tamaño de firmas y costo computacional impulsaron el desarrollo de alternativas más eficientes.

**ECDSA** y, especialmente, **Ed25519** representan la evolución moderna de las firmas digitales: claves más pequeñas, firmas más compactas, mayor velocidad y —en el caso de Ed25519— una implementación intrínsecamente más segura gracias a la firma determinista. Ambos algoritmos son la base de tecnologías críticas como HTTPS, SSH y blockchain, lo que demuestra su relevancia más allá del contexto académico.

Este proyecto no es solo un laboratorio abstracto sobre texto plano. Representa un caso de uso real: la emisión y validación criptográfica de documentos PDF institucionales, con protección de las claves privadas mediante Java KeyStore PKCS12 (RFC 7292), el mismo estándar que usan navegadores, OpenSSL y sistemas operativos modernos. Permite observar de forma directa cómo una firma digital protege la integridad de un certificado, cómo una modificación mínima lo invalida, y cómo difieren en comportamiento los dos algoritmos modernos más relevantes.

La evolución desde RSA hacia ECDSA y Ed25519 no es solo un dato técnico. Con este sistema, es algo que se puede ver, medir y comprobar.
