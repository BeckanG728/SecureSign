# SecureSign

Backend REST para la generación y verificación de firmas digitales y certificados institucionales en PDF. Desarrollado
con Spring Boot 4 y Java 17, orientado a un curso universitario de criptografía.

---

## Tecnologías

| Tecnología             | Versión           |
|------------------------|-------------------|
| Java                   | 17                |
| Spring Boot            | 4.0.6             |
| Apache PDFBox          | 3.0.1             |
| Spring Security Crypto | (BOM Spring Boot) |
| Maven                  | Wrapper incluido  |

---

## Estructura del proyecto

```
src/main/java/es/faustino/securesign/
├── SecureSignApplication.java
├── config/
│   └── WebConfig.java
├── controller/
│   ├── SignatureController.java
│   └── CertificateController.java
├── service/
│   ├── SignatureService.java
│   └── CertificateService.java
├── model/
│   ├── SignRequest.java
│   ├── SignResponse.java
│   ├── VerifyRequest.java
│   ├── KeyInfoResponse.java
│   └── CertificateRequest.java
└── exception/
    ├── GlobalExceptionHandler.java
    └── KeyNotFoundException.java
```

---

## Ejecución

```bash
./mvnw spring-boot:run       # Linux / macOS
mvnw.cmd spring-boot:run     # Windows
```

El servidor escucha en `http://localhost:8080`.

---

## API Reference

### Claves y firma (`/api`)

#### Generar par de claves

```
POST /api/keys/generate?algorithm={algorithm}
```

`algorithm`: `Ed25519` o `ECDSA`.

```json
{ "keyId": "uuid-generado", "algorithm": "Ed25519" }
```

#### Obtener clave pública

```
GET /api/keys/{keyId}
```

```json
{ "keyId": "...", "algorithm": "Ed25519", "publicKey": "<base64>" }
```

#### Firmar datos

```
POST /api/sign
{ "keyId": "...", "algorithm": "Ed25519", "data": "<base64>" }
```

```json
{ "keyId": "...", "algorithm": "Ed25519", "signature": "<base64>" }
```

#### Verificar firma

```
POST /api/verify
{ "keyId": "...", "algorithm": "Ed25519", "data": "<base64>", "signature": "<base64>" }
```

```json
{ "valid": true }
```

### Certificados PDF (`/api/certificates`)

#### Generar certificado firmado

```
POST /api/certificates/generate
{ "nombre": "Juan Pérez", "dni": "12345678A", "tipo": "Asistencia", "fecha": "2026-05-30", "algorithm": "Ed25519" }
```

Respuesta: binario PDF (`application/pdf`). Headers: `X-Key-Id`, `X-Algorithm`.

#### Verificar certificado PDF

```
POST /api/certificates/verify?keyId={keyId}&algorithm={algorithm}
Content-Type: multipart/form-data   →   file: <PDF>
```

```json
{ "valid": true, "keyId": "...", "algorithm": "..." }
```

---

## Explicación del código

### Flujo general

El proyecto sigue una arquitectura en capas estándar de Spring Boot:

```
HTTP Request → Controller → Service → (JCA / PDFBox) → Response
```

Los controladores solo traducen HTTP a llamadas de servicio. Toda la lógica criptográfica vive en los servicios.

---

### `SignatureService` — núcleo criptográfico

Es el componente más importante del proyecto. Gestiona el ciclo de vida completo de las claves y las operaciones
criptográficas usando la **Java Cryptography Architecture (JCA)**.

#### Almacén de claves en memoria

```java
private final Map<String, KeyPairEntry> keyStore = new ConcurrentHashMap<>();

private record KeyPairEntry(KeyPair keyPair, String algorithm) {}
```

Cada par de claves generado se guarda en un `ConcurrentHashMap` indexado por un UUID (`keyId`). Se usa
`ConcurrentHashMap` para garantizar seguridad ante accesos concurrentes. El `record` interno `KeyPairEntry` agrupa el
`KeyPair` con el algoritmo que le corresponde, evitando que se intente verificar con un algoritmo distinto al que se usó
para firmar.

> **Limitación importante:** este almacén es volátil. Si el servidor se reinicia, todos los `keyId` dejan de existir y
> los certificados emitidos no podrán verificarse.

#### Generación de claves

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance(
    normalizedAlgorithm.equals(ED25519) ? "Ed25519" : "EC"
);

if (!normalizedAlgorithm.equals(ED25519)) {
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
}
```

Para **Ed25519** se instancia el generador directamente con ese nombre (la curva ya está fija en el estándar). Para *
*ECDSA** se usa el generador `"EC"` y se especifica explícitamente la curva `secp256r1` (también conocida como P-256),
que es la curva estándar de 256 bits del NIST.

#### Firma y verificación

```java
// Firma
Signature sig = Signature.getInstance(signatureAlgorithm(normalizeAlgorithm(algorithm)));
sig.initSign(entry.keyPair().getPrivate());
sig.update(data);
return sig.sign();

// Verificación
sig.initVerify(entry.keyPair().getPublic());
sig.update(data);
return sig.verify(firma);
```

El algoritmo de firma que se pasa a la JCA depende del tipo de clave:

| Clave   | Algoritmo JCA       |
|---------|---------------------|
| Ed25519 | `"Ed25519"`         |
| ECDSA   | `"SHA256withECDSA"` |

Para ECDSA el algoritmo incluye el hash (`SHA-256`) porque ECDSA solo firma hashes, no datos crudos. Ed25519 hace el
hash internamente, por eso no se especifica.

#### Normalización de algoritmos

```java
return switch (algorithm.toUpperCase()) {
    case "ED25519"       -> ED25519;
    case "ECDSA", "EC"   -> ECDSA;
    default -> throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm);
};
```

Permite que el cliente envíe `"Ed25519"`, `"ED25519"`, `"ECDSA"` o `"EC"` indistintamente, evitando errores por
capitalización.

---

### `CertificateService` — emisión y verificación de certificados

Orquesta la generación de un PDF institucional y su firma digital.

#### Emisión

```java
byte[] pdfBytes = generarCertificadoPDF(nombre, dni, tipo, fecha);

String keyId = signatureService.generateKeyPair(algorithm);
byte[] firma = signatureService.sign(keyId, algorithm, pdfBytes);

signatureStore.put(keyId, firma);
```

El flujo es:

1. Generar el PDF con PDFBox.
2. Generar un par de claves nuevo (exclusivo para este certificado).
3. Firmar los bytes del PDF con la clave privada.
4. Guardar la firma en `signatureStore` asociada al `keyId`.
5. Devolver el PDF al cliente junto con el `keyId` en el header `X-Key-Id`.

Cada certificado tiene su propio par de claves, lo que significa que un `keyId` identifica de forma única tanto la clave
como el certificado que firmó.

#### Verificación

```java
byte[] firmaOriginal = signatureStore.get(keyId);
if (firmaOriginal == null) return false;
return signatureService.verify(keyId, algorithm, pdfBytes, firmaOriginal);
```

Se recupera la firma original del `signatureStore` y se verifica contra los bytes del PDF recibido. Si el PDF fue
modificado después de emitirse, los bytes serán distintos y la verificación fallará.

#### Generación del PDF con PDFBox

```java
PDDocument document = new PDDocument();
PDPage page = new PDPage(PDRectangle.A4);
document.addPage(page);

try (PDPageContentStream content = new PDPageContentStream(document, page)) {
    content.beginText();
    content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
    content.newLineAtOffset(100, 750);
    content.showText("CERTIFICADO INSTITUCIONAL");
    // ...
}
```

PDFBox trabaja con un sistema de coordenadas donde el origen `(0, 0)` está en la esquina inferior izquierda de la
página. El título se posiciona a `(100, 750)` en una página A4 que mide 595 × 842 puntos. Los campos del certificado se
van desplazando con `newLineAtOffset(0, -25)` para espaciarlos verticalmente.

---

### `WebConfig` — CORS

```java
registry.addMapping("/api/**")
    .allowedOrigins("http://localhost:5173", "http://localhost:5500", "http://127.0.0.1:5500")
    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
    .allowedHeaders("*")
    .exposedHeaders("X-Key-Id", "X-Algorithm");
```

La línea `.exposedHeaders(...)` es crítica: por defecto los navegadores no permiten que el JavaScript del frontend lea
headers personalizados de la respuesta a menos que el servidor los exponga explícitamente. Sin esta línea el frontend no
podría leer el `X-Key-Id` del certificado generado.

---

### Manejo de errores — `GlobalExceptionHandler`

```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(KeyNotFoundException.class)
    public ResponseEntity<Map<String, String>> handleKeyNotFound(KeyNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(...);
    }
}
```

`@RestControllerAdvice` intercepta excepciones lanzadas desde cualquier controlador y las convierte en respuestas JSON
estructuradas con el código HTTP adecuado, en lugar de devolver el stacktrace por defecto de Spring.
`KeyNotFoundException` se lanza desde `SignatureService` cuando se consulta un `keyId` inexistente y se mapea a
`404 Not Found`.

---

### Modelos — Records de Java

Todos los DTOs del proyecto usan `record` de Java 16+:

```java
public record SignRequest(String keyId, String algorithm, String data) {}
```

Los records son clases inmutables que generan automáticamente constructor, getters, `equals`, `hashCode` y `toString`.
Son ideales para objetos de transferencia de datos donde no se necesita mutabilidad. Spring los deserializa desde JSON
sin configuración adicional.

---

## Algoritmos soportados

| Nombre en la API | Algoritmo JCA     | Hash              |
|------------------|-------------------|-------------------|
| `Ed25519`        | `Ed25519`         | Interno (SHA-512) |
| `ECDSA` / `EC`   | `SHA256withECDSA` | SHA-256 externo   |

---

## Consideraciones

- Las claves y firmas se almacenan **solo en memoria**. No persisten entre reinicios.
- La firma del certificado PDF no se embebe en la estructura interna del PDF; se almacena en el servidor asociada al
  `keyId`. Si el servidor se reinicia, los certificados emitidos no pueden verificarse.
- Para un entorno de producción sería necesario persistir el `keyStore` y el `signatureStore` en base de datos o HSM.
