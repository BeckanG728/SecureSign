# SecureSign — Guía de Implementación
### Sistema de Emisión y Validación Criptográfica de Certificados PDF

> **Objetivo:** Implementar un sistema educativo para emitir y validar certificados PDF firmados digitalmente usando algoritmos modernos: ECDSA y Ed25519. El sistema simula una entidad institucional que genera documentos como antecedentes penales, constancias académicas y certificados laborales, demostrando integridad documental, autenticación y no repudio de forma práctica.

---

## 1. Introducción conceptual

### ¿Qué garantiza una firma digital sobre un PDF?

Una firma digital aplicada a un documento PDF garantiza tres propiedades fundamentales:

- **Integridad:** el documento no fue modificado desde que fue firmado.
- **Autenticación:** fue emitido por quien dice haberlo emitido.
- **No repudio:** el emisor no puede negar haber firmado el documento.

A diferencia de firmar texto plano, en este sistema la firma se aplica directamente sobre los **bytes completos del documento PDF**. Cualquier modificación posterior al PDF —aunque sea de un solo byte— invalida la firma por completo.

### Flujo criptográfico sobre PDF

```
Documento PDF (bytes completos)
          ↓
      SHA-256  (hash del contenido exacto)
          ↓
Firma con clave privada (ECDSA o Ed25519)
          ↓
   Firma digital  (bytes que acompañan al documento)
          ↓
Verificación con clave pública  → ✅ válida / ❌ inválida
```

El hash SHA-256 actúa como huella digital del documento. Si el PDF se modifica —incluso cambiando un solo carácter invisible— el hash resultante será completamente diferente y la verificación fallará. Esto es lo que hace posible la detección de alteraciones.

ECDSA y Ed25519 siguen este mismo flujo, pero difieren en cómo realizan internamente la operación de firma.

---

## 2. Contexto histórico

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

## 3. Algoritmos implementados

### 3.1 ECDSA (P-256)

Basado en curvas elípticas tradicionales. Es ampliamente usado en TLS, certificados web y protocolos de red.

**Característica clave:** la firma requiere un número aleatorio por cada operación. Si ese número se repite o es predecible, la clave privada queda expuesta.

**Implementación en Java:**

```java
// Generación de claves
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair keyPair = kpg.generateKeyPair();

// Firma sobre bytes del PDF
byte[] pdfBytes = Files.readAllBytes(path);
Signature sig = Signature.getInstance("SHA256withECDSA");
sig.initSign(keyPair.getPrivate());
sig.update(pdfBytes);
byte[] firma = sig.sign();
```

---

### 3.2 Ed25519

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

## 4. Comparación educativa

| Característica       | RSA-2048 *(referencia histórica)* | ECDSA (P-256) | Ed25519       |
|----------------------|-----------------------------------|---------------|---------------|
| Tamaño de clave      | 2048 bits                         | 256 bits      | 256 bits      |
| Tamaño de firma      | 256 bytes                         | ~72 bytes     | 64 bytes      |
| Velocidad relativa   | Lenta                             | Rápida        | Muy rápida    |
| Firma determinista   | No                                | No            | Sí            |
| Uso moderno          | Legacy                            | TLS, Web PKI  | SSH, Blockchain |

> RSA aparece aquí solo como punto de comparación histórica. Este proyecto no lo implementa.

---

## 5. Arquitectura del proyecto

### Tecnologías utilizadas

| Capa         | Tecnología                               |
|--------------|------------------------------------------|
| Backend      | Java 17, Spring Boot                     |
| Criptografía | `java.security` (ECDSA, Ed25519)         |
| Generación PDF | Apache PDFBox o iText                  |
| Frontend     | HTML + CSS + JavaScript (vanilla)        |
| API          | REST / JSON + multipart para archivos    |

### Flujo general

```
Cliente (frontend)
       ↓  envía formulario (nombre, DNI, tipo, fecha, algoritmo)
   Backend (Java)
       ↓  genera documento PDF institucional
       ↓  calcula hash SHA-256 de los bytes del PDF
       ↓  firma los bytes con clave privada (ECDSA o Ed25519)
       ↓  almacena: PDF + firma + algoritmo + keyId
       ↓  devuelve PDF al cliente para descarga
   Cliente
       ↓  descarga el certificado PDF
       ↓  puede subir el PDF posteriormente para verificarlo
   Backend
       ↓  recibe el PDF subido
       ↓  recalcula hash de los bytes recibidos
       ↓  verifica firma con la clave pública asociada al keyId
       ↓  responde: válida / inválida
```

### Principio de seguridad central

> **La clave privada nunca sale del backend.**
> El cliente solo recibe el PDF generado y un identificador temporal (`keyId`) que permite referenciar el par de claves en el servidor para verificaciones posteriores.

Esto se apoya en las bibliotecas estándar de Java (`java.security`) sin implementar criptografía manualmente.

---

## 6. Generación de certificados PDF

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

## 7. Implementación del backend

### 7.1 Configuración del proyecto

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

### 7.2 Estructura de paquetes recomendada

```
src/main/java/com/securesign/
├── controller/
│   └── CertificateController.java   ← endpoints REST
├── service/
│   ├── CertificateService.java      ← generación de PDF y coordinación
│   └── SignatureService.java        ← lógica de firma y verificación
├── model/
│   ├── CertificateRequest.java
│   └── CertificateRecord.java       ← almacena PDF + firma + keyId
└── SecureSignApplication.java
```

### 7.3 Servicio de criptografía

El servicio centraliza la generación de claves, la firma y la verificación sobre bytes de PDF. Las claves se almacenan en memoria asociadas a un `keyId` único.

```java
@Service
public class SignatureService {

    private final Map<String, KeyPair> keyStore = new ConcurrentHashMap<>();

    public String generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "EC"
        );
        if (!algorithm.equals("Ed25519")) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        String keyId = UUID.randomUUID().toString();
        keyStore.put(keyId, kpg.generateKeyPair());
        return keyId;
    }

    public byte[] sign(String keyId, String algorithm, byte[] pdfBytes) throws Exception {
        KeyPair keyPair = keyStore.get(keyId);
        Signature sig = Signature.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA"
        );
        sig.initSign(keyPair.getPrivate());
        sig.update(pdfBytes);
        return sig.sign();
    }

    public boolean verify(String keyId, String algorithm, byte[] pdfBytes, byte[] firma) throws Exception {
        KeyPair keyPair = keyStore.get(keyId);
        Signature sig = Signature.getInstance(
            algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA"
        );
        sig.initVerify(keyPair.getPublic());
        sig.update(pdfBytes);
        return sig.verify(firma);
    }
}
```

### 7.4 Servicio de certificados

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

        // 2. Generar par de claves y firmar
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
        // (ver sección 6 para implementación completa)
        // ...
    }
}
```

### 7.5 Controlador REST

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

## 8. Endpoints de la API

| Método | Ruta                           | Descripción                                      |
|--------|--------------------------------|--------------------------------------------------|
| POST   | `/api/certificates/generate`   | Genera PDF, lo firma y devuelve el archivo       |
| POST   | `/api/certificates/verify`     | Verifica integridad y autenticidad de un PDF     |

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

## 9. Implementación del frontend

El frontend es un único archivo HTML autocontenido (`index.html`) sin dependencias externas ni framework. Incluye CSS embebido y JavaScript vanilla.

### 9.1 Estructura de archivos

```
securesign-frontend/
└── index.html    ← aplicación completa (HTML + CSS + JS)
```

### 9.2 Estructura HTML

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

### 9.3 CSS: variables y layout

Todo el sistema visual se gestiona con variables CSS. El layout principal usa `grid-template-columns: 1fr 1fr`:

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

### 9.4 Selector de algoritmo

El selector es par de botones `<button>` con clase `.algo-btn`. Al hacer clic se activa la clase `.active` sobre el seleccionado y se actualiza la variable `selectedAlgo`:

```javascript
let selectedAlgo = 'ECDSA';

function selectAlgo(algo) {
  selectedAlgo = algo;
  document.getElementById('btn-ecdsa').classList.toggle('active',    algo === 'ECDSA');
  document.getElementById('btn-ed25519').classList.toggle('active',  algo === 'Ed25519');
}
```

### 9.5 Emisión de certificado

Recoge los valores del formulario, valida que estén completos y hace `fetch` con `Content-Type: application/json`. La respuesta es el PDF binario (`res.blob()`) con los headers `X-Key-Id` y `X-Algorithm`. Al recibir la respuesta, autocompleta el panel de verificación con el Key ID y algoritmo usados.

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

  // Guardar para descarga
  lastEmission = { keyId, algorithm: algo, pdfBlob, nombre };

  // Autocompletar verificación
  document.getElementById('ver-keyid').value = keyId;
  document.getElementById('ver-algo').value  = algo;
}
```

### 9.6 Descarga del PDF

Usa `URL.createObjectURL` para generar una URL temporal del blob y simula un clic sobre un `<a>` dinámico:

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

### 9.7 Drop zone para verificación

La zona de arrastre combina un `<input type="file">` invisible posicionado en absolute sobre un `<div>` estilizado. Responde a los eventos `dragover`, `dragleave` y `drop` del div, además del `change` del input:

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

### 9.8 Verificación del certificado

Envía el PDF como `multipart/form-data` junto al Key ID y algoritmo. Muestra el resultado con estilo visual diferenciado según `data.valid`:

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

### 9.9 Flujo de uso en el sistema

1. El usuario completa el formulario: nombre, DNI, tipo de certificado, fecha.
2. Selecciona el algoritmo de firma (ECDSA o Ed25519).
3. Hace clic en **"Emitir certificado"** → el backend genera el PDF, lo firma y lo devuelve.
4. El usuario descarga el PDF firmado; el Key ID y algoritmo se autocompletan en el panel de verificación.
5. En el módulo de verificación, el usuario sube el PDF (clic o drag & drop).
6. El sistema responde si la firma es válida o si el documento fue alterado.

---

## 10. Evaluación comparativa

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

Una diferencia observable entre los dos algoritmos:

- **Ed25519** produce siempre la misma firma para el mismo documento y la misma clave privada. Firmar el PDF dos veces genera bytes idénticos.
- **ECDSA** produce una firma diferente en cada ejecución, incluso para el mismo documento, debido al número aleatorio interno.

Esto es visible directamente en el frontend al comparar las firmas generadas en distintas emisiones.

---

## 11. Escenarios de demostración

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

---

## 12. Seguridad

### La clave privada nunca sale del backend

El principio central del sistema es que la clave privada nunca es transmitida al cliente ni almacenada fuera del servidor. El cliente únicamente recibe:

- El PDF firmado para su descarga.
- Un `keyId` que actúa como referencia temporal al par de claves en el servidor.

Esto es importante porque la exposición de la clave privada comprometería completamente el sistema: cualquiera que la posea podría emitir documentos fraudulentos que pasen la verificación. Mantenerla exclusivamente en el backend elimina esa superficie de ataque.

La implementación se apoya en `java.security`, sin criptografía manual. Implementar criptografía desde cero introduce riesgos significativos; usar las bibliotecas estándar del lenguaje es la práctica recomendada.

---

## 13. Alcance del proyecto

Este sistema es un laboratorio educativo. No implementa:

- **PKI real** (infraestructura de clave pública).
- **Certificados X.509** ni cadenas de confianza.
- **Autoridades certificadoras** (CA).

El objetivo es estrictamente educativo y se centra en:

- Demostrar cómo funcionan las firmas digitales modernas sobre documentos reales.
- Comparar ECDSA y Ed25519 de forma práctica y observable.
- Ilustrar los principios de integridad documental y no repudio.

Para un sistema de producción real se requeriría una arquitectura PKI completa, almacenamiento persistente de claves (HSM o similar), y cumplimiento de estándares como eIDAS o PAdES para firmas PDF.

---

## 14. Pasos para ejecutar el proyecto

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

## 15. Conclusión

RSA fue un pilar histórico de la criptografía, pero sus limitaciones en tamaño de claves, tamaño de firmas y costo computacional impulsaron el desarrollo de alternativas más eficientes.

**ECDSA** y, especialmente, **Ed25519** representan la evolución moderna de las firmas digitales: claves más pequeñas, firmas más compactas, mayor velocidad y —en el caso de Ed25519— una implementación intrínsecamente más segura gracias a la firma determinista.

Este proyecto ya no es solo un laboratorio abstracto sobre texto plano. Representa un caso de uso real: la emisión y validación criptográfica de documentos PDF institucionales. Permite observar de forma directa cómo una firma digital protege la integridad de un certificado, cómo una modificación mínima lo invalida, y cómo difieren en comportamiento los dos algoritmos modernos más relevantes.

La evolución desde RSA hacia ECDSA y Ed25519 no es solo un dato técnico. Con este sistema, es algo que se puede ver, medir y comprobar.
