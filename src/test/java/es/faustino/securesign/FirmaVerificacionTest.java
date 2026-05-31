package es.faustino.securesign;

import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.services.certificate.CertificateX509Service;
import es.faustino.securesign.services.document.DocumentService;
import es.faustino.securesign.services.signature.SignatureService;
import es.faustino.securesign.services.verification.VerificationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test de integración PAdES — sin contexto Spring.
 *
 * <h2>Cobertura</h2>
 * <ol>
 *   <li>PDF firmado → verificación válida (Estado 0: integridad total)</li>
 *   <li>PDF modificado post-firma → Estado 1 CORRECTO (firma inválida, estructura intacta)</li>
 *   <li>PDF sin firma → detectado correctamente</li>
 *   <li>Estado 1 vs Estado 2: verificar que los flags los diferencian</li>
 * </ol>
 *
 * <h2>Diferencia crítica que este test valida</h2>
 * <pre>
 * Estado 1 (firma inválida — CORRECTO):
 *   firmaExtraible=true, cmsParseable=true, certificadoExtraible=true,
 *   byteRangeValido=true, firmaValida=false
 *
 * Estado 2 (PDF corrupto — NUNCA debe ocurrir):
 *   firmaExtraible=false, cmsParseable=false, byteRangeValido=false
 * </pre>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FirmaVerificacionTest {

    private static Path keystoreTemp;
    private static final String KEYSTORE_PASS = "test-pass-aislado-2024";

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        keystoreTemp = Files.createTempFile("securesign-test-", ".p12");
        keystoreTemp.toFile().delete();
    }

    @AfterAll
    static void teardown() throws Exception {
        if (keystoreTemp != null) Files.deleteIfExists(keystoreTemp);
    }

    private DocumentService crearDocumentService() throws Exception {
        CertificateX509Service certService = new CertificateX509Service();
        SignatureService signatureService = new SignatureService(certService);
        setField(signatureService, "keystorePath", keystoreTemp.toString());
        setField(signatureService, "keystorePassword", KEYSTORE_PASS);
        return new DocumentService(signatureService);
    }

    private void setField(Object target, String fieldName, String value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 1: PDF firmado → válido
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(1)
    @DisplayName("✅ Estado 0: PDF firmado → integridad total")
    void pdfFirmadoEsValido() throws Exception {
        byte[] pdfFirmado = crearDocumentService().emitirDocumentoFirmado(
                "Juan Perez", "12345678", "Constancia", LocalDate.now().toString(), "EC"
        );

        assertNotNull(pdfFirmado, "El PDF firmado no debe ser null");
        assertTrue(pdfFirmado.length > 5000, "El PDF firmado debe tener tamaño razonable");

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfFirmado);
        imprimirResultado("✅ PDF VÁLIDO", r);

        // Integridad estructural
        assertTrue(r.firmaExtraible(), "Estado 0: el bloque /Contents debe ser extraíble");
        assertTrue(r.cmsParseable(), "Estado 0: el CMS debe ser parseable");
        assertTrue(r.certificadoExtraible(), "Estado 0: el certificado debe ser extraíble");
        assertTrue(r.byteRangeValido(), "Estado 0: el ByteRange debe ser coherente");

        // Resultado criptográfico
        assertTrue(r.firmaValida(), "Estado 0: la firma debe ser criptográficamente válida");
        assertTrue(r.certificadoVigente(), "Estado 0: el certificado debe estar vigente");
        assertTrue(r.valid(), "Estado 0: el resultado global debe ser válido");
        assertNull(r.razon(), "Estado 0: no debe haber razón de fallo");

        // Datos del certificado
        assertNotNull(r.subject(), "El subject no debe ser null");
        assertTrue(r.subject().contains("SecureSign"), "El subject debe contener 'SecureSign'");
        assertNotNull(r.validoDesde(), "La fecha de inicio debe existir");
        assertNotNull(r.validoHasta(), "La fecha de fin debe existir");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 2: PDF modificado post-firma → Estado 1 CORRECTO
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(2)
    @DisplayName("❌ Estado 1: PDF modificado → firma inválida, estructura intacta")
    void pdfModificadoEsEstado1Correcto() throws Exception {
        byte[] pdfFirmado = crearDocumentService().emitirDocumentoFirmado(
                "Maria Garcia", "87654321", "Certificado", LocalDate.now().toString(), "EC"
        );

        // Modificar un byte en el contenido firmado (fuera del bloque /Contents)
        // Esto invalida el hash pero no destruye el CMS
        byte[] pdfModificado = modificarContenidoFirmado(pdfFirmado);

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfModificado);
        imprimirResultado("❌ PDF MODIFICADO (Estado 1)", r);

        /*
         * ESTADO 1 CORRECTO:
         * La estructura PAdES sigue intacta — el CMS sobrevivió a la modificación.
         * Solo falla la verificación criptográfica.
         * Esto es lo que debe pasar cuando un usuario modifica el PDF.
         */

        // Estructura DEBE seguir intacta
        assertTrue(r.firmaExtraible(),
                "Estado 1: la firma debe seguir siendo extraíble del PDF modificado");
        assertTrue(r.cmsParseable(),
                "Estado 1: el CMS debe seguir siendo parseable aunque el doc esté modificado");
        assertTrue(r.certificadoExtraible(),
                "Estado 1: el certificado X.509 debe seguir existiendo en el CMS");
        assertTrue(r.byteRangeValido(),
                "Estado 1: el ByteRange debe seguir siendo coherente");

        // Solo falla la criptografía
        assertFalse(r.firmaValida(),
                "Estado 1: la firma DEBE ser inválida tras la modificación");
        assertFalse(r.valid(),
                "Estado 1: el resultado global debe ser inválido");
        assertNotNull(r.razon(), "Estado 1: debe indicar el motivo del fallo");
        assertTrue(r.razon().contains("modificado"),
                "Estado 1: el mensaje debe mencionar que el documento fue modificado");

        // El certificado sigue siendo accesible (independiente de la firma)
        assertNotNull(r.subject(), "Estado 1: el subject sigue accesible");
        assertNotNull(r.algoritmoFirma(), "Estado 1: el algoritmo sigue accesible");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 3: PDF sin firma
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(3)
    @DisplayName("⚠️ PDF sin firma → detectado sin firma")
    void pdfSinFirmaEsDetectado() {
        // Un PDF mínimo válido sin firma
        byte[] pdfSinFirma = (
                "%PDF-1.4\n" +
                "1 0 obj\n<</Type /Catalog /Pages 2 0 R>>\nendobj\n" +
                "2 0 obj\n<</Type /Pages /Kids [] /Count 0>>\nendobj\n" +
                "xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n" +
                "0000000058 00000 n \n" +
                "trailer\n<</Size 3 /Root 1 0 R>>\nstartxref\n118\n%%EOF\n"
        ).getBytes();

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfSinFirma);
        imprimirResultado("⚠️ PDF SIN FIRMA", r);

        assertFalse(r.valid(), "Un PDF sin firma no debe ser válido");
        assertFalse(r.firmaExtraible(), "No hay firma que extraer");
        assertFalse(r.firmaValida(), "No hay firma válida");
        assertNotNull(r.razon(), "Debe indicar que no hay firma");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 4: Ed25519 — mismo comportamiento
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(4)
    @DisplayName("✅ Ed25519: PDF firmado → válido")
    void pdfFirmadoEd25519EsValido() throws Exception {
        byte[] pdfFirmado = crearDocumentService().emitirDocumentoFirmado(
                "Carlos Lopez", "11223344", "Diploma", LocalDate.now().toString(), "Ed25519"
        );

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfFirmado);
        imprimirResultado("✅ PDF VÁLIDO (Ed25519)", r);

        assertTrue(r.firmaValida(), "Ed25519: la firma debe ser criptográficamente válida");
        assertTrue(r.byteRangeValido(), "Ed25519: ByteRange coherente");
        assertTrue(r.cmsParseable(), "Ed25519: CMS parseable");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Utilidades de test
    // ═════════════════════════════════════════════════════════════════════════

    /**
     * Modifica un byte del contenido firmado para invalidar la firma.
     * La modificación se hace dentro del tramo 1 del ByteRange (antes de /Contents).
     */
    private byte[] modificarContenidoFirmado(byte[] pdf) {
        byte[] modificado = pdf.clone();
        // Cambiar un byte en la zona del encabezado del PDF (siempre en el tramo firmado)
        // El offset 10 es seguro: siempre está antes del primer objeto del PDF
        if (modificado.length > 20) {
            // Buscar "INSTITUCIONAL" y cambiar la 'I'
            byte[] buscar = "INSTITUCIONAL".getBytes();
            for (int i = 0; i < modificado.length - buscar.length; i++) {
                boolean encontrado = true;
                for (int j = 0; j < buscar.length; j++) {
                    if (modificado[i + j] != buscar[j]) {
                        encontrado = false;
                        break;
                    }
                }
                if (encontrado) {
                    modificado[i] = 'X'; // "XNSTITUCIONAL"
                    return modificado;
                }
            }
            // Si no se encontró la cadena, modificar un byte genérico en el encabezado
            modificado[10] ^= 0x01;
        }
        return modificado;
    }

    private void imprimirResultado(String titulo, VerificationResultResponse r) {
        System.out.println("\n=== " + titulo + " ===");
        System.out.println("  valid               : " + r.valid());
        System.out.println("  firmaExtraible      : " + r.firmaExtraible());
        System.out.println("  cmsParseable        : " + r.cmsParseable());
        System.out.println("  certificadoExtraible: " + r.certificadoExtraible());
        System.out.println("  byteRangeValido     : " + r.byteRangeValido());
        System.out.println("  firmaValida         : " + r.firmaValida());
        System.out.println("  certificadoVigente  : " + r.certificadoVigente());
        System.out.println("  subject             : " + r.subject());
        System.out.println("  algoritmo           : " + r.algoritmoFirma());
        System.out.println("  razon               : " + r.razon());
    }
}
