package es.faustino.securesign;

import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.keys.KeyManagementService;
import es.faustino.securesign.keys.KeyStoreService;
import es.faustino.securesign.services.certificate.CertificateX509Service;
import es.faustino.securesign.services.document.DocumentService;
import es.faustino.securesign.services.signature.SignatureService;
import es.faustino.securesign.services.verification.VerificationService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test de integración PAdES — sin contexto Spring.
 *
 * <h2>Cobertura</h2>
 * <ol>
 *   <li>PDF firmado → verificación válida (Estado 0: integridad total)</li>
 *   <li>PDF modificado post-firma → Estado 1 CORRECTO (firma inválida, estructura intacta)</li>
 *   <li>PDF sin firma → detectado correctamente</li>
 *   <li>Ed25519: PDF firmado → válido</li>
 * </ol>
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
        KeyStoreService keyStoreService = new KeyStoreService(
                keystoreTemp.toString(), "PKCS12", KEYSTORE_PASS
        );
        CertificateX509Service certService = new CertificateX509Service();
        KeyManagementService keyManagementService = new KeyManagementService(keyStoreService, certService);
        SignatureService signatureService = new SignatureService(keyStoreService);
        return new DocumentService(keyManagementService, signatureService);
    }

    /**
     * Genera un PDF mínimo en memoria para usar como entrada en los tests.
     */
    private byte[] crearPdfSimple(String texto) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(80, 700);
                cs.showText(texto);
                cs.endText();
            }
            doc.save(out);
        }
        return out.toByteArray();
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 1: PDF firmado → válido
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(1)
    @DisplayName("✅ Estado 0: PDF firmado → integridad total")
    void pdfFirmadoEsValido() throws Exception {
        byte[] pdfSinFirmar = crearPdfSimple("Documento de prueba — Juan Perez 12345678");
        byte[] pdfFirmado = crearDocumentService().firmarDocumento(pdfSinFirmar, "EC");

        assertNotNull(pdfFirmado, "El PDF firmado no debe ser null");
        assertTrue(pdfFirmado.length > 5000, "El PDF firmado debe tener tamaño razonable");

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfFirmado);
        imprimirResultado("✅ PDF VÁLIDO", r);

        assertTrue(r.firmaExtraible(), "Estado 0: el bloque /Contents debe ser extraíble");
        assertTrue(r.cmsParseable(), "Estado 0: el CMS debe ser parseable");
        assertTrue(r.certificadoExtraible(), "Estado 0: el certificado debe ser extraíble");
        assertTrue(r.estructuraValida(), "Estado 0: el ByteRange debe ser coherente");
        assertTrue(r.firmaValida(), "Estado 0: la firma debe ser criptográficamente válida");
        assertTrue(r.certificadoVigente(), "Estado 0: el certificado debe estar vigente");
        assertTrue(r.valido(), "Estado 0: el resultado global debe ser válido");
        assertNull(r.razon(), "Estado 0: no debe haber razón de fallo");
        assertNotNull(r.subject(), "El subject no debe ser null");
        assertTrue(r.subject().contains("SecureSign"), "El subject debe contener 'SecureSign'");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 2: PDF modificado post-firma → Estado 1 CORRECTO
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(2)
    @DisplayName("❌ Estado 1: PDF modificado → firma inválida, estructura intacta")
    void pdfModificadoEsEstado1Correcto() throws Exception {
        byte[] pdfSinFirmar = crearPdfSimple("Documento de prueba — Maria Garcia 87654321");
        byte[] pdfFirmado = crearDocumentService().firmarDocumento(pdfSinFirmar, "EC");
        byte[] pdfModificado = modificarContenidoFirmado(pdfFirmado);

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfModificado);
        imprimirResultado("❌ PDF MODIFICADO (Estado 1)", r);

        assertTrue(r.firmaExtraible(), "Estado 1: la firma debe seguir siendo extraíble");
        assertTrue(r.cmsParseable(), "Estado 1: el CMS debe seguir siendo parseable");
        assertTrue(r.certificadoExtraible(), "Estado 1: el certificado X.509 debe seguir existiendo");
        assertTrue(r.estructuraValida(), "Estado 1: el ByteRange debe seguir siendo coherente");
        assertFalse(r.firmaValida(), "Estado 1: la firma DEBE ser inválida tras la modificación");
        assertFalse(r.valido(), "Estado 1: el resultado global debe ser inválido");
        assertNotNull(r.razon(), "Estado 1: debe indicar el motivo del fallo");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 3: PDF sin firma
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(3)
    @DisplayName("⚠️ PDF sin firma → detectado sin firma")
    void pdfSinFirmaEsDetectado() throws Exception {
        byte[] pdfSinFirma = crearPdfSimple("Documento sin firmar");

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfSinFirma);
        imprimirResultado("⚠️ PDF SIN FIRMA", r);

        assertFalse(r.valido(), "Un PDF sin firma no debe ser válido");
        assertFalse(r.firmaExtraible(), "No hay firma que extraer");
        assertFalse(r.firmaValida(), "No hay firma válida");
        assertNotNull(r.razon(), "Debe indicar que no hay firma");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Test 4: Ed25519
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    @Order(4)
    @DisplayName("✅ Ed25519: PDF firmado → válido")
    void pdfFirmadoEd25519EsValido() throws Exception {
        byte[] pdfSinFirmar = crearPdfSimple("Documento de prueba — Carlos Lopez 11223344");
        byte[] pdfFirmado = crearDocumentService().firmarDocumento(pdfSinFirmar, "Ed25519");

        VerificationResultResponse r = new VerificationService().verificarDocumentoFirmado(pdfFirmado);
        imprimirResultado("✅ PDF VÁLIDO (Ed25519)", r);

        assertTrue(r.firmaValida(), "Ed25519: la firma debe ser criptográficamente válida");
        assertTrue(r.estructuraValida(), "Ed25519: ByteRange coherente");
        assertTrue(r.cmsParseable(), "Ed25519: CMS parseable");
        assertTrue(r.valido(), "Ed25519: resultado global válido");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Utilidades
    // ═════════════════════════════════════════════════════════════════════════

    private byte[] modificarContenidoFirmado(byte[] pdf) {
        byte[] modificado = pdf.clone();
        if (modificado.length > 20) {
            modificado[10] ^= 0x01;
        }
        return modificado;
    }

    private void imprimirResultado(String titulo, VerificationResultResponse r) {
        System.out.println("\n=== " + titulo + " ===");
        System.out.println("  valido               : " + r.valido());
        System.out.println("  firmaExtraible      : " + r.firmaExtraible());
        System.out.println("  cmsParseable        : " + r.cmsParseable());
        System.out.println("  certificadoExtraible: " + r.certificadoExtraible());
        System.out.println("  estructuraValida     : " + r.estructuraValida());
        System.out.println("  firmaValida         : " + r.firmaValida());
        System.out.println("  certificadoVigente  : " + r.certificadoVigente());
        System.out.println("  subject             : " + r.subject());
        System.out.println("  algoritmo           : " + r.algoritmoFirma());
        System.out.println("  razon               : " + r.razon());
    }
}

