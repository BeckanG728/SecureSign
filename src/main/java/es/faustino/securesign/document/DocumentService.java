package es.faustino.securesign.document;

import es.faustino.securesign.signature.SignatureService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Coordina el flujo completo de emisión de documentos PDF firmados (PAdES).
 *
 * <h2>Flujo obligatorio (no modificar el orden)</h2>
 * <pre>
 * 1. generarDocumentoPDF()  → PDFBox 3.x genera el PDF limpio
 *                              document.save() → ByteArrayOutputStream
 *                              document.close() → CIERRE COMPLETO
 *                              ↓
 * 2. signatureService.firmarPDF()
 *    → DSS abre el PDF como InMemoryDocument (stream read-only)
 *    → DSS calcula ByteRange y reserva espacio para /Contents
 *    → DSS serializa el incremento (saveIncremental) con xref correcto
 *    → DSS cierra el documento interno
 *    → Devuelve byte[] del PDF firmado
 *                              ↓
 * 3. Return byte[] al controller
 *    → NO volver a abrir, modificar ni re-serializar el PDF
 * </pre>
 *
 * <h2>Por qué se cierra PDFBox ANTES de firmar</h2>
 * PDFBox 3.x tiene estado interno (COSDocument, xref table, stream positions).
 * Si el PDDocument no está completamente cerrado cuando DSS lo lee, puede haber
 * referencias pendientes en el stream de output que modifiquen los offsets
 * DESPUÉS de que DSS haya calculado el ByteRange. Resultado: "ByteRange invalid".
 *
 * <h2>Por qué NO se usa PDFBox para firmar</h2>
 * PDFBox.PDDocument.saveIncremental() con PDSignature tiene una limitación:
 * no puede garantizar el espacio exacto del bloque /Contents antes de serializar
 * el CMS real. DSS resuelve esto con un proceso en dos fases:
 * fase 1 → reserva espacio estimado, fase 2 → escribe el CMS real en ese espacio.
 */
@Service
public class DocumentService {

    private final SignatureService signatureService;

    public DocumentService(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    /**
     * Flujo completo de emisión.
     *
     * @param nombre    nombre del destinatario
     * @param dni       documento de identidad
     * @param tipo      tipo de documento institucional
     * @param fecha     fecha de emisión
     * @param algorithm "ECDSA" o "Ed25519"
     * @return bytes del PDF firmado con PAdES-BASELINE-B, autocontenible
     */
    public byte[] emitirDocumentoFirmado(String nombre, String dni,
                                         String tipo, String fecha,
                                         String algorithm) throws Exception {

        // Paso 1: Generar PDF limpio con PDFBox 3.x
        // El documento se cierra completamente dentro de generarDocumentoPDF()
        byte[] pdfBytes = generarDocumentoPDF(nombre, dni, tipo, fecha);

        // Paso 2: Generar KeyPair + certificado X.509 → almacenar en PKCS12
        String keyId = signatureService.generateKeyPairWithCertificate(algorithm);

        // Paso 3: Cargar claves desde KeyStore
        PrivateKey privateKey = signatureService.getPrivateKey(keyId);
        X509Certificate cert = signatureService.getCertificate(keyId);

        // Paso 4: Firmar con DSS (abre y cierra su propio stream interno)
        // Después de este punto el PDF NO debe ser modificado
        return signatureService.firmarPDF(pdfBytes, privateKey, cert, algorithm);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Generación del PDF con PDFBox 3.x
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Genera el PDF institucional.
     *
     * <p><b>IMPORTANTE:</b> el {@code try-with-resources} garantiza que
     * {@code document.close()} se llama ANTES de devolver los bytes.
     * Esto es obligatorio para que PDFBox 3.x termine de escribir todos
     * los objetos pendientes (xref, trailer) en el output stream.</p>
     *
     * <p>No usar {@code Standard14Fonts.FontName} con PDFBox 2.x —
     * esa API es exclusiva de PDFBox 3.x.</p>
     */
    private byte[] generarDocumentoPDF(String nombre, String dni,
                                       String tipo, String fecha) throws IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // try-with-resources → document.close() garantizado al salir del bloque
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            // PDFBox 3.x: constructor de PDType1Font cambia a Standard14Fonts.FontName
            try (PDPageContentStream content = new PDPageContentStream(document, page)) {

                // Encabezado institucional
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
                content.newLineAtOffset(80, 760);
                content.showText("DOCUMENTO INSTITUCIONAL");
                content.endText();

                // Línea separadora
                content.setLineWidth(1.5f);
                content.moveTo(80, 750);
                content.lineTo(515, 750);
                content.stroke();

                // Cuerpo del documento
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
                content.newLineAtOffset(80, 720);
                content.showText("Tipo de documento:");
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                content.newLineAtOffset(160, 0);
                content.showText(tipo);
                content.endText();

                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
                content.newLineAtOffset(80, 695);
                content.showText("Nombre:");
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                content.newLineAtOffset(160, 0);
                content.showText(nombre);
                content.endText();

                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
                content.newLineAtOffset(80, 670);
                content.showText("DNI / ID:");
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                content.newLineAtOffset(160, 0);
                content.showText(dni);
                content.endText();

                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
                content.newLineAtOffset(80, 645);
                content.showText("Fecha de emision:");
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                content.newLineAtOffset(160, 0);
                content.showText(fecha);
                content.endText();

                // Pie de página
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_OBLIQUE), 9);
                content.newLineAtOffset(80, 60);
                content.showText("Documento generado y firmado electronicamente con PAdES-BASELINE-B (DSS/EU)");
                content.endText();
            }

            // document.close() se llama aquí — garantiza xref completo en 'out'
            document.save(out);
        }
        // En este punto el ByteArrayOutputStream contiene un PDF 100% válido y cerrado

        return out.toByteArray();
    }
}
