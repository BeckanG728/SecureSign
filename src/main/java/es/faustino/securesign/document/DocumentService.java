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
 * Coordina el flujo completo de emisión de documentos PDF firmados (PAdES):
 * genera el PDF institucional, el KeyPair con su certificado X.509,
 * firma el PDF y embebe la firma. Devuelve un PDF autocontenible.
 */
@Service
public class DocumentService {

    private final SignatureService signatureService;

    public DocumentService(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    // ── Emisión ───────────────────────────────────────────────────────────────

    /**
     * Flujo completo:
     * 1. Generar PDF institucional
     * 2. Generar KeyPair + certificado X.509 → almacenar en PKCS12
     * 3. Firmar PDF y embeber firma + certificado en el PDF (PAdES)
     * 4. Devolver PDF autocontenible
     */
    public byte[] emitirDocumentoFirmado(String nombre, String dni,
                                         String tipo, String fecha,
                                         String algorithm) throws Exception {
        byte[] pdfBytes = generarDocumentoPDF(nombre, dni, tipo, fecha);

        String keyId = signatureService.generateKeyPairWithCertificate(algorithm);

        PrivateKey privateKey = signatureService.getPrivateKey(keyId);
        X509Certificate cert = signatureService.getCertificate(keyId);

        return signatureService.firmarPDF(pdfBytes, privateKey, cert, algorithm);
    }

    // ── Generación PDF institucional ──────────────────────────────────────────

    private byte[] generarDocumentoPDF(String nombre, String dni,
                                       String tipo, String fecha) throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            try (PDPageContentStream content = new PDPageContentStream(document, page)) {
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
                content.newLineAtOffset(100, 750);
                content.showText("DOCUMENTO INSTITUCIONAL");

                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 13);
                content.newLineAtOffset(0, -50);
                content.showText("Tipo: " + tipo);

                content.newLineAtOffset(0, -25);
                content.showText("Nombre: " + nombre);

                content.newLineAtOffset(0, -25);
                content.showText("DNI: " + dni);

                content.newLineAtOffset(0, -25);
                content.showText("Fecha de emision: " + fecha);

                content.endText();
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        }
    }
}
