package es.faustino.securesign.service;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CertificateService {

    private final SignatureService signatureService;

    // keyId → firma original del PDF emitido
    private final Map<String, byte[]> signatureStore = new ConcurrentHashMap<>();

    public CertificateService(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    // ── Emisión ───────────────────────────────────────────────────────────────

    public Map<String, Object> emitirCertificado(String nombre, String dni,
                                                 String tipo, String fecha,
                                                 String algorithm) throws Exception {
        byte[] pdfBytes = generarCertificadoPDF(nombre, dni, tipo, fecha);

        String keyId = signatureService.generateKeyPair(algorithm);
        byte[] firma = signatureService.sign(keyId, algorithm, pdfBytes);

        signatureStore.put(keyId, firma);

        return Map.of(
                "keyId", keyId,
                "algorithm", algorithm,
                "pdf", pdfBytes,
                "signatureB64", java.util.Base64.getEncoder().encodeToString(firma)
        );
    }

    // ── Verificación ──────────────────────────────────────────────────────────

    public boolean verificarCertificado(String keyId, String algorithm,
                                        byte[] pdfBytes) throws Exception {
        byte[] firmaOriginal = signatureStore.get(keyId);
        if (firmaOriginal == null) return false;
        return signatureService.verify(keyId, algorithm, pdfBytes, firmaOriginal);
    }

    // ── Generación PDF ────────────────────────────────────────────────────────

    private byte[] generarCertificadoPDF(String nombre, String dni,
                                         String tipo, String fecha) throws IOException {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            try (PDPageContentStream content = new PDPageContentStream(document, page)) {
                // Título
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
                content.newLineAtOffset(100, 750);
                content.showText("CERTIFICADO INSTITUCIONAL");

                // Datos
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
