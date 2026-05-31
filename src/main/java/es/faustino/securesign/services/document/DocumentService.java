package es.faustino.securesign.services.document;

import es.faustino.securesign.keys.KeyManagementService;
import es.faustino.securesign.services.signature.SignatureService;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

@Service
public class DocumentService {

    private final KeyManagementService keyManagementService;
    private final SignatureService signatureService;

    public DocumentService(KeyManagementService keyManagementService,
                           SignatureService signatureService) {
        this.keyManagementService = keyManagementService;
        this.signatureService = signatureService;
    }

    public byte[] emitirDocumentoFirmado(String nombreDestinatario, String documentoIdentidad,
                                         String tipoDocumento, String fechaEmision,
                                         String algoritmo) throws Exception {

        byte[] bytesPdfSinFirmar = construirPdf(
                nombreDestinatario, documentoIdentidad,
                tipoDocumento, fechaEmision
        );

        String alias = keyManagementService.generarYAlmacenarParDeClaves(algoritmo);
        X509Certificate certificado = keyManagementService.buscarCertificadoPorAlias(alias);

        return signatureService.firmarPdf(bytesPdfSinFirmar, certificado, algoritmo);
    }

    private byte[] construirPdf(String nombreDestinatario, String documentoIdentidad,
                                String tipoDocumento, String fechaEmision) throws IOException {

        ByteArrayOutputStream flujoSalida = new ByteArrayOutputStream();

        try (PDDocument documento = new PDDocument()) {
            PDPage pagina = new PDPage(PDRectangle.A4);
            documento.addPage(pagina);

            try (PDPageContentStream contenido = new PDPageContentStream(documento, pagina)) {
                escribirEncabezado(contenido);
                escribirCuerpo(contenido, nombreDestinatario, documentoIdentidad, tipoDocumento, fechaEmision);
                escribirPiePagina(contenido);
            }

            documento.save(flujoSalida);
        }

        return flujoSalida.toByteArray();
    }

    private void escribirEncabezado(PDPageContentStream contenido) throws IOException {
        contenido.beginText();
        contenido.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 20);
        contenido.newLineAtOffset(80, 760);
        contenido.showText("DOCUMENTO INSTITUCIONAL");
        contenido.endText();

        contenido.setLineWidth(1.5f);
        contenido.moveTo(80, 750);
        contenido.lineTo(515, 750);
        contenido.stroke();
    }

    private void escribirCuerpo(PDPageContentStream contenido, String nombreDestinatario,
                                String documentoIdentidad, String tipoDocumento,
                                String fechaEmision) throws IOException {

        escribirCampoEtiquetado(contenido, "Tipo de documento:", tipoDocumento, 720);
        escribirCampoEtiquetado(contenido, "Nombre:", nombreDestinatario, 695);
        escribirCampoEtiquetado(contenido, "DNI / ID:", documentoIdentidad, 670);
        escribirCampoEtiquetado(contenido, "Fecha de emision:", fechaEmision, 645);
    }

    private void escribirCampoEtiquetado(PDPageContentStream contenido, String etiqueta,
                                         String valor, float posicionY) throws IOException {
        contenido.beginText();
        contenido.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
        contenido.newLineAtOffset(80, posicionY);
        contenido.showText(etiqueta);
        contenido.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
        contenido.newLineAtOffset(160, 0);
        contenido.showText(valor);
        contenido.endText();
    }

    private void escribirPiePagina(PDPageContentStream contenido) throws IOException {
        contenido.beginText();
        contenido.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA_OBLIQUE), 9);
        contenido.newLineAtOffset(80, 60);
        contenido.showText("Documento generado y firmado electronicamente con PAdES-BASELINE-B (DSS/EU)");
        contenido.endText();
    }
}
