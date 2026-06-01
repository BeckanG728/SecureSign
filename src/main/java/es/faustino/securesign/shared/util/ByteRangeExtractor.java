package es.faustino.securesign.shared.util;

import es.faustino.securesign.dto.internal.ResultadoExtraccion;
import eu.europa.esig.dss.pades.validation.ByteRange;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ByteRangeExtractor {

    private static final Logger log = LoggerFactory.getLogger(ByteRangeExtractor.class);

    public static ResultadoExtraccion extraer(byte[] bytesPdf) throws Exception {
        try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
            PDSignature firma = obtenerPrimeraFirma(documento);

            ByteRange byteRange = new ByteRange(firma.getByteRange());
            log.info("[EXTRACCION] ByteRange: {} | PDF: {} bytes", byteRange, bytesPdf.length);

            boolean byteRangeValido = validarByteRange(byteRange, bytesPdf.length);

            byte[] bytesPdfCubiertos = ensamblarContenidoFirmado(bytesPdf, byteRange);
            log.info("[EXTRACCION] Bytes PDF cubiertos ensamblados: {} bytes (segmento1={} + segmento2={})",
                    bytesPdfCubiertos.length, byteRange.getFirstPartEnd(), byteRange.getSecondPartEnd());

            byte[] bytesCMS = extraerBloqueCmsDer(firma);
            log.info("[EXTRACCION] Bloque CMS DER extraido: {} bytes", bytesCMS.length);

            return new ResultadoExtraccion(
                    byteRange.getFirstPartStart(), byteRange.getFirstPartEnd(),
                    byteRange.getSecondPartStart(), byteRange.getSecondPartEnd(),
                    bytesPdfCubiertos, bytesCMS, byteRangeValido
            );
        }
    }

    private static PDSignature obtenerPrimeraFirma(PDDocument documento) throws Exception {
        List<PDSignature> firmas = documento.getSignatureDictionaries();
        if (firmas == null || firmas.isEmpty()) {
            throw new PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
        }
        return firmas.get(0);
    }

    private static byte[] extraerBloqueCmsDer(PDSignature firma) {
        COSString bloqueContents = (COSString) firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
        if (bloqueContents == null) {
            throw new IllegalStateException("El diccionario /Sig no contiene la clave /Contents");
        }
        return bloqueContents.getBytes();
    }

    private static byte[] ensamblarContenidoFirmado(byte[] bytesPdf, ByteRange byteRange) {
        int offset1 = byteRange.getFirstPartStart();
        int longitud1 = byteRange.getFirstPartEnd();
        int offset2 = byteRange.getSecondPartStart();
        int longitud2 = byteRange.getSecondPartEnd();

        int disponible1 = Math.min(longitud1, bytesPdf.length - offset1);
        int disponible2 = Math.min(longitud2, bytesPdf.length - offset2);

        byte[] bytesPdfCubiertos = new byte[disponible1 + disponible2];
        System.arraycopy(bytesPdf, offset1, bytesPdfCubiertos, 0, disponible1);
        System.arraycopy(bytesPdf, offset2, bytesPdfCubiertos, disponible1, disponible2);
        return bytesPdfCubiertos;
    }

    private static boolean validarByteRange(ByteRange byteRange, long longitudTotalPdf) {
        try {
            byteRange.validate();
        } catch (Exception e) {
            log.warn("[VALIDACION] ByteRange inválido según DSS: {}", e.getMessage());
            byteRange.setValid(false);
            return false;
        }

        long finDelPdf = byteRange.getSecondPartStart() + (long) byteRange.getSecondPartEnd();
        boolean cubreTotalPdf = finDelPdf == longitudTotalPdf;
        if (!cubreTotalPdf) {
            log.warn("[VALIDACION] ByteRange no cubre el PDF completo: fin calculado={} != longitudTotalPdf={} (desalineacion={} bytes)",
                    finDelPdf, longitudTotalPdf, finDelPdf - longitudTotalPdf);
        }

        byteRange.setValid(cubreTotalPdf);
        return cubreTotalPdf;
    }

    public static class PdfNoFirmadoException extends Exception {
        public PdfNoFirmadoException(String mensaje) {
            super(mensaje);
        }
    }
}
