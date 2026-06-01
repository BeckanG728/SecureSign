package es.faustino.securesign.shared.util;

import es.faustino.securesign.dto.internal.ResultadoExtraccion;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class ByteRangeExtractor {

    private static final Logger log = LoggerFactory.getLogger(ByteRangeExtractor.class);

    public static ResultadoExtraccion extraer(byte[] bytesPdf) throws Exception {
        long[] byteRange = leerByteRangeDelPdf(bytesPdf);
        long offsetSegmento1 = byteRange[0];
        long longitudSegmento1 = byteRange[1];
        long offsetSegmento2 = byteRange[2];
        long longitudSegmento2 = byteRange[3];

        log.info("[EXTRACCION] ByteRange: [{}, {}, {}, {}] | PDF: {} bytes",
                offsetSegmento1, longitudSegmento1, offsetSegmento2, longitudSegmento2, bytesPdf.length);

        boolean byteRangeValido = validarByteRange(offsetSegmento1, longitudSegmento1, offsetSegmento2, longitudSegmento2, bytesPdf.length);

        verificarLimitesDeSegmentos(bytesPdf, offsetSegmento1, longitudSegmento1, offsetSegmento2, longitudSegmento2);
        verificarTamanosDentroDeRango(longitudSegmento1, longitudSegmento2, offsetSegmento2);

        byte[] pdfRecortadoAlTamanoOriginal = recortarPdfAlTamanoOriginal(bytesPdf, offsetSegmento2, longitudSegmento2);

        byte[] bytesPdfCubiertos = ensamblarContenidoFirmado(pdfRecortadoAlTamanoOriginal, offsetSegmento1, longitudSegmento1, offsetSegmento2, longitudSegmento2);
        log.info("[EXTRACCION] Bytes PDF cubiertos ensamblados: {} bytes (segmento1={} + segmento2={})",
                bytesPdfCubiertos.length, longitudSegmento1, longitudSegmento2);

        // Se usa el PDF original (no el recortado) para extraer el bloque CMS,
        // ya que PDFBox puede no reconocer la firma si el PDF tiene bytes extra al final
        // y el recorte elimina parte de la estructura que PDFBox necesita para indexar /Sig.
        byte[] bytesCMS = extraerBloqueCmsDer(bytesPdf);
        log.info("[EXTRACCION] Bloque CMS DER extraido: {} bytes", bytesCMS.length);

        return new ResultadoExtraccion(offsetSegmento1, longitudSegmento1, offsetSegmento2, longitudSegmento2, bytesPdfCubiertos, bytesCMS, byteRangeValido);
    }

    private static long[] leerByteRangeDelPdf(byte[] bytesPdf) throws Exception {
        try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
            List<PDSignature> firmas = documento.getSignatureDictionaries();
            if (firmas == null || firmas.isEmpty()) {
                throw new PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
            }
            int[] byteRangeRaw = firmas.get(0).getByteRange();
            return new long[]{
                    Integer.toUnsignedLong(byteRangeRaw[0]),
                    Integer.toUnsignedLong(byteRangeRaw[1]),
                    Integer.toUnsignedLong(byteRangeRaw[2]),
                    Integer.toUnsignedLong(byteRangeRaw[3])
            };
        }
    }

    private static byte[] recortarPdfAlTamanoOriginal(byte[] bytesPdf, long offsetSegmento2, long longitudSegmento2) {
        int tamanoOriginal = (int) (offsetSegmento2 + longitudSegmento2);
        return (bytesPdf.length == tamanoOriginal)
                ? bytesPdf
                : Arrays.copyOf(bytesPdf, tamanoOriginal);
    }

    private static byte[] ensamblarContenidoFirmado(byte[] bytesPdf,
                                                    long offsetSegmento1, long longitudSegmento1,
                                                    long offsetSegmento2, long longitudSegmento2) {
        byte[] bytesPdfCubiertos = new byte[(int) (longitudSegmento1 + longitudSegmento2)];
        ByteBuffer ensamblador = ByteBuffer.wrap(bytesPdfCubiertos);
        ensamblador.put(bytesPdf, (int) offsetSegmento1, (int) longitudSegmento1);
        ensamblador.put(bytesPdf, (int) offsetSegmento2, (int) longitudSegmento2);
        return bytesPdfCubiertos;
    }

    private static byte[] extraerBloqueCmsDer(byte[] bytesPdf) throws Exception {
        try (PDDocument documento = Loader.loadPDF(bytesPdf)) {
            PDSignature firma = documento.getSignatureDictionaries().get(0);
            COSString bloqueContents = (COSString) firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
            if (bloqueContents == null) {
                throw new IllegalStateException("El diccionario /Sig no contiene la clave /Contents");
            }
            return bloqueContents.getBytes();
        }
    }

    private static boolean validarByteRange(long offsetSegmento1, long longitudSegmento1,
                                            long offsetSegmento2, long longitudSegmento2,
                                            long longitudTotalPdf) {
        if (offsetSegmento1 != 0) {
            log.warn("[VALIDACION] offsetSegmento1={} debe ser 0 en PAdES", offsetSegmento1);
            return false;
        }
        if (longitudSegmento1 <= 0) {
            log.warn("[VALIDACION] longitudSegmento1={} es 0 o negativo", longitudSegmento1);
            return false;
        }
        if (offsetSegmento2 <= longitudSegmento1) {
            log.warn("[VALIDACION] offsetSegmento2={} <= longitudSegmento1={} — los segmentos se solapan", offsetSegmento2, longitudSegmento1);
            return false;
        }
        if (longitudSegmento2 <= 0) {
            log.warn("[VALIDACION] longitudSegmento2={} es 0 o negativo", longitudSegmento2);
            return false;
        }
        long finDelPdf = offsetSegmento2 + longitudSegmento2;
        if (finDelPdf != longitudTotalPdf) {
            log.warn("[VALIDACION] fin calculado={} != longitudTotalPdf={} — desalineacion de {} bytes",
                    finDelPdf, longitudTotalPdf, finDelPdf - longitudTotalPdf);
            return false;
        }
        return true;
    }

    private static void verificarLimitesDeSegmentos(byte[] bytesPdf,
                                                    long offsetSegmento1, long longitudSegmento1,
                                                    long offsetSegmento2, long longitudSegmento2) {
        verificarTramo(offsetSegmento1, longitudSegmento1, bytesPdf.length, "segmento1");
        verificarTramo(offsetSegmento2, longitudSegmento2, bytesPdf.length, "segmento2");
    }

    private static void verificarTramo(long offset, long longitud, long longitudPdf, String nombreTramo) {
        if (offset < 0 || longitud < 0 || offset + longitud > longitudPdf) {
            throw new IllegalStateException(
                    "ByteRange " + nombreTramo + " [" + offset + ", " + (offset + longitud) + ")" +
                    " excede el tamaño del PDF (" + longitudPdf + " bytes)"
            );
        }
    }

    private static void verificarTamanosDentroDeRango(long longitudSegmento1, long longitudSegmento2, long offsetSegmento2) {
        verificarTamanoDentroDeRango(longitudSegmento1, "longitudSegmento1");
        verificarTamanoDentroDeRango(longitudSegmento2, "longitudSegmento2");
        verificarTamanoDentroDeRango(longitudSegmento1 + longitudSegmento2, "longitudSegmento1 + longitudSegmento2");
        verificarTamanoDentroDeRango(offsetSegmento2 + longitudSegmento2, "offsetSegmento2 + longitudSegmento2");
    }

    private static void verificarTamanoDentroDeRango(long valor, String nombreValor) {
        if (valor < 0 || valor > Integer.MAX_VALUE) {
            throw new IllegalStateException(
                    "ByteRange " + nombreValor + "=" + valor + " excede Integer.MAX_VALUE"
            );
        }
    }

    public static class PdfNoFirmadoException extends Exception {
        public PdfNoFirmadoException(String mensaje) {
            super(mensaje);
        }
    }
}
