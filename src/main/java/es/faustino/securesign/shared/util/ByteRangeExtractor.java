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
        long offsetTramo1 = byteRange[0];
        long longitudTramo1 = byteRange[1];
        long offsetTramo2 = byteRange[2];
        long longitudTramo2 = byteRange[3];

        log.info("[EXTRACCION] ByteRange: [{}, {}, {}, {}] | PDF: {} bytes",
                offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2, bytesPdf.length);

        boolean byteRangeValido = validarByteRange(offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2, bytesPdf.length);

        verificarQueLosTramosNoCaenFueraDelPdf(bytesPdf, offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2);
        verificarQueLosValoresCabenEnUnEntero(longitudTramo1, longitudTramo2, offsetTramo2);

        byte[] pdfRecortadoAlTamanoOriginal = recortarPdfAlTamanoOriginal(bytesPdf, offsetTramo2, longitudTramo2);

        byte[] contenidoFirmado = ensamblarContenidoFirmado(pdfRecortadoAlTamanoOriginal, offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2);
        log.info("[EXTRACCION] Contenido firmado ensamblado: {} bytes (tramo1={} + tramo2={})",
                contenidoFirmado.length, longitudTramo1, longitudTramo2);

        byte[] cmsDerBytes = extraerBloqueCmsDer(pdfRecortadoAlTamanoOriginal);
        log.info("[EXTRACCION] Bloque CMS DER extraido: {} bytes", cmsDerBytes.length);

        return new ResultadoExtraccion(offsetTramo1, longitudTramo1, offsetTramo2, longitudTramo2, contenidoFirmado, cmsDerBytes, byteRangeValido);
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

    private static byte[] recortarPdfAlTamanoOriginal(byte[] bytesPdf, long offsetTramo2, long longitudTramo2) {
        int tamanoOriginal = (int) (offsetTramo2 + longitudTramo2);
        return (bytesPdf.length == tamanoOriginal)
                ? bytesPdf
                : Arrays.copyOf(bytesPdf, tamanoOriginal);
    }

    private static byte[] ensamblarContenidoFirmado(byte[] bytesPdf,
                                                    long offsetTramo1, long longitudTramo1,
                                                    long offsetTramo2, long longitudTramo2) {
        byte[] contenidoFirmado = new byte[(int) (longitudTramo1 + longitudTramo2)];
        ByteBuffer ensamblador = ByteBuffer.wrap(contenidoFirmado);
        ensamblador.put(bytesPdf, (int) offsetTramo1, (int) longitudTramo1);
        ensamblador.put(bytesPdf, (int) offsetTramo2, (int) longitudTramo2);
        return contenidoFirmado;
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

    private static boolean validarByteRange(long offsetTramo1, long longitudTramo1,
                                            long offsetTramo2, long longitudTramo2,
                                            long longitudTotalPdf) {
        if (offsetTramo1 != 0) {
            log.warn("[VALIDACION] offsetTramo1={} debe ser 0 en PAdES", offsetTramo1);
            return false;
        }
        if (longitudTramo1 <= 0) {
            log.warn("[VALIDACION] longitudTramo1={} es 0 o negativo", longitudTramo1);
            return false;
        }
        if (offsetTramo2 <= longitudTramo1) {
            log.warn("[VALIDACION] offsetTramo2={} <= longitudTramo1={} — los tramos se solapan", offsetTramo2, longitudTramo1);
            return false;
        }
        if (longitudTramo2 <= 0) {
            log.warn("[VALIDACION] longitudTramo2={} es 0 o negativo", longitudTramo2);
            return false;
        }
        long finDelPdf = offsetTramo2 + longitudTramo2;
        if (finDelPdf != longitudTotalPdf) {
            log.warn("[VALIDACION] fin calculado={} != longitudTotalPdf={} — desalineacion de {} bytes",
                    finDelPdf, longitudTotalPdf, finDelPdf - longitudTotalPdf);
            return false;
        }
        return true;
    }

    private static void verificarQueLosTramosNoCaenFueraDelPdf(byte[] bytesPdf,
                                                               long offsetTramo1, long longitudTramo1,
                                                               long offsetTramo2, long longitudTramo2) {
        verificarTramo(offsetTramo1, longitudTramo1, bytesPdf.length, "tramo1");
        verificarTramo(offsetTramo2, longitudTramo2, bytesPdf.length, "tramo2");
    }

    private static void verificarTramo(long offset, long longitud, long longitudPdf, String nombreTramo) {
        if (offset < 0 || longitud < 0 || offset + longitud > longitudPdf) {
            throw new IllegalStateException(
                    "ByteRange " + nombreTramo + " [" + offset + ", " + (offset + longitud) + ")" +
                    " excede el tamaño del PDF (" + longitudPdf + " bytes)"
            );
        }
    }

    private static void verificarQueLosValoresCabenEnUnEntero(long longitudTramo1, long longitudTramo2, long offsetTramo2) {
        verificarQueElValorCabeEnUnEntero(longitudTramo1, "longitudTramo1");
        verificarQueElValorCabeEnUnEntero(longitudTramo2, "longitudTramo2");
        verificarQueElValorCabeEnUnEntero(longitudTramo1 + longitudTramo2, "longitudTramo1 + longitudTramo2");
        verificarQueElValorCabeEnUnEntero(offsetTramo2 + longitudTramo2, "offsetTramo2 + longitudTramo2");
    }

    private static void verificarQueElValorCabeEnUnEntero(long valor, String nombreValor) {
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
