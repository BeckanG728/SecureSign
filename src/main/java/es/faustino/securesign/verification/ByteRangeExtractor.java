package es.faustino.securesign.verification;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

/**
 * Extrae el ByteRange y el bloque /Contents de un PDF firmado usando PDFBox 3.x.
 *
 * <h2>Responsabilidad única</h2>
 * <p>Esta clase solo hace parsing estructural PDF. No hace criptografía.
 * Toda la lógica CMS/ASN.1/X.509 está en {@link VerificationService}.</p>
 *
 * <h2>Anatomía del ByteRange</h2>
 * <pre>
 * /ByteRange [o1  l1  o2  l2]
 *
 * pdf: [ T1 (firmado) ][ /Contents hex + padding ][ T2 (firmado) ]
 *        0 ──── l1-1    l1 ─────────────── o2-1    o2 ─── o2+l2-1
 *
 * Hash = SHA256( pdf[0..l1-1] || pdf[o2..o2+l2-1] )
 *                   T1                  T2
 * </pre>
 *
 * <h2>Problema 2 — int vs long para offsets</h2>
 * <p>{@code PDSignature.getByteRange()} devuelve {@code int[4]}.
 * Esto es una limitación de la API de PDFBox (el PDF spec permite offsets hasta 2^31-1
 * en práctica, aunque teóricamente pueden ser mayores en PDF 1.5+ con xref streams).
 * Para PDFs educativos esto no es un problema real, pero el código usa {@code long}
 * en el record y hace las comprobaciones de overflow antes de los arraycopy.</p>
 *
 * <p>El verdadero riesgo con {@code int} es el cast silencioso {@code (int) longValue}
 * cuando {@code longValue > Integer.MAX_VALUE} (~2 GB). Para PDFs de firma
 * institucionales (< 50 MB en la práctica) esto no ocurre, pero el código
 * lo valida explícitamente en lugar de silenciarlo.</p>
 */
public class ByteRangeExtractor {

    private static final Logger log = LoggerFactory.getLogger(ByteRangeExtractor.class);

    /**
     * Resultado inmutable de la extracción.
     *
     * <p>Los offsets usan {@code long} aunque PDFBox devuelva {@code int[]}.
     * El método {@link #extraer} convierte a {@code long} inmediatamente
     * para que los comparadores de validación trabajen sin riesgo de overflow.</p>
     */
    public record ResultadoExtraccion(
            long offset1, long length1,
            long offset2, long length2,
            byte[] contenidoFirmado,
            byte[] cmsDerBytes,
            boolean byteRangeValido
    ) {
    }

    /**
     * Extrae el ByteRange y el CMS del primer campo de firma del PDF.
     *
     * <p>Usa {@code Loader.loadPDF(byte[])} de PDFBox 3.x.
     * En PDFBox 2.x era {@code PDDocument.load(InputStream)} — ese método
     * no existe en 3.x.</p>
     *
     * <p>{@code firma.getContents(pdf)} devuelve los bytes DER del /Contents
     * (decodificados desde hex, con el padding de ceros de DSS incluido).
     * El padding es inofensivo para {@code ASN1InputStream} que se detiene
     * en el primer objeto ASN.1 completo.</p>
     *
     * @throws PdfNoFirmadoException si el PDF no contiene campos /Sig
     * @throws IOException           si el PDF no puede ser parseado
     */
    public static ResultadoExtraccion extraer(byte[] pdf) throws Exception {

        // ── Pasada 1: leer ByteRange ────────────────────────────────────────
        // PDFBox puede parsear el xref aunque el PDF tenga bytes extra al final.
        final long o1, l1, o2, l2;
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            if (sigs == null || sigs.isEmpty()) {
                throw new PdfNoFirmadoException("El PDF no contiene ningún campo de firma (/Sig)");
            }
            int[] raw = sigs.get(0).getByteRange();
            o1 = Integer.toUnsignedLong(raw[0]);
            l1 = Integer.toUnsignedLong(raw[1]);
            o2 = Integer.toUnsignedLong(raw[2]);
            l2 = Integer.toUnsignedLong(raw[3]);
        }

        log.info("[EXTRACT] ByteRange: [{}, {}, {}, {}] | PDF: {} bytes", o1, l1, o2, l2, pdf.length);
        boolean valido = validarByteRange(o1, l1, o2, l2, pdf.length);

        // ── Validaciones de rango ────────────────────────────────────────────
        assertDentroDelArray(o1, l1, pdf.length, "T1");
        assertDentroDelArray(o2, l2, pdf.length, "T2");
        assertCabEnInt(l1,      "l1");
        assertCabEnInt(l2,      "l2");
        assertCabEnInt(l1 + l2, "l1+l2");
        assertCabEnInt(o2 + l2, "o2+l2");

        // ── Truncar al tamaño original firmado ───────────────────────────────
        // Cuando hay bytes extra al final (PDF modificado post-firma), truncamos
        // a o2+l2 para que PDFBox vea el PDF tal como fue firmado.
        int pdfOriginalLen = (int) (o2 + l2);
        byte[] pdfParaParseo = (pdf.length == pdfOriginalLen)
                ? pdf
                : Arrays.copyOf(pdf, pdfOriginalLen);

        // ── Extraer contenido firmado T1 + T2 ──────────────────────────────
        byte[] contenidoFirmado = new byte[(int) (l1 + l2)];
        ByteBuffer buf = ByteBuffer.wrap(contenidoFirmado);
        buf.put(pdfParaParseo, (int) o1, (int) l1);
        buf.put(pdfParaParseo, (int) o2, (int) l2);
        log.info("[EXTRACT] Contenido firmado: {} bytes (T1={} + T2={})", contenidoFirmado.length, l1, l2);

        // ── Extraer CMS DER desde el diccionario COS ────────────────────────
        // PDSignature.getContents(byte[]) está roto en PDFBox 3.x para PDFs con
        // object streams: escanea el byte[] buscando el hexstring por posición
        // absoluta con heurísticas que fallan con cualquier variación del tamaño.
        //
        // La alternativa correcta: acceder al COSString del /Contents directamente
        // desde el diccionario COS parseado. PDFBox ya descomprimió el object stream
        // durante el parseo — el COSString tiene los bytes DER en memoria,
        // sin necesidad de releer ni redecodificar el array raw.
        final byte[] cmsDerBytes;
        try (PDDocument doc = Loader.loadPDF(pdfParaParseo)) {
            PDSignature firma = doc.getSignatureDictionaries().get(0);
            COSString cosContents = (COSString) firma.getCOSObject().getDictionaryObject(COSName.CONTENTS);
            if (cosContents == null) {
                throw new IllegalStateException("El diccionario /Sig no contiene la clave /Contents");
            }
            cmsDerBytes = cosContents.getBytes();
        }
        log.info("[EXTRACT] CMS DER: {} bytes", cmsDerBytes.length);

        return new ResultadoExtraccion(o1, l1, o2, l2, contenidoFirmado, cmsDerBytes, valido);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Valida coherencia estructural del ByteRange contra el tamaño real del PDF.
     *
     * <h3>Condiciones de validez</h3>
     * <ul>
     *   <li>{@code o1 == 0} — PAdES siempre cubre desde el byte 0</li>
     *   <li>{@code l1 > 0} — el tramo 1 tiene contenido</li>
     *   <li>{@code o2 > l1} — el tramo 2 empieza después del tramo 1
     *       (hay espacio para el /Contents entre ellos)</li>
     *   <li>{@code o2 + l2 == pdfLength} — el PDF termina exactamente
     *       donde dice el ByteRange; si no, hay truncación o bytes extra</li>
     * </ul>
     *
     * <h3>Por qué o2 + l2 debe ser exactamente pdfLength</h3>
     * <p>DSS genera el PDF firmado añadiendo un único incremento al final.
     * El ByteRange cubre exactamente hasta el último byte de ese incremento.
     * Si el PDF tiene bytes extra al final (ej. por una re-serialización posterior),
     * {@code o2 + l2 < pdfLength} — señal de modificación post-firma.</p>
     */
    private static boolean validarByteRange(long o1, long l1, long o2, long l2, long pdfLength) {
        if (o1 != 0) {
            log.warn("[VALIDATE] o1={} debe ser 0 en PAdES", o1);
            return false;
        }
        if (l1 <= 0) {
            log.warn("[VALIDATE] l1={} es 0 o negativo — tramo 1 vacío", l1);
            return false;
        }
        if (o2 <= l1) {
            log.warn("[VALIDATE] o2={} <= l1={} — tramos solapados o /Contents vacío", o2, l1);
            return false;
        }
        if (l2 <= 0) {
            log.warn("[VALIDATE] l2={} es 0 o negativo — tramo 2 vacío", l2);
            return false;
        }
        long fin = o2 + l2;
        if (fin != pdfLength) {
            log.warn("[VALIDATE] o2+l2={} != pdfLength={} — desalineación de {} bytes",
                    fin, pdfLength, fin - pdfLength);
            return false;
        }
        log.debug("[VALIDATE] ByteRange válido — /Contents={} bytes entre offsets {} y {}",
                o2 - l1, l1, o2);
        return true;
    }

    /**
     * Lanza excepción si {@code value} no cabe en un {@code int} sin pérdida de signo.
     */
    private static void assertCabEnInt(long value, String nombre) {
        if (value < 0 || value > Integer.MAX_VALUE) {
            throw new IllegalStateException(
                    "ByteRange " + nombre + "=" + value +
                    " excede Integer.MAX_VALUE — PDF demasiado grande para arraycopy en int"
            );
        }
    }

    /**
     * Lanza excepción si el tramo [offset, offset+length) excede el array.
     * Protege contra PDFs truncados donde el ByteRange apunta fuera del array.
     */
    private static void assertDentroDelArray(long offset, long length, long arrayLen, String tramo) {
        if (offset < 0 || length < 0 || offset + length > arrayLen) {
            throw new IllegalStateException(
                    "ByteRange tramo " + tramo + " [" + offset + ", " + (offset + length) + ")" +
                    " excede el tamaño del PDF (" + arrayLen + " bytes) — PDF truncado o corrupto"
            );
        }
    }

    /**
     * Extrae y decodifica el bloque /Contents del PDF sin usar PDFBox.
     *
     * <p>El /Contents en un PDF firmado PAdES es un string hex delimitado por
     * {@code <} y {@code >} ubicado entre los offsets {@code l1} y {@code o2}.
     * PDFBox busca ese bloque usando los offsets del ByteRange, pero falla si
     * el PDF tiene bytes extra al final (el scanner se desorienta).
     * Este método lee directamente los bytes entre {@code l1} y {@code o2},
     * localiza el {@code <...>} y decodifica el hex — independientemente del
     * tamaño total del PDF.</p>
     *
     * @param pdf  bytes completos del PDF (potencialmente con bytes extra al final)
     * @param l1   offset de fin de T1 = inicio del bloque /Contents
     * @param o2   offset de inicio de T2 = fin del bloque /Contents
     * @return bytes DER del CMS (con padding de ceros al final, ignorado por ASN1InputStream)
     */
    /**
     * PDF sin campos de firma
     */
    public static class PdfNoFirmadoException extends Exception {
        public PdfNoFirmadoException(String msg) {
            super(msg);
        }
    }
}
