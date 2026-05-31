package es.faustino.securesign.dto.response;

import java.time.Instant;

/**
 * Resultado detallado de una verificación PAdES.
 *
 * <h2>Mapa completo de estados posibles</h2>
 * <pre>
 * ┌─────────────────────────────┬────────────────┬───────────┬──────────────┬──────────────┬───────────┬──────────────┐
 * │ Estado                      │firmaExtraible  │byteRange  │cmsParseable  │certExtraible │firmaValida│ valid        │
 * ├─────────────────────────────┼────────────────┼───────────┼──────────────┼──────────────┼───────────┼──────────────┤
 * │ SIN_FIRMA                   │ false          │ false     │ false        │ false        │ false     │ false        │
 * │ PDF_CORRUPTO                │ false          │ false     │ false        │ false        │ false     │ false        │
 * │ BYTERANGE_INVALIDO          │ true           │ false     │ false        │ false        │ false     │ false        │
 * │ CMS_CORRUPTO                │ true           │ true      │ false        │ false        │ false     │ false        │
 * │ CMS_SIN_CERTIFICADO         │ true           │ true      │ true         │ false        │ false     │ false        │
 * │ FIRMA_INVALIDA (doc modif.) │ true           │ true      │ true         │ true         │ false     │ false        │
 * │ CERT_EXPIRADO               │ true           │ true      │ true         │ true         │ true      │ false        │
 * │ VALIDO                      │ true           │ true      │ true         │ true         │ true      │ true         │
 * └─────────────────────────────┴────────────────┴───────────┴──────────────┴──────────────┴───────────┴──────────────┘
 * </pre>
 *
 * <h2>Estados críticos a distinguir</h2>
 * <p><b>FIRMA_INVALIDA</b> — comportamiento CORRECTO cuando el usuario modifica el PDF.
 * La estructura PAdES sobrevive: ByteRange coherente, CMS parseable, certificado extraíble.
 * Solo falla el hash. Adobe sigue mostrando el certificado con "firma inválida".</p>
 *
 * <p><b>CMS_CORRUPTO / PDF_CORRUPTO</b> — nunca debe ocurrir desde el backend.
 * Indica que el motor de firma destruyó la estructura interna del PDF.</p>
 *
 * <p><b>CMS_SIN_CERTIFICADO</b> — el CMS es parseable pero incompleto.
 * No es "sin firma" ni "corrupto" — es un estado estructural diferente.</p>
 */
public record VerificationResultResponse(

        // ── Veredicto final ──────────────────────────────────────────────────
        boolean valid,

        // ── Integridad estructural PAdES (capas acumulativas) ────────────────
        /** El diccionario /Sig fue encontrado y el bloque /Contents extraído del PDF */
        boolean firmaExtraible,

        /** Los 4 valores del /ByteRange son coherentes con el tamaño real del PDF */
        boolean byteRangeValido,

        /** El bloque /Contents fue parseado como CMS ASN.1 sin errores */
        boolean cmsParseable,

        /** Se encontró y decodificó al menos un certificado X.509 dentro del CMS */
        boolean certificadoExtraible,

        // ── Resultado criptográfico ───────────────────────────────────────────
        /** La firma criptográfica coincide con el hash del contenido firmado */
        boolean firmaValida,

        /** El certificado no había expirado en el momento de la verificación */
        boolean certificadoVigente,

        // ── Datos del certificado X.509 ───────────────────────────────────────
        // Presentes siempre que certificadoExtraible=true, independientemente
        // de si la firma es válida o no. Un PDF modificado post-firma sigue
        // teniendo un certificado íntegro y extraíble dentro del CMS.
        String subject,
        Instant validoDesde,
        Instant validoHasta,

        /**
         * Algoritmo de firma reportado por el SignerInfo del CMS.
         * Refleja el algoritmo real usado para firmar el documento
         * (distinto de {@code cert.getSigAlgName()} que devuelve
         * el algoritmo del certificado X.509, no necesariamente el mismo).
         */
        String algoritmoFirma,

        // ── Diagnóstico ───────────────────────────────────────────────────────
        String razon

) {}
