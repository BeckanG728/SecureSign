package es.faustino.securesign.dto.response;

import java.time.Instant;

public record VerificationResultResponse(

        boolean valido,

        boolean firmaExtraible,
        boolean estructuraValida,
        boolean cmsParseable,
        boolean certificadoExtraible,

        boolean firmaValida,
        boolean certificadoVigente,

        String subject,
        Instant validoDesde,
        Instant validoHasta,
        String algoritmoFirma,

        String razon

) {
    public static VerificationResultResponse sinFirma(String razon) {
        return new VerificationResultResponse(
                false,
                false, false, false, false,
                false, false,
                null, null, null, null,
                razon);
    }

    public static VerificationResultResponse cmsCorrupto(boolean estructuraValida, String razon) {
        return new VerificationResultResponse(
                false,
                true, estructuraValida, false, false,
                false, false,
                null, null, null, null,
                razon);
    }

    public static VerificationResultResponse sinCertificado(boolean estructuraValida, String razon) {
        return new VerificationResultResponse(
                false,
                true, estructuraValida, true, false,
                false, false,
                null, null, null, null,
                razon);
    }

    public static VerificationResultResponse sinFirmante(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String razon) {
        return new VerificationResultResponse(
                false,
                true, estructuraValida, true, true,
                false, certVigente,
                subject, validoDesde, validoHasta, null,
                razon);
    }

    public static VerificationResultResponse errorVerificacion(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo, String razon) {
        return new VerificationResultResponse(
                false,
                true, estructuraValida, true, true,
                false, certVigente,
                subject, validoDesde, validoHasta, algoritmo,
                razon);
    }

    public static VerificationResultResponse firmaInvalida(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo) {
        return new VerificationResultResponse(
                false,
                true, estructuraValida, true, true,
                false, certVigente,
                subject, validoDesde, validoHasta, algoritmo,
                "El documento fue modificado después de ser firmado");
    }

    public static VerificationResultResponse firmaVerificada(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo) {
        String razon = certVigente ? null : "El certificado ha expirado (válido hasta: " + validoHasta + ")";
        return new VerificationResultResponse(
                certVigente,
                true, estructuraValida, true, true,
                true, certVigente,
                subject, validoDesde, validoHasta, algoritmo,
                razon);
    }
}
