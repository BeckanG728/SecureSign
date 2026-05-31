package es.faustino.securesign.dto.response;

import java.time.Instant;

public record VerificationResultResponse(

        boolean valid,

        boolean firmaExtraible,
        boolean byteRangeValido,
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
                razon
        );
    }
}
