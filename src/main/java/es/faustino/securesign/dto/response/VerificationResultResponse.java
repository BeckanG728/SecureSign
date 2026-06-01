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
        return builder().razon(razon).build();
    }

    public static VerificationResultResponse cmsCorrupto(boolean estructuraValida, String razon) {
        return builder()
                .firmaExtraible(true)
                .estructuraValida(estructuraValida)
                .razon(razon)
                .build();
    }

    public static VerificationResultResponse sinCertificado(boolean estructuraValida, String razon) {
        return builder()
                .firmaExtraible(true)
                .estructuraValida(estructuraValida)
                .cmsParseable(true)
                .razon(razon)
                .build();
    }

    public static VerificationResultResponse sinFirmante(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String razon) {
        return builder()
                .firmaExtraible(true).estructuraValida(estructuraValida).cmsParseable(true)
                .certificadoExtraible(true)
                .certificadoVigente(certVigente)
                .subject(subject).validoDesde(validoDesde).validoHasta(validoHasta)
                .razon(razon)
                .build();
    }

    public static VerificationResultResponse errorVerificacion(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo, String razon) {
        return builder()
                .firmaExtraible(true).estructuraValida(estructuraValida).cmsParseable(true)
                .certificadoExtraible(true)
                .certificadoVigente(certVigente)
                .subject(subject).validoDesde(validoDesde).validoHasta(validoHasta).algoritmoFirma(algoritmo)
                .razon(razon)
                .build();
    }

    public static VerificationResultResponse firmaInvalida(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo) {
        return builder()
                .firmaExtraible(true).estructuraValida(estructuraValida).cmsParseable(true)
                .certificadoExtraible(true)
                .certificadoVigente(certVigente)
                .subject(subject).validoDesde(validoDesde).validoHasta(validoHasta).algoritmoFirma(algoritmo)
                .razon("El documento fue modificado después de ser firmado")
                .build();
    }

    public static VerificationResultResponse firmaVerificada(
            boolean estructuraValida, boolean certVigente,
            String subject, Instant validoDesde, Instant validoHasta,
            String algoritmo) {
        String razon = certVigente ? null : "El certificado ha expirado (válido hasta: " + validoHasta + ")";
        return builder()
                .valido(certVigente)
                .firmaExtraible(true).estructuraValida(estructuraValida).cmsParseable(true)
                .certificadoExtraible(true)
                .firmaValida(true).certificadoVigente(certVigente)
                .subject(subject).validoDesde(validoDesde).validoHasta(validoHasta).algoritmoFirma(algoritmo)
                .razon(razon)
                .build();
    }

    private static Builder builder() {
        return new Builder();
    }

    private static final class Builder {
        private boolean valido;
        private boolean firmaExtraible;
        private boolean estructuraValida;
        private boolean cmsParseable;
        private boolean certificadoExtraible;
        private boolean firmaValida;
        private boolean certificadoVigente;
        private String subject;
        private Instant validoDesde;
        private Instant validoHasta;
        private String algoritmoFirma;
        private String razon;

        Builder valido(boolean v) {
            this.valido = v;
            return this;
        }

        Builder firmaExtraible(boolean v) {
            this.firmaExtraible = v;
            return this;
        }

        Builder estructuraValida(boolean v) {
            this.estructuraValida = v;
            return this;
        }

        Builder cmsParseable(boolean v) {
            this.cmsParseable = v;
            return this;
        }

        Builder certificadoExtraible(boolean v) {
            this.certificadoExtraible = v;
            return this;
        }

        Builder firmaValida(boolean v) {
            this.firmaValida = v;
            return this;
        }

        Builder certificadoVigente(boolean v) {
            this.certificadoVigente = v;
            return this;
        }

        Builder subject(String v) {
            this.subject = v;
            return this;
        }

        Builder validoDesde(Instant v) {
            this.validoDesde = v;
            return this;
        }

        Builder validoHasta(Instant v) {
            this.validoHasta = v;
            return this;
        }

        Builder algoritmoFirma(String v) {
            this.algoritmoFirma = v;
            return this;
        }

        Builder razon(String v) {
            this.razon = v;
            return this;
        }

        VerificationResultResponse build() {
            return new VerificationResultResponse(
                    valido,
                    firmaExtraible, estructuraValida, cmsParseable, certificadoExtraible,
                    firmaValida, certificadoVigente,
                    subject, validoDesde, validoHasta, algoritmoFirma,
                    razon
            );
        }
    }
}
