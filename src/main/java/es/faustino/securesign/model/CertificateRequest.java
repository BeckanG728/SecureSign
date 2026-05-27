package es.faustino.securesign.model;

public record CertificateRequest(
        String nombre,
        String dni,
        String tipo,
        String fecha,
        String algorithm
) {
}
