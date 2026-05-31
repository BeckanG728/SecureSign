package es.faustino.securesign.dto.request;

public record DocumentRequest(
        String nombre,
        String dni,
        String tipo,
        String fecha,
        String algorithm
) {
}
