package es.faustino.securesign.model;

public record DocumentRequest(
        String nombre,
        String dni,
        String tipo,
        String fecha,
        String algorithm
) {
}
