package es.faustino.securesign.dto.internal;

public record ResultadoExtraccion(
        long offsetSegmento1, long longitudSegmento1,
        long offsetSegmento2, long longitudSegmento2,
        byte[] bytesPdfCubiertos,
        byte[] bytesCMS,
        boolean estructuraValida
) {
}