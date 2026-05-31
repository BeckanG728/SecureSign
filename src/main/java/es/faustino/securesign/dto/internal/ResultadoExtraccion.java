package es.faustino.securesign.dto.internal;

public record ResultadoExtraccion(
        long offsetTramo1, long longitudTramo1,
        long offsetTramo2, long longitudTramo2,
        byte[] contenidoFirmado,
        byte[] cmsDerBytes,
        boolean byteRangeValido
) {
}