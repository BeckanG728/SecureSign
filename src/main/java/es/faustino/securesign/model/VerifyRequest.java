package es.faustino.securesign.model;

public record VerifyRequest(
        String keyId,
        String algorithm,
        String data,
        String signature
) {
}
