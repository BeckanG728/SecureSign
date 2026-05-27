package es.faustino.securesign.model;

public record SignResponse(
        String keyId,
        String algorithm,
        String signature
) {
}
