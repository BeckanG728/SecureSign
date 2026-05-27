package es.faustino.securesign.model;

public record KeyInfoResponse(
        String keyId,
        String algorithm,
        String publicKey
) {
}
