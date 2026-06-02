package es.faustino.securesign.model;

public record SignResponse(
        String keyId,
        String algorithm,
        String dataHash,    // SHA-256 del texto original, en hex
        String signature    // Firma sobre el hash, en Base64
) {
}
