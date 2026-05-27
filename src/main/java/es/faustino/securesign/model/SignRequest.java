package es.faustino.securesign.model;

public record SignRequest(
        String keyId,
        String algorithm,
        String data
) {
}
