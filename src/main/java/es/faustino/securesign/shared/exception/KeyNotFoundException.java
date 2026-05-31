package es.faustino.securesign.shared.exception;

public class KeyNotFoundException extends RuntimeException {
    public KeyNotFoundException(String keyId) {
        super("No se encontró ningún par de claves con id: " + keyId);
    }
}
