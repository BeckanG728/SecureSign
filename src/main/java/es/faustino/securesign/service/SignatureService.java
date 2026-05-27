package es.faustino.securesign.service;

import es.faustino.securesign.exception.KeyNotFoundException;
import es.faustino.securesign.model.KeyInfoResponse;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SignatureService {

    private static final String ECDSA = "ECDSA";
    private static final String ED25519 = "Ed25519";

    // Almacén temporal de pares de claves (en memoria)
    private final Map<String, KeyPairEntry> keyStore = new ConcurrentHashMap<>();

    // ── Generación de claves ──────────────────────────────────────────────────

    public String generateKeyPair(String algorithm) throws Exception {
        String normalizedAlgorithm = normalizeAlgorithm(algorithm);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                normalizedAlgorithm.equals(ED25519) ? ED25519 : "EC"
        );

        if (!normalizedAlgorithm.equals(ED25519)) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }

        String keyId = UUID.randomUUID().toString();
        keyStore.put(keyId, new KeyPairEntry(kpg.generateKeyPair(), normalizedAlgorithm));
        return keyId;
    }

    // ── Firma ─────────────────────────────────────────────────────────────────

    public byte[] sign(String keyId, String algorithm, byte[] data) throws Exception {
        KeyPairEntry entry = getEntry(keyId);
        Signature sig = Signature.getInstance(signatureAlgorithm(normalizeAlgorithm(algorithm)));
        sig.initSign(entry.keyPair().getPrivate());
        sig.update(data);
        return sig.sign();
    }

    // ── Verificación ──────────────────────────────────────────────────────────

    public boolean verify(String keyId, String algorithm, byte[] data, byte[] firma) throws Exception {
        KeyPairEntry entry = getEntry(keyId);
        Signature sig = Signature.getInstance(signatureAlgorithm(normalizeAlgorithm(algorithm)));
        sig.initVerify(entry.keyPair().getPublic());
        sig.update(data);
        return sig.verify(firma);
    }

    // ── Info de clave pública ─────────────────────────────────────────────────

    public KeyInfoResponse getKeyInfo(String keyId) {
        KeyPairEntry entry = getEntry(keyId);
        String pubKeyB64 = Base64.getEncoder()
                .encodeToString(entry.keyPair().getPublic().getEncoded());
        return new KeyInfoResponse(keyId, entry.algorithm(), pubKeyB64);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private KeyPairEntry getEntry(String keyId) {
        KeyPairEntry entry = keyStore.get(keyId);
        if (entry == null) throw new KeyNotFoundException(keyId);
        return entry;
    }

    private String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("El algoritmo no puede ser nulo");
        return switch (algorithm.toUpperCase()) {
            case "ED25519" -> ED25519;
            case "ECDSA", "EC" -> ECDSA;
            default ->
                    throw new IllegalArgumentException("Algoritmo no soportado: " + algorithm + ". Use ECDSA o Ed25519");
        };
    }

    private String signatureAlgorithm(String algorithm) {
        return algorithm.equals(ED25519) ? "Ed25519" : "SHA256withECDSA";
    }

    // ── Record interno ────────────────────────────────────────────────────────

    private record KeyPairEntry(KeyPair keyPair, String algorithm) {
    }
}
