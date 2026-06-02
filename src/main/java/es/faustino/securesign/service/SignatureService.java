package es.faustino.securesign.service;

import es.faustino.securesign.exception.KeyNotFoundException;
import es.faustino.securesign.model.KeyInfoResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.math.BigInteger;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private static final String ECDSA   = "ECDSA";
    private static final String ED25519 = "Ed25519";
    private static final String RSA     = "RSA";

    private final Map<String, KeyPairEntry> keyStore = new ConcurrentHashMap<>();

    // ── Generación de claves ──────────────────────────────────────────────────

    public String generateKeyPair(String algorithm) throws Exception {
        String norm = normalizeAlgorithm(algorithm);
        log.info("[KEY-GEN] Algoritmo solicitado: '{}' → normalizado: '{}'", algorithm, norm);

        KeyPairGenerator kpg = switch (norm) {
            case ED25519 -> KeyPairGenerator.getInstance(ED25519);
            case RSA -> {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537)));
                yield g;
            }
            default -> {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                yield g;
            }
        };

        String keyId = UUID.randomUUID().toString();
        keyStore.put(keyId, new KeyPairEntry(kpg.generateKeyPair(), norm));
        log.info("[KEY-GEN] Par de claves generado → keyId: {}, algoritmo: {}", keyId, norm);
        return keyId;
    }

    // ── Firma ─────────────────────────────────────────────────────────────────

    /**
     * Hashea el texto plano con SHA-256 y firma el hash resultante.
     * Devuelve un array de dos elementos: [hash hex, firma bytes].
     */
    public Object[] sign(String keyId, String algorithm, byte[] plainText) throws Exception {
        String norm = normalizeAlgorithm(algorithm);
        log.info("[SIGN] keyId: {}, algoritmo: {}, bytes de texto: {}", keyId, norm, plainText.length);

        byte[] hash = hashSHA256(plainText);
        String hashHex = HexFormat.of().formatHex(hash);
        log.debug("[SIGN] SHA-256 del texto: {}", hashHex);

        KeyPairEntry entry = getEntry(keyId);
        String sigAlgo = signatureAlgorithm(norm);
        log.debug("[SIGN] Usando algoritmo de firma JCA: {}", sigAlgo);

        Signature sig = Signature.getInstance(sigAlgo);
        sig.initSign(entry.keyPair().getPrivate());
        sig.update(hash);
        byte[] firma = sig.sign();

        log.info("[SIGN] Firma generada → {} bytes, keyId: {}", firma.length, keyId);
        return new Object[]{hashHex, firma};
    }

    // ── Verificación ──────────────────────────────────────────────────────────

    public boolean verify(String keyId, String algorithm, byte[] plainText, byte[] firma) throws Exception {
        String norm = normalizeAlgorithm(algorithm);
        log.info("[VERIFY] keyId: {}, algoritmo: {}, bytes texto: {}, bytes firma: {}",
                keyId, norm, plainText.length, firma.length);

        byte[] hash = hashSHA256(plainText);
        log.debug("[VERIFY] SHA-256 del texto: {}", HexFormat.of().formatHex(hash));

        KeyPairEntry entry = getEntry(keyId);
        String sigAlgo = signatureAlgorithm(norm);
        log.debug("[VERIFY] Usando algoritmo de firma JCA: {}", sigAlgo);

        Signature sig = Signature.getInstance(sigAlgo);
        sig.initVerify(entry.keyPair().getPublic());
        sig.update(hash);
        boolean valida = sig.verify(firma);

        log.info("[VERIFY] Resultado: {} → keyId: {}", valida ? "VÁLIDA" : "INVÁLIDA", keyId);
        return valida;
    }

    // ── Info de clave pública ─────────────────────────────────────────────────

    public KeyInfoResponse getKeyInfo(String keyId) {
        log.info("[KEY-INFO] Consultando clave pública → keyId: {}", keyId);
        KeyPairEntry entry = getEntry(keyId);
        String pubKeyB64 = Base64.getEncoder()
                .encodeToString(entry.keyPair().getPublic().getEncoded());
        log.debug("[KEY-INFO] Clave pública ({}): {}...{}", entry.algorithm(),
                pubKeyB64.substring(0, Math.min(16, pubKeyB64.length())),
                pubKeyB64.substring(Math.max(0, pubKeyB64.length() - 8)));
        return new KeyInfoResponse(keyId, entry.algorithm(), pubKeyB64);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private KeyPairEntry getEntry(String keyId) {
        KeyPairEntry entry = keyStore.get(keyId);
        if (entry == null) {
            log.warn("[KEY-STORE] keyId no encontrado: {}", keyId);
            throw new KeyNotFoundException(keyId);
        }
        return entry;
    }

    private String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("El algoritmo no puede ser nulo");
        return switch (algorithm.toUpperCase()) {
            case "ED25519"       -> ED25519;
            case "ECDSA", "EC"   -> ECDSA;
            case "RSA"           -> RSA;
            default -> throw new IllegalArgumentException(
                    "Algoritmo no soportado: " + algorithm + ". Use ECDSA, Ed25519 o RSA");
        };
    }

    private String signatureAlgorithm(String algorithm) {
        return switch (algorithm) {
            case ED25519 -> "Ed25519";
            case RSA     -> "SHA256withRSA";
            default      -> "SHA256withECDSA";
        };
    }

    // ── Hash ──────────────────────────────────────────────────────────────────

    private byte[] hashSHA256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    // ── Record interno ────────────────────────────────────────────────────────

    private record KeyPairEntry(KeyPair keyPair, String algorithm) {}
}
