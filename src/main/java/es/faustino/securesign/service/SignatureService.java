package es.faustino.securesign.service;

import es.faustino.securesign.exception.KeyNotFoundException;
import es.faustino.securesign.model.KeyInfoResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private static final String ECDSA = "ECDSA";
    private static final String ED25519 = "Ed25519";
    private static final String RSA = "RSA";

    private final Map<String, KeyPairEntry> keyStore = new ConcurrentHashMap<>();

    // ── Generación de claves ──────────────────────────────────────────────────

    public String generateKeyPair(String algorithm) throws Exception {
        String norm = normalizeAlgorithm(algorithm);
        log.info("[KEY-GEN] Algoritmo solicitado: '{}' → normalizado: '{}'", algorithm, norm);

        // TODO A-1: Instancia el KeyPairGenerator según el algoritmo normalizado.
        // - Ed25519 → no necesita parámetros adicionales
        // - RSA     → tamaño 2048 bits, exponente público 65537
        // - ECDSA   → curva secp256r1
        KeyPairGenerator kpg = null;

        // TODO A-2: Genera un identificador único y almacena el par en el keyStore.
        String keyId = null;

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

        // TODO B-1: Calcula el hash SHA-256 del texto en bytes usando hashSHA256.
        byte[] hash = null;
        String hashHex = null;
        log.debug("[SIGN] SHA-256 del texto: {}", hashHex);

        // TODO B-2: Recupera el par de claves del almacén, obtiene el nombre JCA
        // del algoritmo e inicializa Signature con la clave PRIVADA para firmar.
        KeyPairEntry entry = null;
        String sigAlgo = null;
        Signature sig = null;

        // TODO B-3: Carga el HASH (no el texto plano) en el objeto Signature
        // y ejecuta la operación de firma. El resultado es byte[] con la firma.
        byte[] firma = null;

        log.info("[SIGN] Firma generada → {} bytes, keyId: {}", firma == null ? 0 : firma.length, keyId);
        return new Object[]{hashHex, firma};
    }

    // ── Verificación ──────────────────────────────────────────────────────────

    public boolean verify(String keyId, String algorithm, byte[] plainText, byte[] firma) throws Exception {
        String norm = normalizeAlgorithm(algorithm);
        log.info("[VERIFY] keyId: {}, algoritmo: {}, bytes texto: {}, bytes firma: {}",
                keyId, norm, plainText.length, firma.length);

        // TODO C-1: Recalcula el SHA-256 del texto recibido usando hashSHA256.
        // Si el texto fue alterado, este hash será diferente y la verificación fallará.
        byte[] hash = null;
        log.debug("[VERIFY] SHA-256 del texto: {}", hash == null ? "null" : HexFormat.of().formatHex(hash));

        // TODO C-2: Recupera la entrada del almacén e inicializa Signature con
        // la clave PÚBLICA para la operación de verificación.
        KeyPairEntry entry = null;
        String sigAlgo = null;
        Signature sig = null;

        // TODO C-3: Carga el hash recalculado y verifica contra la firma recibida.
        // sig.verify devuelve true si la firma es matemáticamente válida.
        boolean valida = false;

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
            case "ED25519" -> ED25519;
            case "ECDSA", "EC" -> ECDSA;
            case "RSA" -> RSA;
            default -> throw new IllegalArgumentException(
                    "Algoritmo no soportado: " + algorithm + ". Use ECDSA, Ed25519 o RSA");
        };
    }

    private String signatureAlgorithm(String algorithm) {
        return switch (algorithm) {
            case ED25519 -> "Ed25519";
            case RSA -> "SHA256withRSA";
            default -> "SHA256withECDSA";
        };
    }

    // TODO B-1 (método): Implementa hashSHA256 con MessageDigest.
    // MessageDigest.getInstance("SHA-256").digest(data) aplica el hash y devuelve byte[].
    private byte[] hashSHA256(byte[] data) throws Exception {
        // TODO: reemplaza esta línea con la implementación correcta
        return null;
    }

    // ── Record interno ────────────────────────────────────────────────────────

    private record KeyPairEntry(KeyPair keyPair, String algorithm) {
    }
}
