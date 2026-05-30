package es.faustino.securesign.service;

import es.faustino.securesign.exception.KeyNotFoundException;
import es.faustino.securesign.model.KeyInfoResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private static final String ECDSA = "ECDSA";
    private static final String ED25519 = "Ed25519";
    private static final String KS_TYPE = "PKCS12";
    private static final String KS_PATH = "securesign.p12";

    @Value("${securesign.keystore-password}")
    private String keystorePassword;

    private final Map<String, PublicKey> publicKeyStore = new ConcurrentHashMap<>();

    // ── KeyStore I/O ──────────────────────────────────────────────────────────

    private KeyStore cargarKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KS_TYPE);
        File archivo = new File(KS_PATH);
        if (archivo.exists()) {
            try (FileInputStream fis = new FileInputStream(archivo)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
        } else {
            log.info("Inicializando nuevo KeyStore PKCS12: {}", archivo.getAbsolutePath());
            ks.load(null, keystorePassword.toCharArray());
        }
        return ks;
    }

    private synchronized void guardarKeyStore(KeyStore ks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KS_PATH)) {
            ks.store(fos, keystorePassword.toCharArray());
        }
    }

    // ── Certificado autofirmado ───────────────────────────────────────────────

    private X509Certificate generarCertAutofirmado(KeyPair keyPair, String algo) throws Exception {
        X500Name subject = new X500Name("CN=SecureSign-" + algo + ",O=SecureSign,C=ES");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10L * 365 * 24 * 3600 * 1000);
        String sigAlgo = algo.equals(ED25519) ? "Ed25519" : "SHA256withECDSA";

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // ── Generación de claves ──────────────────────────────────────────────────

    public String generateKeyPair(String algorithm) throws Exception {
        String algo = normalizeAlgorithm(algorithm);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo.equals(ED25519) ? ED25519 : "EC");
        if (!algo.equals(ED25519)) {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        KeyPair keyPair = kpg.generateKeyPair();
        String keyId = UUID.randomUUID().toString();

        X509Certificate cert = generarCertAutofirmado(keyPair, algo);
        Certificate[] chain = new Certificate[]{cert};

        KeyStore ks = cargarKeyStore();
        ks.setKeyEntry(keyId, keyPair.getPrivate(), keystorePassword.toCharArray(), chain);
        guardarKeyStore(ks);

        publicKeyStore.put(keyId, keyPair.getPublic());

        log.info("Par de claves generado — keyId={}, algoritmo={}", keyId, algo);
        return keyId;
    }

    // ── Firma ─────────────────────────────────────────────────────────────────

    public byte[] sign(String keyId, String algorithm, byte[] data) throws Exception {
        String algo = normalizeAlgorithm(algorithm);

        KeyStore ks = cargarKeyStore();
        PrivateKey privateKey = (PrivateKey) ks.getKey(keyId, keystorePassword.toCharArray());
        if (privateKey == null) throw new KeyNotFoundException(keyId);

        // Extraer clave pública del certificado X.509 almacenado en el KeyStore
        X509Certificate cert = (X509Certificate) ks.getCertificate(keyId);
        PublicKey publicKeyFromCert = (cert != null) ? cert.getPublicKey() : publicKeyStore.get(keyId);

        // Firmar
        Signature sig = Signature.getInstance(signatureAlgorithm(algo));
        sig.initSign(privateKey);
        sig.update(data);
        byte[] firma = sig.sign();

        // ── Log de emisión ────────────────────────────────────────────────────
        String hashDoc = sha256Hex(data);
        String pubKeyB64 = (publicKeyFromCert != null)
                ? Base64.getEncoder().encodeToString(publicKeyFromCert.getEncoded())
                : "no disponible";
        String firmaB64 = Base64.getEncoder().encodeToString(firma);
        String certSubject = (cert != null) ? cert.getSubjectX500Principal().getName() : "—";
        String certSigAlgo = (cert != null) ? cert.getSigAlgName() : "—";

        log.info("""
                        
                        ╔══════════════════════════════════════════════════════════════╗
                        ║                     EMISIÓN  —  FIRMA PDF                   ║
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  Key ID          : {}
                        ║  Algoritmo       : {}
                        ║  Tamaño PDF      : {} bytes
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [DOCUMENTO]
                        ║  SHA-256         : {}
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [CERTIFICADO X.509]
                        ║  Subject         : {}
                        ║  Alg. firma cert : {}
                        ║  Clave pública   : {}
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [FIRMA DIGITAL]
                        ║  Tamaño firma    : {} bytes
                        ║  Firma (Base64)  : {}
                        ╚══════════════════════════════════════════════════════════════╝
                        """,
                keyId, algo, data.length,
                hashDoc,
                certSubject, certSigAlgo, pubKeyB64,
                firma.length, firmaB64
        );

        return firma;
    }

    // ── Verificación ──────────────────────────────────────────────────────────

    public boolean verify(String keyId, String algorithm, byte[] data, byte[] firma) throws Exception {
        String algo = normalizeAlgorithm(algorithm);

        // Extraer clave pública directamente del certificado X.509 en el KeyStore
        KeyStore ks = cargarKeyStore();
        X509Certificate cert = (X509Certificate) ks.getCertificate(keyId);

        PublicKey publicKey;
        String certSubject, certIssuer, certSigAlgo, certSerial, certNotAfter;

        if (cert != null) {
            publicKey = cert.getPublicKey();
            certSubject = cert.getSubjectX500Principal().getName();
            certIssuer = cert.getIssuerX500Principal().getName();
            certSigAlgo = cert.getSigAlgName();
            certSerial = cert.getSerialNumber().toString();
            certNotAfter = cert.getNotAfter().toString();
        } else {
            // Fallback: clave en memoria si el cert no está disponible
            publicKey = publicKeyStore.get(keyId);
            certSubject = "— (cert no disponible en KS)";
            certIssuer = "—";
            certSigAlgo = "—";
            certSerial = "—";
            certNotAfter = "—";
        }

        if (publicKey == null) throw new KeyNotFoundException(keyId);

        // Verificar
        Signature sig = Signature.getInstance(signatureAlgorithm(algo));
        sig.initVerify(publicKey);
        sig.update(data);
        boolean valida = sig.verify(firma);

        // ── Log de verificación ───────────────────────────────────────────────
        String hashDoc = sha256Hex(data);
        String pubKeyB64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String firmaB64 = Base64.getEncoder().encodeToString(firma);

        log.info("""
                        
                        ╔══════════════════════════════════════════════════════════════╗
                        ║                  VERIFICACIÓN  —  FIRMA PDF                 ║
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  Key ID          : {}
                        ║  Algoritmo usado : {}
                        ║  Tamaño PDF      : {} bytes
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [DOCUMENTO]
                        ║  SHA-256         : {}
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [CERTIFICADO X.509  —  extraído del KeyStore PKCS12]
                        ║  Subject         : {}
                        ║  Issuer          : {}
                        ║  Alg. firma cert : {}
                        ║  Nro. de serie   : {}
                        ║  Válido hasta    : {}
                        ║  Clave pública   : {}
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  [FIRMA RECIBIDA]
                        ║  Tamaño firma    : {} bytes
                        ║  Firma (Base64)  : {}
                        ╠══════════════════════════════════════════════════════════════╣
                        ║  RESULTADO       : {}
                        ╚══════════════════════════════════════════════════════════════╝
                        """,
                keyId, algo, data.length,
                hashDoc,
                certSubject, certIssuer, certSigAlgo, certSerial, certNotAfter, pubKeyB64,
                firma.length, firmaB64,
                valida ? "✔  FIRMA VÁLIDA — documento íntegro" : "✘  FIRMA INVÁLIDA — documento alterado"
        );

        return valida;
    }

    // ── Info de clave pública ─────────────────────────────────────────────────

    public KeyInfoResponse getKeyInfo(String keyId) {
        PublicKey publicKey = publicKeyStore.get(keyId);
        if (publicKey == null) throw new KeyNotFoundException(keyId);
        String pubKeyB64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String algo = publicKey.getAlgorithm().contains("EC") ? ECDSA : ED25519;
        return new KeyInfoResponse(keyId, algo, pubKeyB64);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Calcula SHA-256 del array de bytes y lo devuelve como string hexadecimal.
     * Muestra la huella digital del documento tal como la "ve" el algoritmo de firma.
     */
    private String sha256Hex(byte[] data) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) throw new IllegalArgumentException("El algoritmo no puede ser nulo");
        return switch (algorithm.toUpperCase()) {
            case "ED25519" -> ED25519;
            case "ECDSA", "EC" -> ECDSA;
            default -> throw new IllegalArgumentException(
                    "Algoritmo no soportado: " + algorithm + ". Use ECDSA o Ed25519");
        };
    }

    private String signatureAlgorithm(String algorithm) {
        return algorithm.equals(ED25519) ? "Ed25519" : "SHA256withECDSA";
    }
}
