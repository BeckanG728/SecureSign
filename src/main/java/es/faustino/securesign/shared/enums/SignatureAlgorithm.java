package es.faustino.securesign.shared.enums;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public enum SignatureAlgorithm {

    // NIST SP 800-186: P-256 es el mínimo recomendado para ECDSA
    SHA256_WITH_ECDSA(
            "1.2.840.10045.4.3.2",
            "SHA256withECDSA",
            DigestAlgorithm.SHA256
    ) {
        @Override
        public KeyPair generarParDeClaves() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1")); // P-256
            return gen.generateKeyPair();
        }
    },

    // NIST SP 800-186 (draft): Ed25519 ofrece seguridad equivalente a P-256
    ED25519(
            "1.3.101.112",
            "Ed25519",
            DigestAlgorithm.SHA512
    ) {
        @Override
        public KeyPair generarParDeClaves() throws Exception {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        }
    },

    // Solo para traducción de OID durante verificación — no se usa para firmar
    SHA256_WITH_RSA("1.2.840.113549.1.1.11", "SHA256withRSA", DigestAlgorithm.SHA256),
    SHA512_WITH_RSA("1.2.840.113549.1.1.13", "SHA512withRSA", DigestAlgorithm.SHA512);

    private final String oid;
    private final String jcaName;
    private final DigestAlgorithm digestAlgorithmDss;

    SignatureAlgorithm(String oid, String jcaName, DigestAlgorithm digestAlgorithmDss) {
        this.oid = oid;
        this.jcaName = jcaName;
        this.digestAlgorithmDss = digestAlgorithmDss;
    }

    /** Genera un par de claves con el tamaño recomendado por NIST. Solo válido para ECDSA y Ed25519. */
    public KeyPair generarParDeClaves() throws Exception {
        throw new UnsupportedOperationException("Generación de claves no soportada para: " + jcaName);
    }

    public String getJcaName() { return jcaName; }

    public DigestAlgorithm getDigestAlgorithmDss() { return digestAlgorithmDss; }

    /** Dado un OID, retorna el nombre JCA. Si no se reconoce, retorna el OID tal cual. */
    public static String resolve(String oid) {
        return Arrays.stream(values())
                .filter(a -> a.oid.equals(oid))
                .findFirst()
                .map(SignatureAlgorithm::getJcaName)
                .orElse(oid);
    }

    /** Dado un nombre JCA, retorna el DigestAlgorithm DSS. Si no se reconoce, retorna SHA256 por defecto. */
    public static DigestAlgorithm resolverDigestDss(String jcaName) {
        return Arrays.stream(values())
                .filter(a -> a.jcaName.equals(jcaName))
                .findFirst()
                .map(a -> a.digestAlgorithmDss)
                .orElse(DigestAlgorithm.SHA256);
    }

    /** Dado un nombre JCA, retorna la entrada del enum o lanza excepción si no se reconoce. */
    public static SignatureAlgorithm fromJcaName(String jcaName) {
        return Arrays.stream(values())
                .filter(a -> a.jcaName.equals(jcaName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Algoritmo no soportado: '" + jcaName + "'"));
    }
}
