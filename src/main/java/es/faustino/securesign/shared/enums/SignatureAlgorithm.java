package es.faustino.securesign.shared.enums;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public enum SignatureAlgorithm {

    SHA256_WITH_ECDSA(
            "1.2.840.10045.4.3.2",
            "SHA256withECDSA",
            "EC",
            DigestAlgorithm.SHA256
    ) {
        @Override
        public KeyPair generarParDeClaves() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        }
    },

    ED25519(
            "1.3.101.112",
            "Ed25519",
            "EdDSA",
            DigestAlgorithm.SHA512
    ) {
        @Override
        public KeyPair generarParDeClaves() throws Exception {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        }
    },

    SHA256_WITH_RSA("1.2.840.113549.1.1.11", "SHA256withRSA", "RSA", DigestAlgorithm.SHA256),
    SHA512_WITH_RSA("1.2.840.113549.1.1.13", "SHA512withRSA", "RSA", DigestAlgorithm.SHA512);

    private final String oid;
    private final String jcaName;
    private final String jcaKeyAlias;
    private final DigestAlgorithm digestAlgorithmDss;

    SignatureAlgorithm(String oid, String jcaName, String jcaKeyAlias, DigestAlgorithm digestAlgorithmDss) {
        this.oid = oid;
        this.jcaName = jcaName;
        this.jcaKeyAlias = jcaKeyAlias;
        this.digestAlgorithmDss = digestAlgorithmDss;
    }

    public KeyPair generarParDeClaves() throws Exception {
        throw new UnsupportedOperationException("Generación de claves no soportada para: " + jcaName);
    }

    public String getJcaName() {
        return jcaName;
    }

    public DigestAlgorithm getDigestAlgorithmDss() {
        return digestAlgorithmDss;
    }

    public static String resolve(String oid) {
        return Arrays.stream(values())
                .filter(a -> a.oid.equals(oid))
                .findFirst()
                .map(SignatureAlgorithm::getJcaName)
                .orElse(oid);
    }

    public static DigestAlgorithm resolverDigestDss(String jcaName) {
        return Arrays.stream(values())
                .filter(a -> a.jcaName.equals(jcaName))
                .findFirst()
                .map(a -> a.digestAlgorithmDss)
                .orElse(DigestAlgorithm.SHA256);
    }

    public static SignatureAlgorithm fromJcaName(String jcaName) {
        return Arrays.stream(values())
                .filter(a -> a.jcaName.equals(jcaName) || a.jcaKeyAlias.equals(jcaName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Algoritmo no soportado: '" + jcaName + "'"));
    }
}
