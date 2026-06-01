package es.faustino.securesign.shared.enums;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.Arrays;

public enum SignatureAlgorithm {

    SHA256_WITH_ECDSA(
            "1.2.840.10045.4.3.2",
            "SHA256withECDSA",
            DigestAlgorithm.SHA256
    ),

    ED25519(
            "1.3.101.112",
            "Ed25519",
            DigestAlgorithm.SHA512
    ),

    SHA256_WITH_RSA(
            "1.2.840.113549.1.1.11",
            "SHA256withRSA",
            DigestAlgorithm.SHA256
    ),
    SHA512_WITH_RSA(
            "1.2.840.113549.1.1.13",
            "SHA512withRSA",
            DigestAlgorithm.SHA512
    );

    private final String oid;
    private final String jcaName;
    private final DigestAlgorithm digestAlgorithmDss;

    SignatureAlgorithm(String oid, String jcaName, DigestAlgorithm digestAlgorithmDss) {
        this.oid = oid;
        this.jcaName = jcaName;
        this.digestAlgorithmDss = digestAlgorithmDss;
    }

    public String getJcaName() {
        return jcaName;
    }

    public DigestAlgorithm getDigestAlgorithmDss() {
        return digestAlgorithmDss;
    }

    /** Dado un OID, retorna el nombre JCA (e.g. "Ed25519"). Si no se reconoce, retorna el OID tal cual. */
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

    /** Dado un nombre JCA de algoritmo, retorna el nombre JCA canónico del enum.
     *  Útil para normalizar strings antes de pasarlos a BouncyCastle. */
    public static String resolverNombreJca(String jcaName) {
        return Arrays.stream(values())
                .filter(a -> a.jcaName.equals(jcaName))
                .findFirst()
                .map(SignatureAlgorithm::getJcaName)
                .orElse("SHA256withECDSA");
    }
}