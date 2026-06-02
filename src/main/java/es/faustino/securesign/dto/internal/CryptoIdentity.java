package es.faustino.securesign.dto.internal;

import java.security.cert.X509Certificate;

/**
 * Agrupa el alias del KeyStore y el certificado X.509 que le corresponde,
 * evitando tener que resolver el alias nuevamente a partir del certificado
 * en etapas posteriores del proceso de firma.
 */
public record CryptoIdentity(String alias, X509Certificate certificado) {
}
