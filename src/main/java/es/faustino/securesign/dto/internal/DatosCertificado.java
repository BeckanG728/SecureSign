package es.faustino.securesign.dto.internal;

import org.bouncycastle.cert.X509CertificateHolder;

import java.security.cert.X509Certificate;

public record DatosCertificado(
        X509CertificateHolder certHolder,
        X509Certificate cert
) {
}
