package es.faustino.securesign.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class CertificateX509Service {

    /**
     * Genera un certificado X.509 autofirmado que vincula la identidad
     * institucional con la clave pública del par de claves recibido.
     * El certificado incluye subject, issuer (mismo, por ser autofirmado),
     * número de serie, fechas de validez y la firma del propio certificado.
     */
    public X509Certificate generarCertificadoX509(KeyPair keyPair, String algorithm) throws Exception {
        X500Name subject = new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,                                               // issuer = subject (autofirmado)
                BigInteger.valueOf(System.currentTimeMillis()),        // serial number
                Date.from(Instant.now()),                              // not before
                Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),   // not after (1 año)
                subject,                                               // subject
                keyPair.getPublic()
        );

        String sigAlg = algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA";

        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(
                                new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate())
                        )
                );
    }
}
