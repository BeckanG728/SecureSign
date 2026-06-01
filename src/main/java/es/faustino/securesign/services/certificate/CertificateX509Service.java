package es.faustino.securesign.services.certificate;

import es.faustino.securesign.shared.enums.SignatureAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class CertificateX509Service {

    private static final X500Name SUBJECT =
            new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");

    public X509Certificate generarCertificadoX509(KeyPair keyPair, String algoritmo) throws Exception {

        BigInteger serialNumber = new BigInteger(128, new SecureRandom());
        Instant now = Instant.now();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                SUBJECT,
                serialNumber,
                Date.from(now.minus(1, ChronoUnit.MINUTES)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                SUBJECT,
                keyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(false));

        String sigAlg = SignatureAlgorithm.resolverNombreJca(algoritmo);

        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder(sigAlg).build(keyPair.getPrivate()))
        );
    }
}
