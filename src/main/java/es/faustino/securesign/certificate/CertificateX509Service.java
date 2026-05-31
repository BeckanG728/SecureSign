package es.faustino.securesign.certificate;

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

/**
 * Genera certificados X.509 v3 autofirmados para firma PAdES.
 *
 * <h2>Extensiones incluidas</h2>
 * <ul>
 *   <li><b>SubjectKeyIdentifier</b> — obligatorio para que Adobe Acrobat
 *       identifique el certificado dentro del CMS sin recorrer toda la cadena.</li>
 *   <li><b>AuthorityKeyIdentifier</b> — igual al SKI porque es autofirmado.
 *       Sin él, validadores estrictos marcan el certificado como "issuer desconocido".</li>
 *   <li><b>KeyUsage: digitalSignature + nonRepudiation</b> — requerido por el
 *       perfil PAdES-BASELINE-B para que el certificado sea válido como signing cert.</li>
 *   <li><b>BasicConstraints: CA=false</b> — el certificado es de entidad final,
 *       no de CA intermedia.</li>
 * </ul>
 *
 * <h2>Por qué son necesarias estas extensiones</h2>
 * Sin SubjectKeyIdentifier, Adobe no puede construir la cadena de confianza
 * desde el bloque /Contents hacia el certificado, aunque el CMS sea válido.
 * El resultado visible: "firma inválida" pero con certificado extraíble —
 * exactamente el estado 1 que queremos poder diferenciar del estado 2 (corrupción).
 */
@Service
public class CertificateX509Service {

    /**
     * Genera un certificado X.509 v3 autofirmado con extensiones PAdES-compatibles.
     *
     * @param keyPair   par de claves (ECDSA secp256r1 o Ed25519)
     * @param algorithm "ECDSA" o "Ed25519"
     * @return certificado listo para embeber en el bloque /Contents del PDF
     */
    public X509Certificate generarCertificadoX509(KeyPair keyPair, String algorithm) throws Exception {

        X500Name subject = new X500Name("CN=SecureSign Institucional, O=Universidad, C=PE");

        // Serial number criptográficamente aleatorio (RFC 5280 §4.1.2.2)
        // No usar currentTimeMillis — puede colisionar si se generan dos certs en el mismo milisegundo
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        Instant now = Instant.now();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,                                        // issuer = subject (autofirmado)
                serialNumber,
                Date.from(now.minus(1, ChronoUnit.MINUTES)),   // notBefore — margen de skew de reloj
                Date.from(now.plus(365, ChronoUnit.DAYS)),      // notAfter — 1 año
                subject,                                        // subject
                keyPair.getPublic()
        );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        // SubjectKeyIdentifier: huella SHA-1 de la clave pública
        // Adobe usa esto para localizar el certificado dentro del CMS
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic())
        );

        // AuthorityKeyIdentifier: apunta al mismo certificado (autofirmado)
        // Sin esto, el validador no puede construir la cadena issuer→subject
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(keyPair.getPublic())
        );

        // KeyUsage: digitalSignature + nonRepudiation
        // PAdES-BASELINE-B exige al menos digitalSignature para la firma del documento
        builder.addExtension(
                Extension.keyUsage,
                true, // critical — debe respetarse
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation)
        );

        // BasicConstraints: CA=false — certificado de entidad final, no de CA
        builder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(false)
        );

        // Algoritmo de firma del propio certificado X.509
        String sigAlg = switch (algorithm) {
            case "Ed25519" -> "Ed25519";
            default -> "SHA256withECDSA"; // ECDSA secp256r1
        };

        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(
                                new JcaContentSignerBuilder(sigAlg)
                                        .build(keyPair.getPrivate())
                        )
                );
    }
}
