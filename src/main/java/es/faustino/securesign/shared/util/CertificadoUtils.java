package es.faustino.securesign.shared.util;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collection;

public class CertificadoUtils {

    private static final Logger log = LoggerFactory.getLogger(CertificadoUtils.class);

    private CertificadoUtils() {
    }

    public static X509CertificateHolder extraerCertHolder(CMSSignedData cms) throws Exception {
        Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
        if (certs.isEmpty()) {
            log.warn("[VERIFY] CMS sin certificados embebidos");
            return null;
        }
        return certs.iterator().next();
    }

    public static X509Certificate convertirCertificado(X509CertificateHolder certHolder) throws Exception {
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        log.info("[VERIFY] Certificado extraído — subject: {}", cert.getSubjectX500Principal());
        return cert;
    }
}
