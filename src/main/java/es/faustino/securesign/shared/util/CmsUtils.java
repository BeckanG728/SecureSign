package es.faustino.securesign.shared.util;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import java.io.ByteArrayInputStream;
import java.util.Collection;

public class CmsUtils {

    private CmsUtils() {
    }

    public static CMSSignedData parsearCMS(byte[] bytesCMS, byte[] bytesPdfCubiertos) throws Exception {
        ContentInfo contentInfo;
        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(bytesCMS))) {
            contentInfo = ContentInfo.getInstance(asn1.readObject());
        }
        return new CMSSignedData(new CMSProcessableByteArray(bytesPdfCubiertos), contentInfo);
    }

    public static SignerInformation buscarSignerParaCertificado(
            Collection<SignerInformation> signers, X509CertificateHolder certHolder) {
        return signers.stream()
                .filter(s -> s.getSID().match(certHolder))
                .findFirst()
                .orElse(null);
    }
}
