package es.faustino.securesign.verification;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Verifica documentos PDF firmados (PAdES) de forma completamente independiente
 * del servidor emisor. Extrae la firma y el certificado X.509 directamente del PDF.
 * No requiere keyId ni ningún estado del servidor.
 */
@Service
public class VerificationService {

    /**
     * Verifica la firma PAdES embebida en el PDF.
     * Retorna un mapa con el resultado completo de la verificación.
     */
    public Map<String, Object> verificarDocumentoFirmado(byte[] pdfFirmadoBytes) throws Exception {
        try (PDDocument document = Loader.loadPDF(pdfFirmadoBytes)) {

            // 1. Extraer firma embebida del PDF
            List<PDSignature> signatures = document.getSignatureDictionaries();
            if (signatures.isEmpty()) {
                return Map.of("valid", false, "reason", "El PDF no contiene firma digital");
            }

            PDSignature signature = signatures.get(0);
            byte[] signatureBytes = signature.getContents(pdfFirmadoBytes);
            byte[] signedContent = signature.getSignedContent(pdfFirmadoBytes);

            // 2. Parsear estructura CMS (PKCS#7) que contiene firma + certificado
            CMSSignedData cmsSignedData = new CMSSignedData(
                    new CMSProcessableByteArray(signedContent), signatureBytes
            );

            // 3. Extraer certificado X.509 embebido en el CMS
            Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
            X509CertificateHolder certHolder = certStore.getMatches(null).iterator().next();
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

            // 4. Verificar la firma usando la clave pública del certificado
            SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
            SignerInformation signerInfo = signerInfoStore.getSigners().iterator().next();
            boolean firmaValida = signerInfo.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().build(cert)
            );

            // 5. Validar vigencia del certificado
            boolean certVigente;
            try {
                cert.checkValidity();
                certVigente = true;
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                certVigente = false;
            }

            return Map.of(
                    "valid", firmaValida && certVigente,
                    "firmaValida", firmaValida,
                    "certificadoVigente", certVigente,
                    "subject", cert.getSubjectX500Principal().getName(),
                    "validoDesde", cert.getNotBefore().toString(),
                    "validoHasta", cert.getNotAfter().toString()
            );
        }
    }
}
