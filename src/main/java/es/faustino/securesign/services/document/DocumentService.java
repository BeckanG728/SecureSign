package es.faustino.securesign.services.document;

import es.faustino.securesign.crypto.CryptoIdentityService;
import es.faustino.securesign.services.signature.SignatureService;
import es.faustino.securesign.shared.enums.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;

@Service
public class DocumentService {

    private final CryptoIdentityService cryptoIdentityService;
    private final SignatureService signatureService;

    public DocumentService(CryptoIdentityService cryptoIdentityService,
                           SignatureService signatureService) {
        this.cryptoIdentityService = cryptoIdentityService;
        this.signatureService = signatureService;
    }

    public byte[] firmarDocumento(byte[] bytesPdf, String jcaName) throws Exception {
        SignatureAlgorithm algoritmo = SignatureAlgorithm.fromJcaName(jcaName);
        X509Certificate certificado = cryptoIdentityService.obtenerCertificado(algoritmo);
        return signatureService.firmarPdf(bytesPdf, certificado, jcaName);
    }
}
