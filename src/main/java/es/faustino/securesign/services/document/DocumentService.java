package es.faustino.securesign.services.document;

import es.faustino.securesign.keys.KeyManagementService;
import es.faustino.securesign.services.signature.SignatureService;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;

@Service
public class DocumentService {

    private final KeyManagementService keyManagementService;
    private final SignatureService signatureService;

    public DocumentService(KeyManagementService keyManagementService,
                           SignatureService signatureService) {
        this.keyManagementService = keyManagementService;
        this.signatureService = signatureService;
    }

    public byte[] firmarDocumento(byte[] bytesPdf, String algoritmo) throws Exception {
        String alias = keyManagementService.generarYAlmacenarParDeClaves(algoritmo);
        X509Certificate certificado = keyManagementService.buscarCertificadoPorAlias(alias);
        return signatureService.firmarPdf(bytesPdf, certificado, algoritmo);
    }
}
