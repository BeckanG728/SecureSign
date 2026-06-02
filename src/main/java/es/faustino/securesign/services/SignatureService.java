package es.faustino.securesign.services;

import es.faustino.securesign.crypto.CryptoIdentityService;
import es.faustino.securesign.crypto.KeyStoreAccessService;
import es.faustino.securesign.dto.internal.CryptoIdentity;
import es.faustino.securesign.shared.enums.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);
    private final KeyStoreAccessService keyStoreService;
    private final CryptoIdentityService cryptoIdentityService;

    public SignatureService(KeyStoreAccessService keyStoreService,
                            CryptoIdentityService cryptoIdentityService) {
        this.keyStoreService = keyStoreService;
        this.cryptoIdentityService = cryptoIdentityService;
    }

    public byte[] firmarDocumento(byte[] bytesPdf, String jcaName) throws Exception {
        SignatureAlgorithm algoritmo = SignatureAlgorithm.fromJcaName(jcaName);
        CryptoIdentity identidad = cryptoIdentityService.obtenerIdentidad(algoritmo);
        return firmarPdf(bytesPdf, identidad, algoritmo);
    }

    private byte[] firmarPdf(byte[] bytesPdf, CryptoIdentity identidad, SignatureAlgorithm algoritmo) throws Exception {
        log.info("[FIRMA] Iniciando firma PAdES — alias={}, algoritmo={}, tamañoPdf={} bytes",
                identidad.alias(), algoritmo, bytesPdf.length);

        try (KeyStoreSignatureTokenConnection conexionToken = keyStoreService.abrirConexionToken()) {
            KSPrivateKeyEntry crendencialesFirma = (KSPrivateKeyEntry) conexionToken.getKey(identidad.alias());

            PAdESSignatureParameters parametrosFirma = construirParametrosFirma(crendencialesFirma, algoritmo);
            PAdESService servicioPades = construirServicioPades();
            DSSDocument documentoPdf = new InMemoryDocument(bytesPdf);

            ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
            log.debug("[FIRMA] Datos a firmar obtenidos — {} bytes", datosAFirmar.getBytes().length);

            SignatureValue valorFirma = conexionToken.sign(datosAFirmar, parametrosFirma.getDigestAlgorithm(), crendencialesFirma);
            log.debug("[FIRMA] Valor de firma calculado");

            DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);

            byte[] bytesPdfFirmado = documentoFirmado.openStream().readAllBytes();
            log.info("[FIRMA] Firma completada — pdfOriginal={} bytes, pdfFirmado={} bytes", bytesPdf.length, bytesPdfFirmado.length);

            return bytesPdfFirmado;
        }
    }

    private PAdESSignatureParameters construirParametrosFirma(KSPrivateKeyEntry crendencialFirma, SignatureAlgorithm algoritmo) {
        PAdESSignatureParameters parametros = new PAdESSignatureParameters();
        parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parametros.setSigningCertificate(crendencialFirma.getCertificate());
        parametros.setCertificateChain(crendencialFirma.getCertificateChain());
        parametros.setDigestAlgorithm(algoritmo.getDigestAlgorithmDss());
        return parametros;
    }

    private PAdESService construirServicioPades() {
        CommonCertificateVerifier verificador = new CommonCertificateVerifier();
        verificador.setCheckRevocationForUntrustedChains(false);
        return new PAdESService(verificador);
    }
}
