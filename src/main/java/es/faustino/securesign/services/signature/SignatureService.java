package es.faustino.securesign.services.signature;

import es.faustino.securesign.keys.KeyStoreService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private final KeyStoreService keyStoreService;

    public SignatureService(KeyStoreService keyStoreService) {
        this.keyStoreService = keyStoreService;
    }

    public byte[] firmarPdf(byte[] bytesPdf,
                            X509Certificate certificado, String algoritmo) throws Exception {

        String alias = buscarAliasPorCertificado(certificado);

        log.info("[FIRMA] Iniciando firma PAdES — alias={}, algoritmo={}, tamañoPdf={} bytes",
                alias, algoritmo, bytesPdf.length);

        try (KeyStoreSignatureTokenConnection conexionToken = abrirConexionToken()) {
            KSPrivateKeyEntry entradaClave = (KSPrivateKeyEntry) conexionToken.getKey(alias);

            PAdESSignatureParameters parametrosFirma = construirParametrosFirma(entradaClave, algoritmo);
            PAdESService servicioPades = construirServicioPades();
            DSSDocument documentoPdf = new InMemoryDocument(bytesPdf);

            ToBeSigned datosAFirmar = servicioPades.getDataToSign(documentoPdf, parametrosFirma);
            log.debug("[FIRMA] Datos a firmar obtenidos — {} bytes", datosAFirmar.getBytes().length);

            SignatureValue valorFirma = conexionToken.sign(datosAFirmar, parametrosFirma.getDigestAlgorithm(), entradaClave);
            log.debug("[FIRMA] Valor de firma calculado");

            DSSDocument documentoFirmado = servicioPades.signDocument(documentoPdf, parametrosFirma, valorFirma);

            ByteArrayOutputStream flujoSalida = new ByteArrayOutputStream();
            documentoFirmado.writeTo(flujoSalida);

            byte[] bytesPdfFirmado = flujoSalida.toByteArray();
            log.info("[FIRMA] Firma completada — pdfOriginal={} bytes, pdfFirmado={} bytes",
                    bytesPdf.length, bytesPdfFirmado.length);

            return bytesPdfFirmado;
        }
    }

    private String buscarAliasPorCertificado(X509Certificate certificado) throws Exception {
        KeyStore keyStore = keyStoreService.cargar();
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (certificado.equals(keyStore.getCertificate(alias))) {
                return alias;
            }
        }

        throw new IllegalStateException(
                "No se encontró el alias en el KeyStore para el certificado proporcionado."
        );
    }

    private KeyStoreSignatureTokenConnection abrirConexionToken() throws IOException {
        return new KeyStoreSignatureTokenConnection(
                new File(keyStoreService.getRutaArchivo()),
                keyStoreService.getTipo(),
                new KeyStore.PasswordProtection(keyStoreService.getClaveAccesoComoChars())
        );
    }

    private PAdESSignatureParameters construirParametrosFirma(KSPrivateKeyEntry entradaClave, String algoritmo) {
        PAdESSignatureParameters parametros = new PAdESSignatureParameters();
        parametros.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parametros.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parametros.setSigningCertificate(entradaClave.getCertificate());
        parametros.setCertificateChain(entradaClave.getCertificateChain());

        if ("Ed25519".equals(algoritmo)) {
            parametros.setDigestAlgorithm(DigestAlgorithm.SHA512);
        } else {
            parametros.setDigestAlgorithm(DigestAlgorithm.SHA256);
        }

        return parametros;
    }

    private PAdESService construirServicioPades() {
        CommonCertificateVerifier verificador = new CommonCertificateVerifier();
        verificador.setCheckRevocationForUntrustedChains(false);
        return new PAdESService(verificador);
    }
}
