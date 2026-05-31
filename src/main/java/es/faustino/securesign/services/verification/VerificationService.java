package es.faustino.securesign.services.verification;

import es.faustino.securesign.dto.internal.ResultadoExtraccion;
import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.shared.util.ByteRangeExtractor;
import es.faustino.securesign.shared.util.ByteRangeExtractor.PdfNoFirmadoException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;

import static es.faustino.securesign.dto.response.VerificationResultResponse.sinFirma;

@Service
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);
    
    private static final Map<String, String> ALGORITMOS = Map.of(
            // ECDSA
            "1.2.840.10045.4.3.2", "SHA256withECDSA",
            "1.2.840.10045.4.3.3", "SHA384withECDSA",
            "1.2.840.10045.4.3.4", "SHA512withECDSA",

            // EdDSA
            "1.3.101.112", "Ed25519",

            // RSA (PKCS#1 v1.5)
            "1.2.840.113549.1.1.5", "SHA1withRSA",
            "1.2.840.113549.1.1.11", "SHA256withRSA",
            "1.2.840.113549.1.1.12", "SHA384withRSA",
            "1.2.840.113549.1.1.13", "SHA512withRSA"
    );

    public VerificationResultResponse verificarDocumentoFirmado(byte[] pdf) {

        ResultadoExtraccion extraccion;
        try {
            extraccion = ByteRangeExtractor.extraer(pdf);
        } catch (PdfNoFirmadoException e) {
            log.warn("[VERIFY] PDF sin firma: {}", e.getMessage());
            return sinFirma("El PDF no contiene firma digital");
        } catch (Exception e) {
            log.error("[VERIFY] Error al parsear PDF", e);
            return sinFirma("Error al parsear el PDF: " + e.getMessage());
        }

        if (!extraccion.byteRangeValido()) {
            log.warn("[VERIFY] ByteRange inválido — posible corrupción estructural del PDF o firma mal formada");
        }

        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = parsearCMS(extraccion.cmsDerBytes(), extraccion.contenidoFirmado());
        } catch (Exception e) {
            log.error("[VERIFY] CMS no parseable: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), false, false,
                    false, false,
                    null, null, null, null,
                    "El bloque CMS (/Contents) está estructuralmente corrupto: " + e.getMessage()
            );
        }

        X509CertificateHolder certHolder;
        X509Certificate cert;
        try {
            Collection<X509CertificateHolder> certs = cmsSignedData.getCertificates().getMatches(null);
            if (certs.isEmpty()) {
                log.warn("[VERIFY] CMS sin certificados embebidos");
                return new VerificationResultResponse(
                        false,
                        true, extraccion.byteRangeValido(), true, false,
                        false, false,
                        null, null, null, null,
                        "El CMS no contiene ningún certificado X.509"
                );
            }
            certHolder = certs.iterator().next();
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            log.info("[VERIFY] Certificado extraído — subject: {}", cert.getSubjectX500Principal());
        } catch (CertificateException e) {
            log.error("[VERIFY] Certificado corrupto: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, false,
                    false, false,
                    null, null, null, null,
                    "El certificado X.509 dentro del CMS está corrupto: " + e.getMessage()
            );
        } catch (Exception e) {
            log.error("[VERIFY] Error al extraer certificado: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, false,
                    false, false,
                    null, null, null, null,
                    "Error al extraer el certificado X.509: " + e.getMessage()
            );
        }

        String subject = cert.getSubjectX500Principal().getName();
        Instant validoDesde = cert.getNotBefore().toInstant();
        Instant validoHasta = cert.getNotAfter().toInstant();
        Instant ahora = Instant.now();
        boolean certVigente = ahora.isAfter(validoDesde) && ahora.isBefore(validoHasta);

        Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            log.warn("[VERIFY] CMS sin SignerInfo");
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, true,
                    false, certVigente,
                    subject, validoDesde, validoHasta, null,
                    "El CMS no contiene ningún SignerInfo"
            );
        }

        SignerInformation signerInfo = buscarSignerParaCertificado(signers, certHolder);
        if (signerInfo == null) {
            log.warn("[VERIFY] Ningún SignerInfo corresponde al certificado extraído");
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, true,
                    false, certVigente,
                    subject, validoDesde, validoHasta, null,
                    "El certificado no corresponde a ningún firmante en el CMS"
            );
        }

        String algoritmo = resolverNombreAlgoritmo(signerInfo);

        boolean firmaValida;
        try {
            firmaValida = signerInfo.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)
            );
            log.info("[VERIFY] Verificación completada — firmaValida={}", firmaValida);
        } catch (CMSException e) {
            log.warn("[VERIFY] Firma inválida (CMSException): {}", e.getMessage());
            firmaValida = false;
        } catch (OperatorCreationException | CertificateException e) {
            log.error("[VERIFY] Error al construir el verificador de firma: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, true,
                    false, certVigente,
                    subject, validoDesde, validoHasta, algoritmo,
                    "Error interno al preparar la verificación criptográfica: " + e.getMessage()
            );
        }

        log.info("[VERIFY] Resultado — firmaValida={}, certVigente={}, subject={}", firmaValida, certVigente, subject);

        boolean valido = firmaValida && certVigente;

        if (firmaValida) {
            return new VerificationResultResponse(
                    valido,
                    true, extraccion.byteRangeValido(), true, true,
                    true, certVigente,
                    subject, validoDesde, validoHasta, algoritmo,
                    certVigente ? null : "El certificado ha expirado (válido hasta: " + validoHasta + ")"
            );
        } else {
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, true,
                    false, certVigente,
                    subject, validoDesde, validoHasta, algoritmo,
                    "El hash del documento no coincide con la firma"
            );
        }
    }

    private SignerInformation buscarSignerParaCertificado(
            Collection<SignerInformation> signers, X509CertificateHolder certHolder) {
        for (SignerInformation signer : signers) {
            if (signer.getSID().match(certHolder)) {
                return signer;
            }
        }
        return null;
    }

    private String resolverNombreAlgoritmo(SignerInformation signerInfo) {
        String oidFirma = signerInfo.getEncryptionAlgOID();
        String oidHash = signerInfo.getDigestAlgOID();

        String nombre = ALGORITMOS.get(oidFirma);
        if (nombre != null) {
            return nombre;
        }

        String nombreHash = ALGORITMOS.entrySet().stream()
                .filter(e -> e.getKey().equals(oidHash))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(oidHash);
        String nombreCifrado = ALGORITMOS.getOrDefault(oidFirma, oidFirma);
        return nombreHash + "with" + nombreCifrado;
    }

    private CMSSignedData parsearCMS(byte[] cmsDerBytes, byte[] contenidoFirmado) throws Exception {
        ContentInfo contentInfo;
        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(cmsDerBytes))) {
            contentInfo = ContentInfo.getInstance(asn1.readObject());
        }
        return new CMSSignedData(new CMSProcessableByteArray(contenidoFirmado), contentInfo);
    }
}
