package es.faustino.securesign.services;

import es.faustino.securesign.dto.internal.DatosCertificado;
import es.faustino.securesign.dto.internal.ResultadoExtraccion;
import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.shared.enums.SignatureAlgorithm;
import es.faustino.securesign.shared.util.ByteRangeExtractor;
import es.faustino.securesign.shared.util.ByteRangeExtractor.PdfNoFirmadoException;
import es.faustino.securesign.shared.util.CertificadoUtils;
import es.faustino.securesign.shared.util.CmsUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;

import static es.faustino.securesign.dto.response.VerificationResultResponse.*;

@Service
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);

    public VerificationResultResponse verificarDocumentoFirmado(byte[] pdf) {

        ResultadoExtraccion extraccion = extraerDatosPdf(pdf);
        if (extraccion == null) return sinFirma("El PDF no contiene firma digital");

        CMSSignedData cms = parsearBloquesCMS(extraccion);
        if (cms == null)
            return cmsCorrupto(extraccion.estructuraValida(), "El bloque CMS (/Contents) está estructuralmente corrupto");

        DatosCertificado datosCert = extraerCertificado(cms, extraccion);
        if (datosCert == null)
            return sinCertificado(extraccion.estructuraValida(), "El CMS no contiene ningún certificado X.509");

        return verificarFirma(cms, datosCert, extraccion);
    }

    private ResultadoExtraccion extraerDatosPdf(byte[] pdf) {
        try {
            ResultadoExtraccion extraccion = ByteRangeExtractor.extraer(pdf);
            if (!extraccion.estructuraValida()) {
                log.warn("[VERIFY] Estructura del PDF inválida — posible corrupción o firma mal formada");
            }
            return extraccion;
        } catch (PdfNoFirmadoException e) {
            log.warn("[VERIFY] PDF sin firma: {}", e.getMessage());
        } catch (Exception e) {
            log.error("[VERIFY] Error al parsear PDF", e);
        }
        return null;
    }

    private CMSSignedData parsearBloquesCMS(ResultadoExtraccion extraccion) {
        try {
            return CmsUtils.parsearCMS(extraccion.bytesCMS(), extraccion.bytesPdfCubiertos());
        } catch (Exception e) {
            log.error("[VERIFY] CMS no parseable: {}", e.getMessage());
            return null;
        }
    }

    private DatosCertificado extraerCertificado(CMSSignedData cms, ResultadoExtraccion extraccion) {
        try {
            X509CertificateHolder certHolder = CertificadoUtils.extraerCertHolder(cms);
            if (certHolder == null) return null;
            X509Certificate cert = CertificadoUtils.convertirCertificado(certHolder);
            return new DatosCertificado(certHolder, cert);
        } catch (Exception e) {
            log.error("[VERIFY] Error al extraer certificado: {}", e.getMessage());
            return null;
        }
    }

    private VerificationResultResponse verificarFirma(CMSSignedData cms, DatosCertificado datosCert, ResultadoExtraccion extraccion) {
        boolean estructuraValida = extraccion.estructuraValida();
        String subject = datosCert.cert().getSubjectX500Principal().getName();
        Instant validoDesde = datosCert.cert().getNotBefore().toInstant();
        Instant validoHasta = datosCert.cert().getNotAfter().toInstant();
        Instant ahora = Instant.now();
        boolean certVigente = ahora.isAfter(validoDesde) && ahora.isBefore(validoHasta);

        Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            log.warn("[VERIFY] CMS sin SignerInfo");
            return sinFirmante(estructuraValida, certVigente, subject, validoDesde, validoHasta,
                    "El CMS no contiene ningún SignerInfo");
        }

        SignerInformation signerInfo = CmsUtils.buscarSignerParaCertificado(signers, datosCert.certHolder());
        if (signerInfo == null) {
            log.warn("[VERIFY] Ningún SignerInfo corresponde al certificado extraído");
            return sinFirmante(estructuraValida, certVigente, subject, validoDesde, validoHasta,
                    "El certificado no corresponde a ningún firmante en el CMS");
        }

        String algoritmo = SignatureAlgorithm.resolve(signerInfo.getEncryptionAlgOID());

        boolean firmaValida;
        try {
            firmaValida = signerInfo.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(datosCert.certHolder())
            );
            log.info("[VERIFY] Verificación completada — firmaValida={}", firmaValida);
        } catch (CMSException e) {
            log.warn("[VERIFY] Firma inválida (CMSException): {}", e.getMessage());
            firmaValida = false;
        } catch (OperatorCreationException | CertificateException e) {
            log.error("[VERIFY] Error al construir el verificador de firma: {}", e.getMessage());
            return errorVerificacion(estructuraValida, certVigente, subject, validoDesde, validoHasta, algoritmo,
                    "Error interno al preparar la verificación criptográfica: " + e.getMessage());
        }

        log.info("[VERIFY] Resultado — firmaValida={}, certVigente={}, subject={}", firmaValida, certVigente, subject);

        if (firmaValida) {
            return firmaVerificada(estructuraValida, certVigente, subject, validoDesde, validoHasta, algoritmo);
        } else {
            return firmaInvalida(estructuraValida, certVigente, subject, validoDesde, validoHasta, algoritmo);
        }
    }
}
