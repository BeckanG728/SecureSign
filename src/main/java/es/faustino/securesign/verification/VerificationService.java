package es.faustino.securesign.verification;

import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.verification.ByteRangeExtractor.PdfNoFirmadoException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;

/**
 * Verifica firmas PAdES diferenciando entre dos estados críticos:
 *
 * <h2>Estado 1 — Firma inválida (comportamiento CORRECTO)</h2>
 * <p>El PDF fue modificado por el usuario DESPUÉS de descargarlo.
 * La estructura PAdES permanece intacta: ByteRange válido, CMS parseable,
 * certificado extraíble. Solo falla la comparación de hashes.</p>
 * <pre>
 * firmaExtraible=true, cmsParseable=true, certificadoExtraible=true,
 * byteRangeValido=true, firmaValida=false
 * </pre>
 *
 * <h2>Estado 2 — PDF corrupto (debe NUNCA ocurrir desde el backend)</h2>
 * <p>El PDF fue dañado estructuralmente: ByteRange incoherente, CMS ASN.1
 * destruido, /Contents inaccesible.</p>
 * <pre>
 * firmaExtraible=false, cmsParseable=false, byteRangeValido=false
 * </pre>
 *
 * <h2>Arquitectura de la verificación</h2>
 * <pre>
 * PDF bytes
 *     │
 *     ▼
 * [1] ByteRangeExtractor (PDFBox 3.x)
 *     ├─ Parsea xref (table o stream comprimido)
 *     ├─ Localiza el diccionario /Sig
 *     ├─ Extrae /ByteRange como int[4]
 *     ├─ Extrae /Contents como bytes DER
 *     └─ Valida coherencia ByteRange vs. tamaño PDF
 *         │
 *         ▼
 * [2] CMS Parser (BouncyCastle)
 *     ├─ ASN1InputStream.readObject() → ContentInfo (detiene en primer objeto)
 *     ├─ CMSSignedData con CMSProcessableByteArray(contenidoFirmado)
 *     ├─ Extrae colección de X509CertificateHolder
 *     └─ Extrae colección de SignerInformation
 *         │
 *         ▼
 * [3] Verificación criptográfica (BouncyCastle)
 *     ├─ JcaSimpleSignerInfoVerifierBuilder.build(certHolder)
 *     ├─ signerInfo.verify(verifier)
 *     │   = recalcula SHA-256(contenidoFirmado) y compara con
 *     │     el messageDigest attribute del SignedAttributes del CMS
 *     └─ Devuelve boolean firmaValida
 *         │
 *         ▼
 * [4] VerificationResultResponse
 *     ├─ Todos los flags de integridad estructural
 *     ├─ Resultado criptográfico
 *     └─ Datos del certificado X.509
 * </pre>
 *
 * <h2>Por qué CMSProcessableByteArray y no null</h2>
 * <p>En CMS detached, el contenido (eContent) no está embebido en el SignedData.
 * BouncyCastle necesita que se le provea el contenido externamente para poder
 * verificar la firma. {@code CMSProcessableByteArray(contenidoFirmado)} hace
 * exactamente eso: le dice a BC "el contenido a hashear es este byte[]".
 * Sin él, BC lanzaría "content not found in signed data" aunque la firma sea válida.</p>
 *
 * <h2>Por qué Adobe puede mostrar el certificado aunque la firma sea inválida</h2>
 * <p>Adobe Acrobat usa una lógica de dos capas:</p>
 * <ol>
 *   <li><b>Capa estructural:</b> puede el PDF ser parseado correctamente?
 *       ¿Tiene ByteRange coherente? ¿El /Contents contiene ASN.1 válido?
 *       Si sí → extrae y muestra el certificado.</li>
 *   <li><b>Capa criptográfica:</b> ¿el hash recalculado coincide con el CMS?
 *       Si no → muestra "firma inválida" o "documento modificado".</li>
 * </ol>
 * <p>Esto es exactamente el comportamiento que este sistema replica.</p>
 */
@Service
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);

    /**
     * Verifica un PDF firmado.
     *
     * <p>El método nunca lanza excepción — todos los errores se capturan
     * y se devuelven como {@code VerificationResultResponse} con los flags apropiados.
     * Esto permite al cliente diferenciar entre "no firmado", "corrupto" e "inválido".</p>
     *
     * @param pdf bytes del PDF (original o modificado por el usuario)
     * @return resultado detallado con flags de integridad estructural y criptográfica
     */
    public VerificationResultResponse verificarDocumentoFirmado(byte[] pdf) {

        // ── Paso 1: Extraer ByteRange y CMS ──────────────────────────────────
        ByteRangeExtractor.ResultadoExtraccion extraccion;
        try {
            extraccion = ByteRangeExtractor.extraer(pdf);
        } catch (PdfNoFirmadoException e) {
            log.warn("[VERIFY] PDF sin firma: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    false, false, false, false,
                    false, false,
                    null, null, null, null,
                    "El PDF no contiene firma digital"
            );
        } catch (Exception e) {
            log.error("[VERIFY] Error al parsear PDF — posible corrupción estructural", e);
            return new VerificationResultResponse(
                    false,
                    false, false, false, false,
                    false, false,
                    null, null, null, null,
                    "Error al parsear el PDF: " + e.getMessage()
            );
        }

        // ByteRange incoherente = PDF modificado post-firma.
        // NO se corta aquí — la verificación criptográfica (hash vs firma descifrada)
        // es la que determina el veredicto. El ByteRange desalineado es evidencia
        // adicional, pero el hash fallará de todas formas si el contenido cambió.
        if (!extraccion.byteRangeValido()) {
            log.warn("[VERIFY] ByteRange incoherente — posible modificación post-firma, continuando verificación criptográfica");
        }

        // ── Paso 2: Parsear CMS ASN.1 ────────────────────────────────────────
        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = parsearCMS(extraccion.cmsDerBytes(), extraccion.contenidoFirmado());
        } catch (Exception e) {
            log.error("[VERIFY] CMS no parseable — ASN.1 corrupto: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), false, false,
                    false, false,
                    null, null, null, null,
                    "El bloque CMS (/Contents) está estructuralmente corrupto: " + e.getMessage()
            );
        }

        // ── Paso 3: Extraer certificado X.509 ────────────────────────────────
        X509CertificateHolder certHolder;
        X509Certificate cert;
        try {
            Collection<X509CertificateHolder> certs =
                    cmsSignedData.getCertificates().getMatches(null);
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
            cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certHolder);
            log.info("[VERIFY] Certificado extraído — subject: {}", cert.getSubjectX500Principal());
        } catch (Exception e) {
            log.error("[VERIFY] Error al extraer certificado del CMS: {}", e.getMessage());
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, false,
                    false, false,
                    null, null, null, null,
                    "Error al extraer el certificado X.509 del CMS: " + e.getMessage()
            );
        }

        // Datos del certificado — disponibles desde aquí en adelante
        // independientemente del resultado criptográfico
        String subject      = cert.getSubjectX500Principal().getName();
        Instant validoDesde = cert.getNotBefore().toInstant();
        Instant validoHasta = cert.getNotAfter().toInstant();
        boolean certVigente = Instant.now().isAfter(validoDesde) && Instant.now().isBefore(validoHasta);

        // ── Paso 4: Extraer firmante ──────────────────────────────────────────
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
        SignerInformation signerInfo = signers.iterator().next();
        String algoritmo = signerInfo.getEncryptionAlgOID();

        // ── Paso 5: Verificar firma criptográficamente ────────────────────────
        boolean firmaValida;
        try {
            firmaValida = signerInfo.verify(
                    new JcaSimpleSignerInfoVerifierBuilder()
                            .setProvider("BC")
                            .build(certHolder)
            );
            log.info("[VERIFY] Verificación criptográfica completada — firmaValida={}", firmaValida);
        } catch (Exception e) {
            log.warn("[VERIFY] Excepción durante verificación criptográfica (firma inválida): {}",
                    e.getMessage());
            firmaValida = false;
        }

        // ── Paso 6: Construir respuesta ───────────────────────────────────────
        log.info("[VERIFY] Resultado final — firmaValida={}, certVigente={}, subject={}",
                firmaValida, certVigente, subject);

        if (firmaValida) {
            return new VerificationResultResponse(
                    certVigente,      // valid solo si además el cert no expiró
                    true, extraccion.byteRangeValido(), true, true,
                    true, certVigente,
                    subject, validoDesde, validoHasta, algoritmo,
                    certVigente ? null : "El certificado ha expirado (validez hasta: " + validoHasta + ")"
            );
        } else {
            String razon = extraccion.byteRangeValido()
                    ? "El hash del documento no coincide con la firma — contenido alterado"
                    : "El hash del documento no coincide con la firma — ByteRange desalineado (bytes extra al final del PDF)";
            return new VerificationResultResponse(
                    false,
                    true, extraccion.byteRangeValido(), true, true,
                    false, certVigente,
                    subject, validoDesde, validoHasta, algoritmo,
                    razon
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Parseo del CMS ASN.1
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Parsea el bloque DER del CMS con BouncyCastle.
     *
     * <h3>Manejo del padding de ceros</h3>
     * <p>DSS reserva un bloque /Contents fijo (ej. 32768 bytes) y lo rellena
     * con ceros tras el CMS real. {@code ASN1InputStream.readObject()} lee
     * exactamente el primer objeto ASN.1 completo y se detiene — el padding
     * de ceros es ignorado automáticamente según la especificación DER.
     * NO se necesita recortar los ceros manualmente.</p>
     *
     * <h3>Por qué ContentInfo y no CMSSignedData directamente</h3>
     * <p>{@code new CMSSignedData(bytes)} requiere que los bytes estén sin padding.
     * Pasarlos con padding haría que BC intentase parsear los ceros como parte
     * del objeto y lanzase {@code IOException: extra data found after object}.
     * La vía {@code ASN1InputStream → ContentInfo → CMSSignedData(contentInfo)}
     * es la forma correcta para bytes con padding.</p>
     *
     * @param cmsDerBytes      bytes DER del /Contents (con posible padding de ceros)
     * @param contenidoFirmado bytes T1+T2 del ByteRange (el "contenido externo" del CMS detached)
     * @return {@code CMSSignedData} listo para verificación
     */
    private CMSSignedData parsearCMS(byte[] cmsDerBytes, byte[] contenidoFirmado) throws Exception {
        ContentInfo contentInfo;
        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(cmsDerBytes))) {
            contentInfo = ContentInfo.getInstance(asn1.readObject());
        }

        /*
         * CMSProcessableByteArray: provee el contenido "externo" del CMS detached.
         * En PAdES, el campo eContent de encapContentInfo es null (detached).
         * BouncyCastle necesita este objeto para recalcular el hash y compararlo
         * con el messageDigest embebido en los SignedAttributes.
         */
        return new CMSSignedData(
                new CMSProcessableByteArray(contenidoFirmado),
                contentInfo
        );
    }
}
