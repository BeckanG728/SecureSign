package es.faustino.securesign.signature;

import es.faustino.securesign.certificate.CertificateX509Service;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;
import java.util.UUID;

/**
 * Gestiona el KeyStore PKCS12 y la firma PAdES usando DSS.
 *
 * <h2>Responsabilidades</h2>
 * <ul>
 *   <li>Mantener el KeyStore PKCS12 en disco (un archivo, múltiples aliases)</li>
 *   <li>Generar KeyPairs (ECDSA secp256r1 / Ed25519) con certificados X.509 v3</li>
 *   <li>Firmar PDFs con PAdES-BASELINE-B usando DSS como único motor de firma</li>
 * </ul>
 *
 * <h2>Por qué DSS y no PDFBox para firmar</h2>
 * <p>PDFBox puede hacer firma PAdES pero tiene un problema crítico en su implementación
 * de {@code saveIncremental}: los offsets del ByteRange se calculan ANTES de que
 * el objeto COSDictionary de la firma esté completamente serializado, lo que puede
 * generar una discrepancia de bytes entre el ByteRange declarado y el real.
 * Adobe Acrobat detecta esta discrepancia y reporta "Document modified after signing".</p>
 *
 * <p>DSS resuelve esto con un protocolo de dos fases:</p>
 * <ol>
 *   <li><b>Fase 1 — getDataToSign():</b> reserva un bloque /Contents de tamaño fijo
 *       (estimado con margen) y calcula el ByteRange exacto sobre el PDF con ese
 *       placeholder. Devuelve los bytes a firmar (los dos tramos del ByteRange).</li>
 *   <li><b>Fase 2 — signDocument():</b> inserta el CMS real dentro del placeholder
 *       ya reservado, sin mover ningún byte fuera del bloque /Contents.
 *       El ByteRange calculado en fase 1 sigue siendo válido.</li>
 * </ol>
 *
 * <h2>CMS detached</h2>
 * <p>PAdES usa CMS detached: el bloque /Contents contiene una estructura
 * {@code SignedData} de PKCS#7/CMS donde el campo {@code encapContentInfo.eContent}
 * está AUSENTE (null). El contenido firmado (los bytes del ByteRange) está
 * referenciado externamente, no embebido dentro del CMS.
 * Esto es lo que permite que el hash del contenido sea verificable
 * sin extraer los bytes del propio bloque /Contents.</p>
 *
 * <h2>Qué hace ByteRange exactamente</h2>
 * <p>El ByteRange es un array de 4 enteros: {@code [o1, l1, o2, l2]}</p>
 * <ul>
 *   <li>{@code o1} = 0 (siempre empieza al inicio del PDF)</li>
 *   <li>{@code l1} = offset del inicio de {@code <} (inicio del hex del /Contents)</li>
 *   <li>{@code o2} = offset del {@code >} final del /Contents + 1</li>
 *   <li>{@code l2} = bytes restantes hasta el final del PDF</li>
 * </ul>
 * <p>Los bytes firmados = {@code pdf[o1..o1+l1]} + {@code pdf[o2..o2+l2]}.
 * El bloque {@code pdf[l1..o2]} (el /Contents hex) está EXCLUIDO del hash.</p>
 */
@Service
public class SignatureService {

    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    private static final String KEYSTORE_TYPE = "PKCS12";

    @Value("${securesign.keystore-path:securesign.p12}")
    private String keystorePath;

    @Value("${securesign.keystore-password}")
    private String keystorePassword;

    private final CertificateX509Service certificateX509Service;

    public SignatureService(CertificateX509Service certificateX509Service) {
        this.certificateX509Service = certificateX509Service;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PKCS12 KeyStore
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Carga el KeyStore desde disco o crea uno nuevo si no existe.
     * El KeyStore PKCS12 actúa como contenedor de todos los aliases (una entrada por firma).
     */
    private KeyStore cargarKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        File archivo = new File(keystorePath);
        if (archivo.exists()) {
            try (FileInputStream fis = new FileInputStream(archivo)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
        } else {
            ks.load(null, keystorePassword.toCharArray());
        }
        return ks;
    }

    /**
     * Persiste el KeyStore en disco de forma sincronizada.
     * El {@code synchronized} previene corrupción del .p12 si hay
     * dos peticiones concurrentes de generación de claves.
     */
    private synchronized void guardarKeyStore(KeyStore ks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, keystorePassword.toCharArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Generación de KeyPair + Certificado X.509
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Genera un par de claves y un certificado X.509 autofirmado,
     * los almacena en el KeyStore PKCS12 y devuelve el keyId (alias).
     *
     * <p>La curva {@code secp256r1} (NIST P-256) es la que mejor soportan
     * los validadores de Adobe: ECDSA con SHA-256 está en el perfil
     * PAdES-BASELINE-B como algoritmo recomendado.</p>
     *
     * <p>Ed25519 es más moderno y seguro pero algunos validadores legacy
     * no lo reconocen en el CMS. Para compatibilidad máxima usar ECDSA.</p>
     */
    public String generateKeyPairWithCertificate(String algorithm) throws Exception {
        KeyPairGenerator kpg;
        if ("Ed25519".equals(algorithm)) {
            kpg = KeyPairGenerator.getInstance("Ed25519");
        } else {
            kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        KeyPair keyPair = kpg.generateKeyPair();

        X509Certificate cert = certificateX509Service.generarCertificadoX509(keyPair, algorithm);

        String keyId = UUID.randomUUID().toString();
        KeyStore ks = cargarKeyStore();
        ks.setKeyEntry(
                keyId,
                keyPair.getPrivate(),
                keystorePassword.toCharArray(),
                new Certificate[]{cert}
        );
        guardarKeyStore(ks);
        log.info("[KEYGEN] KeyPair generado — alias={}, algorithm={}", keyId, algorithm);
        return keyId;
    }

    public PrivateKey getPrivateKey(String keyId) throws Exception {
        KeyStore ks = cargarKeyStore();
        return (PrivateKey) ks.getKey(keyId, keystorePassword.toCharArray());
    }

    public X509Certificate getCertificate(String keyId) throws Exception {
        KeyStore ks = cargarKeyStore();
        return (X509Certificate) ks.getCertificate(keyId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Firma PAdES con DSS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Firma el PDF con PAdES-BASELINE-B usando DSS como motor exclusivo.
     *
     * <h3>Protocolo DSS de dos fases</h3>
     * <ol>
     *   <li><b>getDataToSign()</b> — DSS escribe un PDF temporal con:
     *     <ul>
     *       <li>el diccionario de firma {@code /Type /Sig /Filter /SubFilter ...}</li>
     *       <li>el ByteRange calculado con exactitud de byte</li>
     *       <li>el bloque /Contents relleno de ceros (placeholder de tamaño fijo)</li>
     *     </ul>
     *     Devuelve {@code ToBeSigned}: los bytes exactos a hashear
     *     (los dos tramos del ByteRange del PDF temporal).
     *   </li>
     *   <li><b>token.sign()</b> — ECDSA/Ed25519 sobre SHA-256 del ToBeSigned.
     *     Devuelve el valor de firma bruto (r||s para ECDSA).</li>
     *   <li><b>signDocument()</b> — DSS construye el CMS SignedData completo,
     *     lo escribe en el placeholder /Contents del PDF temporal,
     *     y devuelve el {@code DSSDocument} final.</li>
     * </ol>
     *
     * <h3>Por qué InMemoryDocument y no FileDocument</h3>
     * <p>InMemoryDocument evita I/O a disco temporal. El PDF de entrada
     * ya está en memoria (byte[]) y DSS opera directamente sobre él.
     * Si usáramos FileDocument con un archivo ya cerrado por PDFBox,
     * DSS podría detectar que el archivo fue modificado durante la operación
     * y lanzar {@code DSSException: File has been modified}.</p>
     *
     * <h3>CommonCertificateVerifier sin revocación</h3>
     * <p>Para certificados autofirmados NO hay OCSP ni CRL.
     * {@code setCheckRevocationForUntrustedChains(false)} es obligatorio,
     * de lo contrario DSS lanza excepción al no encontrar puntos de distribución CRL.</p>
     *
     * @param pdfBytes   PDF generado por PDFBox, completamente cerrado
     * @param privateKey clave privada (solo para referencia en este método — se usa via token)
     * @param cert       certificado X.509 del firmante
     * @param algorithm  "ECDSA" o "Ed25519"
     * @return bytes del PDF firmado con incremento PAdES
     */
    public byte[] firmarPDF(byte[] pdfBytes, PrivateKey privateKey,
                            X509Certificate cert, String algorithm) throws Exception {

        // Localizar el alias del certificado en el KeyStore
        KeyStore ks = cargarKeyStore();
        String alias = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (cert.equals(ks.getCertificate(a))) {
                alias = a;
                break;
            }
        }
        if (alias == null) {
            throw new IllegalStateException(
                    "Alias no encontrado en el KeyStore para el certificado proporcionado. " +
                    "Asegúrate de que generateKeyPairWithCertificate() fue llamado antes de firmarPDF()."
            );
        }

        log.info("[SIGN] Iniciando firma PAdES — alias={}, algorithm={}, pdfSize={} bytes",
                alias, algorithm, pdfBytes.length);

        /*
         * KeyStoreSignatureTokenConnection: adaptador DSS para PKCS12.
         * Encapsula la PrivateKey y expone token.sign() que usa internamente
         * Signature.getInstance() + initSign(privateKey) + sign(dataToSign).
         * Es THREAD-SAFE a nivel de instancia: cada llamada a sign() es atómica.
         *
         * IMPORTANTE: se abre como try-with-resources para garantizar que
         * el KeyStore interno de DSS se cierre aunque haya excepción en medio
         * del protocolo de firma.
         */
        try (KeyStoreSignatureTokenConnection token = new KeyStoreSignatureTokenConnection(
                new File(keystorePath),
                KEYSTORE_TYPE,
                new KeyStore.PasswordProtection(keystorePassword.toCharArray())
        )) {
            KSPrivateKeyEntry keyEntry = (KSPrivateKeyEntry) token.getKey(alias);

            // ── Parámetros PAdES-BASELINE-B ──────────────────────────────────
            PAdESSignatureParameters params = new PAdESSignatureParameters();

            /*
             * PAdES_BASELINE_B:
             * - No incluye sello de tiempo (TSA)
             * - No incluye respuesta OCSP ni CRL
             * - Embebe el certificado del firmante en el CMS
             * - Compatible con verificación offline
             * Suficiente para el propósito educativo de este proyecto.
             */
            params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            /*
             * ENVELOPED: la firma se embebe DENTRO del propio PDF (incremento).
             * ENVELOPING (firma wrapping): no aplica a PAdES.
             * DETACHED (firma separada): crea un archivo .p7s externo — no usamos.
             */
            params.setSignaturePackaging(SignaturePackaging.ENVELOPED);

            params.setSigningCertificate(keyEntry.getCertificate());
            params.setCertificateChain(keyEntry.getCertificateChain());

            /*
             * SHA256 para el DigestAlgorithm del CMS:
             * - Es el hash del "message digest" attribute dentro del SignedAttributes
             * - NO es el hash del contenido del PDF (ese lo calcula DSS internamente
             *   sobre los bytes del ByteRange)
             * - Para ECDSA P-256: SHA256 es el par natural (suite recomendada)
             * - Para Ed25519: el algoritmo internamente usa SHA-512 pero DSS lo maneja
             */
            params.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // ── Verificador de certificados (sin PKI completa) ────────────────
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            /*
             * Para certificados autofirmados sin CRL ni OCSP.
             * Si se omite esta línea, DSS intentará construir la cadena de confianza
             * y lanzará NullPointerException al no encontrar AIA/CDP en el certificado.
             */
            verifier.setCheckRevocationForUntrustedChains(false);

            PAdESService service = new PAdESService(verifier);

            // InMemoryDocument: DSS opera sobre bytes en RAM, sin I/O a disco
            DSSDocument pdfDoc = new InMemoryDocument(pdfBytes);

            // ── Fase 1: calcular bytes a firmar ───────────────────────────────
            // DSS genera el PDF con placeholder y devuelve los bytes del ByteRange
            ToBeSigned dataToSign = service.getDataToSign(pdfDoc, params);
            log.debug("[SIGN] Fase 1 completada — {} bytes a firmar", dataToSign.getBytes().length);

            // ── Fase 2: firmar los bytes del ByteRange ────────────────────────
            // token.sign() = Signature.getInstance(algo).initSign(pk).update(dataToSign).sign()
            SignatureValue signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), keyEntry);
            log.debug("[SIGN] Fase 2 completada — valor de firma generado");

            // ── Fase 3: empaquetar CMS en el PDF ─────────────────────────────
            // DSS escribe el CMS dentro del placeholder /Contents sin mover ningún byte
            DSSDocument signedDoc = service.signDocument(pdfDoc, params, signatureValue);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            signedDoc.writeTo(out);

            byte[] result = out.toByteArray();
            log.info("[SIGN] Firma completada — PDF firmado: {} bytes (original: {} bytes)",
                    result.length, pdfBytes.length);

            return result;
        }
    }
}
