package es.faustino.securesign.signature;

import es.faustino.securesign.certificate.CertificateX509Service;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;

/**
 * Gestiona el KeyStore PKCS12 persistente en disco y la firma PAdES sobre PDFs.
 * La clave privada solo existe en memoria durante el tiempo de firma.
 */
@Service
public class SignatureService {

    private static final String KEYSTORE_PATH = "securesign.p12";
    private static final String KEYSTORE_TYPE = "PKCS12";

    @Value("${securesign.keystore-password}")
    private String keystorePassword;

    private final CertificateX509Service certificateX509Service;

    public SignatureService(CertificateX509Service certificateX509Service) {
        this.certificateX509Service = certificateX509Service;
    }

    // ── PKCS12 KeyStore ───────────────────────────────────────────────────────

    private KeyStore cargarKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        File archivo = new File(KEYSTORE_PATH);
        if (archivo.exists()) {
            try (FileInputStream fis = new FileInputStream(archivo)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
        } else {
            ks.load(null, keystorePassword.toCharArray());
        }
        return ks;
    }

    private synchronized void guardarKeyStore(KeyStore ks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            ks.store(fos, keystorePassword.toCharArray());
        }
    }

    // ── Generación de KeyPair + Certificado X.509 → PKCS12 ───────────────────

    /**
     * Genera un KeyPair, un certificado X.509 autofirmado y los almacena
     * juntos en el KeyStore PKCS12. Devuelve el keyId (alias en el KeyStore).
     */
    public String generateKeyPairWithCertificate(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                algorithm.equals("Ed25519") ? "Ed25519" : "EC"
        );
        if (!algorithm.equals("Ed25519")) {
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

    // ── Firma PAdES ───────────────────────────────────────────────────────────

    /**
     * Firma el PDF y embebe la firma + certificado X.509 en el propio documento (PAdES).
     * Devuelve los bytes del PDF autocontenible y verificable de forma independiente.
     */
    public byte[] firmarPDF(byte[] pdfBytes, PrivateKey privateKey,
                            X509Certificate cert, String algorithm) throws Exception {

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("SecureSign Institucional");
            signature.setSignDate(Calendar.getInstance());

            SignatureOptions options = new SignatureOptions();
            options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

            final String sigAlg = algorithm.equals("Ed25519") ? "Ed25519" : "SHA256withECDSA";
            final X509Certificate finalCert = cert;
            final PrivateKey finalKey = privateKey;

            document.addSignature(signature, signedContent -> {
                byte[] content = signedContent.readAllBytes();
                try {
                    return buildCmsSignature(content, finalKey, finalCert, sigAlg);
                } catch (Exception e) {
                    throw new IOException("Error al construir la firma CMS", e);
                }
            }, options);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.saveIncremental(out);
            return out.toByteArray();
        }
    }

    // ── Helpers CMS ───────────────────────────────────────────────────────────

    private byte[] buildCmsSignature(byte[] content, PrivateKey privateKey,
                                     X509Certificate cert, String sigAlg) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).build(privateKey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().build()
                ).build(signer, cert)
        );
        gen.addCertificates(new JcaCertStore(List.of(cert)));

        CMSSignedData signedData = gen.generate(
                new CMSProcessableByteArray(content), false
        );
        return signedData.getEncoded();
    }
}
