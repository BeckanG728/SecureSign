package es.faustino.securesign.crypto;

import es.faustino.securesign.crypto.CertificateX509Service;
import es.faustino.securesign.shared.enums.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

@Service
public class CryptoIdentityService {

    private static final Logger log = LoggerFactory.getLogger(CryptoIdentityService.class);

    private final KeyStoreAccessService keyStoreAccessService;
    private final CertificateX509Service certificateX509Service;

    @Value("${securesign.alias-ecdsa}")
    private String aliasEcdsa;

    @Value("${securesign.alias-ed25519}")
    private String aliasEd25519;

    public CryptoIdentityService(KeyStoreAccessService keyStoreAccessService,
                                 CertificateX509Service certificateX509Service) {
        this.keyStoreAccessService = keyStoreAccessService;
        this.certificateX509Service = certificateX509Service;
    }

    public void inicializarIdentidades() throws Exception {
        KeyStore keyStore = keyStoreAccessService.cargar();
        inicializarSiAusente(keyStore, aliasEcdsa, SignatureAlgorithm.SHA256_WITH_ECDSA);
        inicializarSiAusente(keyStore, aliasEd25519, SignatureAlgorithm.ED25519);
        keyStoreAccessService.guardar(keyStore);
    }

    public X509Certificate obtenerCertificado(SignatureAlgorithm algoritmo) throws Exception {
        String alias = resolverAlias(algoritmo);
        KeyStore keyStore = keyStoreAccessService.cargar();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        if (cert == null) {
            throw new IllegalStateException("Identidad no inicializada — alias: " + alias);
        }
        return cert;
    }

    public String resolverAlias(SignatureAlgorithm algoritmo) {
        return switch (algoritmo) {
            case SHA256_WITH_ECDSA -> aliasEcdsa;
            case ED25519 -> aliasEd25519;
            default -> throw new IllegalArgumentException("Algoritmo no firmante: " + algoritmo);
        };
    }

    private void inicializarSiAusente(KeyStore keyStore, String alias, SignatureAlgorithm algoritmo) throws Exception {
        if (keyStore.containsAlias(alias)) {
            log.info("[CRYPTO_IDENTITY] Identidad ya existe — alias={}", alias);
            return;
        }

        log.info("[CRYPTO_IDENTITY] Inicializando identidad — alias={}, algoritmo={}", alias, algoritmo.getJcaName());

        KeyPair parDeClaves = algoritmo.generarParDeClaves();
        X509Certificate certificado = certificateX509Service.generarCertificadoX509(parDeClaves, algoritmo.getJcaName());

        keyStore.setKeyEntry(alias, parDeClaves.getPrivate(),
                keyStoreAccessService.getClaveAccesoComoChars(), new Certificate[]{certificado});

        log.info("[CRYPTO_IDENTITY] Identidad creada — alias={}, subject={}", alias,
                certificado.getSubjectX500Principal().getName());
    }
}
