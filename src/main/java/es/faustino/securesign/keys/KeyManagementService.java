package es.faustino.securesign.keys;

import es.faustino.securesign.services.certificate.CertificateX509Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.UUID;

@Service
public class KeyManagementService {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);

    private final KeyStoreService keyStoreService;
    private final CertificateX509Service certificateX509Service;

    public KeyManagementService(KeyStoreService keyStoreService,
                                CertificateX509Service certificateX509Service) {
        this.keyStoreService = keyStoreService;
        this.certificateX509Service = certificateX509Service;
    }

    public String generarYAlmacenarParDeClaves(String algoritmo) throws Exception {
        KeyPair parDeClaves = generarParDeClaves(algoritmo);
        X509Certificate certificado = certificateX509Service.generarCertificadoX509(parDeClaves, algoritmo);

        String alias = UUID.randomUUID().toString();
        KeyStore keyStore = keyStoreService.cargar();
        keyStore.setKeyEntry(
                alias,
                parDeClaves.getPrivate(),
                keyStoreService.getClaveAccesoComoChars(),
                new Certificate[]{certificado}
        );
        keyStoreService.guardar(keyStore);

        log.info("[GESTION_CLAVES] Par de claves almacenado — alias={}, algoritmo={}", alias, algoritmo);
        return alias;
    }

    public X509Certificate buscarCertificadoPorAlias(String alias) throws Exception {
        KeyStore keyStore = keyStoreService.cargar();
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    private KeyPair generarParDeClaves(String algoritmo) throws Exception {
        if ("Ed25519".equals(algoritmo)) {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        }

        KeyPairGenerator generadorEC = KeyPairGenerator.getInstance("EC");
        generadorEC.initialize(new ECGenParameterSpec("secp256r1"));
        return generadorEC.generateKeyPair();
    }
}
