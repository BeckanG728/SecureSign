package es.faustino.securesign.crypto;

import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Service
public class KeyStoreAccessService {

    private static final String PKCS12 = "PKCS12";

    @Value("${securesign.keystore-path:securesign.p12}")
    private String rutaArchivo;

    @Value("${securesign.keystore-password}")
    private String claveAcceso;

    public KeyStoreAccessService() {
    }

    public KeyStoreAccessService(String rutaArchivo, String claveAcceso) {
        this.rutaArchivo = rutaArchivo;
        this.claveAcceso = claveAcceso;
    }

    public char[] getClaveAccesoComoChars() {
        return claveAcceso.toCharArray();
    }

    public KeyStore cargar() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        File archivo = new File(rutaArchivo);

        if (archivo.exists()) {
            try (FileInputStream flujoEntrada = new FileInputStream(archivo)) {
                keyStore.load(flujoEntrada, claveAcceso.toCharArray());
            }
        } else {
            keyStore.load(null, claveAcceso.toCharArray());
        }

        return keyStore;
    }

    public synchronized void guardar(KeyStore keyStore) throws Exception {
        try (FileOutputStream flujoSalida = new FileOutputStream(rutaArchivo)) {
            keyStore.store(flujoSalida, claveAcceso.toCharArray());
        }
    }

    public String buscarAliasPorCertificado(X509Certificate certificado) throws Exception {
        KeyStore keyStore = cargar();
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

    public KeyStoreSignatureTokenConnection abrirConexionToken() throws IOException {
        return new KeyStoreSignatureTokenConnection(
                new File(rutaArchivo),
                PKCS12,
                new KeyStore.PasswordProtection(claveAcceso.toCharArray())
        );
    }
}
