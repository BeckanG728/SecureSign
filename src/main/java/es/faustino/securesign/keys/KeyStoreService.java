package es.faustino.securesign.keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;

@Service
public class KeyStoreService {

    private static final String PKCS12 = "PKCS12";

    @Value("${securesign.keystore-path:securesign.p12}")
    private String rutaArchivo;

    @Value("${securesign.keystore-password}")
    private String claveAcceso;

    public String getRutaArchivo() {
        return rutaArchivo;
    }

    public String getTipo() {
        return PKCS12;
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
}
