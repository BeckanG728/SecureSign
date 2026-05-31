package es.faustino.securesign.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

/**
 * Registra BouncyCastle como provider de seguridad de Java.
 *
 * <h2>Por qué es necesario</h2>
 * <p>Algunas operaciones criptográficas usadas por DSS y BouncyCastle requieren
 * que el provider {@code BC} esté registrado en {@code java.security.Security}
 * antes de ser invocadas:</p>
 * <ul>
 *   <li>{@code JcaX509CertificateConverter.setProvider("BC")} en la verificación</li>
 *   <li>{@code JcaSimpleSignerInfoVerifierBuilder.setProvider("BC")} para ECDSA/Ed25519</li>
 *   <li>Ed25519 (no disponible en el JDK 17 por defecto sin BouncyCastle)</li>
 *   <li>ECDSA con curvas no estándar</li>
 * </ul>
 *
 * <h2>Posición del provider</h2>
 * <p>{@code Security.insertProviderAt(bc, 1)} registra BC como el provider
 * de MAYOR prioridad. Esto evita que el JDK SunEC provider intercepte las
 * operaciones ECDSA antes que BouncyCastle, lo que puede causar
 * {@code SignatureException} con claves generadas por BC.</p>
 *
 * <p>Alternativa más segura: {@code Security.addProvider()} (posición final).
 * Funciona si el JDK soporta el algoritmo; usar posición 1 solo si hay
 * conflictos entre providers.</p>
 */
@Configuration
public class BouncyCastleConfig {

    @PostConstruct
    public void registrarBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }
}
