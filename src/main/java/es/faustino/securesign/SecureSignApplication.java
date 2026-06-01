package es.faustino.securesign;

import es.faustino.securesign.crypto.CryptoIdentityService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Security;

@SpringBootApplication
public class SecureSignApplication {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SecureSignApplication.class, args);
    }

    @Bean
    public ApplicationRunner inicializarIdentidades(CryptoIdentityService cryptoIdentityService) {
        return args -> cryptoIdentityService.inicializarIdentidades();
    }
}
