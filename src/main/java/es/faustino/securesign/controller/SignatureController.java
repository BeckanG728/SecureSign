package es.faustino.securesign.controller;

import es.faustino.securesign.model.KeyInfoResponse;
import es.faustino.securesign.model.SignRequest;
import es.faustino.securesign.model.SignResponse;
import es.faustino.securesign.model.VerifyRequest;
import es.faustino.securesign.service.SignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin("http://localhost:5500")
public class SignatureController {

    private final SignatureService signatureService;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    /**
     * POST /api/keys/generate?algorithm=Ed25519|ECDSA|RSA
     * Genera un par de claves y devuelve el keyId.
     */
    @PostMapping("/keys/generate")
    public ResponseEntity<Map<String, String>> generateKeys(@RequestParam String algorithm) throws Exception {
        String keyId = signatureService.generateKeyPair(algorithm);
        return ResponseEntity.ok(Map.of(
                "keyId", keyId,
                "algorithm", algorithm
        ));
    }

    /**
     * GET /api/keys/{keyId}
     * Devuelve la clave pública (Base64) y el algoritmo asociado al keyId.
     */
    @GetMapping("/keys/{keyId}")
    public ResponseEntity<KeyInfoResponse> getKeyInfo(@PathVariable String keyId) {
        return ResponseEntity.ok(signatureService.getKeyInfo(keyId));
    }

    /**
     * POST /api/sign
     * Body: { "keyId": "...", "algorithm": "Ed25519|ECDSA|RSA", "data": "texto plano" }
     * Hashea el texto con SHA-256 en el backend, firma el hash y devuelve ambos.
     */
    // TODO B-4: El campo "data" llega como texto plano (String). Conviértelo a bytes UTF-8.
    // Llama al servicio que devuelve Object[]{ hashHex, firma[] }.
    // Decodifica cada elemento y construye la respuesta SignResponse con Base64 de la firma.
    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@RequestBody SignRequest request) throws Exception {
        // TODO: implementar
        return null;
    }

    /**
     * POST /api/verify
     * Body: { "keyId": "...", "algorithm": "Ed25519|ECDSA|RSA", "data": "texto plano", "signature": "<base64>" }
     * Recalcula el hash SHA-256 del texto y verifica la firma contra él.
     */
    // TODO C-4: "data" llega como texto plano; "signature" llega en Base64 y debe decodificarse.
    // El servicio devuelve un boolean que se incluye directamente en la respuesta.
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestBody VerifyRequest request) throws Exception {
        // TODO: implementar
        return null;
    }
}
