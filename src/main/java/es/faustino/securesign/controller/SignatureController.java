package es.faustino.securesign.controller;

import es.faustino.securesign.model.KeyInfoResponse;
import es.faustino.securesign.model.SignRequest;
import es.faustino.securesign.model.SignResponse;
import es.faustino.securesign.model.VerifyRequest;
import es.faustino.securesign.service.SignatureService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
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
     * POST /api/keys/generate?algorithm=Ed25519
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
     * Body: { "keyId": "...", "algorithm": "Ed25519", "data": "<base64>" }
     * Firma el dato y devuelve la firma en Base64.
     */
    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@RequestBody SignRequest request) throws Exception {
        byte[] data = Base64.getDecoder().decode(request.data());
        byte[] firma = signatureService.sign(request.keyId(), request.algorithm(), data);
        return ResponseEntity.ok(new SignResponse(
                request.keyId(),
                request.algorithm(),
                Base64.getEncoder().encodeToString(firma)
        ));
    }

    /**
     * POST /api/verify
     * Body: { "keyId": "...", "algorithm": "Ed25519", "data": "<base64>", "signature": "<base64>" }
     * Verifica si la firma corresponde al dato y clave indicados.
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestBody VerifyRequest request) throws Exception {
        byte[] data = Base64.getDecoder().decode(request.data());
        byte[] firma = Base64.getDecoder().decode(request.signature());
        boolean valida = signatureService.verify(request.keyId(), request.algorithm(), data, firma);
        return ResponseEntity.ok(Map.of("valid", valida));
    }
}
