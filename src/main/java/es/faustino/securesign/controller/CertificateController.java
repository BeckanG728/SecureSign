package es.faustino.securesign.controller;

import es.faustino.securesign.model.CertificateRequest;
import es.faustino.securesign.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api/certificates")
@CrossOrigin("http://localhost:5500")
public class CertificateController {

    private final CertificateService certificateService;

    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    /**
     * POST /api/certificates/generate
     * Body JSON: { nombre, dni, tipo, fecha, algorithm }
     * Genera el PDF institucional, lo firma y lo devuelve como application/pdf.
     * Headers de respuesta: X-Key-Id, X-Algorithm
     */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generate(@RequestBody CertificateRequest request) throws Exception {
        Map<String, Object> result = certificateService.emitirCertificado(
                request.nombre(), request.dni(),
                request.tipo(), request.fecha(),
                request.algorithm()
        );

        byte[] pdf = (byte[]) result.get("pdf");
        String keyId = (String) result.get("keyId");

        return ResponseEntity.ok()
                .header("Content-Type", "application/pdf")
                .header("X-Key-Id", keyId)
                .header("X-Algorithm", request.algorithm())
                .body(pdf);
    }

    /**
     * POST /api/certificates/verify
     * Params: keyId, algorithm
     * Body: multipart/form-data con el PDF a verificar
     * Respuesta: { valid, keyId, algorithm }
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(
            @RequestParam String keyId,
            @RequestParam String algorithm,
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfBytes = file.getBytes();
        boolean valida = certificateService.verificarCertificado(keyId, algorithm, pdfBytes);

        return ResponseEntity.ok(Map.of(
                "valid", valida,
                "keyId", keyId,
                "algorithm", algorithm
        ));
    }
}
