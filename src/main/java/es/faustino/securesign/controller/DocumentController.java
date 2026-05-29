package es.faustino.securesign.controller;

import es.faustino.securesign.document.DocumentService;
import es.faustino.securesign.model.DocumentRequest;
import es.faustino.securesign.verification.VerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

/**
 * Endpoints REST del modelo PAdES:
 * - POST /api/documents/generate → PDF firmado autocontenible
 * - POST /api/documents/verify   → verificación independiente del servidor
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentService documentService;
    private final VerificationService verificationService;

    public DocumentController(DocumentService documentService,
                              VerificationService verificationService) {
        this.documentService = documentService;
        this.verificationService = verificationService;
    }

    /**
     * POST /api/documents/generate
     * Body JSON: { nombre, dni, tipo, fecha, algorithm }
     * Genera el PDF, lo firma y embebe la firma (PAdES).
     * Devuelve un único PDF autocontenible. No devuelve keyId.
     */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generate(@RequestBody DocumentRequest request) throws Exception {
        byte[] pdfFirmado = documentService.emitirDocumentoFirmado(
                request.nombre(), request.dni(),
                request.tipo(), request.fecha(),
                request.algorithm()
        );

        return ResponseEntity.ok()
                .header("Content-Type", "application/pdf")
                .header("Content-Disposition", "attachment; filename=documento_firmado.pdf")
                .body(pdfFirmado);
    }

    /**
     * POST /api/documents/verify
     * Param multipart: file (PDF firmado)
     * Extrae la firma y el certificado X.509 directamente del PDF.
     * No requiere keyId ni algorithm — el PDF es autocontenible.
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfFirmadoBytes = file.getBytes();
        Map<String, Object> resultado = verificationService.verificarDocumentoFirmado(pdfFirmadoBytes);

        return ResponseEntity.ok(resultado);
    }
}
