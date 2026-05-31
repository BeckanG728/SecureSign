package es.faustino.securesign.controller;

import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.services.document.DocumentService;
import es.faustino.securesign.services.verification.VerificationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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

    @PostMapping("/sign")
    public ResponseEntity<byte[]> generate(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "algorithm", defaultValue = "EC") String algorithm) throws Exception {

        byte[] pdfFirmado = documentService.firmarDocumento(file.getBytes(), algorithm);

        String nombreOriginal = file.getOriginalFilename();
        String nombreBase = (nombreOriginal != null && nombreOriginal.endsWith(".pdf"))
                ? nombreOriginal.replace(".pdf", "")
                : "documento";
        String nombreArchivo = nombreBase + "_firmado.pdf";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + nombreArchivo + "\"")
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(pdfFirmado.length))
                .body(pdfFirmado);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerificationResultResponse> verify(
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfFirmadoBytes = file.getBytes();
        VerificationResultResponse resultado =
                verificationService.verificarDocumentoFirmado(pdfFirmadoBytes);

        return ResponseEntity.ok(resultado);
    }
}
