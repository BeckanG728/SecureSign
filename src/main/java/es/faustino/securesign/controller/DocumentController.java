package es.faustino.securesign.controller;

import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.services.SignatureService;
import es.faustino.securesign.services.VerificationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final SignatureService signatureService;
    private final VerificationService verificationService;

    public DocumentController(SignatureService signatureService,
                              VerificationService verificationService) {
        this.signatureService = signatureService;
        this.verificationService = verificationService;
    }

    @PostMapping("/sign")
    public ResponseEntity<byte[]> sign(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "algorithm") String algoritmo) throws Exception {

        byte[] pdfFirmado = signatureService.firmarDocumento(file.getBytes(), algoritmo);
        String nombreArchivo = construirNombreArchivo(file.getOriginalFilename());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + nombreArchivo + "\"")
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(pdfFirmado.length))
                .body(pdfFirmado);
    }

    private String construirNombreArchivo(String nombreOriginal) {
        String nombreBase = (nombreOriginal != null && nombreOriginal.endsWith(".pdf"))
                ? nombreOriginal.replace(".pdf", "")
                : "documento";
        return nombreBase + "_firmado.pdf";
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
