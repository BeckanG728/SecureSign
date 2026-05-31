package es.faustino.securesign.controller;

import es.faustino.securesign.document.DocumentService;
import es.faustino.securesign.dto.response.VerificationResultResponse;
import es.faustino.securesign.model.DocumentRequest;
import es.faustino.securesign.verification.VerificationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * Endpoints REST PAdES.
 *
 * <ul>
 *   <li>{@code POST /api/documents/generate} — genera y firma un PDF (PAdES-BASELINE-B)</li>
 *   <li>{@code POST /api/documents/verify} — verifica un PDF firmado</li>
 * </ul>
 *
 * <h2>Diseño: el PDF es autocontenible</h2>
 * <p>El endpoint {@code /generate} devuelve un único PDF firmado.
 * El PDF contiene embebidos el certificado X.509 y la firma CMS en el bloque /Contents.
 * No se requiere el keyId para verificar — el PDF es suficiente por sí solo.
 * Esto es el modelo PAdES: verificación offline sin contactar al servidor.</p>
 *
 * <h2>Respuesta de verificación diferenciada</h2>
 * <p>El endpoint {@code /verify} devuelve los flags de integridad estructural
 * ({@code firmaExtraible}, {@code cmsParseable}, {@code byteRangeValido})
 * además del resultado criptográfico ({@code firmaValida}).
 * Esto permite al cliente diferenciar entre un PDF corrupto (nunca debe ocurrir)
 * y un PDF con firma inválida (comportamiento correcto cuando el usuario lo modifica).</p>
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
     * Genera un PDF institucional y lo firma con PAdES-BASELINE-B.
     *
     * <p>Flujo interno:</p>
     * <ol>
     *   <li>PDFBox 3.x genera el PDF y lo cierra completamente</li>
     *   <li>Se genera un KeyPair + certificado X.509 autofirmado</li>
     *   <li>DSS firma el PDF con PAdES (protocolo de dos fases)</li>
     *   <li>Se devuelve el PDF firmado como application/pdf</li>
     * </ol>
     *
     * <p>El PDF devuelto NO debe ser procesado ni modificado en el backend.
     * Cualquier modificación posterior invalidará la firma criptográfica.</p>
     *
     * @param request datos del documento (nombre, dni, tipo, fecha, algorithm)
     * @return PDF firmado como application/pdf para descarga directa
     */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generate(@RequestBody DocumentRequest request) throws Exception {
        byte[] pdfFirmado = documentService.emitirDocumentoFirmado(
                request.nombre(), request.dni(),
                request.tipo(), request.fecha(),
                request.algorithm()
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"documento_firmado.pdf\"")
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(pdfFirmado.length))
                .body(pdfFirmado);
    }

    /**
     * Verifica un PDF firmado de forma completamente offline.
     *
     * <p>No requiere keyId ni ningún estado del servidor.
     * Toda la información necesaria (certificado, firma, ByteRange) está
     * embebida en el propio PDF.</p>
     *
     * <p>La respuesta incluye flags que diferencian entre:</p>
     * <ul>
     *   <li><b>PDF no firmado:</b> {@code firmaExtraible=false}</li>
     *   <li><b>PDF estructuralmente corrupto:</b> {@code byteRangeValido=false} o {@code cmsParseable=false}</li>
     *   <li><b>PDF modificado (firma inválida):</b> {@code firmaExtraible=true, cmsParseable=true, firmaValida=false}</li>
     *   <li><b>PDF íntegro:</b> {@code firmaValida=true, valid=true}</li>
     * </ul>
     *
     * @param file PDF firmado (puede haber sido modificado por el usuario)
     * @return resultado de verificación con flags detallados
     */
    @PostMapping("/verify")
    public ResponseEntity<VerificationResultResponse> verify(
            @RequestParam MultipartFile file) throws Exception {

        byte[] pdfFirmadoBytes = file.getBytes();
        VerificationResultResponse resultado =
                verificationService.verificarDocumentoFirmado(pdfFirmadoBytes);

        return ResponseEntity.ok(resultado);
    }
}
