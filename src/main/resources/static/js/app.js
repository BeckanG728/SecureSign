/**
 * app.js
 * Lógica principal: tabs, event listeners, orquestación.
 * Depende de: api.js, ui.js
 */

document.addEventListener('DOMContentLoaded', () => {

    // ── Tabs ──────────────────────────────────────────────────────────────────
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanels = document.querySelectorAll('.tab-panel');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.dataset.tab;
            navItems.forEach(n => n.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));
            item.classList.add('active');
            document.getElementById('tab-' + target).classList.add('active');
        });
    });

    // ── Elementos ─────────────────────────────────────────────────────────────
    const btnGenerate    = document.getElementById('btn-generate');
    const generateStatus = document.getElementById('generate-status');

    const btnVerify      = document.getElementById('btn-verify');
    const verifyResult   = document.getElementById('verify-result');
    const fileInput      = document.getElementById('file-input');
    const fileSelected   = document.getElementById('file-selected');
    const fileNameEl     = document.getElementById('file-name');
    const btnClearFile   = document.getElementById('btn-clear-file');
    const dropZone       = document.getElementById('drop-zone');

    // Fecha actual por defecto
    document.getElementById('fecha').value = new Date().toISOString().split('T')[0];

    // ── Drop-zone ─────────────────────────────────────────────────────────────
    let selectedFile = null;

    dropZone.addEventListener('dragover', e => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file && file.type === 'application/pdf') handleFileSelected(file);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) handleFileSelected(fileInput.files[0]);
    });
    btnClearFile.addEventListener('click', e => {
        e.stopPropagation();
        clearFile();
    });

    function handleFileSelected(file) {
        selectedFile = file;
        fileNameEl.textContent = file.name;
        fileSelected.classList.remove('hidden');
        btnVerify.disabled = false;
        hideElement(verifyResult);
        verifyResult.className = 'verify-result hidden';
    }

    function clearFile() {
        selectedFile = null;
        fileInput.value = '';
        fileSelected.classList.add('hidden');
        btnVerify.disabled = true;
        hideElement(verifyResult);
        verifyResult.className = 'verify-result hidden';
    }

    // ── Generar documento ─────────────────────────────────────────────────────
    btnGenerate.addEventListener('click', async () => {
        const nombre    = document.getElementById('nombre').value.trim();
        const dni       = document.getElementById('dni').value.trim();
        const tipo      = document.getElementById('tipo').value;
        const fecha     = document.getElementById('fecha').value;
        const algorithm = document.querySelector('input[name="algorithm"]:checked').value;

        if (!nombre || !dni || !fecha) {
            showStatus(generateStatus, 'error', 'Completa todos los campos antes de continuar.');
            return;
        }

        setButtonLoading(btnGenerate, true, 'Generando...', 'Generar y descargar PDF', 'ti-download');
        showStatus(generateStatus, 'loading', 'Generando documento firmado, por favor espera…');

        try {
            const blob = await apiGenerateDocument({ nombre, dni, tipo, fecha, algorithm });
            downloadBlob(blob, 'documento_firmado.pdf');
            showStatus(generateStatus, 'success', 'Documento generado y descargado correctamente.');
        } catch (error) {
            showStatus(generateStatus, 'error', 'Error: ' + error.message);
        } finally {
            setButtonLoading(btnGenerate, false, '', 'Generar y descargar PDF', 'ti-download');
        }
    });

    // ── Verificar documento ───────────────────────────────────────────────────
    btnVerify.addEventListener('click', async () => {
        if (!selectedFile) return;

        setButtonLoading(btnVerify, true, 'Verificando...', 'Verificar firma', 'ti-shield-search');
        hideElement(verifyResult);

        try {
            const result = await apiVerifyDocument(selectedFile);
            renderVerifyResult(verifyResult, result);
        } catch (error) {
            verifyResult.className = 'verify-result invalid';
            verifyResult.classList.remove('hidden');
            verifyResult.innerHTML = `
                <div class="result-header">
                    <i class="ti ti-circle-x" aria-hidden="true"></i>
                    Error al verificar: ${error.message}
                </div>
            `;
        } finally {
            setButtonLoading(btnVerify, false, '', 'Verificar firma', 'ti-shield-search');
        }
    });
});
