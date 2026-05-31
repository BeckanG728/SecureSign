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

    // ── Elementos: Firmar ─────────────────────────────────────────────────────
    const btnGenerate      = document.getElementById('btn-generate');
    const generateStatus   = document.getElementById('generate-status');
    const fileInputSign    = document.getElementById('file-input-sign');
    const fileSelectedSign = document.getElementById('file-selected-sign');
    const fileNameSign     = document.getElementById('file-name-sign');
    const btnClearSign     = document.getElementById('btn-clear-sign');
    const dropZoneSign     = document.getElementById('drop-zone-sign');

    // ── Elementos: Verificar ──────────────────────────────────────────────────
    const btnVerify      = document.getElementById('btn-verify');
    const verifyResult   = document.getElementById('verify-result');
    const fileInput      = document.getElementById('file-input');
    const fileSelected   = document.getElementById('file-selected');
    const fileNameEl     = document.getElementById('file-name');
    const btnClearFile   = document.getElementById('btn-clear-file');
    const dropZone       = document.getElementById('drop-zone');

    // ── Drop-zone: Firmar ─────────────────────────────────────────────────────
    let selectedFileSign = null;

    dropZoneSign.addEventListener('dragover', e => {
        e.preventDefault();
        dropZoneSign.classList.add('drag-over');
    });
    dropZoneSign.addEventListener('dragleave', () => dropZoneSign.classList.remove('drag-over'));
    dropZoneSign.addEventListener('drop', e => {
        e.preventDefault();
        dropZoneSign.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file && file.type === 'application/pdf') handleFileSignSelected(file);
    });
    fileInputSign.addEventListener('change', () => {
        if (fileInputSign.files[0]) handleFileSignSelected(fileInputSign.files[0]);
    });
    btnClearSign.addEventListener('click', e => {
        e.stopPropagation();
        clearFileSign();
    });

    function handleFileSignSelected(file) {
        selectedFileSign = file;
        fileNameSign.textContent = file.name;
        fileSelectedSign.classList.remove('hidden');
        btnGenerate.disabled = false;
        hideElement(generateStatus);
        generateStatus.className = 'status-msg hidden';
    }

    function clearFileSign() {
        selectedFileSign = null;
        fileInputSign.value = '';
        fileSelectedSign.classList.add('hidden');
        btnGenerate.disabled = true;
        hideElement(generateStatus);
        generateStatus.className = 'status-msg hidden';
    }

    // ── Drop-zone: Verificar ──────────────────────────────────────────────────
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

    // ── Firmar documento ──────────────────────────────────────────────────────
    btnGenerate.addEventListener('click', async () => {
        if (!selectedFileSign) return;

        const algorithm = document.querySelector('input[name="algorithm"]:checked').value;

        setButtonLoading(btnGenerate, true, 'Firmando...', 'Firmar y descargar PDF', 'ti-pen');
        showStatus(generateStatus, 'loading', 'Firmando documento, por favor espera…');

        try {
            const blob = await apiGenerateDocument(selectedFileSign, algorithm);
            const nombreFirmado = selectedFileSign.name.replace(/\.pdf$/i, '_firmado.pdf');
            downloadBlob(blob, nombreFirmado);
            showStatus(generateStatus, 'success', 'Documento firmado y descargado correctamente.');
        } catch (error) {
            showStatus(generateStatus, 'error', 'Error: ' + error.message);
        } finally {
            setButtonLoading(btnGenerate, false, '', 'Firmar y descargar PDF', 'ti-pen');
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
