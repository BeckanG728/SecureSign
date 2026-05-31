/**
 * ui.js
 * Funciones de manipulación del DOM: estados, renderizado de resultados, drop-zone.
 */

function showStatus(el, type, text) {
    el.className = 'status-msg ' + type;
    el.textContent = text;
    el.classList.remove('hidden');
}

function hideElement(el) {
    el.classList.add('hidden');
}

function setButtonLoading(btn, loading, loadingText, defaultText, icon) {
    btn.disabled = loading;
    btn.innerHTML = loading
        ? loadingText
        : `<i class="ti ${icon}" aria-hidden="true"></i> ${defaultText}`;
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

/**
 * Renderiza el resultado de verificación.
 * @param {HTMLElement} container
 * @param {Object} result
 */
function renderVerifyResult(container, result) {
    const isValid = result.valid === true;
    container.className = 'verify-result ' + (isValid ? 'valid' : 'invalid');
    container.classList.remove('hidden');

    const headerIcon = isValid ? 'ti-circle-check' : 'ti-circle-x';
    const headerText = isValid
        ? 'Documento auténtico y verificado'
        : result.razon || 'El documento ha sido modificado o la firma no es válida';

    function boolBadge(val) {
        return val
            ? `<span class="badge-ok"><i class="ti ti-check"></i> Válido</span>`
            : `<span class="badge-fail"><i class="ti ti-x"></i> Inválido</span>`;
    }

    const rows = [
        { label: 'Firma criptográfica',    value: boolBadge(result.firmaValida) },
        { label: 'Certificado vigente',    value: boolBadge(result.certificadoVigente) },
        { label: 'Algoritmo de firma',     value: result.algoritmo  || '—' },
        { label: 'Sujeto del certificado', value: result.subject     || '—' },
        { label: 'Válido desde',           value: result.validoDesde || '—' },
        { label: 'Válido hasta',           value: result.validoHasta || '—' },
    ];

    container.innerHTML = `
        <div class="result-header">
            <i class="ti ${headerIcon}" aria-hidden="true"></i>
            ${headerText}
        </div>
        <div class="result-body">
            ${rows.map(r => `
                <div class="result-row">
                    <span class="result-row-label">${r.label}</span>
                    <span class="result-row-value">${r.value}</span>
                </div>
            `).join('')}
        </div>
    `;
}

/**
 * Configura la drop-zone: arrastrar/soltar y selección de archivo.
 * @param {Object} opts
 */
function initDropZone({ dropZone, fileInput, fileSelected, fileName, btnClear, onFile, onClear }) {
    dropZone.addEventListener('dragover', e => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) onFile(file);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) onFile(fileInput.files[0]);
    });
    btnClear.addEventListener('click', e => {
        e.stopPropagation();
        fileInput.value = '';
        fileSelected.classList.add('hidden');
        onClear();
    });

    function onFile(file) {
        fileName.textContent = file.name;
        fileSelected.classList.remove('hidden');
        onFile._current = file;
        if (onFile._cb) onFile._cb(file);
    }
    onFile._cb = onFile;

    return {
        getFile: () => fileInput.files[0] || onFile._current
    };
}
