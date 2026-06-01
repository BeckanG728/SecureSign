document.addEventListener('DOMContentLoaded', () => {

    const elementosNav = document.querySelectorAll('.nav-item');
    const panelesPestana = document.querySelectorAll('.tab-panel');

    elementosNav.forEach(item => {
        item.addEventListener('click', () => {
            const destino = item.dataset.tab;
            elementosNav.forEach(n => n.classList.remove('active'));
            panelesPestana.forEach(p => p.classList.remove('active'));
            item.classList.add('active');
            document.getElementById('tab-' + destino).classList.add('active');
        });
    });

    const btnGenerar              = document.getElementById('btn-generate');
    const estadoGenerar           = document.getElementById('generate-status');
    const inputArchivoFirma       = document.getElementById('file-input-sign');
    const archivoSeleccionadoFirma = document.getElementById('file-selected-sign');
    const nombreArchivoFirma      = document.getElementById('file-name-sign');
    const btnLimpiarFirma         = document.getElementById('btn-clear-sign');
    const zonaArrastreFirma       = document.getElementById('drop-zone-sign');

    const btnVerificar             = document.getElementById('btn-verify');
    const resultadoVerificacion    = document.getElementById('verify-result');
    const inputArchivo             = document.getElementById('file-input');
    const archivoSeleccionado      = document.getElementById('file-selected');
    const nombreArchivoEl          = document.getElementById('file-name');
    const btnLimpiarArchivo        = document.getElementById('btn-clear-file');
    const zonaArrastre             = document.getElementById('drop-zone');

    let archivoFirmaSeleccionado = null;

    zonaArrastreFirma.addEventListener('dragover', e => {
        e.preventDefault();
        zonaArrastreFirma.classList.add('drag-over');
    });
    zonaArrastreFirma.addEventListener('dragleave', () => zonaArrastreFirma.classList.remove('drag-over'));
    zonaArrastreFirma.addEventListener('drop', e => {
        e.preventDefault();
        zonaArrastreFirma.classList.remove('drag-over');
        const archivo = e.dataTransfer.files[0];
        if (archivo && archivo.type === 'application/pdf') alSeleccionarArchivoFirma(archivo);
    });
    inputArchivoFirma.addEventListener('change', () => {
        if (inputArchivoFirma.files[0]) alSeleccionarArchivoFirma(inputArchivoFirma.files[0]);
    });
    btnLimpiarFirma.addEventListener('click', e => {
        e.stopPropagation();
        limpiarArchivoFirma();
    });

    function alSeleccionarArchivoFirma(archivo) {
        archivoFirmaSeleccionado = archivo;
        nombreArchivoFirma.textContent = archivo.name;
        archivoSeleccionadoFirma.classList.remove('hidden');
        btnGenerar.disabled = false;
        hideElement(estadoGenerar);
        estadoGenerar.className = 'status-msg hidden';
    }

    function limpiarArchivoFirma() {
        archivoFirmaSeleccionado = null;
        inputArchivoFirma.value = '';
        archivoSeleccionadoFirma.classList.add('hidden');
        btnGenerar.disabled = true;
        hideElement(estadoGenerar);
        estadoGenerar.className = 'status-msg hidden';
    }

    let archivoVerificacionSeleccionado = null;

    zonaArrastre.addEventListener('dragover', e => {
        e.preventDefault();
        zonaArrastre.classList.add('drag-over');
    });
    zonaArrastre.addEventListener('dragleave', () => zonaArrastre.classList.remove('drag-over'));
    zonaArrastre.addEventListener('drop', e => {
        e.preventDefault();
        zonaArrastre.classList.remove('drag-over');
        const archivo = e.dataTransfer.files[0];
        if (archivo && archivo.type === 'application/pdf') alSeleccionarArchivo(archivo);
    });
    inputArchivo.addEventListener('change', () => {
        if (inputArchivo.files[0]) alSeleccionarArchivo(inputArchivo.files[0]);
    });
    btnLimpiarArchivo.addEventListener('click', e => {
        e.stopPropagation();
        limpiarArchivo();
    });

    function alSeleccionarArchivo(archivo) {
        archivoVerificacionSeleccionado = archivo;
        nombreArchivoEl.textContent = archivo.name;
        archivoSeleccionado.classList.remove('hidden');
        btnVerificar.disabled = false;
        hideElement(resultadoVerificacion);
        resultadoVerificacion.className = 'verify-result hidden';
    }

    function limpiarArchivo() {
        archivoVerificacionSeleccionado = null;
        inputArchivo.value = '';
        archivoSeleccionado.classList.add('hidden');
        btnVerificar.disabled = true;
        hideElement(resultadoVerificacion);
        resultadoVerificacion.className = 'verify-result hidden';
    }

    btnGenerar.addEventListener('click', async () => {
        if (!archivoFirmaSeleccionado) return;

        const algoritmo = document.querySelector('input[name="algorithm"]:checked').value;

        setButtonLoading(btnGenerar, true, 'Firmando...', 'Firmar y descargar PDF', 'ti-pen');
        showStatus(estadoGenerar, 'loading', 'Firmando documento, por favor espera…');

        try {
            const blob = await firmarDocumento(archivoFirmaSeleccionado, algoritmo);
            const nombreFirmado = archivoFirmaSeleccionado.name.replace(/\.pdf$/i, '_firmado.pdf');
            downloadBlob(blob, nombreFirmado);
            showStatus(estadoGenerar, 'success', 'Documento firmado y descargado correctamente.');
        } catch (error) {
            showStatus(estadoGenerar, 'error', 'Error: ' + error.message);
        } finally {
            setButtonLoading(btnGenerar, false, '', 'Firmar y descargar PDF', 'ti-pen');
        }
    });

    btnVerificar.addEventListener('click', async () => {
        if (!archivoVerificacionSeleccionado) return;

        setButtonLoading(btnVerificar, true, 'Verificando...', 'Verificar firma', 'ti-shield-search');
        hideElement(resultadoVerificacion);

        try {
            const resultado = await verificarDocumento(archivoVerificacionSeleccionado);
            renderVerifyResult(resultadoVerificacion, resultado);
        } catch (error) {
            resultadoVerificacion.className = 'verify-result invalid';
            resultadoVerificacion.classList.remove('hidden');
            resultadoVerificacion.innerHTML = `
                <div class="result-header">
                    <i class="ti ti-circle-x" aria-hidden="true"></i>
                    Error al verificar: ${error.message}
                </div>
            `;
        } finally {
            setButtonLoading(btnVerificar, false, '', 'Verificar firma', 'ti-shield-search');
        }
    });
});
