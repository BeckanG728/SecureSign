const urlBase = '/api/documents';

async function firmarDocumento(file, algorithm) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('algorithm', algorithm);

    const respuesta = await fetch(`${urlBase}/sign`, {
        method: 'POST',
        body: formData,
    });

    if (!respuesta.ok) {
        const mensajeError = await respuesta.text();
        throw new Error(mensajeError || `Error ${respuesta.status} al firmar el documento`);
    }

    return respuesta.blob();
}

async function verificarDocumento(file) {
    const formData = new FormData();
    formData.append('file', file);

    const respuesta = await fetch(`${urlBase}/verify`, {
        method: 'POST',
        body: formData,
    });

    if (!respuesta.ok) {
        const mensajeError = await respuesta.text();
        throw new Error(mensajeError || `Error ${respuesta.status} al verificar el documento`);
    }

    return respuesta.json();
}
