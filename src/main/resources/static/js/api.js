/**
 * api.js
 * Contiene todas las llamadas fetch a los endpoints del backend.
 * Cada función devuelve una Promise con la respuesta procesada.
 */

const API_BASE = '/api/documents';

/**
 * Genera un documento PDF firmado (PAdES).
 * @param {Object} payload - { nombre, dni, tipo, fecha, algorithm }
 * @returns {Promise<Blob>} - Blob del PDF firmado
 */
async function apiGenerateDocument(payload) {
    const response = await fetch(`${API_BASE}/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Error ${response.status} al generar el documento`);
    }

    return response.blob();
}

/**
 * Verifica la firma digital de un PDF firmado (PAdES).
 * @param {File} file - Archivo PDF a verificar
 * @returns {Promise<Object>} - Resultado de la verificación
 */
async function apiVerifyDocument(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/verify`, {
        method: 'POST',
        body: formData,
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Error ${response.status} al verificar el documento`);
    }

    return response.json();
}
