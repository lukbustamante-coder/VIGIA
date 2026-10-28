"use strict";

(() => {
    const form = document.querySelector("[data-upload-form]");
    if (!form) return;
    const input = form.querySelector('input[type="file"]');
    const zone = form.querySelector("[data-dropzone]");
    const selection = form.querySelector("[data-upload-selection]");
    const feedback = form.querySelector("[data-upload-feedback]");
    const overlay = document.querySelector("[data-drop-overlay]");
    if (!input || !zone || !selection || !feedback || !overlay) return;

    input.setAttribute("aria-describedby", "file-upload-help");
    const allowed = (input.accept || "").split(",").map(value => value.trim().toLowerCase());
    let depth = 0;

    function hideDrag() {
        depth = 0;
        overlay.hidden = true;
        zone.classList.remove("is-dragging");
    }

    function isFileDrag(event) {
        return event.dataTransfer && Array.from(event.dataTransfer.types).includes("Files");
    }

    function resetConsent() {
        form.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = false;
        });
    }

    function reject(message) {
        input.value = "";
        input.setCustomValidity(message);
        selection.textContent = "";
        selection.hidden = true;
        feedback.textContent = message;
        feedback.classList.add("is-error");
        resetConsent();
    }

    function validate(file) {
        if (!file || file.size === 0) return "El archivo está vacío o no se puede leer. Elige un archivo válido.";
        if (file.size > 20 * 1024 * 1024) return "El archivo supera el máximo de 20 MB.";
        const dot = file.name.lastIndexOf(".");
        const extension = dot >= 0 ? file.name.slice(dot).toLowerCase() : "";
        if (!allowed.includes(extension)) return "Ese formato no está permitido en este módulo. Revisa los formatos indicados debajo.";
        return "";
    }

    function selected() {
        resetConsent();
        input.setCustomValidity("");
        const file = input.files[0];
        if (!file) {
            selection.textContent = "";
            selection.hidden = true;
            feedback.textContent = "";
            feedback.classList.remove("is-error");
            return;
        }
        const error = validate(file);
        if (error) {
            reject(error);
            return;
        }
        const size = file.size >= 1024 * 1024
            ? `${(file.size / (1024 * 1024)).toLocaleString("es-CL", {maximumFractionDigits: 1})} MB`
            : `${Math.max(1, Math.ceil(file.size / 1024))} KB`;
        selection.textContent = `${file.name} · ${size}`;
        selection.hidden = false;
        feedback.textContent = "Archivo seleccionado. Revisa las autorizaciones y pulsa «Enviar a analizar» cuando estés listo.";
        feedback.classList.remove("is-error");
    }

    input.addEventListener("change", selected);
    document.addEventListener("dragenter", event => {
        if (!isFileDrag(event)) return;
        event.preventDefault();
        depth += 1;
        overlay.hidden = false;
        zone.classList.add("is-dragging");
    });
    document.addEventListener("dragover", event => {
        if (!isFileDrag(event)) return;
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
    });
    document.addEventListener("dragleave", () => {
        if (depth > 0) depth -= 1;
        if (depth === 0) hideDrag();
    });
    document.addEventListener("drop", event => {
        hideDrag();
        if (!isFileDrag(event)) return;
        event.preventDefault();
        const files = event.dataTransfer.files;
        if (files.length !== 1) {
            reject("Suelta un solo archivo por análisis.");
            return;
        }
        const entry = event.dataTransfer.items[0]?.webkitGetAsEntry?.();
        if (entry?.isDirectory) {
            reject("No se pueden cargar carpetas. Elige un archivo.");
            return;
        }
        const error = validate(files[0]);
        if (error) {
            reject(error);
            return;
        }
        try {
            input.files = files;
            input.dispatchEvent(new Event("change", {bubbles: true}));
        } catch {
            reject("Tu navegador no permite seleccionar el archivo arrastrándolo. Usa el selector del explorador.");
        }
    });
    document.addEventListener("dragend", hideDrag);
    window.addEventListener("blur", hideDrag);
})();
