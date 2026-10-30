"use strict";

(() => {
    const report = document.querySelector("[data-analysis-status]");
    const incident = document.querySelector("[data-report-status]");
    if (!report && !incident) return;
    const endpoint = new URL((report || incident).dataset.pollUrl, window.location.origin);
    if (endpoint.origin !== window.location.origin) return;

    async function poll() {
        if (document.hidden) {
            window.setTimeout(poll, 4000);
            return;
        }
        try {
            const response = await fetch(endpoint, {
                credentials: "same-origin",
                redirect: "error",
                cache: "no-store",
                headers: {Accept: "application/json"},
            });
            if (response.status === 401 || response.status === 403 || response.status === 404) return;
            if (response.ok) {
                const result = await response.json();
                if ((report && ["queued", "running", "waiting_vt", "polling_vt", "done", "failed"].includes(result.status) &&
                    result.status !== report.dataset.analysisStatus) ||
                    (incident && result.report && result.report.status !== incident.dataset.reportStatus)) {
                    window.location.reload();
                    return;
                }
            }
        } catch {
            // Keep the manual refresh link available when the connection is interrupted.
        }
        window.setTimeout(poll, 4000);
    }
    window.setTimeout(poll, 4000);
})();
