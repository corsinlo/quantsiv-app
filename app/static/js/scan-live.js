// Live scan progress over Server-Sent Events. The /api/scans/{id}/events endpoint arrives with
// WP4. Statuses are the ScanStatus values: queued, running, done, failed (A32).
document.addEventListener("DOMContentLoaded", function () {
  const root = document.querySelector("[data-scan-id]");
  if (!root) return;
  const scanId = root.dataset.scanId;
  const eventSource = new EventSource(`/api/scans/${scanId}/events`);

  function updateScanProgress(data) {
    const progressPercent = data.progress || 0;
    document.getElementById("progress-percent").textContent = progressPercent + "%";
    document.getElementById("progress").setAttribute("aria-valuenow", String(progressPercent));
    document.getElementById("progress-bar").style.width = progressPercent + "%";

    (data.steps || []).forEach(function (step, index) {
      const statusEl = document.getElementById(`step-${index + 1}-status`);
      if (statusEl) statusEl.textContent = step.status || "Pending";
    });

    const findingsCount = data.findings_count || 0;
    document.getElementById("findings-counter").textContent = `${findingsCount} findings`;
    document.getElementById("current-step").textContent = data.current_step || "Processing...";

    if (data.status === "done" || data.status === "failed") {
      eventSource.close();
      window.location.href = `/dashboard/scans/${scanId}`;
    }
  }

  eventSource.onmessage = function (event) {
    updateScanProgress(JSON.parse(event.data));
  };

  eventSource.onerror = function () {
    document.getElementById("current-step").textContent =
      "Live progress is unavailable. Reload the page to check the scan status.";
    eventSource.close();
  };
});
