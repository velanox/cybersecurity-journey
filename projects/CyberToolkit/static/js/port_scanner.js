// port_scanner.js — wires the scan form to the Flask API and renders
// results live, without reloading the page. Falls back to a normal
// form submission (handled server-side by Flask) if anything here fails.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("scan-form");
  if (!form) return;

  const button = form.querySelector(".btn-scan");
  const resultsContainer = document.getElementById("scan-results");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const restoreButton = setButtonLoading(button, "Scanning…");
    resultsContainer.innerHTML = "";

    const payload = {
      target: form.target.value.trim(),
      start_port: Number(form.start_port.value),
      end_port: Number(form.end_port.value),
      timeout: Number(form.timeout.value),
      threads: Number(form.threads.value),
    };

    try {
      const data = await apiRequest(form.action, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      renderResults(data);
    } catch (err) {
      resultsContainer.innerHTML = `<div class="alert-error">${escapeHtml(err.message)}</div>`;
      showToast(err.message, "error");
    } finally {
      restoreButton();
    }
  });

  function statusBadge(status) {
    if (status === "open") return `<span class="status-open">open</span>`;
    return `<span class="status-closed">${escapeHtml(status)}</span>`;
  }

  function buildTable(rows, columns = ["Port", "Status", "Name", "Description"]) {
    const head = columns.map(c => `<th>${c}</th>`).join("");
    return `
      <table class="results__table">
        <thead><tr>${head}</tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  function renderResults({ open_ports, known_ports, duration }) {
    let html = "";

    // ---- Open ports block ----
    if (!open_ports.length) {
      html += `
        <div class="results">
          <div class="results__head">
            <span class="results__title">Open Ports</span>
            <span class="results__meta">0 open · ${duration}s</span>
          </div>
          <p class="results__empty">No open ports found in that range.</p>
        </div>`;
    } else {
      const rows = open_ports.map(r => `
        <tr>
          <td class="mono">${r.port}</td>
          <td>${statusBadge("open")}</td>
          <td class="mono">${escapeHtml(r.name || "—")}</td>
          <td class="results__desc">${escapeHtml(r.description || "—")}</td>
        </tr>`).join("");

      html += `
        <div class="results">
          <div class="results__head">
            <span class="results__title">Open Ports</span>
            <span class="results__meta">${open_ports.length} open · ${duration}s</span>
          </div>
          ${buildTable(rows)}
        </div>`;
    }

    // ---- Well-known ports block (open or closed) ----
    if (known_ports && known_ports.length) {
      const rows = known_ports.map(r => `
        <tr>
          <td class="mono">${r.port}</td>
          <td>${statusBadge(r.status)}</td>
          <td class="mono">${escapeHtml(r.name)}</td>
          <td class="results__desc">${escapeHtml(r.description)}</td>
        </tr>`).join("");

      html += `
        <div class="results">
          <div class="results__head">
            <span class="results__title">Well-known ports checked</span>
            <span class="results__meta">${known_ports.length} recognized</span>
          </div>
          ${buildTable(rows)}
        </div>`;
    }

    resultsContainer.innerHTML = html;
  }
});