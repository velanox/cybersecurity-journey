// dns.js — wires the DNS lookup form to the Flask API and renders
// results live, without reloading the page. Falls back to a normal
// form submission (handled server-side by Flask) if anything here fails.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("dns-form");
  if (!form) return;

  const button = form.querySelector(".btn-lookup");
  const resultsContainer = document.getElementById("dns-results");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const restoreButton = setButtonLoading(button, "Looking up…");
    resultsContainer.innerHTML = "";

    const recordTypes = Array.from(form.querySelectorAll('input[name="record_types"]:checked'))
      .map(input => input.value);

    const payload = {
      domain: form.domain.value.trim(),
      record_types: recordTypes,
      timeout: Number(form.timeout.value),
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
    if (status === "found") return `<span class="status-open">found</span>`;
    if (status === "not_found") return `<span class="status-closed">no record</span>`;
    return `<span class="status-error">${escapeHtml(status)}</span>`;
  }

  function renderResults({ domain, results, found_count, duration }) {
    const blocks = Object.entries(results).map(([recordType, r]) => {
      let body = "";

      if (r.records && r.records.length) {
        const items = r.records.map(rec => `<li class="mono">${escapeHtml(rec)}</li>`).join("");
        body = `<ul class="record-block__list">${items}</ul>`;
      } else if (r.error) {
        body = `<p class="record-block__error">${escapeHtml(r.error)}</p>`;
      }

      return `
        <div class="record-block">
          <div class="record-block__head">
            <span class="record-block__type">${recordType}</span>
            ${statusBadge(r.status)}
          </div>
          ${body}
        </div>`;
    }).join("");

    resultsContainer.innerHTML = `
      <div class="results">
        <div class="results__head">
          <span class="results__title">Results for ${escapeHtml(domain)}</span>
          <span class="results__meta">${found_count} record type(s) found · ${duration}s</span>
        </div>
        <div class="results__body">${blocks}</div>
      </div>`;
  }
});