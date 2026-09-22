// whois.js — intercepts the lookup form, calls the Flask API, and renders
// the result live. Falls back to a normal form submission (handled
// server-side by Flask) if anything here fails, exactly like the Port
// Scanner and DNS Lookup tools.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("whois-form");
  if (!form) return;

  const domainInput = document.getElementById("domain");
  const submitBtn = document.getElementById("whois-submit-btn");
  const newSearchBtn = document.getElementById("whois-new-btn");
  const loading = document.getElementById("whois-loading");
  const resultsContainer = document.getElementById("whois-results");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const domain = domainInput.value.trim();
    resultsContainer.innerHTML = "";
    loading.hidden = false;
    const restoreButton = setButtonLoading(submitBtn, "Looking up…");

    try {
      const { result } = await apiRequest(form.action, {
        method: "POST",
        body: JSON.stringify({ domain }),
      });
      renderResult(result);
      newSearchBtn.hidden = false;
    } catch (err) {
      resultsContainer.innerHTML = `<div class="alert-error">${escapeHtml(err.message)}</div>`;
      showToast(err.message, "error");
    } finally {
      loading.hidden = true;
      restoreButton();
    }
  });

  newSearchBtn.addEventListener("click", () => {
    domainInput.value = "";
    domainInput.focus();
    resultsContainer.innerHTML = "";
    newSearchBtn.hidden = true;
  });

  function renderResult(result) {
    if (result.error) {
      resultsContainer.innerHTML = `<div class="alert-error">${escapeHtml(result.error)}</div>`;
      return;
    }

    if (result.not_found) {
      resultsContainer.innerHTML = `
        <div class="results">
          <div class="results__head">
            <span class="results__title">${escapeHtml(result.domain)}</span>
            <span class="results__meta">not registered</span>
          </div>
          <p class="results__empty">No WHOIS record found — this domain doesn't appear to be registered.</p>
        </div>`;
      return;
    }

    const row = (label, value) => `<tr><td class="mono">${label}</td><td class="mono">${escapeHtml(value || "—")}</td></tr>`;
    const statusText = result.status && result.status.length ? result.status.join(", ") : null;
    const nsText = result.nameservers && result.nameservers.length ? result.nameservers.join(", ") : null;

    let html = `
      <div class="results">
        <div class="results__head">
          <span class="results__title">${escapeHtml(result.domain)}</span>
        </div>
        <table class="results__table">
          <tbody>
            ${row("Registrar", result.registrar)}
            ${row("Created", result.created)}
            ${row("Updated", result.updated)}
            ${row("Expires", result.expires)}
            ${row("Status", statusText)}
            ${row("Nameservers", nsText)}
          </tbody>
        </table>
      </div>`;

    if (result.raw) {
      html += `
        <details class="whois-raw">
          <summary>Raw WHOIS response</summary>
          <pre class="whois-raw__content">${escapeHtml(result.raw)}</pre>
        </details>`;
    }

    resultsContainer.innerHTML = html;
  }
});