// base.js — small shared utilities available on every page

/**
 * Show a short-lived toast notification, top-right corner.
 * Usage: showToast("Something went wrong", "error")
 */
function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast toast--${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add("toast--visible"));

  setTimeout(() => {
    toast.classList.remove("toast--visible");
    toast.addEventListener("transitionend", () => toast.remove(), { once: true });
  }, 3500);
}

/**
 * Wrapper around fetch() that sends/expects JSON and throws a readable
 * error when the response isn't ok. Every page-specific JS file uses this
 * instead of calling fetch() directly.
 *
 * On a non-ok response, the thrown Error carries:
 *   - err.status  — the HTTP status code
 *   - err.payload — the full parsed JSON body, so callers can read extra
 *                   fields beyond the message (e.g. "requires_confirmation"
 *                   and "estimate" on a 422 from the hash cracker).
 */
async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const err = new Error(data.error || `Request failed (${response.status})`);
    err.status = response.status;
    err.payload = data;
    throw err;
  }

  return data;
}

/** Escape user-controlled text before injecting it into innerHTML. */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Puts a submit button into a "loading" state: disables it, swaps its
 * label, and returns a function to restore it to normal.
 */
function setButtonLoading(button, loadingLabel = "Working…") {
  const originalLabel = button.textContent;
  button.disabled = true;
  button.dataset.originalLabel = originalLabel;
  button.textContent = loadingLabel;

  return function restore() {
    button.disabled = false;
    button.textContent = button.dataset.originalLabel || originalLabel;
  };
}