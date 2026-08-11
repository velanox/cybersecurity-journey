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
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

/** Escape user-controlled text before injecting it into innerHTML. */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}