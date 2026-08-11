// components.js — shared UI behaviors used by multiple pages

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