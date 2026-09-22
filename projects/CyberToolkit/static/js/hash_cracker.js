// hash_cracker.js — analyze -> pick strategy -> (estimate) -> start job ->
// poll live status -> render result. No no-JS fallback: the live engine
// (pause/resume/stop, progress, feasibility checks) only makes sense
// client-side against the Flask API.

const HC_MAX_SPREAD = 8;
const HC_ABSOLUTE_MAX_LENGTH = 24;
const HC_DEFAULT_WORDLIST = "passwords.txt"; // shipped by default, always present

document.addEventListener("DOMContentLoaded", () => {
  const app = document.getElementById("hc-app");
  if (!app) return;

  // ---- element refs ----
  const hashInput = document.getElementById("hc-hash-input");
  const analyzeBtn = document.getElementById("hc-analyze-btn");
  const clearBtn = document.getElementById("hc-clear-btn");
  const inputError = document.getElementById("hc-input-error");

  const analysisPanel = document.getElementById("hc-analysis-panel");
  const analysisBody = document.getElementById("hc-analysis-body");

  const strategyPanel = document.getElementById("hc-strategy-panel");
  const strategyError = document.getElementById("hc-strategy-error");
  const startBtn = document.getElementById("hc-start-btn");

  const wordlistSelect = document.getElementById("hc-wordlist-select");
  const wordlistUpload = document.getElementById("hc-wordlist-upload");
  const wordlistCaption = document.getElementById("hc-wordlist-caption");

  const bfMin = document.getElementById("hc-bf-min");
  const bfMax = document.getElementById("hc-bf-max");
  const bfFeasibility = document.getElementById("hc-bf-feasibility");

  const rbLength = document.getElementById("hc-rb-length");
  const rbPreview = document.getElementById("hc-rb-preview");
  const rainbowCompat = document.getElementById("hc-rainbow-compat");

  const saltEnable = document.getElementById("hc-salt-enable");
  const saltFields = document.getElementById("hc-salt-fields");
  const saltValue = document.getElementById("hc-salt-value");

  const confirmBlock = document.getElementById("hc-confirm-block");
  const confirmText = document.getElementById("hc-confirm-text");
  const confirmYesBtn = document.getElementById("hc-confirm-yes");
  const confirmNoBtn = document.getElementById("hc-confirm-no");

  const livePanel = document.getElementById("hc-live-panel");
  const liveStatus = document.getElementById("hc-live-status");
  const liveAlgorithm = document.getElementById("hc-live-algorithm");
  const liveStrategy = document.getElementById("hc-live-strategy");
  const livePhaseRow = document.getElementById("hc-live-phase-row");
  const livePhase = document.getElementById("hc-live-phase");
  const liveCandidates = document.getElementById("hc-live-candidates");
  const liveSpeed = document.getElementById("hc-live-speed");
  const liveElapsed = document.getElementById("hc-live-elapsed");
  const progressBar = document.getElementById("hc-progress-bar");
  const progressLabel = document.getElementById("hc-progress-label");
  const pauseBtn = document.getElementById("hc-pause-btn");
  const stopBtn = document.getElementById("hc-stop-btn");
  const autoLog = document.getElementById("hc-auto-log");

  const resultPanel = document.getElementById("hc-result-panel");
  const resultBody = document.getElementById("hc-result-body");

  // ---- state ----
  let currentAnalysis = null;
  let currentJobId = null;
  let pollTimer = null;
  let pendingConfirmAction = null; // function to call if user confirms
  let automaticSteps = [];
  let automaticStepIndex = 0;

  // ---------------------------------------------------------------------
  // Hash input / analysis
  // ---------------------------------------------------------------------

  analyzeBtn.addEventListener("click", () => analyzeHash());
  hashInput.addEventListener("keydown", (e) => { if (e.key === "Enter") analyzeHash(); });

  clearBtn.addEventListener("click", () => {
    hashInput.value = "";
    inputError.innerHTML = "";
    currentAnalysis = null;
    hidePanel(analysisPanel);
    hidePanel(strategyPanel);
    hidePanel(livePanel);
    hidePanel(resultPanel);
    hideConfirm();
    stopPolling();
  });

  document.querySelectorAll(".hc-testcase-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      hashInput.value = btn.dataset.hash;
      analyzeHash();
    });
  });

  async function analyzeHash() {
    inputError.innerHTML = "";
    hideConfirm();

    const value = hashInput.value.trim();
    if (!value) {
      inputError.innerHTML = `<div class="alert-error">Hash value is required.</div>`;
      return;
    }
    if (!/^[0-9a-fA-F:$._]+$/.test(value)) {
      inputError.innerHTML = `<div class="alert-error">Hash contains unexpected characters.</div>`;
      return;
    }

    const restore = setButtonLoading(analyzeBtn, "Analyzing…");
    try {
      const { analysis } = await apiRequest("/api/hash-cracker/analyze", {
        method: "POST",
        body: JSON.stringify({ hash_value: value }),
      });
      currentAnalysis = analysis;
      renderAnalysis(analysis);
      showPanel(strategyPanel);
      hidePanel(livePanel);
      hidePanel(resultPanel);
      refreshStrategyAvailability();
    } catch (err) {
      inputError.innerHTML = `<div class="alert-error">${escapeHtml(err.message)}</div>`;
    } finally {
      restore();
    }
  }

  function renderAnalysis(a) {
    const rows = [
      ["Input", `<span class="mono">${escapeHtml(a.input)}</span>`],
      ["Length", a.length],
      ["Format", escapeHtml(a.format)],
      ["Structured", a.structured ? "yes" : "no"],
      ["Salt detected", a.salt_format ? escapeHtml(a.salt_format) : "no"],
      ["Possible algorithms", a.possible_algorithms.length ? escapeHtml(a.possible_algorithms.join(", ")) : "—"],
      ["Crackable locally", a.crackable_locally ? "yes" : "no"],
    ];
    analysisBody.innerHTML = rows.map(([k, v]) => `<tr><td class="mono">${k}</td><td class="mono">${v}</td></tr>`).join("");
    showPanel(analysisPanel);
  }

  // ---------------------------------------------------------------------
  // Strategy selection
  // ---------------------------------------------------------------------

  document.querySelectorAll('input[name="strategy"]').forEach(radio => {
    radio.addEventListener("change", () => { hideConfirm(); refreshStrategyAvailability(); });
  });

  function refreshStrategyAvailability() {
    const selected = document.querySelector('input[name="strategy"]:checked').value;

    ["dictionary", "brute_force", "rainbow", "automatic"].forEach(name => {
      document.getElementById(`hc-sub-${name}`).hidden = (name !== selected);
    });

    document.getElementById("hc-salt-block").hidden = (selected === "rainbow" || selected === "automatic");

    if (selected === "rainbow" && currentAnalysis) {
      const compatible = !currentAnalysis.salt_format && !currentAnalysis.structured;
      rainbowCompat.innerHTML = compatible
        ? `<div class="hc-compat-ok">Compatible — this hash isn't salted or structured.</div>`
        : `<div class="hc-compat-bad">Incompatible — rainbow tables don't work against salted or structured (bcrypt/crypt) hashes. Pick Dictionary or Brute Force instead.</div>`;
      startBtn.disabled = !compatible;
      if (compatible) updateRainbowPreview();
    } else {
      startBtn.disabled = false;
    }

    if (selected === "brute_force") checkBruteForceFeasibility();
  }

  // ---------------------------------------------------------------------
  // Brute force: real feasibility check via /estimate, debounced
  // ---------------------------------------------------------------------

  let bfDebounce = null;
  function scheduleBruteForceCheck() {
    clearTimeout(bfDebounce);
    bfDebounce = setTimeout(checkBruteForceFeasibility, 350);
  }

  [bfMin, bfMax, "hc-bf-lower", "hc-bf-upper", "hc-bf-numbers", "hc-bf-symbols"].forEach(el => {
    const node = typeof el === "string" ? document.getElementById(el) : el;
    node.addEventListener("change", scheduleBruteForceCheck);
    node.addEventListener("input", scheduleBruteForceCheck);
  });

  function getBruteForceParams() {
    return {
      lowercase: document.getElementById("hc-bf-lower").checked,
      uppercase: document.getElementById("hc-bf-upper").checked,
      numbers: document.getElementById("hc-bf-numbers").checked,
      symbols: document.getElementById("hc-bf-symbols").checked,
      min_length: Number(bfMin.value),
      max_length: Number(bfMax.value),
    };
  }

  function clientSideRangeError(min, max) {
    if (!Number.isInteger(min) || !Number.isInteger(max) || min < 1) {
      return "Minimum length must be a whole number, at least 1.";
    }
    if (max < min) {
      return "Maximum length must be greater than or equal to minimum length.";
    }
    if (max > HC_ABSOLUTE_MAX_LENGTH) {
      return `Maximum length cannot exceed ${HC_ABSOLUTE_MAX_LENGTH}.`;
    }
    if (max - min > HC_MAX_SPREAD) {
      return `The range is too wide (${max - min} — max allowed is ${HC_MAX_SPREAD}). Narrow it if you have any idea of the actual length.`;
    }
    return null;
  }

  async function checkBruteForceFeasibility() {
    const params = getBruteForceParams();
    const rangeError = clientSideRangeError(params.min_length, params.max_length);
    if (rangeError) {
      bfFeasibility.innerHTML = `<div class="alert-error">${escapeHtml(rangeError)}</div>`;
      return null;
    }
    if (!params.lowercase && !params.uppercase && !params.numbers && !params.symbols) {
      bfFeasibility.innerHTML = `<div class="alert-error">Select at least one character set.</div>`;
      return null;
    }
    if (!currentAnalysis || !currentAnalysis.possible_algorithms.length) return null;

    const algorithm = currentAnalysis.possible_algorithms[0];
    bfFeasibility.innerHTML = `<p class="hc-note">Checking feasibility on this machine…</p>`;

    try {
      const { estimate } = await apiRequest("/api/hash-cracker/estimate", {
        method: "POST",
        body: JSON.stringify({ algorithm, ...params }),
      });
      renderFeasibility(bfFeasibility, estimate);
      return estimate;
    } catch (err) {
      bfFeasibility.innerHTML = `<div class="alert-error">${escapeHtml(err.message)}</div>`;
      return null;
    }
  }

  function renderFeasibility(container, estimate) {
    const timeLabel = estimate.estimated_seconds !== null ? formatElapsed(estimate.estimated_seconds) : "unknown";
    if (estimate.feasible) {
      container.innerHTML = `
        <div class="hc-compat-ok">
          ~${estimate.total_candidates.toLocaleString()} candidates at ~${estimate.speed.toLocaleString()} candidates/s
          on this machine — estimated time: <strong>${timeLabel}</strong>.
        </div>`;
    } else {
      container.innerHTML = `
        <div class="hc-compat-bad">
          ~${estimate.total_candidates.toLocaleString()} candidates — estimated time: <strong>${timeLabel}</strong>,
          well beyond what's reasonable locally (limit: ${formatElapsed(estimate.hard_cap_seconds)}).
        </div>`;
    }
  }

  // ---------------------------------------------------------------------
  // Rainbow: client-side rough preview (no server round-trip needed to
  // just show a ballpark before the real benchmarked estimate on Start)
  // ---------------------------------------------------------------------

  [rbLength, "hc-rb-lower", "hc-rb-upper", "hc-rb-numbers", "hc-rb-symbols"].forEach(el => {
    const node = typeof el === "string" ? document.getElementById(el) : el;
    node.addEventListener("change", updateRainbowPreview);
    node.addEventListener("input", updateRainbowPreview);
  });

  function getRainbowCharsetSize() {
    let size = 0;
    if (document.getElementById("hc-rb-lower").checked) size += 26;
    if (document.getElementById("hc-rb-upper").checked) size += 26;
    if (document.getElementById("hc-rb-numbers").checked) size += 10;
    if (document.getElementById("hc-rb-symbols").checked) size += 14;
    return size;
  }

  function updateRainbowPreview() {
    const length = Number(rbLength.value);
    const size = getRainbowCharsetSize();
    if (!size || length < 1) { rbPreview.innerHTML = ""; return; }
    const spaceSize = Math.pow(size, length);
    rbPreview.innerHTML = `<p class="hc-note">Search space: ~${spaceSize.toLocaleString()} candidates. Table size is capped server-side to keep this quick locally — the exact time is measured with a benchmark right before starting.</p>`;
  }

  saltEnable.addEventListener("change", () => {
    saltFields.hidden = !saltEnable.checked;
  });

  // ---------------------------------------------------------------------
  // Wordlists
  // ---------------------------------------------------------------------

  async function loadWordlists(selectName) {
    try {
      const { wordlists } = await apiRequest("/api/hash-cracker/wordlists");
      wordlistSelect.innerHTML = wordlists.map(w => `<option value="${escapeHtml(w)}">${escapeHtml(w)}</option>`).join("");
      if (selectName) wordlistSelect.value = selectName;
      wordlistCaption.textContent = `${wordlists.length} wordlist${wordlists.length !== 1 ? "s" : ""} available. Uploading a file selects it automatically.`;
    } catch (err) {
      showToast(err.message, "error");
    }
  }
  loadWordlists();

  wordlistUpload.addEventListener("change", async () => {
    const file = wordlistUpload.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    try {
      const response = await fetch("/api/hash-cracker/wordlists/upload", { method: "POST", body: formData });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed.");
      showToast(`Wordlist "${data.name}" uploaded and selected.`, "info");
      await loadWordlists(data.name); // auto-selects the uploaded file
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      wordlistUpload.value = "";
    }
  });

  // ---------------------------------------------------------------------
  // Confirmation block (for >24h estimates)
  // ---------------------------------------------------------------------

  function showConfirm(estimate, onConfirm) {
    const timeLabel = estimate.estimated_seconds !== null ? formatElapsed(estimate.estimated_seconds) : "an unknown amount of time";
    confirmText.textContent = `Estimated time is ${timeLabel} — well beyond the ${formatElapsed(estimate.hard_cap_seconds)} local limit. Continue anyway?`;
    confirmBlock.hidden = false;
    pendingConfirmAction = onConfirm;
  }

  function hideConfirm() {
    confirmBlock.hidden = true;
    pendingConfirmAction = null;
  }

  confirmYesBtn.addEventListener("click", () => {
    const action = pendingConfirmAction;
    hideConfirm();
    if (action) action();
  });
  confirmNoBtn.addEventListener("click", hideConfirm);

  // ---------------------------------------------------------------------
  // Start job
  // ---------------------------------------------------------------------

  startBtn.addEventListener("click", () => startSelectedStrategy());

  function getSalt() {
    if (!saltEnable.checked) return { salt: null, salt_order: "suffix" };
    return {
      salt: saltValue.value.trim() || null,
      salt_order: document.querySelector('input[name="salt-order"]:checked').value,
    };
  }

  async function startSelectedStrategy() {
    strategyError.innerHTML = "";
    hideConfirm();
    const selected = document.querySelector('input[name="strategy"]:checked').value;
    const hash_value = hashInput.value.trim();
    const algorithm = currentAnalysis.possible_algorithms[0];

    if (!algorithm) {
      strategyError.innerHTML = `<div class="alert-error">No compatible algorithm to try for this hash format.</div>`;
      return;
    }

    try {
      if (selected === "dictionary") {
        await startDictionary(hash_value, algorithm, wordlistSelect.value || HC_DEFAULT_WORDLIST);
      } else if (selected === "brute_force") {
        await startBruteForce(hash_value, algorithm, false);
      } else if (selected === "rainbow") {
        await startRainbow(hash_value, algorithm, false);
      } else if (selected === "automatic") {
        await startAutomatic(hash_value, algorithm);
      }
    } catch (err) {
      strategyError.innerHTML = `<div class="alert-error">${escapeHtml(err.message)}</div>`;
    }
  }

  async function startDictionary(hash_value, algorithm, wordlistName) {
    const { salt, salt_order } = getSalt();
    const transformations = Array.from(document.querySelectorAll("#hc-sub-dictionary input[type=checkbox]:checked")).map(el => el.value);

    const data = await apiRequest("/api/hash-cracker/start/dictionary", {
      method: "POST",
      body: JSON.stringify({ hash_value, algorithm, salt, salt_order, transformations, wordlist: wordlistName }),
    });
    beginJob(data.job_id, data.snapshot);
    return data;
  }

  async function startBruteForce(hash_value, algorithm, confirmed) {
    const params = getBruteForceParams();
    const rangeError = clientSideRangeError(params.min_length, params.max_length);
    if (rangeError) {
      strategyError.innerHTML = `<div class="alert-error">${escapeHtml(rangeError)}</div>`;
      return;
    }
    const { salt, salt_order } = getSalt();

    try {
      const data = await apiRequest("/api/hash-cracker/start/brute_force", {
        method: "POST",
        body: JSON.stringify({ hash_value, algorithm, salt, salt_order, confirmed, ...params }),
      });
      beginJob(data.job_id, data.snapshot);
      return data;
    } catch (err) {
      if (err.payload && err.payload.requires_confirmation) {
        showConfirm(err.payload.estimate, () => startBruteForce(hash_value, algorithm, true));
      } else {
        throw err;
      }
    }
  }

  async function startRainbow(hash_value, algorithm, confirmed) {
    const length = Number(rbLength.value);
    if (!length || length < 1 || length > HC_ABSOLUTE_MAX_LENGTH) {
      strategyError.innerHTML = `<div class="alert-error">Length must be between 1 and ${HC_ABSOLUTE_MAX_LENGTH}.</div>`;
      return;
    }
    const body = {
      hash_value, algorithm, length, confirmed,
      lowercase: document.getElementById("hc-rb-lower").checked,
      uppercase: document.getElementById("hc-rb-upper").checked,
      numbers: document.getElementById("hc-rb-numbers").checked,
      symbols: document.getElementById("hc-rb-symbols").checked,
    };

    try {
      const data = await apiRequest("/api/hash-cracker/start/rainbow", { method: "POST", body: JSON.stringify(body) });
      beginJob(data.job_id, data.snapshot);
      return data;
    } catch (err) {
      if (err.payload && err.payload.requires_confirmation) {
        showConfirm(err.payload.estimate, () => startRainbow(hash_value, algorithm, true));
      } else {
        throw err;
      }
    }
  }

  // ---------------------------------------------------------------------
  // Automatic: a real, visible, sequential pipeline — not a silent no-op.
  // Step 1: built-in dictionary (explicit filename, no dependency on the
  //         <select> being loaded). Step 2: short brute force fallback.
  // ---------------------------------------------------------------------

  async function startAutomatic(hash_value, algorithm) {
    automaticSteps = [
      { label: "Dictionary (built-in wordlist)", run: () => startDictionary(hash_value, algorithm, HC_DEFAULT_WORDLIST) },
      { label: "Brute force (lowercase + numbers, 1–4 chars)", run: () => startBruteForce.call(null, hash_value, algorithm, false) },
    ];
    automaticStepIndex = 0;
    autoLog.hidden = false;
    autoLog.innerHTML = "";
    await runNextAutomaticStep();
  }

  async function runNextAutomaticStep() {
    if (automaticStepIndex >= automaticSteps.length) {
      logAutoStep("All automatic steps exhausted — no match found.", "not_found");
      return;
    }
    const step = automaticSteps[automaticStepIndex];
    logAutoStep(`Trying: ${step.label}…`, "running");
    await step.run();
  }

  function logAutoStep(text, state) {
    const line = document.createElement("div");
    line.className = `hc-auto-line hc-auto-line--${state}`;
    line.textContent = text;
    autoLog.appendChild(line);
  }

  // ---------------------------------------------------------------------
  // Live job: polling, pause/resume/stop
  // ---------------------------------------------------------------------

  function beginJob(jobId, snapshot) {
    currentJobId = jobId;
    hidePanel(resultPanel);
    showPanel(livePanel);
    renderLiveStatus(snapshot);
    startPolling();
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 400);
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  async function pollStatus() {
    if (!currentJobId) return;
    try {
      const { snapshot } = await apiRequest(`/api/hash-cracker/jobs/${currentJobId}/status`);
      renderLiveStatus(snapshot);

      if (["completed", "not_found", "stopped", "error"].includes(snapshot.status)) {
        stopPolling();

        const isAutomatic = automaticSteps.length > 0;
        if (isAutomatic) {
          const step = automaticSteps[automaticStepIndex];
          if (snapshot.status === "completed") {
            logAutoStep(`✓ Found via: ${step.label}`, "completed");
            renderResult(snapshot);
          } else if (snapshot.status === "not_found") {
            logAutoStep(`✗ Not found via: ${step.label}`, "not_found");
            automaticStepIndex += 1;
            await runNextAutomaticStep();
          } else {
            renderResult(snapshot);
          }
        } else {
          renderResult(snapshot);
        }
      }
    } catch (err) {
      stopPolling();
      showToast(err.message, "error");
    }
  }

  function renderLiveStatus(snap) {
    liveStatus.textContent = snap.status;
    liveStatus.dataset.state = snap.status;
    liveAlgorithm.textContent = snap.algorithm;
    liveStrategy.textContent = snap.strategy;
    liveCandidates.textContent = snap.candidates_tested.toLocaleString();
    liveSpeed.textContent = `${snap.speed.toLocaleString()} candidates/s`;
    liveElapsed.textContent = formatElapsed(snap.elapsed);

    if (snap.phase) {
      livePhaseRow.hidden = false;
      livePhase.textContent = snap.phase === "building" ? "Building table" : "Searching table";
    } else {
      livePhaseRow.hidden = true;
    }

    if (snap.progress !== null && snap.progress !== undefined) {
      progressBar.classList.remove("hc-progress__bar--indeterminate");
      progressBar.style.width = `${snap.progress}%`;
      progressLabel.textContent = `${snap.progress}%${snap.estimated_seconds ? ` · est. ${formatElapsed(snap.estimated_seconds)}` : ""}`;
    } else {
      progressBar.classList.add("hc-progress__bar--indeterminate");
      progressLabel.textContent = "progress unknown (dictionary size not precounted)";
    }

    const running = snap.status === "running";
    const paused = snap.status === "paused";
    pauseBtn.hidden = !(running || paused);
    pauseBtn.textContent = paused ? "Resume" : "Pause";
    stopBtn.hidden = !(running || paused);
  }

  pauseBtn.addEventListener("click", async () => {
    if (!currentJobId) return;
    const action = pauseBtn.textContent === "Resume" ? "resume" : "pause";
    try {
      const { snapshot } = await apiRequest(`/api/hash-cracker/jobs/${currentJobId}/${action}`, { method: "POST" });
      renderLiveStatus(snapshot);
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  stopBtn.addEventListener("click", async () => {
    if (!currentJobId) return;
    try {
      const { snapshot } = await apiRequest(`/api/hash-cracker/jobs/${currentJobId}/stop`, { method: "POST" });
      stopPolling();
      renderLiveStatus(snapshot);
      automaticSteps = []; // a manual stop cancels any automatic chain too
      renderResult(snapshot);
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  // ---------------------------------------------------------------------
  // Result
  // ---------------------------------------------------------------------

  function renderResult(snap) {
    if (snap.status === "completed") {
      resultBody.innerHTML = `
        <div class="hc-result-found">✓ MATCH FOUND</div>
        <table class="results__table"><tbody>
          <tr><td class="mono">Candidate</td><td class="mono">${escapeHtml(snap.found_candidate)}</td></tr>
          <tr><td class="mono">Algorithm</td><td class="mono">${escapeHtml(snap.algorithm)}</td></tr>
          <tr><td class="mono">Strategy</td><td class="mono">${escapeHtml(snap.strategy)}</td></tr>
          <tr><td class="mono">Candidates tested</td><td class="mono">${snap.candidates_tested.toLocaleString()}</td></tr>
          <tr><td class="mono">Time</td><td class="mono">${formatElapsed(snap.elapsed)}</td></tr>
          <tr><td class="mono">Speed</td><td class="mono">${snap.speed.toLocaleString()} candidates/s</td></tr>
        </tbody></table>`;
    } else if (snap.status === "error") {
      resultBody.innerHTML = `<div class="alert-error">${escapeHtml(snap.error || "Unknown error.")}</div>`;
    } else {
      const label = snap.status === "stopped" ? "Stopped by user." : "No match found.";
      resultBody.innerHTML = `
        <div class="hc-result-notfound">${label}</div>
        <table class="results__table"><tbody>
          <tr><td class="mono">Candidates tested</td><td class="mono">${snap.candidates_tested.toLocaleString()}</td></tr>
          <tr><td class="mono">Time</td><td class="mono">${formatElapsed(snap.elapsed)}</td></tr>
          <tr><td class="mono">Strategy</td><td class="mono">${escapeHtml(snap.strategy)}</td></tr>
        </tbody></table>`;
    }
    showPanel(resultPanel);
  }

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  function showPanel(el) { el.hidden = false; }
  function hidePanel(el) { el.hidden = true; }

  function formatElapsed(seconds) {
    if (seconds === null || seconds === undefined) return "—";
    if (!isFinite(seconds)) return "practically forever";
    if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 3 : 1)}s`;
    if (seconds < 3600) {
      const m = Math.floor(seconds / 60), s = Math.floor(seconds % 60);
      return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }
    const days = seconds / 86400;
    if (days < 1) return `${(seconds / 3600).toFixed(1)}h`;
    if (days < 365) return `${days.toFixed(1)} days`;
    return `${(days / 365).toFixed(1)} years`;
  }
});