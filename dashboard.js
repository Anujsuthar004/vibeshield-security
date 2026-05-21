(function () {
  const escape = (value) => String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

  const $ = (selector, scope = document) => scope.querySelector(selector);
  const $$ = (selector, scope = document) => Array.from(scope.querySelectorAll(selector));

  const state = {
    authMode: "login",
    user: null,
    org: null,
    activeMode: "github",
    currentScan: null
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      credentials: "same-origin",
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      return response;
    }
    const data = await response.json();
    if (!response.ok) {
      const error = new Error(data.message || data.error || `Request failed (${response.status})`);
      error.code = data.error;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function showAuth() {
    $("#auth-shell").classList.remove("hidden");
    $("#dashboard").classList.add("hidden");
  }

  function showDashboard() {
    $("#auth-shell").classList.add("hidden");
    $("#dashboard").classList.remove("hidden");
  }

  function setAuthMode(mode) {
    state.authMode = mode;
    $$(".auth-tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.mode === mode));
    $$(".signup-only").forEach((node) => node.classList.toggle("hidden", mode !== "signup"));
    $("#auth-submit").textContent = mode === "signup" ? "Create account" : "Sign in";
    const passwordInput = $("#auth-form input[type=password]");
    if (passwordInput) {
      passwordInput.setAttribute("autocomplete", mode === "signup" ? "new-password" : "current-password");
    }
  }

  function setAuthError(message) {
    const node = $("#auth-error");
    if (!message) {
      node.classList.add("hidden");
      node.textContent = "";
      return;
    }
    node.classList.remove("hidden");
    node.textContent = message;
  }

  async function refreshSession() {
    try {
      const result = await api("/api/auth?action=me");
      if (result.authenticated) {
        state.user = result.user;
        const activeOrgId = result.active_org_id;
        state.org = result.user.orgs?.find((org) => org.id === activeOrgId) || result.user.orgs?.[0] || null;
        renderAccount();
        showDashboard();
        await Promise.all([loadHistory(), loadKeys(), loadRepositories(), loadHealth()]);
        return true;
      }
    } catch (error) {
      console.warn("session check failed", error);
    }
    showAuth();
    return false;
  }

  function renderAccount() {
    if (!state.user || !state.org) return;
    $("#workspace-title").textContent = state.org.name;
    $("#workspace-meta").textContent = `Signed in as ${state.user.email}`;
    $("#account-email").textContent = state.user.email;
    $("#account-org").textContent = `${state.org.name} (${state.org.id})`;
  }

  async function loadHealth() {
    try {
      const health = await api("/api/health");
      $("#github-pill").textContent = `GitHub App: ${health.githubAppConfigured ? "configured" : "not configured"}`;
      $("#github-pill").classList.toggle("ok", health.githubAppConfigured);
      $("#email-pill").textContent = `Email: ${health.emailConfigured ? "ready" : "not configured"}`;
      $("#email-pill").classList.toggle("ok", health.emailConfigured);
    } catch (error) {
      console.warn("health failed", error);
    }
  }

  async function loadHistory() {
    const rows = $("#history-rows");
    rows.innerHTML = "<p class=\"muted\">Loading…</p>";
    try {
      const data = await api("/api/scans");
      if (!data.scans.length) {
        rows.innerHTML = "<p class=\"muted\">No scans yet. Run your first scan above.</p>";
        return;
      }
      rows.innerHTML = data.scans.map((scan) => `
        <article class="history-row" data-scan-id="${escape(scan.id)}">
          <div>
            <p class="row-title">${escape(scan.target)}</p>
            <p class="row-meta">${escape(scan.source_type)} · ${escape(scan.ref || "—")} · ${new Date(scan.created_at).toLocaleString()}</p>
          </div>
          <div class="row-stats">
            <span class="score-chip">${scan.score}/100</span>
            <span class="muted">${scan.finding_count} findings · ${scan.critical_count} critical</span>
          </div>
          <div class="row-actions">
            <button class="button secondary" data-action="view" type="button">Open</button>
            <button class="button secondary" data-action="pdf" type="button">PDF</button>
            <button class="button secondary" data-action="diff" type="button">Diff</button>
            <button class="button danger" data-action="delete" type="button">Delete</button>
          </div>
        </article>
      `).join("");
    } catch (error) {
      rows.innerHTML = `<p class="error-text">${escape(error.message)}</p>`;
    }
  }

  async function loadKeys() {
    const list = $("#keys-list");
    list.innerHTML = "<p class=\"muted\">Loading…</p>";
    try {
      const data = await api("/api/keys");
      if (!data.keys.length) {
        list.innerHTML = "<p class=\"muted\">No API keys yet. Create one to use the scanner API.</p>";
        return;
      }
      list.innerHTML = data.keys.map((key) => `
        <article class="key-row" data-key-id="${escape(key.id)}">
          <div>
            <p class="row-title">${escape(key.label || "default")}</p>
            <p class="row-meta">${escape(key.prefix)}…  ·  created ${new Date(key.created_at).toLocaleString()}  ·  ${key.last_used_at ? "last used " + new Date(key.last_used_at).toLocaleString() : "never used"}</p>
          </div>
          <button class="button danger" data-action="revoke" type="button">Revoke</button>
        </article>
      `).join("");
    } catch (error) {
      list.innerHTML = `<p class="error-text">${escape(error.message)}</p>`;
    }
  }

  async function loadRepositories() {
    const list = $("#repo-list");
    list.innerHTML = "<p class=\"muted\">Loading…</p>";
    try {
      const data = await api("/api/repositories");
      if (!data.repositories.length) {
        list.innerHTML = "<p class=\"muted\">No repositories connected yet.</p>";
        return;
      }
      list.innerHTML = data.repositories.map((repo) => `
        <article class="repo-row" data-repo-id="${escape(repo.id)}">
          <div>
            <p class="row-title">${escape(repo.full_name)}</p>
            <p class="row-meta">install id ${escape(repo.installation_id || "—")} · webhook secret <code>${escape(repo.webhook_secret || "")}</code></p>
          </div>
          <button class="button danger" data-action="remove" type="button">Remove</button>
        </article>
      `).join("");
    } catch (error) {
      list.innerHTML = `<p class="error-text">${escape(error.message)}</p>`;
    }
  }

  function renderScanResult(result) {
    state.currentScan = result;
    const node = $("#scan-result");
    const summary = `
      <header class="result-header">
        <div>
          <p class="muted">Scan ${escape(result.id)}</p>
          <h3>${escape(result.target)} — score ${escape(result.score)}/100</h3>
          <p class="muted">${escape(result.activeFindingsCount)} active · ${escape(result.suppressedFindingsCount)} suppressed · ${escape(result.filesScanned)} files</p>
        </div>
        <div class="result-actions">
          <a class="button secondary" href="/api/reports?action=pdf&scanId=${encodeURIComponent(result.id)}" target="_blank" rel="noopener">Download PDF</a>
          <button class="button secondary" type="button" id="email-report">Email report</button>
        </div>
      </header>
    `;
    const findings = (result.findings || []).map((finding) => `
      <article class="finding-card ${finding.suppressed ? "suppressed" : ""}">
        <div class="finding-top">
          <span class="severity ${escape(finding.severity)}">${escape(finding.severity)}</span>
          <span class="confidence">${escape(finding.confidence)}</span>
        </div>
        <div>
          <p class="eyebrow">${escape(finding.category)}</p>
          <h3>${escape(finding.title)}</h3>
          <p class="muted">Rule <code>${escape(finding.rule)}</code> · ${escape(finding.rule_type)} · ${escape(finding.confidence_source)}</p>
        </div>
        <div class="evidence">${escape(finding.evidence)}</div>
        <p>${escape(finding.fix)}</p>
        ${finding.patch ? `<details><summary>Fix patch</summary><pre>${escape(finding.patch.body)}</pre></details>` : ""}
        ${finding.suppressed ? `<p class="muted">Suppressed: ${escape(finding.suppression_reason || "")}</p>` : `<button class="button secondary" data-action="suppress" data-finding="${escape(finding.id)}" type="button">Suppress</button>`}
      </article>
    `).join("");
    node.innerHTML = `${summary}<div class="findings-grid">${findings || "<p class=\"muted\">No findings.</p>"}</div>`;
  }

  async function runScan(event) {
    event.preventDefault();
    setScanNote("Running scan…");
    const submit = $("#scan-submit");
    submit.disabled = true;
    try {
      const payload = {};
      if (state.activeMode === "github") {
        payload.sourceType = "github";
        payload.repoUrl = $("#repoUrl").value.trim();
        payload.installationId = $("#installationId").value.trim() || undefined;
        payload.ref = $("#branchRef").value.trim() || undefined;
      } else {
        payload.sourceType = "paste";
        payload.code = $("#codePaste").value;
        payload.filename = "pasted-snippet.js";
      }
      payload.dependencyScan = $("#opt-deps").checked;
      payload.generatePatches = $("#opt-patches").checked;
      const result = await api("/api/scans", { method: "POST", body: payload });
      renderScanResult(result);
      await loadHistory();
      setScanNote(`Scan complete in ${(Date.parse(result.completedAt) - Date.parse(result.startedAt)) / 1000}s · ${result.findings.length} findings.`);
    } catch (error) {
      setScanNote(error.message);
    } finally {
      submit.disabled = false;
    }
  }

  function setScanNote(message) {
    $("#scan-note").textContent = message;
  }

  function bindAuth() {
    $$(".auth-tab").forEach((tab) => {
      tab.addEventListener("click", () => setAuthMode(tab.dataset.mode));
    });
    $("#auth-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setAuthError("");
      const formData = new FormData(event.currentTarget);
      const payload = Object.fromEntries(formData.entries());
      const action = state.authMode === "signup" ? "signup" : "login";
      try {
        await api(`/api/auth?action=${action}`, { method: "POST", body: payload });
        await refreshSession();
      } catch (error) {
        setAuthError(error.message);
      }
    });
  }

  function bindDashboard() {
    $("#logout-button").addEventListener("click", async () => {
      await api("/api/auth?action=logout", { method: "POST" }).catch(() => {});
      state.user = null;
      state.org = null;
      showAuth();
    });
    $$(".segment").forEach((segment) => {
      segment.addEventListener("click", () => {
        state.activeMode = segment.dataset.mode;
        $$(".segment").forEach((node) => node.classList.toggle("active", node === segment));
        $$(".github-field").forEach((node) => node.classList.toggle("hidden", state.activeMode !== "github"));
        $$(".paste-field").forEach((node) => node.classList.toggle("hidden", state.activeMode !== "paste"));
      });
    });
    $("#scan-form").addEventListener("submit", runScan);
    $("#refresh-history").addEventListener("click", loadHistory);

    $("#history-rows").addEventListener("click", async (event) => {
      const row = event.target.closest(".history-row");
      if (!row) return;
      const scanId = row.dataset.scanId;
      const action = event.target.dataset.action;
      if (action === "delete") {
        if (!confirm("Delete this scan?")) return;
        await api(`/api/scans/${scanId}`, { method: "DELETE" }).catch((error) => alert(error.message));
        await loadHistory();
      } else if (action === "view") {
        const scan = await api(`/api/scans/${scanId}`);
        renderScanResult(scan);
        window.scrollTo({ top: $("#scan-result").offsetTop - 60, behavior: "smooth" });
      } else if (action === "pdf") {
        window.open(`/api/reports?action=pdf&scanId=${encodeURIComponent(scanId)}`, "_blank");
      } else if (action === "diff") {
        const against = prompt("Diff against which scan id?");
        if (!against) return;
        const diff = await api(`/api/scans/${scanId}/diff?against=${encodeURIComponent(against)}`).catch((error) => ({ error: error.message }));
        alert(diff.error || `${diff.diff.added.length} added · ${diff.diff.removed.length} removed · score Δ ${diff.diff.score_delta}`);
      }
    });

    $("#scan-result").addEventListener("click", async (event) => {
      if (event.target.id === "email-report" && state.currentScan) {
        const to = prompt("Send report to (email address):");
        if (!to) return;
        try {
          await api("/api/reports?action=email", { method: "POST", body: { scanId: state.currentScan.id, to } });
          alert("Report sent.");
        } catch (error) {
          alert(error.message);
        }
        return;
      }
      const findingId = event.target.dataset.finding;
      if (event.target.dataset.action === "suppress" && findingId && state.currentScan) {
        const reason = prompt("Reason for suppressing this finding?", "False positive");
        if (reason === null) return;
        await api("/api/suppressions", { method: "POST", body: { findingId, target: state.currentScan.target, reason } }).catch((error) => alert(error.message));
        event.target.disabled = true;
        event.target.textContent = "Suppressed";
      }
    });

    $("#new-key").addEventListener("click", async () => {
      const label = prompt("Label for this API key", "CI");
      if (label === null) return;
      try {
        const result = await api("/api/keys", { method: "POST", body: { label } });
        prompt(result.notice, result.secret);
        await loadKeys();
      } catch (error) {
        alert(error.message);
      }
    });

    $("#keys-list").addEventListener("click", async (event) => {
      const row = event.target.closest(".key-row");
      if (!row) return;
      if (event.target.dataset.action === "revoke") {
        if (!confirm("Revoke this API key?")) return;
        await api(`/api/keys?id=${encodeURIComponent(row.dataset.keyId)}`, { method: "DELETE" }).catch((error) => alert(error.message));
        await loadKeys();
      }
    });

    $("#repo-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const fullName = $("#repo-full-name").value.trim();
      const installationId = $("#repo-installation").value.trim();
      try {
        await api("/api/repositories", { method: "POST", body: { fullName, installationId } });
        $("#repo-full-name").value = "";
        $("#repo-installation").value = "";
        await loadRepositories();
      } catch (error) {
        alert(error.message);
      }
    });

    $("#repo-list").addEventListener("click", async (event) => {
      const row = event.target.closest(".repo-row");
      if (!row) return;
      if (event.target.dataset.action === "remove") {
        if (!confirm("Remove repository connection?")) return;
        await api(`/api/repositories?id=${encodeURIComponent(row.dataset.repoId)}`, { method: "DELETE" }).catch((error) => alert(error.message));
        await loadRepositories();
      }
    });
  }

  function bindTheme() {
    const toggle = $("#themeToggle");
    if (!toggle) return;
    const saved = localStorage.getItem("vibeshield-theme") || "";
    if (saved) document.documentElement.dataset.theme = saved;
    toggle.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("vibeshield-theme", next);
    });
  }

  function init() {
    bindAuth();
    bindDashboard();
    bindTheme();
    setAuthMode("login");
    refreshSession();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
