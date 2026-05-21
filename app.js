const sampleFindings = [
  {
    severity: "critical",
    title: "Broken ownership check on user data route",
    category: "Authentication & Authorization",
    confidence: "96%",
    evidence: "GET /api/users/:id/data checks session, but never verifies params.id === session.user.id",
    fix: "Add resource ownership checks or policy-gated queries before returning data."
  },
  {
    severity: "critical",
    title: "Supabase table reachable without RLS policy",
    category: "Database & Storage",
    confidence: "93%",
    evidence: "public.orders has RLS disabled and anon role has SELECT permission",
    fix: "Enable RLS and add user_id scoped SELECT, INSERT, UPDATE, and DELETE policies."
  },
  {
    severity: "high",
    title: "Stripe webhook accepts unsigned events",
    category: "API & Third-party Keys",
    confidence: "91%",
    evidence: "api/webhooks/stripe.ts parses req.body before constructEvent signature verification",
    fix: "Verify Stripe-Signature against the raw body before trusting event payloads."
  },
  {
    severity: "high",
    title: "Mass assignment can update privileged fields",
    category: "Business Logic",
    confidence: "88%",
    evidence: "prisma.user.update({ data: req.body }) permits isAdmin, plan, and balance changes",
    fix: "Map only allowed fields into ORM updates and reject unexpected properties server-side."
  },
  {
    severity: "high",
    title: "Secret key exposed to client bundle",
    category: "Data Exposure",
    confidence: "85%",
    evidence: "NEXT_PUBLIC_STRIPE_SECRET_KEY appears in .env.local and frontend imports",
    fix: "Move server-only credentials to unprefixed env vars and rotate the exposed key."
  },
  {
    severity: "medium",
    title: "Login endpoint has no throttling",
    category: "Input Validation",
    confidence: "82%",
    evidence: "POST /api/auth/login has no IP, account, or device rate limit guard",
    fix: "Add rate limits and progressive delay for password, OTP, and magic-link endpoints."
  },
  {
    severity: "medium",
    title: "Raw HTML rendering path accepts user content",
    category: "Cross-Site Scripting",
    confidence: "79%",
    evidence: "dangerouslySetInnerHTML renders project.description from database without sanitization",
    fix: "Render text by default or sanitize with a strict allowlist before storing and displaying."
  },
  {
    severity: "medium",
    title: "CORS allows all origins on credentialed API",
    category: "Infrastructure & Deployment",
    confidence: "77%",
    evidence: "Access-Control-Allow-Origin: * with cookie-backed session endpoints",
    fix: "Restrict origins by environment and disable credentials for public endpoints."
  }
];

let findings = [...sampleFindings];

const controls = {
  "Auth & Access": [
    "Route-level authentication middleware coverage",
    "Per-resource ownership checks",
    "Role and permission enforcement",
    "JWT expiry, storage, and secret hygiene"
  ],
  "Injection": [
    "Parameterized SQL and ORM queries",
    "NoSQL object shape validation",
    "Command execution input isolation",
    "Unsafe template and eval detection"
  ],
  "Data Boundaries": [
    "Sensitive field response filtering",
    "Production-safe error messages",
    "Committed .env and key fingerprint checks",
    "Server-only third-party keys"
  ],
  "App Abuse": [
    "Server-side validation and sanitization",
    "Rate limits for auth and paid actions",
    "Race condition checks for money flows",
    "Predictable token detection"
  ],
  "Storage": [
    "Supabase RLS enabled on all exposed tables",
    "Policy coverage by role and operation",
    "IDOR checks on sequential identifiers",
    "Backup and destructive action safeguards"
  ],
  "Supply Chain": [
    "OSV-backed CVE lookups for npm, PyPI, RubyGems, Go, Packagist",
    "Lockfile and integrity enforcement",
    "Typosquat and dependency confusion hints",
    "Overprivileged package review"
  ],
  "Platform": [
    "Open CORS detection",
    "Debug mode and verbose logging checks",
    "Admin panel exposure review",
    "Default credentials and public service scans"
  ],
  "Webhooks": [
    "Signature verification coverage",
    "Replay protection checks",
    "Raw body parsing correctness",
    "Event idempotency validation"
  ]
};

const grid = document.querySelector("#findingsGrid");
const search = document.querySelector("#findingSearch");
const tabs = document.querySelectorAll(".tab");
const segments = document.querySelectorAll(".segment");
const form = document.querySelector("#scanForm");
const progressBar = document.querySelector("#progressBar");
const scanStatus = document.querySelector("#scanStatus");
const scanTarget = document.querySelector("#scanTarget");
const steps = [...document.querySelectorAll("#scanSteps li")];
const controlList = document.querySelector("#controlList");
const themeToggle = document.querySelector("#themeToggle");
const scoreValue = document.querySelector("#scoreValue");
const scanNote = document.querySelector("#scanNote");
const archiveInput = document.querySelector("#archiveInput");
const depToggle = document.querySelector("#depToggle");
const patchToggle = document.querySelector("#patchToggle");

let activeFilter = "all";

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderFindings() {
  if (!grid) return;
  const query = (search?.value || "").trim().toLowerCase();
  const filtered = findings.filter((finding) => {
    const matchesSeverity = activeFilter === "all" || finding.severity === activeFilter;
    const haystack = `${finding.title} ${finding.category} ${finding.evidence} ${finding.fix}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });

  if (filtered.length === 0) {
    grid.innerHTML = `
      <article class="finding-card">
        <div>
          <p class="eyebrow">No matches</p>
          <h3>No findings match this view</h3>
        </div>
        <p>Try another severity filter or search term.</p>
      </article>
    `;
    return;
  }

  grid.innerHTML = filtered.map((finding) => `
    <article class="finding-card">
      <div class="finding-top">
        <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="confidence">${escapeHtml(finding.confidence)}</span>
      </div>
      <div>
        <p class="eyebrow">${escapeHtml(finding.category)}</p>
        <h3>${escapeHtml(finding.title)}</h3>
      </div>
      <div class="evidence">${escapeHtml(finding.evidence)}</div>
      <p>${escapeHtml(finding.fix)}</p>
    </article>
  `).join("");
}

function renderControls() {
  if (!controlList) return;
  controlList.innerHTML = Object.entries(controls).map(([category, items]) => `
    <article class="control-category">
      <h3>${category}</h3>
      <ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>
    </article>
  `).join("");
}

if (tabs.length) {
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
      activeFilter = tab.dataset.filter;
      renderFindings();
    });
  });
}

if (segments.length) {
  segments.forEach((segment) => {
    segment.addEventListener("click", () => {
      segments.forEach((item) => item.classList.remove("active"));
      segment.classList.add("active");
      document.querySelectorAll(".github-field, .upload-field, .paste-field").forEach((field) => field.classList.add("hidden"));
      document.querySelectorAll(`.${segment.dataset.mode}-field`).forEach((field) => field.classList.remove("hidden"));
    });
  });
}

if (search) search.addEventListener("input", renderFindings);

async function readUpload() {
  const file = archiveInput?.files?.[0];
  if (!file) {
    throw new Error("Choose a source file to scan.");
  }
  if (file.size > 160 * 1024) {
    throw new Error("Upload a text source file under 160 KB for this scanner version.");
  }
  return {
    filename: file.name,
    code: await file.text()
  };
}

function setScanStep(index) {
  if (!progressBar) return;
  steps.forEach((item, itemIndex) => {
    item.className = itemIndex < index ? "done" : itemIndex === index ? "active" : "pending";
  });
  progressBar.style.width = `${Math.min(100, index * 20)}%`;
}

async function startBackendScan(mode) {
  const repoValue = document.querySelector("#repoUrl")?.value?.trim() || "";
  const pasteValue = document.querySelector("#codePaste")?.value?.trim() || "";
  const payload = {
    dependencyScan: Boolean(depToggle?.checked),
    generatePatches: Boolean(patchToggle?.checked)
  };
  if (mode === "github") {
    return { ...payload, sourceType: "github", repoUrl: repoValue };
  }
  if (mode === "upload") {
    return { ...payload, sourceType: "paste", ...(await readUpload()) };
  }
  return {
    ...payload,
    sourceType: "paste",
    filename: "pasted-snippet.js",
    code: pasteValue || "app.get('/api/users/:id', (req, res) => db.query('SELECT * FROM users WHERE id = ' + req.params.id))"
  };
}

if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const mode = document.querySelector(".segment.active")?.dataset?.mode || "paste";
    const repoValue = mode === "github" ? document.querySelector("#repoUrl")?.value || "" : mode;
    const target = (repoValue.split("/").filter(Boolean).pop() || "pasted code");
    if (scanTarget) scanTarget.textContent = target;
    if (scanStatus) scanStatus.textContent = "Scanning";
    if (scanNote) scanNote.textContent = "Running scan in an isolated worker. Secret-looking values are redacted before evidence is returned.";
    if (progressBar) progressBar.style.width = "0%";
    steps.forEach((step) => {
      step.className = "pending";
    });

    try {
      setScanStep(1);
      const payload = await startBackendScan(mode);
      setScanStep(2);
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      setScanStep(3);
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.message || "Scan failed.");
      }
      setScanStep(5);
      steps.forEach((item) => item.className = "done");
      if (scanStatus) scanStatus.textContent = "Complete";
      if (scanTarget) scanTarget.textContent = result.target || target;
      if (scoreValue) scoreValue.textContent = String(result.score);
      findings = result.findings.length ? result.findings : [];
      activeFilter = "all";
      tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.filter === "all"));
      renderFindings();
      if (scanNote) {
        scanNote.textContent = `Scan ${result.id} reviewed ${result.filesScanned} file(s), found ${result.findings.length} issue(s). ${result.org_id ? "Saved to your workspace." : "Anonymous run — sign in to keep history."}`;
      }
      document.querySelector("#findings")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      if (scanStatus) scanStatus.textContent = "Failed";
      if (progressBar) progressBar.style.width = "100%";
      findings = [{
        severity: "high",
        title: "Scanner could not complete",
        category: "Scanner",
        confidence: "100%",
        evidence: error.message,
        fix: "Check the repository URL or pasted input and try again. Sign in for higher quotas and private repos."
      }];
      renderFindings();
      if (scanNote) scanNote.textContent = error.message;
    }
  });
}

if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("vibeshield-theme", next);
  });
}

document.documentElement.dataset.theme = localStorage.getItem("vibeshield-theme") || "";

function drawRiskMap() {
  const canvas = document.querySelector("#riskCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  let frame = 0;

  const nodes = [
    { x: 96, y: 88, label: "auth", risk: 0.95 },
    { x: 268, y: 76, label: "api", risk: 0.72 },
    { x: 482, y: 96, label: "db", risk: 0.88 },
    { x: 584, y: 228, label: "keys", risk: 0.82 },
    { x: 428, y: 330, label: "rls", risk: 0.96 },
    { x: 210, y: 318, label: "xss", risk: 0.56 },
    { x: 108, y: 222, label: "cors", risk: 0.42 }
  ];

  function colorFor(risk) {
    if (risk > 0.86) return "#ef4444";
    if (risk > 0.65) return "#f59e0b";
    return "#22c55e";
  }

  function tick() {
    frame += 1;
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "#0b1110";
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = "rgba(45, 212, 191, 0.10)";
    ctx.lineWidth = 1;
    for (let x = 40; x < width; x += 52) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 38; y < height; y += 52) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    ctx.lineWidth = 2;
    nodes.forEach((node, index) => {
      const next = nodes[(index + 1) % nodes.length];
      ctx.strokeStyle = `rgba(45, 212, 191, ${0.18 + Math.sin(frame / 24 + index) * 0.08})`;
      ctx.beginPath();
      ctx.moveTo(node.x, node.y);
      ctx.lineTo(next.x, next.y);
      ctx.stroke();
    });

    nodes.forEach((node, index) => {
      const pulse = 1 + Math.sin(frame / 18 + index) * 0.12;
      const radius = 24 * pulse;
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + 12, 0, Math.PI * 2);
      ctx.fillStyle = `${colorFor(node.risk)}22`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = colorFor(node.risk);
      ctx.fill();

      ctx.fillStyle = "#07100f";
      ctx.font = "700 13px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(node.label, node.x, node.y);
    });

    ctx.fillStyle = "rgba(237, 243, 239, 0.72)";
    ctx.font = "13px ui-monospace, monospace";
    ctx.textAlign = "left";
    ctx.fillText("trace: /api/users/:id -> prisma.user.findMany -> response body", 34, height - 34);
    requestAnimationFrame(tick);
  }

  tick();
}

renderFindings();
renderControls();
drawRiskMap();
