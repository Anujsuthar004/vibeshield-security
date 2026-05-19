const findings = [
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
    "Known CVE dependency audit",
    "Overprivileged package review",
    "Lockfile and integrity enforcement",
    "Typosquat and dependency confusion hints"
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

let activeFilter = "all";

function renderFindings() {
  const query = search.value.trim().toLowerCase();
  const filtered = findings.filter((finding) => {
    const matchesSeverity = activeFilter === "all" || finding.severity === activeFilter;
    const haystack = `${finding.title} ${finding.category} ${finding.evidence} ${finding.fix}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });

  grid.innerHTML = filtered.map((finding) => `
    <article class="finding-card">
      <div class="finding-top">
        <span class="severity ${finding.severity}">${finding.severity}</span>
        <span class="confidence">${finding.confidence}</span>
      </div>
      <div>
        <p class="eyebrow">${finding.category}</p>
        <h3>${finding.title}</h3>
      </div>
      <div class="evidence">${finding.evidence}</div>
      <p>${finding.fix}</p>
    </article>
  `).join("");
}

function renderControls() {
  controlList.innerHTML = Object.entries(controls).map(([category, items]) => `
    <article class="control-category">
      <h3>${category}</h3>
      <ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>
    </article>
  `).join("");
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    activeFilter = tab.dataset.filter;
    renderFindings();
  });
});

segments.forEach((segment) => {
  segment.addEventListener("click", () => {
    segments.forEach((item) => item.classList.remove("active"));
    segment.classList.add("active");
    document.querySelectorAll(".github-field, .upload-field, .paste-field").forEach((field) => field.classList.add("hidden"));
    document.querySelector(`.${segment.dataset.mode}-field`).classList.remove("hidden");
  });
});

search.addEventListener("input", renderFindings);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const repoValue = document.querySelector("#repoUrl").value || "local upload";
  const target = repoValue.split("/").filter(Boolean).pop() || "pasted code";
  scanTarget.textContent = target;
  scanStatus.textContent = "Scanning";
  progressBar.style.width = "0%";
  steps.forEach((step) => {
    step.className = "pending";
  });

  steps.forEach((step, index) => {
    setTimeout(() => {
      steps.forEach((item, itemIndex) => {
        item.className = itemIndex < index ? "done" : itemIndex === index ? "active" : "pending";
      });
      progressBar.style.width = `${(index + 1) * 20}%`;
      scoreValue.textContent = String(Math.max(54, 76 - index));
      if (index === steps.length - 1) {
        setTimeout(() => {
          steps.forEach((item) => item.className = "done");
          scanStatus.textContent = "Complete";
          scoreValue.textContent = "68";
        }, 450);
      }
    }, 520 * (index + 1));
  });
});

themeToggle.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("vibeshield-theme", next);
});

document.documentElement.dataset.theme = localStorage.getItem("vibeshield-theme") || "";

function drawRiskMap() {
  const canvas = document.querySelector("#riskCanvas");
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
