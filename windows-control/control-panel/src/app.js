import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} from "@simplewebauthn/browser";
const app = document.querySelector("#app"),
  dialog = document.querySelector("#dialog"),
  secureDialog = document.querySelector("#secure");
const state = {
  token: "",
  refresh: "",
  expires: 0,
  context: null,
  department: "",
  page: "overview",
  data: null,
  filter: "",
  lastActivity: Date.now(),
  auditGlobal: false,
  busy: false,
  generation: 0,
  loadId: 0,
};
let refreshPromise = null;
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const cash = (v) => {
  try {
    let n = BigInt(v ?? 0),
      sign = n < 0n ? "-" : "";
    if (n < 0n) n = -n;
    return (
      sign +
      "₹" +
      new Intl.NumberFormat("en-IN").format(n / 100n) +
      "." +
      String(n % 100n).padStart(2, "0")
    );
  } catch {
    return "—";
  }
};
const paise = (v) => {
  const m = String(v)
    .trim()
    .match(/^(\d+)(?:\.(\d{1,2}))?$/);
  if (!m) throw Error("Use a rupee amount with at most two decimal places.");
  const n = BigInt(m[1]) * 100n + BigInt((m[2] ?? "").padEnd(2, "0"));
  if (n <= 0n || n > 9000000000000000n)
    throw Error("Amount is outside the permitted range.");
  return String(n);
};
const date = (v) =>
  v
    ? new Intl.DateTimeFormat("en-IN", {
        dateStyle: "medium",
        timeStyle: "short",
        timeZone: "Asia/Kolkata",
      }).format(new Date(v))
    : "—";
const short = (id) => (id ? esc(String(id).slice(0, 8)) + "…" : "—");
const badge = (v) =>
  `<span class="badge ${["APPROVED", "RECEIVED", "ACTIVE", "RESOLVED", "POSTED"].includes(v) ? "good" : ["DISPUTED", "REJECTED", "DISCREPANCY_OPEN", "REVOKED", "INACTIVE"].includes(v) ? "bad" : ["PENDING_RECEIPT", "PENDING_HOD", "UNDER_REVIEW", "OPEN", "IN_CUSTODY", "HANDED_TO_HOD"].includes(v) ? "warn" : "neutral"}">${esc(String(v).replaceAll("_", " "))}</span>`;
const btn = (label, action, extra = "", kind = "ghost") =>
  `<button class="btn ${kind}" data-action="${action}" ${extra}>${label}</button>`;
const field = (label, id, type = "text", value = "", extra = "") =>
  `<div class="field"><label for="${id}">${label}</label><input id="${id}" name="${id}" type="${type}" value="${esc(value)}" ${extra}></div>`;
const textarea = (label, id, value = "", extra = "") =>
  `<div class="field"><label for="${id}">${label}</label><textarea id="${id}" name="${id}" ${extra}>${esc(value)}</textarea></div>`;
const select = (label, id, options, value, extra = "") =>
  `<div class="field"><label for="${id}">${label}</label><select id="${id}" name="${id}" ${extra}>${options.map(([v, l]) => `<option value="${esc(v)}" ${v === value ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></div>`;
function toast(message, error = false) {
  const node = document.createElement("div");
  node.className = "toast" + (error ? " error" : "");
  node.textContent = message;
  document.querySelector("#notifications").append(node);
  setTimeout(() => node.remove(), 6500);
}
function closeModal() {
  if (dialog.open) dialog.close();
  dialog.innerHTML = "";
}
function modal(title, body, footer = "") {
  dialog.innerHTML = `<div class="modal-header"><h2 id="dialog-title">${esc(title)}</h2><button class="close" data-action="close" aria-label="Close">×</button></div><div class="modal-body">${body}</div>${footer ? `<div class="modal-footer">${footer}</div>` : ""}`;
  dialog.showModal();
}
function formModal(title, body, submit) {
  modal(
    title,
    `<form id="entity-form"><div class="form-error" id="entity-error" role="alert"></div>${body}<div class="modal-footer"><button type="button" class="btn ghost" data-action="close">Cancel</button><button type="submit" class="btn primary">Verify & save</button></div></form>`,
  );
  document
    .querySelector("#entity-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      if (!form.reportValidity()) return;
      const button = form.querySelector("[type=submit]");
      button.disabled = true;
      try {
        await submit(Object.fromEntries(new FormData(form)));
      } catch (err) {
        const n = document.querySelector("#entity-error");
        if (n) n.textContent = err.message;
        else toast(err.message, true);
      } finally {
        button.disabled = false;
      }
    });
}
async function ensureAccess() {
  if (!state.token) throw Error("Sign in to continue.");
  if (state.expires > Date.now() + 15000) return;
  if (!refreshPromise)
    refreshPromise = (async () => {
      const r = await fetch("/v1/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: state.refresh }),
      });
      if (!r.ok) {
        lock("Your session ended. Sign in again.");
        throw Error("Your session ended.");
      }
      const v = await r.json();
      state.token = v.accessToken;
      state.refresh = v.refreshToken;
      state.expires = Date.now() + v.expiresIn * 1000;
    })().finally(() => (refreshPromise = null));
  await refreshPromise;
}
async function api(
  path,
  { method = "GET", body, auth = true, raw = false } = {},
) {
  if (auth) await ensureAccess();
  const generation = state.generation;
  const r = await fetch("/" + path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(auth ? { Authorization: "Bearer " + state.token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (auth && generation !== state.generation)
    throw Error("Session locked. Sign in again.");
  if (!r.ok) {
    let error;
    try {
      error = await r.json();
    } catch {}
    if (auth && r.status === 401)
      lock("Authentication expired or failed. Sign in again.");
    throw Error(error?.message ?? `Request failed (${r.status}).`);
  }
  return raw ? r : r.status === 204 ? null : r.json();
}
function lock(message = "Locked. Sign in to continue.") {
  const token = state.token;
  state.generation++;
  state.token = "";
  state.refresh = "";
  state.context = null;
  state.data = null;
  state.department = "";
  state.filter = "";
  closeModal();
  if (secureDialog.open) secureDialog.close();
  secureDialog.innerHTML = "";
  state.lastActivity = Date.now();
  if (token)
    fetch("/v1/logout", {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
    }).catch(() => {});
  renderAuth("login", message);
}
for (const event of ["pointerdown", "keydown", "touchstart"])
  window.addEventListener(event, () => (state.lastActivity = Date.now()), {
    passive: true,
  });
setInterval(() => {
  if (state.token && Date.now() - state.lastActivity > 120000)
    lock("Locked after 2 minutes of inactivity.");
}, 5000);
window.addEventListener("pagehide", () => {
  if (state.token) lock();
});
window.addEventListener("pageshow", (e) => {
  if (e.persisted) lock();
});
async function secure(action, payload, label) {
  if (state.context?.device.kind !== "WEB")
    throw Error(
      "Use an enrolled Windows Hello/passkey device for the control panel.",
    );
  const generation = state.generation;
  const freshPin = await new Promise((resolve, reject) => {
    secureDialog.className = "secure-dialog";
    secureDialog.innerHTML = `<div class="modal-header"><h2 id="secure-title">CONFIRM SECURE ACTION</h2><button type="button" class="close" id="cancel-secure" aria-label="Cancel">×</button></div><form id="secure-form"><div class="modal-body"><span class="tag">PIN + WINDOWS HELLO</span><p style="margin:18px 0;color:#bdcee1">${esc(label)}</p>${field("Your fresh app PIN", "freshPin", "password", "", 'required inputmode="numeric" pattern="[0-9]{6,12}" minlength="6" maxlength="12" autocomplete="off"')}<p class="tiny muted">Windows Hello or your registered passkey will verify this exact action next.</p></div><div class="modal-footer"><button type="button" class="btn ghost" id="cancel-secure2">Cancel</button><button class="btn cyan" type="submit">Continue to Windows Hello</button></div></form>`;
    const cancel = () => {
      const input = document.querySelector("#freshPin");
      if (input) input.value = "";
      secureDialog.close();
      secureDialog.innerHTML = "";
      reject(Error("Action cancelled."));
    };
    document.querySelector("#cancel-secure").onclick = cancel;
    document.querySelector("#cancel-secure2").onclick = cancel;
    secureDialog.oncancel = (e) => {
      e.preventDefault();
      cancel();
    };
    secureDialog.onclose = () => reject(Error("Secure action closed."));
    document.querySelector("#secure-form").onsubmit = (e) => {
      e.preventDefault();
      const input = document.querySelector("#freshPin");
      if (!e.target.reportValidity()) return;
      const value = input.value;
      input.value = "";
      secureDialog.onclose = null;
      secureDialog.close();
      resolve(value);
    };
    secureDialog.showModal();
    document.querySelector("#freshPin").focus();
  });
  const ch = await api("v1/challenge", {
    method: "POST",
    body: { action, payload },
  });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(ch.message),
  );
  const encoded = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  const assertion = await startAuthentication({
    optionsJSON: {
      challenge: encoded,
      rpId: "localhost",
      allowCredentials: [
        {
          id: state.context.device.credentialId,
          type: "public-key",
          transports: state.context.device.transports,
        },
      ],
      userVerification: "required",
      timeout: 60000,
    },
  });
  if (generation !== state.generation) throw Error("Session locked.");
  return { challengeId: ch.id, pin: freshPin, assertion };
}
async function mutate(path, action, data, label, id) {
  const payload = id ? { id, ...data } : data;
  const proof = await secure(action, payload, label);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      state.context.user.id + "|" + path + "|" + JSON.stringify(payload),
    ),
  );
  const identity =
    "rs-pending-" +
    Array.from(new Uint8Array(digest), (n) =>
      n.toString(16).padStart(2, "0"),
    ).join("");
  let key = sessionStorage.getItem(identity);
  if (!key) {
    key = crypto.randomUUID();
    sessionStorage.setItem(identity, key);
  }
  const result = await api(path, {
    method: "POST",
    body: { key, data, proof },
  });
  sessionStorage.removeItem(identity);
  return result;
}
async function manage(data, label) {
  const proof = await secure("ADMIN", data, label);
  return api("v1/control/manage", { method: "POST", body: { data, proof } });
}
async function legacyAdmin(data, label) {
  const proof = await secure("ADMIN", data, label);
  return api("v1/admin", { method: "POST", body: { data, proof } });
}
async function refreshContext() {
  state.context = await api("v1/control/context");
  if (!state.context.departments.some((d) => d.id === state.department))
    state.department =
      state.context.departments.find((d) => d.active)?.id ??
      state.context.departments[0]?.id ??
      "";
}
const brand = () =>
  `<div class="brand"><img src="./logo.png" alt="Racing Speed logo"><div><div class="brand-name">RACING SPEED</div><small>LOCAL COMMAND CENTER</small></div></div>`;
const strip =
  '<div class="test-strip">LOCAL TEST ENVIRONMENT • USE TEST CASH ONLY • THIS SERVER RUNS ON YOUR COMPUTER</div>';
function renderAuth(mode = "login", message = "", token = "") {
  app.innerHTML =
    strip +
    `<main class="auth-page"><section class="auth-brand"><img src="./logo.png" alt="Racing Speed racing logo"><div class="eyebrow">EVERY COLLECTION. EVERY HAND. ACCOUNTED.</div><h1>TAKE CONTROL.<br>KEEP THE CHAIN.</h1><p>Your cash-custody operations, one secure command center. Separate database. Clear responsibility. Complete visibility.</p><div class="auth-lines">${"<span></span>".repeat(6)}</div><span class="tag">WINDOWS LOCAL TESTING</span></section><section class="auth-card"><div class="eyebrow">${mode === "setup" ? "FIRST RUN / SECURE SETUP" : mode === "enroll" ? "DEVICE ENROLLMENT" : "AUTHORIZED PERSONNEL ONLY"}</div><h2>${mode === "setup" ? "CREATE SUPER ADMIN" : mode === "enroll" ? "ENROLL THIS DEVICE" : "ENTER RACE CONTROL"}</h2><p class="subtext">${mode === "setup" ? "Connect your first administrator account to Windows Hello or a passkey. No default password is supplied." : mode === "enroll" ? "Use your account PIN and this one-time invitation to enroll a browser passkey." : "Sign in with your app PIN and enrolled Windows Hello/passkey."}</p><div class="form-error" id="auth-error" role="alert">${esc(message)}</div><form id="auth-form">${mode === "setup" ? field("One-time setup code", "setupCode", "password", "", 'required autocomplete="off"') + field("Full name", "name", "text", "", 'required maxlength="120"') + field("Email", "email", "email", "", 'required autocomplete="username"') : mode === "login" ? field("Email", "email", "email", localStorage.getItem("rs-email") ?? "", 'required autocomplete="username"') : ""}${field(mode === "setup" ? "Choose an app PIN (6–12 digits)" : "App PIN", "pin", "password", "", 'required inputmode="numeric" pattern="[0-9]{6,12}" minlength="6" maxlength="12" autocomplete="off"')}${mode !== "login" ? field("Device label", "label", "text", "My Windows PC", 'required maxlength="120"') : ""}<button class="btn cyan" type="submit">${mode === "setup" ? "CREATE ACCOUNT & ENROLL PASSKEY" : mode === "enroll" ? "ENROLL WITH WINDOWS HELLO" : "VERIFY PIN & WINDOWS HELLO"}</button></form><p class="auth-footer">Requires Edge or Chrome, HTTPS localhost, and Windows Hello or a security key. WebAuthn verifies the user through device settings; it does not prove that biometrics rather than the Windows PIN were used.<br><br>Auto-locks after 2 minutes of inactivity. No financial records are stored in browser storage.</p></section></main>`;
  document.querySelector("#auth-form").onsubmit = async (e) => {
    e.preventDefault();
    if (!e.target.reportValidity()) return;
    const values = Object.fromEntries(new FormData(e.target));
    const button = e.target.querySelector("button[type=submit]");
    button.disabled = true;
    document.querySelector("#auth-error").textContent = "";
    try {
      if (!browserSupportsWebAuthn())
        throw Error(
          "Passkeys are not available. Use current Edge/Chrome at https://localhost:8443/control/ and configure Windows Hello.",
        );
      if (mode === "setup") {
        const reg = await api("v1/web/bootstrap/options", {
          method: "POST",
          auth: false,
          body: values,
        });
        const response = await startRegistration({ optionsJSON: reg.options });
        const enrolled = await api("v1/web/bootstrap/verify", {
          method: "POST",
          auth: false,
          body: { setupCode: values.setupCode, id: reg.id, response },
        });
        localStorage.setItem("rs-device", enrolled.deviceId);
        localStorage.setItem("rs-email", values.email);
        renderAuth(
          "login",
          "Super Admin created. Sign in with your PIN and enrolled passkey.",
        );
      } else if (mode === "enroll") {
        const reg = await api("v1/web/enroll/options", {
          method: "POST",
          auth: false,
          body: { token, pin: values.pin, label: values.label },
        });
        const response = await startRegistration({ optionsJSON: reg.options });
        const result = await api("v1/web/enroll/verify", {
          method: "POST",
          auth: false,
          body: { token, id: reg.id, response },
        });
        history.replaceState(null, "", location.pathname);
        localStorage.setItem("rs-device", result.deviceId);
        renderAuth("login", "Device enrolled. Sign in to continue.");
      } else {
        const email = values.email.trim();
        const options = await api("v1/web/login/options", {
          method: "POST",
          auth: false,
          body: {
            email,
            ...(localStorage.getItem("rs-email") === email &&
            localStorage.getItem("rs-device")
              ? { deviceId: localStorage.getItem("rs-device") }
              : {}),
          },
        });
        const assertion = await startAuthentication({
          optionsJSON: options.options,
        });
        const result = await api("v1/auth/login", {
          method: "POST",
          auth: false,
          body: {
            userId: options.userId,
            deviceId: options.deviceId,
            proof: {
              challengeId: options.challenge.id,
              pin: values.pin,
              assertion,
            },
          },
        });
        state.token = result.accessToken;
        state.refresh = result.refreshToken;
        state.expires = Date.now() + result.expiresIn * 1000;
        state.lastActivity = Date.now();
        localStorage.setItem("rs-email", email);
        localStorage.setItem("rs-device", options.deviceId);
        await refreshContext();
        state.page = "overview";
        await load();
      }
    } catch (err) {
      document
        .querySelector("#auth-error")
        ?.replaceChildren(
          document.createTextNode(
            err.message ?? "Authentication could not be completed.",
          ),
        );
    } finally {
      const input = document.querySelector("#pin");
      if (input) input.value = "";
      button.disabled = false;
      values.pin = "";
    }
  };
}
const navItems = [
  ["OPERATIONS", "overview", "◉", "Race Control"],
  ["", "collections", "▤", "Collections"],
  ["", "handovers", "⇄", "Handovers"],
  ["", "approvals", "⚑", "Pit Stop / Approvals"],
  ["", "discrepancies", "!", "Discrepancies"],
  ["", "balances", "◫", "Custody balances"],
  ["TEAM & CONFIGURATION", "users", "♙", "Users & roles"],
  ["", "departments", "▦", "Departments"],
  ["", "devices", "◇", "Devices"],
  ["", "sessions", "◷", "Sessions"],
  ["OVERSIGHT", "reports", "↧", "Reports"],
  ["", "audit", "≋", "Audit trail"],
  ["", "database", "▱", "Database & backup"],
];
const adminPages = new Set([
  "users",
  "departments",
  "devices",
  "sessions",
  "database",
]);
const pageTitles = {
  overview: ["RACE CONTROL", "Your department’s cash custody, at a glance."],
  collections: [
    "COLLECTIONS",
    "Original collection income. Internal transfers are never counted twice.",
  ],
  handovers: [
    "HANDOVERS",
    "Two sides. One confirmed transfer of responsibility.",
  ],
  approvals: [
    "PIT STOP",
    "Count physical cash, review the chain, then make the final call.",
  ],
  discrepancies: [
    "DISCREPANCIES",
    "Blocked funds stay blocked until an explicit, audited resolution.",
  ],
  balances: [
    "CUSTODY BALANCES",
    "Current custody, reservations and blocked funds by holder.",
  ],
  users: [
    "USERS & ROLES",
    "Individual accounts. Clear responsibilities. Controlled access.",
  ],
  departments: [
    "DEPARTMENTS",
    "Configure targets, collector hops and overdue thresholds.",
  ],
  devices: [
    "ENROLLED DEVICES",
    "Manage browser passkeys and Android signing keys.",
  ],
  sessions: [
    "ACTIVE SESSIONS",
    "Revoke access immediately without deleting custody history.",
  ],
  reports: [
    "REPORTS & EXPORTS",
    "Department records, secured with fresh PIN and passkey confirmation.",
  ],
  audit: [
    "AUDIT TRAIL",
    "Append-only events with independently verifiable hash chains.",
  ],
  database: [
    "DATABASE CONTROL",
    "Connection health, schema status and local backup operations.",
  ],
};
function shell(content = "") {
  const user = state.context.user;
  app.innerHTML =
    strip +
    `<div class="layout"><aside class="sidebar">${brand()}<nav class="nav" aria-label="Admin navigation">${navItems
      .filter(([, id]) => user.role === "SUPER_ADMIN" || !adminPages.has(id))
      .map(
        ([group, id, icon, label]) =>
          `${group ? `<div class="nav-label">${group}</div>` : ""}<button data-page="${id}" class="${state.page === id ? "active" : ""}"><span class="nav-icon" aria-hidden="true">${icon}</span>${label}</button>`,
      )
      .join(
        "",
      )}</nav><div class="sidebar-bottom"><div class="user-name">${esc(user.name)}</div><div class="user-role">${esc(user.role.replaceAll("_", " "))} · Windows local</div><button data-action="lock">↪ Lock & sign out</button></div></aside><div class="workspace"><header class="topbar"><div class="scope"><span class="eyebrow">DEPARTMENT</span><select id="department-select" aria-label="Department scope">${state.context.departments.length ? state.context.departments.map((d) => `<option value="${d.id}" ${d.id === state.department ? "selected" : ""}>${esc(d.name)}${d.active ? "" : " (archived)"}</option>`).join("") : '<option value="">No departments yet</option>'}</select></div><div class="top-actions"><span class="date tiny muted">${new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeZone: "Asia/Kolkata" }).format(new Date())}</span><span class="connection"><span class="dot"></span> LOCAL SERVER CONNECTED</span><button class="icon-btn" data-action="refresh" aria-label="Refresh">↻</button><button class="icon-btn" data-action="lock" aria-label="Lock session">♙</button></div></header><main class="main" id="main">${content}</main></div></div>`;
  document.querySelector("#department-select").onchange = (e) => {
    state.department = e.target.value;
    state.filter = "";
    load();
  };
}
function header(actions = "") {
  const [title, description] = pageTitles[state.page];
  return `<div class="page-header"><div><div class="eyebrow">RACING SPEED / LOCAL OPERATIONS</div><h1>${title}</h1><p>${description}</p></div><div class="header-actions">${actions}</div></div>`;
}
function empty(title, text, action = "") {
  return `<div class="empty"><div class="empty-icon">◇</div><h2 id="dialog-title">${esc(title)}</h2><p>${esc(text)}</p>${action}</div>`;
}
function table(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map((x) => `<th>${x}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((x) => "<tr>" + x.map((v) => "<td>" + v + "</td>").join("") + "</tr>").join("") : `<tr><td colspan="${headers.length}" style="text-align:center;padding:40px;color:#8499b2">No records in this view.</td></tr>`}</tbody></table></div>`;
}
function searchToolbar(note) {
  return `<div class="toolbar"><input id="search" class="search" type="search" placeholder="Filter visible records…" value="${esc(state.filter)}" aria-label="Filter visible records"><span class="tiny muted">${note}</span></div>`;
}
function filtered(rows) {
  const q = state.filter.toLowerCase();
  return q
    ? rows.filter((x) =>
        Object.values(x).some(
          (v) => typeof v === "string" && v.toLowerCase().includes(q),
        ),
      )
    : rows;
}
async function load() {
  if (!state.token) return;
  const loadId = ++state.loadId;
  const generation = state.generation;
  state.lastActivity = Date.now();
  shell(
    header() +
      '<div class="loading"><span class="spinner"></span> Loading live local data…</div>',
  );
  try {
    if (
      !state.department &&
      !adminPages.has(state.page) &&
      state.page !== "audit"
    ) {
      state.data = null;
      document.querySelector("#main").innerHTML =
        header() +
        empty(
          "START YOUR FIRST DEPARTMENT",
          "Create a department, add accounts, then connect your Android collectors.",
          state.context.user.role === "SUPER_ADMIN"
            ? btn("Create department", "new-department", "", "primary")
            : "Ask your Super Admin to assign your department.",
        );
      return;
    }
    let data;
    const dep = state.department;
    switch (state.page) {
      case "overview":
        data = await api(`v1/departments/${dep}/dashboard`);
        break;
      case "collections":
      case "approvals":
        data = await api(`v1/departments/${dep}/collections`);
        break;
      case "handovers":
        data = await api(`v1/control/handovers?departmentId=${dep}`);
        break;
      case "discrepancies":
        data = await api(`v1/control/discrepancies?departmentId=${dep}`);
        break;
      case "balances":
        data = await api(`v1/control/balances?departmentId=${dep}`);
        break;
      case "users":
        data = await api("v1/admin/users");
        break;
      case "departments":
        data = { departments: state.context.departments };
        break;
      case "devices":
        data = await api("v1/control/devices");
        break;
      case "sessions":
        data = await api("v1/control/sessions");
        break;
      case "audit":
        data = await api(
          `v1/control/audit?departmentId=${state.auditGlobal || !dep ? "GLOBAL" : dep}`,
        );
        break;
      case "database":
        data = await api("v1/control/database");
        break;
      case "reports":
        data = {};
        break;
    }
    if (generation !== state.generation || loadId !== state.loadId) return;
    state.data = data;
    renderPage();
  } catch (err) {
    if (loadId !== state.loadId) return;
    const main = document.querySelector("#main");
    if (main)
      main.innerHTML =
        header() + `<div class="error-box">${esc(err.message)}</div>`;
  }
}
function renderPage() {
  const d = state.data ?? {};
  const user = state.context.user;
  let content = "";
  switch (state.page) {
    case "overview":
      content = overview(d);
      break;
    case "collections":
    case "approvals": {
      const rows = filtered(d.collections ?? []).filter(
        (r) => state.page !== "approvals" || r.state !== "APPROVED",
      );
      content =
        header() +
        searchToolbar(
          state.page === "approvals"
            ? "Final approval is HOD-only."
            : "Latest 500 department records.",
        ) +
        table(
          [
            "Reference / customer",
            "Collected by",
            "Original amount",
            "Custody",
            "Approval",
            "Action",
          ],
          rows.map((r) => [
            `<button class="click-ref" data-action="chain" data-id="${r.id}">${short(r.id)}</button><div class="sub">${esc(r.customer)}</div>`,
            esc(r.collector),
            `<span class="amount">${cash(r.amount)}</span>`,
            badge(r.state),
            badge(r.approval_status),
            btn("Review chain", "chain", `data-id="${r.id}"`),
          ]),
        );
      break;
    }
    case "handovers":
      content =
        header() +
        searchToolbar(
          "Latest 500 handovers. No sender submission proves receipt.",
        ) +
        table(
          [
            "Reference",
            "Custody route",
            "Expected / actual",
            "Status",
            "Created",
            "Action",
          ],
          filtered(d.handovers ?? []).map((h) => [
            short(h.id),
            `${esc(h.sender)} → ${esc(h.receiver)}`,
            `${cash(h.expected)}<div class="sub">Counted: ${h.actual === null ? "Not confirmed" : cash(h.actual)}</div>`,
            badge(h.state),
            date(h.created_at),
            h.receiver_id === user.id && h.state === "PENDING_RECEIPT"
              ? btn("Count / receive", "receive", `data-id="${h.id}"`, "cyan")
              : "—",
          ]),
        );
      break;
    case "discrepancies":
      content =
        header() +
        searchToolbar("Resolution never silently rewrites an original count.") +
        table(
          [
            "Reference",
            "Expected / counted",
            "Reason",
            "Status",
            "Resolution",
            "Action",
          ],
          filtered(d.discrepancies ?? []).map((x) => [
            short(x.id),
            `${cash(x.expected)} / ${cash(x.actual)}`,
            esc(x.reason),
            badge(x.state),
            esc(x.resolution ?? "—"),
            x.state === "OPEN" && user.role === "HOD"
              ? btn("Resolve", "resolve", `data-id="${x.id}"`, "danger")
              : "—",
          ]),
        );
      break;
    case "balances":
      content =
        header() +
        table(
          [
            "Holder",
            "Role",
            "Current custody",
            "Reserved",
            "Blocked",
            "Available",
            "Overdue items",
            "Oldest held collection",
          ],
          (d.balances ?? []).map((x) => [
            esc(x.name),
            esc(x.role),
            cash(x.amount),
            cash(x.reserved),
            `<span class="${BigInt(x.blocked) > 0n ? "danger-text" : ""}">${cash(x.blocked)}</span>`,
            cash(x.available),
            String(x.overdue ?? 0),
            date(x.oldest),
          ]),
        );
      break;
    case "users":
      content =
        header(btn("＋ Create user", "new-user", "", "primary")) +
        searchToolbar(
          "No shared logins. Revoked accounts retain their financial history.",
        ) +
        table(
          ["Account", "Role", "Department", "Status", "Controls"],
          filtered(d.users ?? []).map((u) => [
            `${esc(u.name)}<div class="sub">${esc(u.email)}</div><div class="sub mono">${esc(u.id)}</div>`,
            esc(u.role),
            esc(departmentName(u.department_id)),
            badge(u.active ? "ACTIVE" : "INACTIVE"),
            `<div class="table-actions">${btn("Edit", "edit-user", `data-id="${u.id}"`)}${btn("Reset PIN", "reset-pin", `data-id="${u.id}"`)}${u.active && u.role !== "COLLECTOR" ? btn("Web access", "invite-web", `data-id="${u.id}"`) : ""}</div>`,
          ]),
        );
      break;
    case "departments":
      content =
        header(btn("＋ Create department", "new-department", "", "primary")) +
        table(
          [
            "Department",
            "Daily target",
            "Collector hops",
            "Overdue threshold",
            "Status",
            "Controls",
          ],
          (d.departments ?? []).map((x) => [
            `${esc(x.name)}<div class="sub mono">${esc(x.id)}</div>`,
            cash(x.daily_target),
            x.max_hops ?? "Unlimited",
            x.overdue_minutes + " minutes",
            badge(x.active ? "ACTIVE" : "INACTIVE"),
            `<div class="table-actions">${btn("Configure", "edit-department", `data-id="${x.id}"`)}${btn(x.active ? "Archive" : "Restore", "archive-department", `data-id="${x.id}"`)}</div>`,
          ]),
        );
      break;
    case "devices":
      content =
        header(btn("Enroll Android device", "enroll-android", "", "primary")) +
        searchToolbar(
          "Web access invitations are created from Users & roles.",
        ) +
        table(
          [
            "Device",
            "Owner",
            "Type / assurance",
            "Status",
            "Enrolled",
            "Controls",
          ],
          filtered(d.devices ?? []).map((x) => [
            `${esc(x.label)}<div class="sub mono">${esc(x.id)}</div>`,
            `${esc(x.owner)}<div class="sub">${esc(x.email)}</div>`,
            `${esc(x.kind)}<div class="sub">${x.hardware_verified ? "Operator verified" : "Local test enrollment"}</div>`,
            badge(x.active ? "ACTIVE" : "REVOKED"),
            date(x.enrolled_at),
            x.active && x.id !== state.context.device.id
              ? btn("Revoke", "revoke-device", `data-id="${x.id}"`, "danger")
              : "—",
          ]),
        );
      break;
    case "sessions":
      content =
        header() +
        searchToolbar("Revocation applies to the next API call.") +
        table(
          ["Session", "Account / device", "Expires", "Status", "Control"],
          filtered(d.sessions ?? []).map((s) => [
            `${short(s.id)}${s.id === state.context.sessionId ? '<div class="sub">This session</div>' : ""}`,
            `${esc(s.owner)}<div class="sub">${esc(s.device)}</div>`,
            date(s.expires_at),
            badge(
              s.revoked
                ? "REVOKED"
                : new Date(s.expires_at) > new Date()
                  ? "ACTIVE"
                  : "EXPIRED",
            ),
            !s.revoked
              ? btn(
                  "Revoke session",
                  "revoke-session",
                  `data-id="${s.id}"`,
                  "danger",
                )
              : "—",
          ]),
        );
      break;
    case "audit":
      content =
        header(btn("Export visible audit", "export-audit")) +
        (user.role === "SUPER_ADMIN"
          ? `<div class="tabs"><button data-action="audit-department" class="${!state.auditGlobal ? "active" : ""}">Department activity</button><button data-action="audit-global" class="${state.auditGlobal ? "active" : ""}">Account & security activity</button></div>`
          : "") +
        searchToolbar(
          "Latest 500 events. Audit exports are explicitly bounded to this view.",
        ) +
        table(
          [
            "Sequence / time",
            "Action",
            "Actor / role",
            "Reason",
            "Chain / details",
          ],
          filtered(d.events ?? []).map((e) => [
            `${esc(e.seq)}<div class="sub">${date(e.created_at)}</div>`,
            esc(e.action.replaceAll("_", " ")),
            `${short(e.actor_id)}<div class="sub">${esc(e.role)}</div>`,
            esc(e.reason ?? "—"),
            btn("Inspect event", "audit-detail", `data-id="${e.id}"`),
          ]),
        );
      break;
    case "reports":
      content =
        header() +
        `<div class="grid two-cols"><section class="card"><div class="card-heading"><h2>COLLECTION REPORT</h2><span class="tag">CSV</span></div><p class="muted">Original collection amounts and current states for the selected department. Internal transfers are excluded from income.</p><div class="note">Up to 100,000 rows. PIN + Windows Hello confirmation required. Larger reports are refused rather than silently truncated.</div>${btn("Verify & export collections", "export-collections", "", "cyan")}</section><section class="card"><div class="card-heading"><h2>AUDIT REPORT</h2><span class="tag">CSV</span></div><p class="muted">Latest 500 department events, including actor, reason and hash-chain references.</p><div class="note">Use the full database backup and independent audit-head checkpoints for complete archival verification.</div>${btn("Verify & export audit", "export-audit", "", "ghost")}</section></div><div class="note warn">Financial exports are sensitive. Save them in an access-controlled folder on your computer.</div>`;
      break;
    case "database":
      content =
        header(btn("Backup / restore instructions", "backup-guide")) +
        `<div class="grid two-cols"><section class="card"><div class="card-heading"><h2>POSTGRESQL</h2>${badge("ACTIVE")}</div><div class="info-row"><span>Database</span><strong>${esc(d.database?.name)}</strong></div><div class="info-row"><span>Schema version</span><strong>${esc(d.schemaVersion)}</strong></div><div class="info-row"><span>Stored size</span><strong>${(Number(d.database?.bytes ?? 0) / 1048576).toFixed(1)} MB</strong></div><p class="fine-print">${esc(d.database?.version)}</p></section><section class="card"><div class="card-heading"><h2>LOCAL DATABASE OPERATIONS</h2><span class="tag">WINDOWS</span></div><p class="muted">Your database is a separate PostgreSQL container with a persistent Docker volume. Stopping the server keeps its records.</p><div class="note">Backups and restores run through local Windows scripts. No raw SQL editor or silent ledger edits are exposed by this panel.</div>${btn("View operator instructions", "backup-guide")}</section></div><h2 style="margin:25px 0 15px">SCHEMA INVENTORY</h2>` +
        table(
          ["Table", "Rows"],
          (d.counts ?? []).map((x) => [
            `<span class="mono">${esc(x.table)}</span>`,
            esc(x.rows),
          ]),
        );
      break;
  }
  document.querySelector("#main").innerHTML = content;
  const search = document.querySelector("#search");
  if (search)
    search.oninput = (e) => {
      const value = e.target.value,
        pos = e.target.selectionStart;
      state.filter = value;
      renderPage();
      const next = document.querySelector("#search");
      next.focus();
      next.setSelectionRange(pos, pos);
    };
}
function departmentName(id) {
  return (
    state.context.departments.find((d) => d.id === id)?.name ??
    (id ? "Unknown department" : "All departments")
  );
}
function overview(d) {
  const target = BigInt(d.target ?? 1),
    collected = BigInt(d.collected ?? 0),
    approved = BigInt(d.approved ?? 0),
    held = BigInt(d.held ?? 0);
  const progress = Math.min(
    100,
    (Number(collected) * 100) / Math.max(1, Number(target)),
  );
  const approvedPct =
    collected > 0n
      ? Math.round((Number(approved) * 100) / Number(collected))
      : 0;
  const gaps = (d.discrepancies ?? []).length;
  const circumference = 2 * Math.PI * 108;
  const arc = circumference * 0.7;
  const gauge = `<div class="gauge-wrap"><svg viewBox="0 0 300 225" role="img" aria-label="Daily collection progress ${Math.round(progress)} percent"><defs><linearGradient id="gauge"><stop stop-color="#00e5ff"/><stop offset="1" stop-color="#ff3830"/></linearGradient></defs><circle cx="150" cy="137" r="108" fill="none" stroke="#283341" stroke-width="12" stroke-dasharray="${arc} ${circumference}" transform="rotate(144 150 137)" stroke-linecap="round"/><circle cx="150" cy="137" r="108" fill="none" stroke="url(#gauge)" stroke-width="12" stroke-dasharray="${(arc * progress) / 100} ${circumference}" transform="rotate(144 150 137)" stroke-linecap="round"/>${Array.from(
    { length: 29 },
    (_, i) => {
      const a = ((144 + i * 9) * Math.PI) / 180;
      return `<line x1="${150 + 93 * Math.cos(a)}" y1="${137 + 93 * Math.sin(a)}" x2="${150 + (i % 4 === 0 ? 82 : 88) * Math.cos(a)}" y2="${137 + (i % 4 === 0 ? 82 : 88) * Math.sin(a)}" stroke="${i % 4 === 0 ? "#7e95b0" : "#374759"}" stroke-width="${i % 4 === 0 ? 2 : 1}"/>`;
    },
  ).join(
    "",
  )}</svg><div class="gauge-center"><div class="eyebrow">TODAY’S COLLECTION</div><div class="stat-value">${cash(collected)}</div><span class="tag">${Math.round(progress)}% OF TARGET</span></div><div class="gauge-foot"><span>₹0</span><span>TARGET ${cash(target)}</span></div></div>`;
  const values = (d.trend ?? []).map((x) => Number(x.amount));
  const max = Math.max(...values, 1);
  const points = values
    .map(
      (x, i) =>
        `${20 + (i / Math.max(1, values.length - 1)) * 550},${140 - (x / max) * 110}`,
    )
    .join(" ");
  return (
    header(btn("Review Pit Stop", "go-approvals", "", "primary")) +
    `<section class="grid stats"><div class="stat"><div class="stat-label">TODAY’S COLLECTIONS</div><div class="stat-value">${cash(collected)}</div><div class="stat-sub">Original income · India business day</div></div><div class="stat approved"><div class="stat-label">APPROVED TODAY’S CASH</div><div class="stat-value">${cash(approved)}</div><div class="stat-sub">${approvedPct}% of today’s collections</div></div><div class="stat held"><div class="stat-label">COLLECTOR CUSTODY</div><div class="stat-value">${cash(held)}</div><div class="stat-sub">Current held cash · all dates</div></div><div class="stat alert"><div class="stat-label">OPEN DISCREPANCIES</div><div class="stat-value">${gaps}</div><div class="stat-sub">${Number(d.overdue ?? 0)} overdue custody items</div></div></section><div class="grid overview-main"><section class="card"><div class="card-heading"><h2>DAILY PERFORMANCE</h2><span class="tag">${esc(departmentName(state.department))}</span></div>${gauge}</section><section class="card"><div class="card-heading"><h2>RACE FLAGS</h2><span class="eyebrow">ACTION CENTER</span></div><div class="flag-list"><div class="flag"><span class="flag-icon">⚑</span><div><strong>${gaps} discrepancies</strong><p>Review blocked custody and count mismatches</p></div>${btn("Open", "go-discrepancies")}</div><div class="flag"><span class="flag-icon" style="color:#ffb300">⚑</span><div><strong>${Number(d.overdue ?? 0)} overdue custody items</strong><p>Collector-held cash past the configured collection-age threshold</p></div>${btn("Open", "go-balances")}</div><div class="flag"><span class="flag-icon" style="color:#87f869">✓</span><div><strong>${approvedPct}% approved</strong><p>Reconciled HOD custody only</p></div></div></div><div style="margin-top:20px" class="eyebrow">APPROVAL RPM</div><div class="meter lime"><span style="width:${Math.min(100, approvedPct)}%"></span></div><div class="tiny muted">Daily totals never sum internal handovers as income.</div></section></div><div class="grid two-cols"><section class="card"><div class="card-heading"><h2>PIT LANE</h2><span class="eyebrow">HANDED TO HOD</span></div>${(d.leaderboard ?? []).length ? d.leaderboard.map((u, i) => `<div class="rank"><span class="rank-position">P${i + 1}</span><div class="rank-name">${esc(u.name)}<small>CONFIRMED AT FINISH</small></div><div class="rank-value">${cash(u.amount)}</div></div>`).join("") : '<p class="muted">Confirmed handovers will appear here.</p>'}</section><section class="card"><div class="card-heading"><h2>COLLECTION PACE</h2><span class="tag">30 DAYS</span></div><svg class="trend" viewBox="0 0 590 155" role="img" aria-label="Collection income over the last 30 days">${[30, 70, 110, 145].map((y) => `<line x1="20" y1="${y}" x2="570" y2="${y}" stroke="#273443"/>`).join("")}${points ? `<polyline fill="none" stroke="#00d8f1" stroke-width="3" stroke-linejoin="round" points="${points}"/>` : '<text x="200" y="90" fill="#8a9db3" font-size="12">No collection history yet</text>'}</svg><p class="tiny muted">On-demand refresh · confirmed backend records only</p></section></div>`
  );
}
function departmentOptions() {
  return [
    ["", "— No department / Super Admin —"],
    ...state.context.departments
      .filter((d) => d.active)
      .map((d) => [d.id, d.name]),
  ];
}
async function userForm(id) {
  const existing = id
    ? (state.data.users ?? []).find((x) => x.id === id)
    : null;
  formModal(
    existing ? "EDIT ACCOUNT" : "CREATE ACCOUNT",
    `<div class="form-grid">${field("Full name", "name", "text", existing?.name ?? "", 'required maxlength="120"')}${field("Email", "email", "email", existing?.email ?? "", "required")}${select(
      "Role",
      "role",
      [
        ["COLLECTOR", "Collector — task screen only"],
        ["HOD", "HOD — own department"],
        ["SUPER_ADMIN", "Super Admin — all departments"],
      ],
      existing?.role ?? "COLLECTOR",
    )}${select("Department", "departmentId", departmentOptions(), existing?.department_id ?? "")}${
      existing
        ? select(
            "Account status",
            "active",
            [
              ["true", "Active"],
              ["false", "Disabled"],
            ],
            String(existing.active),
          )
        : field(
            "Initial app PIN",
            "newPin",
            "password",
            "",
            'required inputmode="numeric" pattern="[0-9]{6,12}" minlength="6" maxlength="12" autocomplete="off"',
          )
    }</div>${existing ? textarea("Mandatory change reason", "reason", "", 'required minlength="8" maxlength="1000"') : ""}<div class="note">Collectors have no browser control-panel access. Create their Android device enrollment separately. HOD/Super Admin users need a one-time web-access invitation after account creation.</div>${existing ? '<div class="note warn">Role/department changes are blocked while this account holds custody. Editing an account revokes its sessions. At least one active Super Admin must remain.</div>' : ""}`,
    async (v) => {
      if (v.role !== "SUPER_ADMIN" && !v.departmentId)
        throw Error("Select a department for this role.");
      if (existing)
        await manage(
          {
            operation: "USER_UPDATE",
            userId: id,
            name: v.name,
            email: v.email,
            role: v.role,
            departmentId: v.role === "SUPER_ADMIN" ? null : v.departmentId,
            active: v.active === "true",
            reason: v.reason,
          },
          "Update account " + v.name,
        );
      else
        await legacyAdmin(
          {
            operation: "USER",
            id: crypto.randomUUID(),
            name: v.name,
            email: v.email,
            pin: v.newPin,
            role: v.role,
            departmentId: v.role === "SUPER_ADMIN" ? null : v.departmentId,
          },
          "Create " + v.role.replaceAll("_", " ") + " account for " + v.name,
        );
      closeModal();
      if (existing && id === state.context.user.id) {
        lock("Account updated. Sign in again.");
        return;
      }
      toast(
        existing
          ? "Account updated. Existing sessions were revoked."
          : "Account created. Enroll a device before signing in.",
      );
      await refreshContext();
      await load();
    },
  );
}
function departmentForm(id) {
  const d = state.context.departments.find((x) => x.id === id);
  formModal(
    d ? "CONFIGURE DEPARTMENT" : "CREATE DEPARTMENT",
    `<div class="form-grid">${field("Department name", "name", "text", d?.name ?? "", 'required maxlength="100"')}${field("Daily collection target (₹)", "target", "text", d ? String(BigInt(d.daily_target) / 100n) + "." + String(BigInt(d.daily_target) % 100n).padStart(2, "0") : "100000.00", 'required inputmode="decimal"')}${field("Collector-to-collector hop limit", "maxHops", "number", d?.max_hops ?? "", 'min="1" max="100000" placeholder="Blank = unlimited"')}${field("Overdue alert after minutes", "overdue", "number", d?.overdue_minutes ?? 120, 'required min="1" max="10080"')}</div><label class="switchline"><input type="checkbox" name="gamification" ${d?.gamification ? "checked" : ""}> Enable optional gamification configuration</label><div class="note">Hops are configurable. Final HOD receipt is required regardless of the collector limit. Badge awards are not enabled by this local package.</div>`,
    async (v) => {
      await legacyAdmin(
        {
          operation: "DEPARTMENT",
          id: id ?? crypto.randomUUID(),
          name: v.name,
          dailyTarget: paise(v.target),
          maxHops: v.maxHops ? Number(v.maxHops) : null,
          overdueMinutes: Number(v.overdue),
          gamification: v.gamification === "on",
        },
        "Save department settings for " + v.name,
      );
      closeModal();
      toast("Department settings saved.");
      await refreshContext();
      await load();
    },
  );
}
function reasonAction(title, label, run) {
  formModal(
    title,
    textarea(
      "Mandatory reason / evidence",
      "reason",
      "",
      'required minlength="8" maxlength="1000"',
    ),
    async (v) => {
      const result = await run(v.reason);
      closeModal();
      toast(label);
      await refreshContext();
      await load();
      return result;
    },
  );
}
async function inviteWeb(userId) {
  const u = (state.data.users ?? []).find((x) => x.id === userId);
  formModal(
    "INVITE BROWSER ACCESS",
    `<p class="muted">Create a one-time, 24-hour enrollment link for ${esc(u?.name ?? userId)}. They must know their account PIN and enroll a Windows Hello/passkey on the computer hosting this server.</p><div class="note warn">The link grants an enrollment opportunity. Share it only through an approved channel. It is not a login session.</div>${textarea("Reason", "reason", "", 'required minlength="8" maxlength="1000"')}`,
    async (v) => {
      const result = await manage(
        { operation: "INVITE_WEB", userId, reason: v.reason },
        "Invite browser access for " + (u?.name ?? userId),
      );
      closeModal();
      modal(
        "ONE-TIME ENROLLMENT LINK",
        `<p class="muted">Expires in 24 hours. The recipient must enter their account PIN. Open this link on the Windows PC hosting the server.</p><div class="code" id="enrollment-link" style="margin:18px 0">${esc(result.enrollmentUrl)}</div><div class="note">If this browser already has an administrator signed in, sign out or use another browser profile before opening the enrollment link.</div>`,
        btn(
          "Copy enrollment link",
          "copy-invitation",
          `data-value="${esc(result.enrollmentUrl)}"`,
          "cyan",
        ) + btn("Done", "close"),
      );
    },
  );
}
async function enrollAndroid() {
  const users = (await api("v1/admin/users")).users.filter((u) => u.active);
  formModal(
    "ENROLL ANDROID DEVICE",
    select(
      "Account",
      "userId",
      users.map((u) => [u.id, u.name + " — " + u.role]),
      users[0]?.id ?? "",
    ) +
      field(
        "Device ID (use this UUID in the Android sign-in screen)",
        "deviceId",
        "text",
        crypto.randomUUID(),
        "required",
      ) +
      field(
        "Device label",
        "label",
        "text",
        "Android test phone",
        'required maxlength="120"',
      ) +
      textarea(
        "P-256 public key from Android → Set up this device",
        "publicKey",
        "",
        'class="device-key" required minlength="100" maxlength="4096"',
      ) +
      textarea(
        "Enrollment reason",
        "reason",
        "",
        'required minlength="8" maxlength="1000"',
      ) +
      '<div class="note warn">Local test enrollment only. This does not claim that Android hardware attestation was verified. Never use test enrollment for live cash.</div>',
    async (v) => {
      await manage(
        { operation: "ENROLL_ANDROID", ...v },
        "Enroll Android device for " +
          (users.find((u) => u.id === v.userId)?.name ?? "account"),
      );
      closeModal();
      toast(
        "Android key enrolled. Use the account ID, device ID and PIN in the app.",
      );
      await load();
    },
  );
}
async function receiveForm(id) {
  const h = (state.data.handovers ?? []).find((x) => x.id === id);
  formModal(
    "COUNT PHYSICAL CASH",
    `<p class="muted">${esc(h?.sender ?? "Sender")} → ${esc(h?.receiver ?? "You")}</p><div class="detail-grid"><div><dt>Expected</dt><dd class="amount">${cash(h?.expected)}</dd></div><div><dt>Handover</dt><dd class="mono">${esc(id)}</dd></div></div>${field("Cash you physically counted (₹)", "actual", "text", "", 'required inputmode="decimal"')}${select(
      "Decision",
      "decision",
      [
        ["ACCEPT", "Accept actual counted cash"],
        ["DISPUTE", "Open a discrepancy"],
        ["REJECT", "Reject — cash not received"],
      ],
      "ACCEPT",
    )}${textarea("Reason (mandatory for dispute or rejection)", "reason", "", 'maxlength="1000"')}<div class="note warn">A mismatch blocks the affected funds. A sender’s submission does not prove receipt. Reject only if you did not take physical custody.</div>`,
    async (v) => {
      if (v.decision !== "ACCEPT" && v.reason.trim().length < 8)
        throw Error("Enter a reason of at least 8 characters.");
      const actual =
        v.decision === "REJECT"
          ? "0"
          : v.actual.trim() === "0" || /^0\.0{1,2}$/.test(v.actual.trim())
            ? "0"
            : paise(v.actual);
      const data = {
        actual,
        decision: v.decision,
        ...(v.reason.trim() ? { reason: v.reason.trim() } : {}),
      };
      const result = await mutate(
        `v1/handovers/${id}/receipt`,
        "RECEIPT",
        data,
        "Confirm physical cash count for handover " + id.slice(0, 8),
        id,
      );
      closeModal();
      toast("Receipt status: " + result.status);
      await load();
    },
  );
}
async function resolveForm(id) {
  let discrepancy = (state.data.discrepancies ?? []).find((x) => x.id === id);
  if (!discrepancy)
    discrepancy = (
      await api(`v1/control/discrepancies?departmentId=${state.department}`)
    ).discrepancies.find((x) => x.id === id);
  if (!discrepancy) throw Error("Discrepancy not found. Refresh first.");
  const choices = discrepancy.handover_id
    ? [
        [
          "RECOUNT_MATCHED",
          "Full expected cash physically recounted and confirmed",
        ],
        ["RETURN_CONFIRMED", "Physical return to sender confirmed"],
      ]
    : [["REVIEW_CLEARED", "Review concern cleared with documented evidence"]];
  formModal(
    "RESOLVE DISCREPANCY",
    `<div class="note warn">This decision records physical evidence. It never silently changes the original receipt count. A shortage cannot be approved as reconciled.</div>${select("Verified resolution", "resolution", choices, choices[0][0])}${textarea("Mandatory evidence / reason", "reason", "", 'required minlength="8" maxlength="1000"')}`,
    async (v) => {
      const result = await mutate(
        `v1/discrepancies/${id}/resolve`,
        "RESOLVE",
        v,
        "Resolve discrepancy " +
          id.slice(0, 8) +
          " using " +
          v.resolution.replaceAll("_", " ").toLowerCase(),
        id,
      );
      closeModal();
      toast(result.status);
      await load();
    },
  );
}
async function chain(id) {
  const d = await api("v1/control/chain/" + id),
    c = d.collection;
  const row = (state.data?.collections ?? []).find((x) => x.id === id);
  const timeline = d.ledger
    .map(
      (l) =>
        `<div class="timeline-item"><p><strong>${esc(l.from_name ?? (l.from_user ? l.from_user.slice(0, 8) : "Customer"))} → ${esc(l.to_name ?? l.to_user.slice(0, 8))}</strong> · ${cash(l.amount)}</p><small>${date(l.created_at)} · ${l.handover_id ? "Confirmed handover" : "Original cash received"}</small></div>`,
    )
    .join("");
  modal(
    "CUSTODY CHAIN",
    `<div class="eyebrow">${esc(id)}</div><div class="detail-grid"><div><dt>Original collection</dt><dd class="amount">${cash(c.amount)}</dd></div><div><dt>Custody state</dt><dd>${badge(c.state)}</dd></div><div><dt>Approval state</dt><dd>${badge(d.approval?.state ?? "PENDING_HOD")}</dd></div></div><p class="muted">${esc(c.customerName ?? row?.customer ?? "Customer reference " + c.customer_id)}</p><h3 style="margin-top:23px">CONFIRMED CUSTODY EVENTS</h3><div class="timeline">${timeline}</div><h3>HANDOVER COUNTS</h3>${table(
      ["Reference", "Expected", "Original count", "Status"],
      d.handovers.map((h) => [
        short(h.id),
        cash(h.expected),
        h.actual === null ? "Not confirmed" : cash(h.actual),
        badge(h.state),
      ]),
    )}<h3 style="margin:23px 0 10px">DISCREPANCIES</h3>${d.discrepancies.length ? d.discrepancies.map((x) => `<div class="note ${x.state === "OPEN" ? "warn" : ""}">${badge(x.state)} <p style="margin:8px 0">${esc(x.reason)}</p><p class="tiny">Expected ${cash(x.expected)} · original count ${cash(x.actual)}</p>${x.resolution ? `<p class="tiny">${esc(x.resolution)}</p>` : ""}${x.state === "OPEN" && state.context.user.role === "HOD" ? btn("Resolve", "resolve", `data-id="${x.id}"`) : ""}</div>`).join("") : '<p class="tiny muted">No discrepancies recorded.</p>'}<h3 style="margin:23px 0 10px">AUDITED ADJUSTMENTS</h3>${
      d.adjustments.length
        ? table(
            ["Correction", "Reason", "Date"],
            d.adjustments.map((a) => [
              cash(a.delta),
              esc(a.reason),
              date(a.created_at),
            ]),
          )
        : '<p class="tiny muted">None. Original approved amounts are immutable.</p>'
    }<h3 style="margin:23px 0 10px">RECEIPT ATTACHMENTS</h3><div class="attachment-list">${d.attachments.map((a) => btn("Download receipt " + a.id.slice(0, 8), "download-attachment", `data-id="${a.id}"`)).join("")}${c.state !== "APPROVED" ? btn("Add receipt photo", "upload-attachment", `data-id="${id}"`) : ""}</div><div class="note">Final approval requires the full original amount in your HOD custody, a confirmed receipt, and no reservations, blocked funds or open discrepancies.</div>`,
    (state.context.user.role === "HOD" && c.state !== "APPROVED"
      ? btn(
          "Approve",
          "review",
          `data-id="${id}" data-decision="APPROVE"`,
          "good",
        ) +
        btn(
          "Raise discrepancy",
          "review",
          `data-id="${id}" data-decision="DISCREPANCY"`,
        ) +
        btn(
          "Reject approval",
          "review",
          `data-id="${id}" data-decision="REJECT"`,
          "danger",
        )
      : "") +
      (c.state === "APPROVED"
        ? btn("Post audited adjustment", "adjust", `data-id="${id}"`)
        : "") +
      btn("Close", "close"),
  );
}
async function review(id, decision) {
  closeModal();
  formModal(
    decision === "APPROVE"
      ? "FINAL HOD APPROVAL"
      : decision === "REJECT"
        ? "REJECT APPROVAL"
        : "RAISE DISCREPANCY",
    `<p class="muted">Collection ${esc(id)}</p><div class="note ${decision === "APPROVE" ? "" : "warn"}">${decision === "APPROVE" ? "You confirm that you physically hold the full expected cash and have reviewed the complete custody chain." : "A reason is mandatory. Rejection does not reverse already confirmed custody."}</div>${textarea(decision === "APPROVE" ? "Review note (optional)" : "Mandatory reason", "reason", "", decision === "APPROVE" ? 'maxlength="1000"' : 'required minlength="8" maxlength="1000"')}`,
    async (v) => {
      const result = await mutate(
        `v1/collections/${id}/review`,
        "REVIEW",
        { decision, ...(v.reason.trim() ? { reason: v.reason.trim() } : {}) },
        decision === "APPROVE"
          ? "Approve reconciled collection " + id.slice(0, 8)
          : "Record " +
              decision.toLowerCase() +
              " for collection " +
              id.slice(0, 8),
        id,
      );
      closeModal();
      toast("Approval status: " + result.status);
      await load();
    },
  );
}
function adjustment(id) {
  closeModal();
  formModal(
    "AUDITED CORRECTION",
    field(
      "Adjustment (₹); use a minus sign to reduce reported income",
      "delta",
      "text",
      "",
      'required inputmode="decimal"',
    ) +
      textarea(
        "Mandatory correction reason",
        "reason",
        "",
        'required minlength="8" maxlength="1000"',
      ) +
      '<div class="note warn">This inserts a separate adjustment. It never edits the original amount or silently moves custody. Review existing adjustments before posting another correction.</div>',
    async (v) => {
      const negative = v.delta.trim().startsWith("-");
      const delta =
        (negative ? "-" : "") + paise(v.delta.trim().replace(/^[-+]/, ""));
      await mutate(
        `v1/collections/${id}/adjustments`,
        "ADJUST",
        { delta, reason: v.reason },
        "Post an audited adjustment of " +
          cash(delta) +
          " to " +
          id.slice(0, 8),
        id,
      );
      closeModal();
      toast("Adjustment posted. Original record remains unchanged.");
      await load();
    },
  );
}
async function saveDownload(response, filename) {
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function exportCollections() {
  const id = state.department;
  if (!id) throw Error("Choose a department.");
  const proof = await secure(
    "EXPORT",
    { departmentId: id },
    "Export collection records for " + departmentName(id),
  );
  const r = await api(`v1/departments/${id}/export`, {
    method: "POST",
    body: { proof },
    raw: true,
  });
  await saveDownload(r, "racing-speed-collections.csv");
  toast("Department report downloaded.");
}
async function exportAudit() {
  const id =
    state.page === "audit" && state.auditGlobal ? "GLOBAL" : state.department;
  if (!id) throw Error("Choose a department.");
  const proof = await secure(
    "EXPORT",
    { kind: "AUDIT", departmentId: id },
    "Export latest audit events for " +
      (id === "GLOBAL" ? "account and security activity" : departmentName(id)),
  );
  const r = await api("v1/control/audit-export", {
    method: "POST",
    body: { departmentId: id, proof },
    raw: true,
  });
  await saveDownload(r, "racing-speed-audit.csv");
  toast("Audit report downloaded.");
}
async function uploadAttachment(id) {
  closeModal();
  formModal(
    "ADD RECEIPT PHOTO",
    `<div class="field"><label for="photo">JPEG or PNG, at most 1 MB</label><input id="photo" name="photo" type="file" accept="image/jpeg,image/png" required></div><div class="note">Private S3/KMS storage must be configured by the local operator. The database never stores public attachment URLs.</div>`,
    async () => {
      const file = document.querySelector("#photo").files[0];
      if (!file || file.size > 1000000)
        throw Error("Select a JPEG or PNG no larger than 1 MB.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      let data = "";
      for (let i = 0; i < bytes.length; i += 8192)
        data += String.fromCharCode(...bytes.subarray(i, i + 8192));
      const encoded = btoa(data);
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(encoded),
      );
      const sha256 = Array.from(new Uint8Array(digest), (n) =>
        n.toString(16).padStart(2, "0"),
      ).join("");
      const proof = await secure(
        "ATTACHMENT",
        { id, sha256 },
        "Attach a receipt photo to collection " + id.slice(0, 8),
      );
      await api(`v1/collections/${id}/attachments`, {
        method: "POST",
        body: { data: encoded, proof },
      });
      closeModal();
      toast("Receipt photo stored.");
      await chain(id);
    },
  );
}
app.addEventListener("click", async (e) => {
  const page = e.target.closest("[data-page]");
  if (page) {
    state.page = page.dataset.page;
    state.filter = "";
    return load();
  }
  const target = e.target.closest("[data-action]");
  if (target) await action(target);
});
dialog.addEventListener("click", async (e) => {
  const target = e.target.closest("[data-action]");
  if (target) await action(target);
});
async function action(target) {
  const a = target.dataset.action,
    id = target.dataset.id;
  try {
    switch (a) {
      case "close":
        closeModal();
        break;
      case "lock":
        lock();
        break;
      case "refresh":
        await refreshContext();
        await load();
        break;
      case "go-approvals":
      case "go-discrepancies":
      case "go-handovers":
      case "go-balances":
        state.page = a.slice(3);
        state.filter = "";
        await load();
        break;
      case "new-user":
        await userForm();
        break;
      case "edit-user":
        await userForm(id);
        break;
      case "new-department":
        departmentForm();
        break;
      case "edit-department":
        departmentForm(id);
        break;
      case "reset-pin":
        formModal(
          "RESET ACCOUNT PIN",
          field(
            "New account PIN",
            "newPin",
            "password",
            "",
            'required inputmode="numeric" pattern="[0-9]{6,12}" minlength="6" maxlength="12" autocomplete="off"',
          ) +
            textarea(
              "Mandatory reason",
              "reason",
              "",
              'required minlength="8" maxlength="1000"',
            ) +
            '<div class="note warn">All sessions for this account will be revoked. Resetting your own PIN signs you out. The enrolled passkey is retained.</div>',
          async (v) => {
            await manage(
              { operation: "PIN_RESET", userId: id, ...v },
              "Reset app PIN for account " + id.slice(0, 8),
            );
            closeModal();
            if (id === state.context.user.id) {
              lock("PIN changed. Sign in with your new PIN.");
              return;
            }
            toast("PIN reset and sessions revoked.");
            await load();
          },
        );
        break;
      case "invite-web":
        await inviteWeb(id);
        break;
      case "copy-invitation":
        await navigator.clipboard.writeText(target.dataset.value);
        toast("Enrollment link copied.");
        break;
      case "enroll-android":
        await enrollAndroid();
        break;
      case "revoke-device":
        reasonAction("REVOKE DEVICE", "Device revoked.", (reason) =>
          manage(
            { operation: "REVOKE_DEVICE", deviceId: id, reason },
            "Revoke this device and all of its sessions",
          ),
        );
        break;
      case "revoke-session":
        reasonAction("REVOKE SESSION", "Session revoked.", (reason) =>
          manage(
            { operation: "REVOKE_SESSION", sessionId: id, reason },
            "Revoke session " + id.slice(0, 8),
          ),
        );
        break;
      case "archive-department": {
        const d = state.context.departments.find((x) => x.id === id);
        reasonAction(
          d.active ? "ARCHIVE DEPARTMENT" : "RESTORE DEPARTMENT",
          "Department updated.",
          (reason) =>
            manage(
              {
                operation: "ARCHIVE_DEPARTMENT",
                departmentId: id,
                active: !d.active,
                reason,
              },
              (d.active ? "Archive " : "Restore ") + d.name,
            ),
        );
        break;
      }
      case "chain":
        await chain(id);
        break;
      case "receive":
        await receiveForm(id);
        break;
      case "resolve":
        if (dialog.open) closeModal();
        await resolveForm(id);
        break;
      case "review":
        await review(id, target.dataset.decision);
        break;
      case "adjust":
        adjustment(id);
        break;
      case "export-collections":
        await exportCollections();
        break;
      case "export-audit":
        await exportAudit();
        break;
      case "audit-global":
        state.auditGlobal = true;
        state.filter = "";
        await load();
        break;
      case "audit-department":
        state.auditGlobal = false;
        state.filter = "";
        await load();
        break;
      case "audit-detail": {
        const ev = (state.data.events ?? []).find((x) => x.id === id);
        modal(
          "AUDIT EVENT",
          `<div class="eyebrow">${esc(ev.action)}</div><div class="detail-grid"><div><dt>Actor</dt><dd class="mono">${esc(ev.actor_id)}</dd></div><div><dt>Role</dt><dd>${esc(ev.role)}</dd></div><div><dt>Time</dt><dd>${date(ev.created_at)}</dd></div></div><h3>BEFORE</h3><pre class="code">${esc(JSON.stringify(ev.before_data, null, 2))}</pre><h3>AFTER</h3><pre class="code">${esc(JSON.stringify(ev.after_data, null, 2))}</pre><p class="tiny muted">Previous hash</p><p class="code">${esc(ev.prev_hash)}</p><p class="tiny muted">Event hash</p><p class="code">${esc(ev.event_hash)}</p>`,
          btn("Close", "close"),
        );
        break;
      }
      case "upload-attachment":
        await uploadAttachment(id);
        break;
      case "download-attachment":
        await saveDownload(
          await api("v1/attachments/" + id, { raw: true }),
          "receipt-" + id,
        );
        break;
      case "backup-guide":
        modal(
          "DATABASE BACKUP & RESTORE",
          `<p class="muted">Run these scripts from the extracted Windows package. They require access to Docker Desktop on this computer.</p><ol class="setup-list"><li>Run <strong>Backup-Database.cmd</strong> to create a timestamped backup in the <strong>backups</strong> folder.</li><li>Copy the backup to an approved encrypted location.</li><li>For recovery, run <strong>Restore-Database.cmd</strong>, choose the backup, and type <strong>RESTORE</strong> when prompted.</li></ol><div class="note warn">Restore replaces database contents and temporarily stops the API. It is a local operator recovery action, not a way to edit approved records. Protect backups as financial data.</div><p class="tiny muted">Database credentials are generated in the private .env file. They are not displayed in this panel. Never share .env, .setup-code.txt, runtime files or backups through GitHub.</p>`,
          btn("Close", "close"),
        );
        break;
    }
  } catch (err) {
    toast(err.message ?? "Action failed.", true);
  }
}
async function boot() {
  const fragment = location.hash.startsWith("#enroll=")
    ? location.hash.slice(8)
    : "";
  if (fragment) {
    renderAuth("enroll", "", fragment);
    return;
  }
  try {
    const status = await api("v1/web/status", { auth: false });
    renderAuth(status.configured ? "login" : "setup");
  } catch (err) {
    app.innerHTML =
      strip +
      `<main class="startup"><h1>LOCAL SERVER NOT READY</h1><p>${esc(err.message)}</p><p>Run Setup-Windows.cmd or Start-Backend.cmd from the downloaded control-panel package.</p><button class="btn cyan" id="retry" style="margin-top:20px">Try again</button></main>`;
    document.querySelector("#retry").onclick = boot;
  }
}
boot();
