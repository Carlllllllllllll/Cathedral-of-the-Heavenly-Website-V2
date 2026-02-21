function sanitizeHTML(str) {
  if (typeof str !== "string") return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function containsArabicCharacters(value) {
  if (value == null) return false;
  return /[\u0600-\u06FF]/.test(String(value));
}

function removeArabicCharacters(value) {
  if (value == null) return "";
  return String(value).replace(/[\u0600-\u06FF]/g, "");
}

function parseCooldownSeconds(message) {
  if (!message) return 0;
  const raw = String(message);
  const lower = raw.toLowerCase();

  const patterns = [
    /wait\s+(\d+)\s*seconds?/i,
    /(\d+)\s*seconds?/i,
    /(\d+)\s*secs?/i,
  ];

  for (const p of patterns) {
    const match = raw.match(p);
    if (match && match[1]) {
      const n = Number.parseInt(match[1], 10);
      if (Number.isFinite(n) && n > 0) return n;
    }
  }

  if (lower.includes("24")) return 24;
  return 0;
}

function attachPasswordToggle(inputEl) {
  const input =
    typeof inputEl === "string"
      ? document.getElementById(inputEl)
      : inputEl;

  if (!input || input.dataset.hasPasswordToggle === "1") return;
  if ((input.getAttribute("type") || "").toLowerCase() !== "password") return;

  const parent = input.parentElement;
  if (!parent) return;

  parent.style.position = parent.style.position || "relative";
  input.style.paddingLeft = input.style.paddingLeft || "44px";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.setAttribute("aria-label", "إظهار/إخفاء كلمة المرور");
  btn.style.position = "absolute";
  btn.style.left = "12px";
  btn.style.top = "50%";
  btn.style.transform = "translateY(-50%)";
  btn.style.width = "34px";
  btn.style.height = "34px";
  btn.style.display = "inline-flex";
  btn.style.alignItems = "center";
  btn.style.justifyContent = "center";
  btn.style.padding = "0";
  btn.style.lineHeight = "1";
  btn.style.fontSize = "16px";
  btn.style.border = "none";
  btn.style.borderRadius = "10px";
  btn.style.cursor = "pointer";
  btn.style.background = "rgba(255,255,255,0.06)";
  btn.style.color = "#ffcc00";

  const icon = document.createElement("i");
  icon.className = "fas fa-eye";
  icon.style.pointerEvents = "none";
  btn.appendChild(icon);

  const syncIcon = () => {
    const type = (input.getAttribute("type") || "password").toLowerCase();
    icon.className = type === "password" ? "fas fa-eye" : "fas fa-eye-slash";
  };

  btn.addEventListener("click", () => {
    const type = (input.getAttribute("type") || "password").toLowerCase();
    input.setAttribute("type", type === "password" ? "text" : "password");
    syncIcon();
    input.focus();
  });

  syncIcon();
  parent.appendChild(btn);
  input.dataset.hasPasswordToggle = "1";
}

function startSessionWatcher() {
  if (typeof window === "undefined") return;
  if (window.__sessionWatcherStarted) return;
  window.__sessionWatcherStarted = true;

  let sawAuthenticated = false;
  let inFlight = false;

  const tick = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      const res = await fetch("/api/user-info", { credentials: "include" });
      if (res.status === 401) {
        if (sawAuthenticated) {
          window.location.href = "/login?redirect=" + encodeURIComponent(window.location.pathname + window.location.search);
        }
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (data && data.isAuthenticated === true) {
        sawAuthenticated = true;
      } else if (sawAuthenticated) {
        window.location.href = "/login?redirect=" + encodeURIComponent(window.location.pathname + window.location.search);
      }
    } catch (_) {
      if (sawAuthenticated) {
        window.location.href = "/login?redirect=" + encodeURIComponent(window.location.pathname + window.location.search);
      }
    } finally {
      inFlight = false;
    }
  };

  tick();
  setInterval(tick, 30000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") tick();
  });
}

function safeSetHTML(element, html) {
  if (!element) return;
  if (typeof html !== "string") {
    element.textContent = String(html);
    return;
  }
  element.textContent = "";
  const temp = document.createElement("div");
  temp.innerHTML = html;
  while (temp.firstChild) {
    element.appendChild(temp.firstChild);
  }
}

function createElementWithText(tag, text, className = "") {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = sanitizeHTML(String(text || ""));
  return el;
}

function isValidURL(url) {
  if (!url || typeof url !== "string") return false;
  try {
    const parsed = new URL(url, window.location.origin);
    return parsed.origin === window.location.origin;
  } catch {
    return false;
  }
}

async function safeFetch(url, options = {}) {
  if (!isValidURL(url)) {
    throw new Error("Invalid URL");
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`Request failed: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("[FETCH ERROR]", error.message);
    throw error;
  }
}

function validateInput(input, type = "text") {
  if (typeof input !== "string") return "";

  let sanitized = input.trim();

  switch (type) {
    case "email":
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(sanitized) ? sanitized : "";
    case "number":
      const num = parseInt(sanitized, 10);
      return isNaN(num) ? "" : String(num);
    case "url":
      try {
        new URL(sanitized);
        return sanitized;
      } catch {
        return "";
      }
    default:
      return sanitized;
  }
}

function setButtonLoading(button, isLoading, loadingText) {
  if (!button) return;

  if (isLoading) {
    if (!button.dataset.originalHtml) {
      button.dataset.originalHtml = button.innerHTML;
    }
    button.disabled = true;
    const label =
      typeof loadingText === "string" && loadingText.trim().length
        ? loadingText.trim()
        : button.textContent || "";

    button.innerHTML =
      '<span class="loading-dots" aria-hidden="true"><span></span><span></span><span></span></span>' +
      (label
        ? '<span style="margin-right:8px">' + label.replace(/</g, "&lt;") + "</span>"
        : "");
  } else {
    button.disabled = false;
    if (button.dataset.originalHtml) {
      button.innerHTML = button.dataset.originalHtml;
      delete button.dataset.originalHtml;
    }
  }
}

async function withButtonLoading(button, loadingText, task) {
  if (typeof task !== "function") {
    return;
  }
  setButtonLoading(button, true, loadingText);
  try {
    return await task();
  } finally {
    setButtonLoading(button, false);
  }
}

async function ensureSessionValid(options = {}) {
  const redirect = options && typeof options.redirect === "string"
    ? options.redirect
    : window.location.pathname + window.location.search;

  try {
    const response = await fetch("/api/user-info", { credentials: "include" });
    if (response.status === 401) {
      window.location.href = "/login?redirect=" + encodeURIComponent(redirect);
      return false;
    }
    const data = await response.json().catch(() => ({}));
    if (!data || data.isAuthenticated !== true) {
      window.location.href = "/login?redirect=" + encodeURIComponent(redirect);
      return false;
    }
    return true;
  } catch (_) {
    window.location.href = "/login?redirect=" + encodeURIComponent(redirect);
    return false;
  }
}

if (typeof window !== "undefined") {
  window.setButtonLoading = window.setButtonLoading || setButtonLoading;
  window.withButtonLoading = window.withButtonLoading || withButtonLoading;
  window.ensureSessionValid = window.ensureSessionValid || ensureSessionValid;
  window.startSessionWatcher = window.startSessionWatcher || startSessionWatcher;
  window.containsArabicCharacters = window.containsArabicCharacters || containsArabicCharacters;
  window.removeArabicCharacters = window.removeArabicCharacters || removeArabicCharacters;
  window.parseCooldownSeconds = window.parseCooldownSeconds || parseCooldownSeconds;
  window.attachPasswordToggle = window.attachPasswordToggle || attachPasswordToggle;
  startSessionWatcher();
}
