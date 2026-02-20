function sanitizeHTML(str) {
  if (typeof str !== "string") return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
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

if (typeof window !== "undefined") {
  window.setButtonLoading = window.setButtonLoading || setButtonLoading;
  window.withButtonLoading = window.withButtonLoading || withButtonLoading;
}
