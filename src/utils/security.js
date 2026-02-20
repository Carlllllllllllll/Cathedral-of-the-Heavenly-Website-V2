const axios = require("axios");
const moment = require("moment-timezone");
const UAParser = require("ua-parser-js");
const validator = require("validator");
const escapeHtml = require("escape-html");
const { Types } = require("mongoose");
const { appendOwnerMention } = require("./discord");

const sensitiveKeys = [
  "password",
  "pass",
  "token",
  "secret",
  "code",
  "otp",
  "hash",
  "session",
  "auth",
  "key",
];

function normalizeInput(value) {
  return typeof value === "string" ? value.normalize("NFKC") : value;
}

function sanitizeString(value, options = {}) {
  if (typeof value !== "string") {
    return value;
  }
  const config = {
    maxLength: options.maxLength || 4000,
    stripHtml: options.stripHtml !== false,
    stripControls: options.stripControls !== false,
  };
  let sanitized = normalizeInput(value)
    .replace(/\u0000/g, "")
    .trim();
  if (config.stripControls) {
    sanitized = sanitized.replace(/[\u0000-\u001F\u007F]/g, "");
  }
  if (config.stripHtml) {
    sanitized = sanitized.replace(/<[^>]*>/g, "");
  }
  sanitized = validator.blacklist(sanitized, "`$");
  sanitized = escapeHtml(sanitized);
  if (sanitized.length > config.maxLength) {
    sanitized = sanitized.slice(0, config.maxLength);
  }
  return sanitized;
}

function sanitizePayload(payload, options = {}) {
  if (payload === null || payload === undefined) {
    return payload;
  }
  if (Array.isArray(payload)) {
    return payload.map((entry) => sanitizePayload(entry, options));
  }
  if (payload instanceof Date) {
    return payload;
  }
  if (typeof payload === "object") {
    return Object.entries(payload).reduce((acc, [key, value]) => {
      const safeKey = sanitizeString(key, { maxLength: 120, stripHtml: false });
      acc[safeKey] = sanitizePayload(value, options);
      return acc;
    }, {});
  }
  if (typeof payload === "string") {
    return sanitizeString(payload, options);
  }
  if (typeof payload === "number" && !Number.isFinite(payload)) {
    return 0;
  }
  return payload;
}

function sanitizeRequest(req, options = {}) {
  if (req.body) {
    req.body = sanitizePayload(req.body, options);
  }
  if (req.query) {
    req.query = sanitizePayload(req.query, options);
  }
  if (req.params) {
    req.params = sanitizePayload(req.params, options);
  }
}

function getClientIp(req) {
  const forwardedFor = req?.headers?.["x-forwarded-for"];
  if (forwardedFor) {
    return Array.isArray(forwardedFor)
      ? forwardedFor[0]
      : forwardedFor.split(",")[0].trim();
  }
  return (
    req?.socket?.remoteAddress || req?.connection?.remoteAddress || "unknown"
  );
}

function isSafeObjectId(value) {
  return typeof value === "string" && Types.ObjectId.isValid(value);
}

function ensureNumber(
  value,
  {
    min = Number.MIN_SAFE_INTEGER,
    max = Number.MAX_SAFE_INTEGER,
    fallback = 0,
  } = {}
) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  if (numeric < min) {
    return min;
  }
  if (numeric > max) {
    return max;
  }
  return numeric;
}

function maskSensitiveData(input) {
  if (!input || typeof input !== "object") {
    return input;
  }
  const clone = Array.isArray(input) ? [] : {};
  Object.entries(input).forEach(([key, value]) => {
    const lowered = key.toLowerCase();
    if (sensitiveKeys.some((entry) => lowered.includes(entry))) {
      clone[key] = "[redacted]";
      return;
    }
    if (value && typeof value === "object") {
      clone[key] = maskSensitiveData(value);
    } else if (typeof value === "string") {
      clone[key] = sanitizeString(value, { stripHtml: false });
    } else {
      clone[key] = value;
    }
  });
  return clone;
}

function buildDataSnapshot(data, limit = 3500) {
  try {
    const safe = maskSensitiveData(data);
    const serialized = JSON.stringify(safe, null, 2);
    if (serialized.length > limit) {
      return `${serialized.slice(0, limit)}...`;
    }
    return serialized;
  } catch (error) {
    return "[unserializable]";
  }
}

async function logSecurityEvent(eventType, details, req) {
  const webhookURL =
    process.env.SECURITY_WEBHOOK ||
    process.env.ADMIN_ACTIVITY_WEBHOOK ||
    process.env.ACTIVITY_WEBHOOK;
  if (!webhookURL) {
    return;
  }
  try {
    const ip = getClientIp(req);
    const parser = new UAParser();
    const userAgent = req?.headers?.["user-agent"] || "Unknown";
    const deviceInfo = parser.setUA(userAgent).getResult();
    const device = `${deviceInfo.os.name || "Unknown OS"} (${
      deviceInfo.browser.name || "Unknown Browser"
    })`;
    const timestamp = moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss");
    const eventColors = {
      unauthorized_access: 0xe74c3c,
      permission_denied: 0xf39c12,
      suspicious_activity: 0xe67e22,
      admin_action: 0x3498db,
      user_action: 0x1abc9c,
      security_alert: 0xe74c3c,
      login_attempt: 0x9b59b6,
      form_submission: 0x2ecc71,
      gift_purchase: 0xf59e0b,
    };
    const payload = {
      content: appendOwnerMention(
        `🔒 <@&1126336222206365696> Security Event: ${eventType}`
      ),
      embeds: [
        {
          title: `Security Event: ${eventType}`,
          color: eventColors[eventType] || 0x95a5a6,
          fields: [
            { name: "Event Type", value: eventType, inline: true },
            { name: "Timestamp", value: timestamp, inline: true },
            { name: "IP Address", value: ip || "Unknown", inline: true },
            { name: "Device", value: device, inline: true },
            {
              name: "User Agent",
              value:
                sanitizeString(userAgent, {
                  maxLength: 200,
                  stripHtml: false,
                }) || "Unknown",
              inline: false,
            },
            ...(details || []),
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    };
    await axios
      .post(webhookURL, payload, {
        headers: { "Content-Type": "application/json" },
      })
      .catch((error) => {
        console.error("Error sending security webhook:", error.message);
      });
  } catch (error) {
    console.error("Error preparing security webhook:", error);
  }
}

function getClientInfo(req) {
  const ip = getClientIp(req);
  const parser = new UAParser();
  const userAgent = req?.headers?.["user-agent"] || "Unknown";
  const deviceInfo = parser.setUA(userAgent).getResult();
  const device = `${deviceInfo.os.name || "Unknown OS"} (${
    deviceInfo.browser.name || "Unknown Browser"
  })`;
  return { ip, device, userAgent };
}

module.exports = {
  logSecurityEvent,
  getClientInfo,
  sanitizeString,
  sanitizePayload,
  sanitizeRequest,
  isSafeObjectId,
  ensureNumber,
  maskSensitiveData,
  buildDataSnapshot,
};







