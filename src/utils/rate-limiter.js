const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: "Too many login attempts",
    message:
      "You have exceeded the maximum number of login attempts. Please try again in 15 minutes.",
    retryAfter: 15 * 60,
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  handler: (req, res) => {
    console.warn(`[RATE LIMIT] Login attempt blocked for IP: ${req.ip}`);
    res.status(429).json({
      error: "Too Many Requests",
      message: "Too many login attempts. Please try again in 15 minutes.",
      retryAfter: 900,
    });
  },
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: {
    error: "Too many requests",
    message: "You have exceeded the API rate limit. Please slow down.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(
      `[RATE LIMIT] API request blocked for IP: ${req.ip} - Path: ${req.path}`,
    );
    res.status(429).json({
      error: "Too Many Requests",
      message: "API rate limit exceeded. Please slow down.",
    });
  },
});

const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: {
    error: "Too many attempts",
    message:
      "You have exceeded the maximum number of attempts for this operation. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(
      `[RATE LIMIT] Strict limit triggered for IP: ${req.ip} - Path: ${req.path}`,
    );
    res.status(429).json({
      error: "Too Many Requests",
      message: "Too many attempts. Please try again in 1 hour.",
      retryAfter: 3600,
    });
  },
});

const failedAttempts = new Map();
const BAN_THRESHOLD = 10;
const BAN_DURATION = 24 * 60 * 60 * 1000;
const ATTEMPT_WINDOW = 60 * 60 * 1000;

function trackFailedAttempt(ip) {
  const now = Date.now();

  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, {
      count: 1,
      firstAttempt: now,
      banned: false,
      banExpiry: null,
    });
    return;
  }

  const record = failedAttempts.get(ip);

  if (now - record.firstAttempt > ATTEMPT_WINDOW) {
    record.count = 1;
    record.firstAttempt = now;
    return;
  }

  record.count++;

  if (record.count >= BAN_THRESHOLD) {
    record.banned = true;
    record.banExpiry = now + BAN_DURATION;
    console.error(
      `[SECURITY] IP BANNED for 24 hours: ${ip} - ${record.count} failed attempts`,
    );
  }
}

function isIPBanned(ip) {
  if (!failedAttempts.has(ip)) return false;

  const record = failedAttempts.get(ip);

  if (record.banned && Date.now() > record.banExpiry) {
    record.banned = false;
    record.count = 0;
    return false;
  }

  return record.banned;
}

function clearFailedAttempts(ip) {
  failedAttempts.delete(ip);
}

function checkIPBan(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;

  if (isIPBanned(ip)) {
    const record = failedAttempts.get(ip);
    const timeLeft = Math.ceil((record.banExpiry - Date.now()) / 1000 / 60);

    console.warn(`[SECURITY] Blocked request from banned IP: ${ip}`);
    return res.status(403).json({
      error: "Forbidden",
      message: `Your IP has been temporarily banned due to too many failed login attempts. Please try again in ${timeLeft} minutes.`,
      banExpiry: record.banExpiry,
    });
  }

  next();
}

module.exports = {
  loginLimiter,
  apiLimiter,
  strictLimiter,
  trackFailedAttempt,
  isIPBanned,
  clearFailedAttempts,
  checkIPBan,
};
