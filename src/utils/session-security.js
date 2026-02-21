const crypto = require("crypto");
function createSessionFingerprint(req) {
  const ip = req.ip || req.connection?.remoteAddress || "";
  const userAgent = req.headers["user-agent"] || "";
  const acceptLanguage = req.headers["accept-language"] || "";

  let ipPart = ip;
  if (ip.includes(".")) {
    ipPart = ip.split(".").slice(0, 3).join(".");
  } else if (ip.includes(":")) {
    ipPart = ip.split(":").slice(0, 4).join(":");
  }

  const fingerprintData = `${ipPart}|${userAgent}|${acceptLanguage}`;

  return crypto.createHash("sha256").update(fingerprintData).digest("hex");
}

function validateSessionFingerprint(req, res, next) {
  if (!req.session || !req.session.user) {
    return next();
  }

  const currentFingerprint = createSessionFingerprint(req);

  if (!req.session.fingerprint) {
    req.session.fingerprint = currentFingerprint;
    return next();
  }

  if (req.session.fingerprint !== currentFingerprint) {
    console.error(
      `[SECURITY] Session hijacking detected! Session: ${req.session.id}, User: ${req.session.user?.username}`,
    );
    console.error(
      `[SECURITY] Expected fingerprint: ${req.session.fingerprint}`,
    );
    console.error(`[SECURITY] Received fingerprint: ${currentFingerprint}`);

    req.session.destroy((err) => {
      if (err) {
        console.error("[SECURITY] Error destroying hijacked session:", err);
      }
    });

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return res.status(401).json({
      error: "Session Invalid",
      message:
        "Your session has been invalidated for security reasons. Please log in again.",
      code: "SESSION_HIJACK_DETECTED",
    });
  }

  next();
}

function trackActivity(req, res, next) {
  if (req.session && req.session.user) {
    req.session.lastActivity = Date.now();
  }
  next();
}

function checkSessionTimeout(req, res, next) {
  const TIMEOUT = 30 * 60 * 1000;

  if (req.session && req.session.user && req.session.lastActivity) {
    const now = Date.now();
    const timeSinceActivity = now - req.session.lastActivity;

    if (timeSinceActivity > TIMEOUT) {
      console.warn(
        `[SECURITY] Session timeout for user: ${req.session.user.username}`,
      );

      req.session.destroy((err) => {
        if (err) {
          console.error("[SECURITY] Error destroying timed-out session:", err);
        }
      });

      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      return res.status(401).json({
        error: "Session Expired",
        message:
          "Your session has expired due to inactivity. Please log in again.",
        code: "SESSION_TIMEOUT",
      });
    }
  }

  next();
}

function rotateSessionID(req, res, next) {
  const ROTATION_INTERVAL = 15 * 60 * 1000;

  if (req.session && req.session.user) {
    const now = Date.now();

    if (!req.session.lastRotation) {
      req.session.lastRotation = now;
    }

    const timeSinceRotation = now - req.session.lastRotation;

    if (timeSinceRotation > ROTATION_INTERVAL) {
      const oldSessionID = req.session.id;

      req.session.regenerate((err) => {
        if (err) {
          console.error("[SECURITY] Error rotating session ID:", err);
          return next();
        }

        req.session.lastRotation = now;
        console.log(
          `[SECURITY] Session ID rotated for user: ${req.session.user?.username} (Old: ${oldSessionID}, New: ${req.session.id})`,
        );
        next();
      });

      return;
    }
  }

  next();
}

function detectSuspiciousActivity(req, res, next) {
  if (!req.session || !req.session.user) {
    return next();
  }

  if (!req.session.requestCount) {
    req.session.requestCount = 0;
    req.session.requestWindowStart = Date.now();
  }

  req.session.requestCount++;

  const windowDuration = Date.now() - req.session.requestWindowStart;
  const requestsPerMinute = (req.session.requestCount / windowDuration) * 60000;

  if (requestsPerMinute > 100) {
    console.error(
      `[SECURITY] Suspicious activity detected for user: ${req.session.user.username} - ${requestsPerMinute.toFixed(0)} req/min`,
    );

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    req.session.destroy();

    return res.status(429).json({
      error: "Suspicious Activity",
      message:
        "Unusual activity detected. Your session has been terminated for security reasons.",
      code: "SUSPICIOUS_ACTIVITY",
    });
  }

  if (windowDuration > 60000) {
    req.session.requestCount = 0;
    req.session.requestWindowStart = Date.now();
  }

  next();
}

module.exports = {
  createSessionFingerprint,
  validateSessionFingerprint,
  trackActivity,
  checkSessionTimeout,
  rotateSessionID,
  detectSuspiciousActivity,
};
