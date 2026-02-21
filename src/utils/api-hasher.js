const crypto = require("crypto");
const path = require("path");

const API_SECRET =
  process.env.API_HASH_SECRET || "church-website-ultra-secret-2024-change-this";

function hashEndpoint(endpoint) {
  return crypto
    .createHmac("sha256", API_SECRET)
    .update(endpoint)
    .digest("hex")
    .substring(0, 16);
}

const API_ENDPOINTS = {
  "/api/user-info": hashEndpoint("/api/user-info"),
  "/api/users": hashEndpoint("/api/users"),
  "/api/banned-users": hashEndpoint("/api/banned-users"),

  "/api/admin/users": hashEndpoint("/api/admin/users"),
  "/api/admin/users/:id": hashEndpoint("/api/admin/users/:id"),
  "/api/admin/users/:id/logout-all": hashEndpoint(
    "/api/admin/users/:id/logout-all",
  ),
  "/api/admin/users/:id/password-reset-link": hashEndpoint(
    "/api/admin/users/:id/password-reset-link",
  ),
  "/api/admin/users/:id/password-reset-links": hashEndpoint(
    "/api/admin/users/:id/password-reset-links",
  ),
  "/api/admin/pending-counts": hashEndpoint("/api/admin/pending-counts"),

  "/api/forms": hashEndpoint("/api/forms"),
  "/api/forms/active": hashEndpoint("/api/forms/active"),
  "/api/forms/:id": hashEndpoint("/api/forms/:id"),
  "/api/forms/:id/deactivate": hashEndpoint("/api/forms/:id/deactivate"),
  "/api/forms/:id/submit": hashEndpoint("/api/forms/:id/submit"),
  "/api/forms/:id/leaderboard": hashEndpoint("/api/forms/:id/leaderboard"),

  "/login": hashEndpoint("/login"),
  "/logout": hashEndpoint("/logout"),
  "/register": hashEndpoint("/register"),
  "/api/register": hashEndpoint("/api/register"),
  "/reset-password/:token": hashEndpoint("/reset-password/:token"),
  "/api/reset-password/validate/:token": hashEndpoint(
    "/api/reset-password/validate/:token",
  ),
  "/api/reset-password": hashEndpoint("/api/reset-password"),

  "/api/registrations": hashEndpoint("/api/registrations"),
  "/api/registrations/declined": hashEndpoint("/api/registrations/declined"),
  "/api/registrations/:id/reactivate": hashEndpoint(
    "/api/registrations/:id/reactivate",
  ),
  "/api/registrations/:id/approve": hashEndpoint(
    "/api/registrations/:id/approve",
  ),
  "/api/registrations/:id/decline": hashEndpoint(
    "/api/registrations/:id/decline",
  ),

  "/api/points/give": hashEndpoint("/api/points/give"),
  "/api/points/take": hashEndpoint("/api/points/take"),
  "/api/gift-shop/items": hashEndpoint("/api/gift-shop/items"),
  "/api/gift-shop/purchase": hashEndpoint("/api/gift-shop/purchase"),
  "/api/gift-shop/my-points": hashEndpoint("/api/gift-shop/my-points"),
  "/api/gift-shop/my-purchases": hashEndpoint("/api/gift-shop/my-purchases"),
  "/api/admin/gift-shop/purchases": hashEndpoint(
    "/api/admin/gift-shop/purchases",
  ),
  "/api/admin/gift-shop/purchases/:id/accept": hashEndpoint(
    "/api/admin/gift-shop/purchases/:id/accept",
  ),
  "/api/admin/gift-shop/purchases/:id/decline": hashEndpoint(
    "/api/admin/gift-shop/purchases/:id/decline",
  ),
  "/api/admin/gift-shop/purchases/:id/received": hashEndpoint(
    "/api/admin/gift-shop/purchases/:id/received",
  ),
  "/api/admin/gift-shop/items": hashEndpoint("/api/admin/gift-shop/items"),
  "/api/admin/gift-shop/items/:id": hashEndpoint(
    "/api/admin/gift-shop/items/:id",
  ),
  "/api/gift-shop/approvals": hashEndpoint("/api/gift-shop/approvals"),

  "/api/admin/live/sessions": hashEndpoint("/api/admin/live/sessions"),
  "/api/admin/live/clear-sessions": hashEndpoint(
    "/api/admin/live/clear-sessions",
  ),
  "/api/admin/live/clear-guests": hashEndpoint("/api/admin/live/clear-guests"),

  "/api/admin/leaderboard/access": hashEndpoint(
    "/api/admin/leaderboard/access",
  ),

  "/api/announcements": hashEndpoint("/api/announcements"),
  "/api/announcements/:page": hashEndpoint("/api/announcements/:page"),
  "/api/announcements/:id": hashEndpoint("/api/announcements/:id"),

  "/api/suggestions": hashEndpoint("/api/suggestions"),
  "/api/grades": hashEndpoint("/api/grades"),
};

const REVERSE_MAP = {};
Object.keys(API_ENDPOINTS).forEach((original) => {
  REVERSE_MAP[API_ENDPOINTS[original]] = original;
});

function getHashedEndpoint(original) {
  return API_ENDPOINTS[original] || null;
}

function getOriginalEndpoint(hash) {
  return REVERSE_MAP[hash] || null;
}

function isValidEndpoint(hash) {
  return hash in REVERSE_MAP;
}

function isMatchingEndpoint(path) {
  if (API_ENDPOINTS[path] || API_ENDPOINTS[path.replace(/\/$/, "")]) {
    return true;
  }

  const endpoints = Object.keys(API_ENDPOINTS);
  const pathParts = path.split("/");

  for (const endpoint of endpoints) {
    if (endpoint.includes(":")) {
      const patternParts = endpoint.split("/");
      if (patternParts.length !== pathParts.length) continue;

      let match = true;
      for (let i = 0; i < patternParts.length; i++) {
        if (
          !patternParts[i].startsWith(":") &&
          patternParts[i] !== pathParts[i]
        ) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
  }
  return false;
}

function apiHashMiddleware(req, res, next) {
  var reqPath = req.path;
  var pathParts = reqPath.split("/").filter(function (p) {
    return p;
  });

  if (pathParts.length > 0) {
    var joinedHash = pathParts.join("/");
    var original = getOriginalEndpoint(joinedHash);

    if (original) {
      req.url =
        original +
        (req.url.indexOf("?") !== -1 ? "?" + req.url.split("?")[1] : "");
      req.originalHash = joinedHash;
      return next();
    }
    var hashPart = pathParts[0];
    var patternMatch = getOriginalEndpoint(hashPart);

    if (patternMatch && patternMatch.indexOf(":") !== -1) {
      var patternSegments = patternMatch.split("/").filter(function (p) {
        return p !== "";
      });
      var dynamicParts = pathParts.slice(1);
      var reconstructed = "";
      var dynamicIdx = 0;

      for (var i = 0; i < patternSegments.length; i++) {
        var segment = patternSegments[i];
        if (segment.indexOf(":") === 0) {
          reconstructed += "/" + (dynamicParts[dynamicIdx++] || "");
        } else {
          reconstructed += "/" + segment;
        }
      }
      req.url =
        reconstructed +
        (req.url.indexOf("?") !== -1 ? "?" + req.url.split("?")[1] : "");
      req.originalHash = hashPart;
      return next();
    }
  }

  if (
    reqPath.startsWith("/api/") &&
    !reqPath.startsWith("/api/v1/client-api-map")
  ) {
    if (isMatchingEndpoint(reqPath)) {
      console.warn(
        `[SECURITY] Blocked unhashed access to protected API: ${reqPath} from IP: ${req.ip}`,
      );
      return res
        .status(404)
        .sendFile(path.join(__dirname, "..", "..", "views", "404.html"));
    }
  }

  next();
}

function generateClientAPIMap() {
  const clientMap = {};
  Object.keys(API_ENDPOINTS).forEach((original) => {
    if (
      original.startsWith("/api/") ||
      original === "/login" ||
      original === "/logout" ||
      original === "/register"
    ) {
      clientMap[original] = API_ENDPOINTS[original];
    }
  });
  return clientMap;
}

module.exports = {
  hashEndpoint,
  getHashedEndpoint,
  getOriginalEndpoint,
  isValidEndpoint,
  apiHashMiddleware,
  generateClientAPIMap,
  API_ENDPOINTS,
};
