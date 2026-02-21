const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const axios = require("axios");
const moment = require("moment-timezone");
const UAParser = require("ua-parser-js");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const compression = require("compression");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
let argon2;
try {
  argon2 = require("argon2");
} catch (e) {
  console.warn("[SERVER] argon2 not available, falling back to bcrypt with high salt rounds.");
}

function loadViteManifest() {
  const manifestPath = path.join(__dirname, "public", "dist", ".vite", "manifest.json");
  try {
    if (!fs.existsSync(manifestPath)) {
      return null;
    }
    const raw = fs.readFileSync(manifestPath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.warn("[SERVER] Failed to load Vite manifest:", err?.message || err);
    return null;
  }
}

console.log(`[SERVER] Starting Church Website Application...`);

const { apiHashMiddleware, generateClientAPIMap } = require('./src/utils/api-hasher');
const { requireAPIRole, hasRequiredRole, requireRole: rbacRequireRole } = require('./src/utils/rbac-middleware');
const { encrypt, decrypt, encryptFields, decryptFields, hash } = require('./src/utils/encryption');
const { hashPassword, comparePassword, generateAccessToken, generateRefreshToken, verifyAccessToken, verifyRefreshToken } = require('./src/utils/auth');
const {
  loginLimiter: secureLoginLimiter,
  apiLimiter: secureAPILimiter,
  strictLimiter,
  trackFailedAttempt,
  clearFailedAttempts,
  checkIPBan
} = require('./src/utils/rate-limiter');
const {
  validateSessionFingerprint,
  trackActivity,
  checkSessionTimeout,
  rotateSessionID,
  detectSuspiciousActivity,
} = require('./src/utils/session-security');
const { maliciousFilter, spamBlocker } = require('./src/utils/automod');
const userRegistrationsStore = require("./src/db/userregistrations-store");

const submissionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message:
      "Too many submissions. Please wait 15 minutes before trying again.",
  },
  keyGenerator: (req) => {
    return req.session?.username || req.ip;
  },
});

const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please slow down.",
  },
  skip: (req) => {
    const role = req.session?.role;
    return role === "admin" || role === "leadadmin";
  },
});

const GRADE_SLUGS = [
  "prep1",
  "prep2",
  "prep3",
  "sec1",
  "sec2",
  "sec3",
  "teachers",
  "admins",
];
const ROLE_TYPES = ["student", "teacher", "admin", "leadadmin"];
const FORM_TARGETS = ["all", ...GRADE_SLUGS, "teachers", "admins"];
const GRADE_ALIAS = {
  "prep-1": "prep1",
  "prep-2": "prep2",
  "prep-3": "prep3",
  "prep 1": "prep1",
  "prep 2": "prep2",
  "prep 3": "prep3",
  اعدادي1: "prep1",
  اعدادي2: "prep2",
  اعدادي3: "prep3",
  "sec-1": "sec1",
  "sec-2": "sec2",
  "sec-3": "sec3",
  secondary1: "sec1",
  secondary2: "sec2",
  secondary3: "sec3",
  ثانوي1: "sec1",
  ثانوي2: "sec2",
  ثانوي3: "sec3",
};
const GRADE_LABELS = {
  prep1: {
    short: "أولي إعدادي",
    long: "Preparatory Grade 1",
    verse: "لاَ يَسْتَهِنْ أَحَدٌ بِحَدَاثَتِكَ.",
  },
  prep2: {
    short: "ثانية إعدادي",
    long: "Preparatory Grade 2",
    verse: "ثَبِّتُوا قُلُوبَكُمْ، لأَنَّ مَجِيءَ الرَّبِّ قَدِ اقْتَرَبَ.",
  },
  prep3: {
    short: "ثالثة إعدادي",
    long: "Preparatory Grade 3",
    verse: "إِنَّمَا الْقَلِيلُ حِينَ يُزْرَعُ يُكْثَرُ.",
  },
  sec1: {
    short: "أولي ثانوي",
    long: "Secondary Grade 1",
    verse: "اِذْكُرْ خَالِقَكَ فِي أَيَّامِ شَبَابِكَ.",
  },
  sec2: {
    short: "ثانية ثانوي",
    long: "Secondary Grade 2",
    verse: "كُلُّ شَيْءٍ يَسْتَقِيمُ بِحِكْمَةٍ.",
  },
  sec3: {
    short: "ثالثة ثانوي",
    long: "Secondary Grade 3",
    verse:
      "لأَنِّي عَرَفْتُ الأَفْكَارَ الَّتِي أَنَا مُفَكِّرٌ بِهَا عَنْكُمْ.",
  },
};
const gradeBlueprints = {
  prep1: {
    heroTitle: "أولي إعدادي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
  prep2: {
    heroTitle: "ثانية إعدادي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
  prep3: {
    heroTitle: "ثالثة إعدادي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
  sec1: {
    heroTitle: "أولي ثانوي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
  sec2: {
    heroTitle: "ثانية ثانوي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
  sec3: {
    heroTitle: "ثالثة ثانوي",
    heroSubtitle:
      'لاَ تَخَفْ لأَنِّي مَعَكَ، وَأُبَارِكُكَ (سفر التكوين 26: 24)',
  },
};

dotenv.config();

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.set("etag", "weak");

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      "https://kenisa-el-sama2eyeen.ooguy.com",
      "https://kenisa-el-sama2eyeen.ooguy.com",
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

const staticAssetOptions = {
  cacheControl: true,
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.match(/\.css$/i)) {
      res.setHeader("Content-Type", "text/css; charset=utf-8");
    } else if (filePath.match(/\.js$/i)) {
      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
    }

    // Hashed assets in dist are immutable
    if (filePath.includes(path.join('public', 'dist'))) {
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    } else {
      // Source assets: force validation or short cache to prevent Safari hangs on updates
      res.setHeader("Cache-Control", "public, max-age=0, must-revalidate");
    }
  },
};


app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'", "https://www.google.com", "https://google.com"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
}));

// Safari Compliance & HTTPS enforcement
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(`https://${req.get("Host")}${req.url}`);
  }

  const ua = req.headers["user-agent"] || "";
  const isSafari = ua.includes("Safari") && !ua.includes("Chrome") && !ua.includes("Chromium");

  if (isSafari) {
    // Safari-specific: Force keep-alive and allow document caching to stabilize initial load
    res.setHeader("Connection", "keep-alive");
    if (req.accepts("html")) {
      res.setHeader("Cache-Control", "no-cache, must-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
    // Optimization: Don't vary on User-Agent for Safari to prevent loader confusion
    res.setHeader("Vary", "Accept-Encoding, Cookie");
  } else {
    res.setHeader("Vary", "Accept-Encoding, Cookie, User-Agent");
  }
  next();
});


app.use(mongoSanitize());
app.use(xss());
app.use(compression({
  filter: (req, res) => {
    const ua = req.headers["user-agent"] || "";
    const isSafari = ua.includes("Safari") && !ua.includes("Chrome") && !ua.includes("Chromium");

    // Safari-specific fix: Disable compression for HTML documents to prevent indefinite 'blue line' loading hang
    if (isSafari && res.getHeader("Content-Type")?.toString().includes("text/html")) {
      return false;
    }

    return compression.filter(req, res);
  }
}));
app.use(cookieParser(process.env.COOKIE_SECRET || "default_cookie_secret"));

app.use(cors({
  origin: (origin, callback) => {
    const allowed = [
      "https://kenisa-el-sama2eyeen.ooguy.com",
      "http://localhost:3000",
      "http://localhost:5173"
    ];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: true,
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.get('/health', (req, res) => res.status(200).send('OK'));

app.use("/design", express.static(path.join(__dirname, "src/assets/styles"), staticAssetOptions));
app.use("/scripts", express.static(path.join(__dirname, "src/assets/scripts"), staticAssetOptions));
app.use("/UI", express.static(path.join(__dirname, "src/assets/images"), staticAssetOptions));
app.use("/dist", express.static(path.join(__dirname, "public/dist"), staticAssetOptions));
app.use(express.static(path.join(__dirname, "public"), staticAssetOptions));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const viteManifest = loadViteManifest();

app.locals.vite = (srcPath, fallback = srcPath) => {
  if (!srcPath || typeof srcPath !== "string") {
    return fallback;
  }

  const entry = viteManifest?.[srcPath];
  if (entry?.file) {
    return "/dist/" + entry.file;
  }

  return fallback;
};

app.use(session({
  secret: process.env.SESSION_SECRET || "default_secret_key_12345",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: "sessions",
    ttl: 24 * 60 * 60,
    autoRemove: "native",
  }),
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
  name: "church.sid",
}));

app.use(maliciousFilter);
app.use(apiHashMiddleware);

// Endpoint to provide API mapping to the client
app.get("/api/v1/client-api-map", (req, res) => {
  res.json(generateClientAPIMap());
});

// Middleware to inject the API hasher script into HTML responses
app.use((req, res, next) => {
  if (req.path.startsWith("/api/") || req.path.startsWith("/design/") || req.path.startsWith("/scripts/") || req.path.startsWith("/UI/")) {
    return next();
  }

  // Intercept res.send
  const originalSend = res.send;
  res.send = function (body) {
    if (typeof body === 'string' && body.includes('<head>')) {
      const scriptTag = `
        <!-- API Security Hashing -->
        <script>
          (function() {
            var mapPromise = fetch("/api/v1/client-api-map").then(function(r) { return r.json(); }).catch(function() { return {}; });
            var originalFetch = window.fetch;
            window.fetch = function(url, options) {
              if (typeof url !== 'string' || url.indexOf('/api/v1/client-api-map') !== -1 || (!url.indexOf('/api/') === 0 && !url.indexOf('/login') === 0 && !url.indexOf('/logout') === 0 && !url.indexOf('/register') === 0)) {
                return originalFetch(url, options);
              }
              return mapPromise.then(function(map) {
                var urlObj = new URL(url, window.location.origin);
                var path = urlObj.pathname;
                var finalUrl = url;
                if (map[path]) {
                  finalUrl = "/" + map[path] + urlObj.search + urlObj.hash;
                } else {
                  for (var pattern in map) {
                    if (pattern.indexOf(':') !== -1) {
                      var regexStr = "^" + pattern.split('/').map(function(p) {
                        return p.indexOf(':') === 0 ? '([^/]+)' : p;
                      }).join('/') + "$";
                      var regex = new RegExp(regexStr);
                      var match = path.match(regex);
                      if (match) {
                        var dynamicParts = match.slice(1);
                        finalUrl = "/" + map[pattern] + (dynamicParts.length > 0 ? "/" + dynamicParts.join("/") : "") + urlObj.search + urlObj.hash;
                        break;
                      }
                    }
                  }
                }
                return originalFetch(finalUrl, options);
              });
            };
          })();
        </script>`;
      body = body.replace('</head>', scriptTag + '</head>');
    }
    return originalSend.call(this, body);
  };

  // Intercept res.sendFile to ensure .html views get the script
  const originalSendFile = res.sendFile;
  res.sendFile = function (filePath, options, callback) {
    if (typeof filePath === 'string' && filePath.endsWith('.html') && filePath.includes(path.join(__dirname, 'views'))) {
      fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return originalSendFile.call(res, filePath, options, callback);
        res.send(data); // This will trigger the res.send interceptor above
      });
    } else {
      originalSendFile.call(res, filePath, options, callback);
    }
  };

  next();
});

// Industry Standard JWT Authentication Sync
app.use(async (req, res, next) => {
  if (req.path.startsWith("/design/") || req.path.startsWith("/scripts/") || req.path.startsWith("/UI/")) {
    return next();
  }

  const accessToken = req.cookies?.accessToken;
  const refreshToken = req.cookies?.refreshToken;

  if (accessToken) {
    const payload = verifyAccessToken(accessToken);
    if (payload) {
      req.user = payload;
      // Sync to session for legacy compatibility
      if (!req.session.isAuthenticated) {
        req.session.isAuthenticated = true;
        req.session.username = payload.username;
        req.session.role = payload.role;
        req.session.grade = payload.grade;
      }
      return next();
    }
  }

  // If access token expired but refresh token exists, try to rotate
  if (refreshToken) {
    const payload = verifyRefreshToken(refreshToken);
    if (payload) {
      try {
        const UserRegistration = mongoose.models.UserRegistration;
        let user = null;

        if (mongoose.Types.ObjectId.isValid(payload.id)) {
          user = await UserRegistration.findById(payload.id);
        } else {
          // Fallback: try finding by username if the ID is not a valid ObjectId
          user = await UserRegistration.findOne({ username: payload.id });
        }

        if (user && !user.isLocked && user.approvalStatus === 'approved') {
          const newAccessToken = generateAccessToken(user);
          res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000
          });

          req.user = verifyAccessToken(newAccessToken);
          req.session.isAuthenticated = true;
          req.session.username = user.username;
          req.session.role = user.role;
          req.session.grade = user.grade;
        }
      } catch (err) {
        console.error('[JWT] Refresh Error:', err.message);
      }
    }
  }

  next();
});

app.use(validateSessionFingerprint);
app.use(checkSessionTimeout);
app.use(trackActivity);
app.use(rotateSessionID);
app.use(detectSuspiciousActivity);
app.use(checkIPBan);

app.use((req, res, next) => {
  if (req.session && req.session.isAuthenticated) return next();
  if (req.path.startsWith("/api/") || req.path.startsWith("/design/") || req.path.startsWith("/scripts/") || req.path.startsWith("/UI/") || req.path === "/favicon.ico") return next();
  const GuestSessionModel = mongoose.models.GuestSession;
  if (!GuestSessionModel) return next();
  const crypto = require("crypto");
  const raw = (req.ip || "") + (req.get("user-agent") || "");
  const guestId = crypto.createHash("sha256").update(raw).digest("hex").slice(0, 24);
  const now = new Date();
  GuestSessionModel.findOneAndUpdate(
    { guestId },
    {
      $set: {
        ip: req.ip || "",
        userAgent: (req.get("user-agent") || "").substring(0, 300),
        currentPath: req.path || "",
        currentMethod: req.method || "",
        lastSeenAt: now,
      },
      $setOnInsert: { firstSeenAt: now },
    },
    { upsert: true }
  ).catch((err) => console.error("Guest session tracking error:", err.message));
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login attempts. Try again later.",
  },
});

const adminApiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please slow down.",
  },
  keyGenerator: (req) => {
    return `${req.ip}-${req.session?.username || 'anonymous'}`;
  },
  skip: (req) => {
    const userRole = req.session?.role;
    return userRole === "leadadmin";
  },
});

app.use(globalRateLimiter);

const WEBHOOK_REGISTRY = {
  SECURITY: {
    env: "SECURITY_WEBHOOK",
    fallbackEnvs: ["MASTER_ACTIVITY_WEBHOOK", "SYSTEM_WEBHOOK"],
    label: "Security",
    emoji: "🚨",
  },
  ADMIN: {
    env: "ADMIN_ACTIVITY_WEBHOOK",
    fallbackEnvs: [
      "MASTER_ACTIVITY_WEBHOOK",
      "SYSTEM_WEBHOOK",
      "SECURITY_WEBHOOK",
    ],
    label: "Admin",
    emoji: "🛡️",
  },
  USER: {
    env: "USER_ACTIVITY_WEBHOOK",
    fallbackEnvs: [
      "ACTIVITY_WEBHOOK",
      "ADMIN_ACTIVITY_WEBHOOK",
      "MASTER_ACTIVITY_WEBHOOK",
    ],
    label: "User Activity",
    emoji: "👤",
  },
  REGISTRATION_APPROVAL: {
    env: "REGISTRATION_APPROVAL_WEBHOOK",
    fallbackEnvs: [
      "USER_ACTIVITY_WEBHOOK",
      "ADMIN_ACTIVITY_WEBHOOK",
      "MASTER_ACTIVITY_WEBHOOK",
    ],
    label: "Registration Approval",
    emoji: "📨",
  },
  FORM: {
    env: "FORM_ACTIVITY_WEBHOOK",
    fallbackEnvs: [
      "USER_ACTIVITY_WEBHOOK",
      "ACTIVITY_WEBHOOK",
      "MASTER_ACTIVITY_WEBHOOK",
    ],
    label: "Forms",
    emoji: "📝",
  },
  GIFT: {
    env: "GIFT_SHOP_ACTIVITY_WEBHOOK",
    fallbackEnvs: [
      "ADMIN_ACTIVITY_WEBHOOK",
      "USER_ACTIVITY_WEBHOOK",
      "ACTIVITY_WEBHOOK",
    ],
    label: "Gift Shop",
    emoji: "🎁",
  },
  SUGGESTION: {
    env: "SUGGESTION_ACTIVITY_WEBHOOK",
    fallbackEnvs: [
      "USER_ACTIVITY_WEBHOOK",
      "ACTIVITY_WEBHOOK",
      "MASTER_ACTIVITY_WEBHOOK",
    ],
    label: "Suggestions",
    emoji: "💡",
  },
  DATABASE: {
    env: "DATABASE_BACKUP_WEBHOOK",
    fallbackEnvs: ["SYSTEM_WEBHOOK", "SECURITY_WEBHOOK"],
    label: "Database",
    emoji: "💾",
  },
  ERROR: {
    env: "ERROR_LOGGING_WEBHOOK",
    fallbackEnvs: [
      "SYSTEM_WEBHOOK",
      "SECURITY_WEBHOOK",
      "MASTER_ACTIVITY_WEBHOOK",
    ],
    label: "Errors",
    emoji: "❌",
  },
  ATTENDANCE: {
    env: "ATTENDANCE_ACTIVITY_WEBHOOK",
    fallbackEnvs: ["USER_ACTIVITY_WEBHOOK", "ACTIVITY_WEBHOOK"],
    label: "Attendance",
    emoji: "📋",
  },
  FILE_DELETE: {
    env: "FILE_DELETE_WEBHOOK",
    fallbackEnvs: ["SYSTEM_WEBHOOK", "SECURITY_WEBHOOK"],
    label: "File Deletion",
    emoji: "🗑️",
  },
  SYSTEM: {
    env: "SYSTEM_WEBHOOK",
    fallbackEnvs: ["MASTER_ACTIVITY_WEBHOOK", "ADMIN_ACTIVITY_WEBHOOK"],
    label: "System",
    emoji: "🖥️",
  },
};

const WEBHOOK_TIMEOUT_MS =
  Number(process.env.WEBHOOK_TIMEOUT_MS) > 0
    ? Number(process.env.WEBHOOK_TIMEOUT_MS)
    : 7000;
const WEBHOOK_RETRY_ATTEMPTS = 3;
const WEBHOOK_RETRY_DELAYS = [0, 750, 2000];
const webhookHealth = new Map();

const sleep = (ms) =>
  ms && ms > 0
    ? new Promise((resolve) => setTimeout(resolve, ms))
    : Promise.resolve();

const os = require("os");

function checkMemoryUsage() {
  const used = process.memoryUsage();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memoryUsagePercent = (usedMem / totalMem) * 100;

  return {
    heapUsed: Math.round(used.heapUsed / 1024 / 1024),
    heapTotal: Math.round(used.heapTotal / 1024 / 1024),
    rss: Math.round(used.rss / 1024 / 1024),
    systemTotal: Math.round(totalMem / 1024 / 1024),
    systemUsed: Math.round(usedMem / 1024 / 1024),
    systemFree: Math.round(freeMem / 1024 / 1024),
    memoryUsagePercent: Math.round(memoryUsagePercent * 100) / 100,
  };
}

function isMemoryCritical() {
  const memory = checkMemoryUsage();
  return memory.memoryUsagePercent > 85 || memory.heapUsed > 450;
}

setInterval(async () => {
  const memory = checkMemoryUsage();

  if (memory.memoryUsagePercent > 80) {
    await sendWebhook("SYSTEM", {
      embeds: [
        {
          title: "⚠️ High Memory Usage Warning",
          color: 0xf59e0b,
          fields: [
            { name: "Heap Used", value: `${memory.heapUsed} MB`, inline: true },
            {
              name: "Heap Total",
              value: `${memory.heapTotal} MB`,
              inline: true,
            },
            { name: "RSS", value: `${memory.rss} MB`, inline: true },
            {
              name: "System Usage",
              value: `${memory.memoryUsagePercent}%`,
              inline: true,
            },
            { name: "Status", value: "⚠️ High", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
  }

  if (isMemoryCritical()) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "🚨 Critical Memory Usage",
          color: 0xe74c3c,
          fields: [
            { name: "Heap Used", value: `${memory.heapUsed} MB`, inline: true },
            {
              name: "Memory Usage",
              value: `${memory.memoryUsagePercent}%`,
              inline: true,
            },
            { name: "Status", value: "🚨 CRITICAL", inline: true },
            { name: "Action", value: "Initiated cleanup", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    if (global.gc) {
      global.gc();
    }

    try {
      await cleanupOldFiles();
    } catch (error) {
      console.error("[MEMORY CLEANUP ERROR]", error.message);
    }
  }
}, 60000);

function prefixContent(content, prefix) {
  if (!content || typeof content !== "string") {
    return `${prefix} update`;
  }
  const trimmed = content.trim();
  if (trimmed.startsWith(prefix)) {
    return trimmed;
  }
  return `${prefix} ${trimmed}`;
}

function formatEmbeds(embeds, meta) {
  if (!Array.isArray(embeds)) {
    return [];
  }
  return embeds.map((embed) => {
    const clone = { ...embed };
    if (Array.isArray(embed.fields)) {
      clone.fields = embed.fields.map((field) => ({ ...field }));
    }
    const footerParts = [
      embed.footer?.text,
      `${meta.label || meta.type} • ${meta.eventId.slice(0, 8)}`,
    ].filter(Boolean);
    clone.footer = {
      ...(embed.footer || {}),
      text: footerParts.join(" | "),
    };
    clone.timestamp = embed.timestamp || new Date().toISOString();
    return clone;
  });
}

function buildWebhookPayload(data, meta) {
  const base =
    typeof data === "string"
      ? { content: data }
      : Array.isArray(data)
        ? { embeds: data }
        : { ...data };

  let content = prefixContent(base.content, `${meta.emoji || "📌"} [${meta.label || meta.type}]`);

  if (data.important === true) {
    content = `<@&1126336222206365696> ${content}`;
  }

  base.content = content;

  if (base.embeds) {
    base.embeds = formatEmbeds(base.embeds, meta);
  }

  base.username = base.username || "Church Activity Logs";
  return base;
}

async function dispatchWebhookTarget(target, payload, meta) {
  for (let attempt = 1; attempt <= WEBHOOK_RETRY_ATTEMPTS; attempt++) {
    try {
      console.log(
        `[WEBHOOK][${meta.type}][${meta.eventId}] attempt ${attempt} via ${target.envKey}`
      );
      await axios.post(target.url, payload, {
        headers: { "Content-Type": "application/json" },
        timeout: WEBHOOK_TIMEOUT_MS,
      });
      console.log(
        `[WEBHOOK][${meta.type}][${meta.eventId}] delivered via ${target.envKey}`
      );
      return true;
    } catch (error) {
      console.error(
        `[WEBHOOK][${meta.type}][${meta.eventId}] attempt ${attempt} via ${target.envKey} failed: ${error.message}`
      );
      if (attempt < WEBHOOK_RETRY_ATTEMPTS) {
        const wait =
          WEBHOOK_RETRY_DELAYS[attempt] ||
          WEBHOOK_RETRY_DELAYS[WEBHOOK_RETRY_DELAYS.length - 1];
        await sleep(wait);
      }
    }
  }
  return false;
}

function updateWebhookStats(envKey, success) {
  if (!envKey) return;
  const current = webhookHealth.get(envKey) || {
    success: 0,
    failure: 0,
    consecutiveFailures: 0,
  };
  if (success) {
    current.success += 1;
    current.consecutiveFailures = 0;
    current.lastSuccess = Date.now();
  } else {
    current.failure += 1;
    current.consecutiveFailures += 1;
    current.lastFailure = Date.now();
    if (current.consecutiveFailures % WEBHOOK_RETRY_ATTEMPTS === 0) {
      console.warn(
        `[WEBHOOK][HEALTH] ${envKey} consecutive failures: ${current.consecutiveFailures}`
      );
    }
  }
  webhookHealth.set(envKey, current);
}

async function dispatchWebhook(webhookType, data = {}) {
  const registryEntry = WEBHOOK_REGISTRY[webhookType];
  const eventId = uuidv4();
  if (!registryEntry) {
    console.warn(`[WEBHOOK][${eventId}] unknown type ${webhookType}`);
    return false;
  }

  const broadcastAll =
    String(process.env.WEBHOOK_BROADCAST_ALL || "").toLowerCase() === "true";

  const registryEnvKeys = broadcastAll
    ? Array.from(
        new Set(
          Object.values(WEBHOOK_REGISTRY)
            .flatMap((entry) => [entry.env, ...(entry.fallbackEnvs || [])])
            .filter(Boolean)
        )
      )
    : [registryEntry.env, ...(registryEntry.fallbackEnvs || [])].filter(Boolean);

  const envKeys = [
    ...registryEnvKeys,
  ].filter(Boolean);

  const targets = envKeys
    .map((envKey) => ({
      envKey,
      url: process.env[envKey],
    }))
    .filter((target) => Boolean(target.url));

  const uniqueTargets = Array.from(
    new Map(targets.map((t) => [t.url, t])).values()
  );
  if (uniqueTargets.length === 0) {
    console.warn(
      `[WEBHOOK][${webhookType}][${eventId}] missing webhook env (${envKeys.join(
        ", "
      )})`
    );
    return false;
  }
  const payload = buildWebhookPayload(data, {
    type: webhookType,
    label: registryEntry.label,
    emoji: registryEntry.emoji,
    eventId,
  });

  // In broadcast mode we deliver to every configured channel (best-effort).
  // In normal mode we stop after the first successful delivery.
  let anyDelivered = false;
  for (const target of uniqueTargets) {
    const delivered = await dispatchWebhookTarget(target, payload, {
      type: webhookType,
      eventId,
    });
    updateWebhookStats(target.envKey, delivered);
    if (delivered) anyDelivered = true;
    if (!broadcastAll && delivered) return true;
  }
  if (broadcastAll && anyDelivered) return true;
  console.error(
    `[WEBHOOK][${webhookType}][${eventId}] failed for targets ${targets
      .map((t) => t.envKey)
      .join(", ")}`
  );
  return false;
}

async function runDatabaseBackupSnapshot(trigger = "scheduled") {
  const enabled =
    String(process.env.ENABLE_DATABASE_BACKUP || "").toLowerCase() === "true";
  if (!enabled) return;

  try {
    const backupsDir = path.join(__dirname, "backups");
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }

    const now = new Date();
    const stamp = now.toISOString().replace(/[:.]/g, "-");
    const filePath = path.join(backupsDir, `db-snapshot.${stamp}.json`);

    const safeUsers = await UserRegistration.find(
      {},
      {
        password: 0,
        twoFactorSecret: 0,
        verificationCode: 0,
        passwordResetLinks: 0,
      }
    ).lean();
    const safeForms = await Form.find({}).lean();

    const snapshot = {
      generatedAt: now.toISOString(),
      trigger,
      counts: {
        users: safeUsers.length,
        forms: safeForms.length,
      },
      data: {
        users: safeUsers,
        forms: safeForms,
      },
    };

    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2), "utf8");
    const stats = fs.statSync(filePath);

    await sendWebhook("DATABASE", {
      embeds: [
        {
          title: "💾 Database Snapshot Created",
          color: 0x3498db,
          fields: [
            { name: "Trigger", value: trigger, inline: true },
            {
              name: "File",
              value: `\`${path.basename(filePath)}\``,
              inline: true,
            },
            {
              name: "Size",
              value: formatBytes(stats.size),
              inline: true,
            },
            {
              name: "Users",
              value: String(safeUsers.length),
              inline: true,
            },
            {
              name: "Forms",
              value: String(safeForms.length),
              inline: true,
            },
            {
              name: "Time",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
  } catch (err) {
    console.error("[DATABASE BACKUP] snapshot failed:", err);
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Database Snapshot Failed",
          color: 0xe74c3c,
          fields: [
            { name: "Error", value: err.message || "Unknown", inline: false },
            {
              name: "Time",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
  }
}

setTimeout(() => {
  runDatabaseBackupSnapshot("startup");
}, 60 * 1000);

setInterval(() => {
  runDatabaseBackupSnapshot("scheduled");
}, 24 * 60 * 60 * 1000);

function sendWebhook(webhookType, data = {}, options = {}) {
  const awaitResponse = options.awaitResponse === true;
  const deliveryPromise = dispatchWebhook(webhookType, data);
  if (awaitResponse) {
    return deliveryPromise;
  }
  deliveryPromise.catch((error) => {
    console.error(
      `[WEBHOOK][${webhookType}] async dispatch failed: ${error.message}`
    );
  });
  return Promise.resolve(true);
}
global.sendWebhook = sendWebhook;


async function sendFileDeleteWebhook(
  filePath,
  deletedBy,
  reason = "System cleanup"
) {
  const stats = fs.statSync(filePath);
  const fileInfo = {
    name: path.basename(filePath),
    path: filePath,
    size: formatBytes(stats.size),
    created: stats.birthtime,
    modified: stats.mtime,
    type: path.extname(filePath).toUpperCase() || "Unknown",
  };

  await sendWebhook("FILE_DELETE", {
    embeds: [
      {
        title: "🗑️ File Deleted",
        color: 0xe74c3c,
        fields: [
          { name: "File Name", value: fileInfo.name, inline: true },
          { name: "File Type", value: fileInfo.type, inline: true },
          { name: "File Size", value: fileInfo.size, inline: true },
          { name: "Deleted By", value: deletedBy, inline: true },
          { name: "Reason", value: reason, inline: true },
          { name: "Full Path", value: `\`${filePath}\``, inline: false },
          {
            name: "Created",
            value: moment(fileInfo.created).format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
          {
            name: "Last Modified",
            value: moment(fileInfo.modified).format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
          {
            name: "Timestamp",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

function truncateValue(text, maxLength) {
  if (!text) {
    return "";
  }
  return text.length > maxLength
    ? `${text.slice(0, Math.max(0, maxLength - 3))}...`
    : text;
}

function formatAnswerValue(value, fallback) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : fallback;
  }
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return value.toString();
}

async function cleanupOldFiles() {
  const directories = [
    path.join(__dirname, "uploads"),
    path.join(__dirname, "temp"),
    path.join(__dirname, "backups"),
  ];

  const maxAge = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  for (const dir of directories) {
    if (!fs.existsSync(dir)) continue;

    try {
      const files = fs.readdirSync(dir);

      for (const file of files) {
        const filePath = path.join(dir, file);
        const stats = fs.statSync(filePath);

        if (now - stats.mtime.getTime() > maxAge) {
          await sendFileDeleteWebhook(
            filePath,
            "System",
            "Automatic cleanup of old files"
          );
          fs.unlinkSync(filePath);
          console.log(`[CLEANUP] Deleted old file: ${filePath}`);
        }
      }
    } catch (error) {
      console.error(`[CLEANUP ERROR] ${dir}:`, error.message);
    }
  }
}

setInterval(cleanupOldFiles, 24 * 60 * 60 * 1000);

setTimeout(cleanupOldFiles, 30000);

const AnnouncementSchema = new mongoose.Schema({
  page: String,
  title: String,
  content: String,
  author: String,
  timestamp: { type: Date, default: Date.now },
  priority: { type: String, default: "normal" },
});

const Announcement = mongoose.model("Announcement", AnnouncementSchema);

const PageContentSchema = new mongoose.Schema({
  page: { type: String, unique: true },
  content: String,
  lastEdited: { type: Date, default: Date.now },
  editedBy: String,
});

const PageContent = mongoose.model("PageContent", PageContentSchema);

const FormSchema = new mongoose.Schema({
  topic: { type: String, unique: true },
  expiry: Date,
  description: { type: String, default: "" },
  targetGrade: { type: String, enum: FORM_TARGETS, default: "all" },
  allowedGrades: { type: [String], default: [] },
  status: {
    type: String,
    enum: ["draft", "published", "expired"],
    default: "draft",
  },
  allowRetake: { type: Boolean, default: false },
  createdBy: String,
  updatedBy: String,
  updatedAt: { type: Date, default: Date.now },
  questions: [
    {
      questionText: String,
      questionType: {
        type: String,
        enum: ["true-false", "multiple-choice"],
        default: "multiple-choice",
      },
      options: [String],
      correctAnswer: mongoose.Schema.Types.Mixed,
      correctAnswerIndex: Number,
      required: { type: Boolean, default: true },
      points: { type: Number, default: 10 },
    },
  ],
  link: { type: String, unique: true },
  submissions: [
    {
      username: String,
      score: Number,
      grade: String,
      deviceId: String,
      ip: String,
      submissionTime: { type: Date, default: Date.now },
    },
  ],
});

const Form = mongoose.model("Form", FormSchema);

const SuggestionSchema = new mongoose.Schema({
  username: { type: String, required: true, lowercase: true, index: true },
  displayName: { type: String, default: "" },
  grade: { type: String, enum: GRADE_SLUGS, default: null },
  category: { type: String, default: "meeting" },
  text: { type: String, required: true, trim: true, maxlength: 600 },
  createdAt: { type: Date, default: Date.now },
});

SuggestionSchema.index({ username: 1, category: 1, createdAt: -1 });

const Suggestion = mongoose.model("Suggestion", SuggestionSchema);

const BannedUserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  usernameLower: { type: String, required: true, unique: true },
  banType: { type: String, enum: ["login", "forms", "all"], default: "all" },
  reason: { type: String, default: "" },
  expiresAt: { type: Date, default: null },
  createdBy: String,
  createdAt: { type: Date, default: Date.now },
});

const BannedUser = mongoose.model("BannedUser", BannedUserSchema);

const PasswordResetLinkSchema = new mongoose.Schema({
  token: { type: String, required: true },
  verificationCode: { type: String, default: null },
  verifiedAt: { type: Date, default: null },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, required: true },
  usedAt: { type: Date, default: null },
  supersededAt: { type: Date, default: null },
}, { _id: false });

const UserRegistrationSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  secondName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  emailHash: { type: String, index: true },
  phone: { type: String, required: true },
  phoneHash: { type: String, index: true },
  grade: { type: String, enum: GRADE_SLUGS, required: true },
  role: { type: String, enum: ROLE_TYPES, default: "student" },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, default: null },
  approvalStatus: {
    type: String,
    enum: ["pending", "approved", "declined"],
    default: "pending",
    index: true,
  },
  verificationCode: { type: String, default: null },
  verificationCodeVerified: { type: Boolean, default: false },
  verificationDate: { type: Date, default: null },
  lastLoginAt: { type: Date, default: null, index: true },
  createdAt: { type: Date, default: Date.now },
  reviewedBy: String,
  reviewedAt: Date,
  reviewReason: String,
  passwordResetLinks: { type: [PasswordResetLinkSchema], default: [] },
  loginAttempts: { type: Number, required: true, default: 0 },
  lockUntil: { type: Number }
});

UserRegistrationSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    const currentPassword = (this.password || "").toString();
    const alreadyHashed =
      currentPassword.startsWith("$2a$") ||
      currentPassword.startsWith("$2b$") ||
      currentPassword.startsWith("$2y$") ||
      currentPassword.startsWith("$argon2");

    if (!alreadyHashed) {
      const { hashPassword } = require('./src/utils/auth');
      this.password = await hashPassword(currentPassword);
    }
  }

  if (this.isModified('email')) {
    this.emailHash = hash(this.email.toLowerCase());
  }
  if (this.isModified('phone')) {
    this.phoneHash = hash(this.phone.trim());
  }

  const fieldsToEncrypt = ['firstName', 'secondName', 'email', 'phone'];
  const encrypted = encryptFields(this.toObject(), fieldsToEncrypt);

  fieldsToEncrypt.forEach(field => {
    if (this.isModified(field)) {
      this[field] = encrypted[field];
    }
  });

  next();
});

UserRegistrationSchema.methods.incLoginAttempts = function () {
  // if we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  // otherwise we're incrementing
  const updates = { $inc: { loginAttempts: 1 } };
  // lock the account if we've reached max attempts and it's not already locked
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 };
  }
  return this.updateOne(updates);
};

UserRegistrationSchema.virtual('isLocked').get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

function decryptUser(user) {
  if (!user) return null;
  const fieldsToDecrypt = ['firstName', 'secondName', 'email', 'phone', 'twoFactorSecret'];
  return decryptFields(user, fieldsToDecrypt);
}

const UserRegistration = mongoose.model(
  "UserRegistration",
  UserRegistrationSchema
);

const localUserStore = require("./src/db/userregistrations-store");

async function findUserById(id) {
  try {
    const localUser = await localUserStore.findById(id);
    if (localUser) {
      return { ...localUser, _isLocal: true };
    }
    const mongoUser = await UserRegistration.findById(id);
    if (mongoUser) {
      return { ...decryptUser(mongoUser.toObject()), _isLocal: false };
    }
    return null;
  } catch (error) {
    console.error("Error finding user:", error);
    return null;
  }
}

async function findUserByUsername(username) {
  try {
    const normalized = (username || "").toString().toLowerCase().trim();
    const mongoUser = await UserRegistration.findOne({ username: normalized });
    if (mongoUser) {
      if (mongoUser.isLocked) {
        return { _isLocked: true, lockUntil: mongoUser.lockUntil };
      }
      return mongoUser;
    }
    const localUser = await localUserStore.findByUsername(normalized);
    if (localUser) {
      return { ...localUser, _isLocal: true };
    }
    return null;
  } catch (error) {
    console.error("Error finding user by username:", error);
    return null;
  }
}
async function findUserByEmail(email) {
  try {
    const normalized = (email || "").toString().toLowerCase().trim();
    const emailHash = hash(normalized);
    const mongoUser = await UserRegistration.findOne({ emailHash: emailHash });
    if (mongoUser) {
      if (mongoUser.isLocked) {
        return { _isLocked: true, lockUntil: mongoUser.lockUntil };
      }
      return mongoUser;
    }
    const localUser = await localUserStore.findByEmail(normalized);
    if (localUser) {
      return { ...localUser, _isLocal: true };
    }
    return null;
  } catch (error) {
    console.error("Error finding user by email:", error);
    return null;
  }
}

async function findUserByPhone(phone) {
  try {
    const normalized = (phone || "").toString().trim();
    const phoneHash = hash(normalized);
    const mongoUser = await UserRegistration.findOne({ phoneHash: phoneHash });
    if (mongoUser) {
      if (mongoUser.isLocked) {
        return { _isLocked: true, lockUntil: mongoUser.lockUntil };
      }
      return mongoUser;
    }
    const localUser = await localUserStore.findByPhone(normalized);
    if (localUser) {
      return { ...localUser, _isLocal: true };
    }
    return null;
  } catch (error) {
    console.error("Error finding user by phone:", error);
    return null;
  }
}

async function findUserByName(firstName, secondName) {
  try {
    const normalizedFirstName = (firstName || "").toString().toLowerCase().trim();
    const normalizedSecondName = (secondName || "").toString().toLowerCase().trim();

    const allUsers = await UserRegistration.find({}).lean();
    const mongoUser = allUsers.find(u => {
      const decrypted = decryptUser(u);
      return decrypted.firstName === normalizedFirstName && decrypted.secondName === normalizedSecondName;
    });
    if (mongoUser) {
      return { ...decryptUser(mongoUser), _isLocal: false };
    }
    const localUser = await localUserStore.findByName(normalizedFirstName, normalizedSecondName);
    if (localUser) {
      return { ...localUser, _isLocal: true };
    }
    return null;
  } catch (error) {
    console.error("Error finding user by name:", error);
    return null;
  }
}

async function getAllUsers(query = {}) {
  try {
    const [mongoUsers, localUsers] = await Promise.all([
      UserRegistration.find(query).lean().exec(),
      localUserStore.find(query),
    ]);

    const userMap = new Map();
    mongoUsers.forEach((u) => {
      const decrypted = decryptUser(u);
      const key = (decrypted.username || '').toLowerCase();
      if (key) {
        userMap.set(key, { ...decrypted, _isLocal: false });
      }
    });

    localUsers.forEach((u) => {
      const decrypted = decryptUser(u);
      const key = (decrypted.username || '').toLowerCase();
      if (key && !userMap.has(key)) {
        userMap.set(key, { ...decrypted, _isLocal: true });
      }
    });

    const allUsers = Array.from(userMap.values());

    return allUsers;
  } catch (error) {
    console.error("Error getting all users:", error);
    return [];
  }
}

const UserPointsSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  points: { type: Number, default: 0 },
  transactions: [
    {
      type: {
        type: String,
        enum: ["earned", "spent", "deducted"],
        required: true,
      },
      amount: { type: Number, required: true },
      description: String,
      formLink: String,
      itemId: String,
      timestamp: { type: Date, default: Date.now },
    },
  ],
});

const UserPoints = mongoose.model("UserPoints", UserPointsSchema);

const GiftShopItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  cost: { type: Number, required: true },
  stock: { type: Number, default: -1 },
  purchaseLimit: { type: Number, default: -1 },
  image: String,
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
});

const GiftShopItem = mongoose.model("GiftShopItem", GiftShopItemSchema);

const GiftPurchaseSchema = new mongoose.Schema({
  username: { type: String, required: true, lowercase: true },
  grade: { type: String, default: null },
  itemId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "GiftShopItem",
    required: true,
  },
  itemName: { type: String, required: true },
  cost: { type: Number, required: true },
  status: {
    type: String,
    enum: ["pending", "accepted", "declined"],
    default: "pending",
  },
  declineReason: String,
  reviewedBy: String,
  reviewedAt: Date,
  purchasedAt: { type: Date, default: Date.now },
  pointsRefunded: { type: Boolean, default: false },
  receivedConfirmed: { type: Boolean, default: false },
  receivedConfirmedAt: Date,
  receivedConfirmedBy: String,
});

const GiftPurchase = mongoose.model("GiftPurchase", GiftPurchaseSchema);

const LeaderboardAccessSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  role: { type: String, enum: ROLE_TYPES, required: true },
  hasLeaderboardAccess: { type: Boolean, default: false },
  grantedBy: String,
  grantedAt: { type: Date, default: Date.now },
});

const LeaderboardAccess = mongoose.model(
  "LeaderboardAccess",
  LeaderboardAccessSchema
);

const ActiveSessionSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    lowercase: true,
    index: true,
  },
  sessionId: {
    type: String,
    required: true,
    unique: true,
  },
  userAgent: String,
  ip: String,
  loginTime: {
    type: Date,
    default: Date.now,
  },
  lastSeenAt: {
    type: Date,
    default: Date.now,
  },
  currentPath: { type: String, default: "" },
  currentMethod: { type: String, default: "" },
  expiresAt: {
    type: Date,
    required: true,
    index: true,
  },
});

const ActiveSession = mongoose.model("ActiveSession", ActiveSessionSchema);

const GuestSessionSchema = new mongoose.Schema({
  guestId: { type: String, required: true, index: true },
  ip: String,
  userAgent: String,
  currentPath: { type: String, default: "" },
  currentMethod: { type: String, default: "" },
  firstSeenAt: { type: Date, default: Date.now },
  lastSeenAt: { type: Date, default: Date.now },
}, { timestamps: true });
GuestSessionSchema.index({ lastSeenAt: 1 });
const GuestSession = mongoose.model("GuestSession", GuestSessionSchema);

async function destroyStoredSession(sessionStore, sessionId) {
  if (
    !sessionStore ||
    typeof sessionStore.destroy !== "function" ||
    !sessionId
  ) {
    return;
  }
  await new Promise((resolve) => {
    sessionStore.destroy(sessionId, (err) => {
      if (err) {
        console.error(`[SESSION DESTROY ERROR] ${sessionId}:`, err.message);
      }
      resolve();
    });
  });
}

async function connectToDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    await sendWebhook("DATABASE", {
      content: `[DATABASE] Connected to database`,
    });
    await sendWebhook("SYSTEM", {
      embeds: [
        {
          title: "🔌 Database Connection",
          color: 0x10b981,
          fields: [
            { name: "Status", value: "✅ Connected", inline: true },
            {
              name: "Connection Time",
              value: new Date().toLocaleString(),
              inline: true,
            },
            {
              name: "Environment",
              value: process.env.NODE_ENV || "development",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
  } catch (connectionError) {
    console.error(`[DATABASE] Connection failed:`, connectionError.message);
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Database Connection Failed",
          color: 0xe74c3c,
          fields: [
            { name: "Error", value: connectionError.message },
            { name: "Time", value: new Date().toLocaleString() },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    process.exit(1);
  }
}

connectToDatabase();

function normalizeGradeSlug(value) {
  if (!value) return null;
  const normalized = value
    .toString()
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, "");
  if (GRADE_SLUGS.includes(normalized)) {
    return normalized;
  }
  if (GRADE_ALIAS[normalized]) {
    return GRADE_ALIAS[normalized];
  }
  return null;
}

function validateUsername(username) {
  if (!username || typeof username !== "string") return false;
  if (username.length < 3 || username.length > 30) return false;
  const arabicEnglishPattern = /^[\u0600-\u06FF\u0750-\u077F\w_-]+$/;
  return arabicEnglishPattern.test(username);
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePhone(phone) {
  const phoneRegex = /^(\+20|0)?1[0-9]{9}$/;
  const cleaned = phone.replace(/[\s-]/g, "");
  return phoneRegex.test(cleaned);
}

function parseUsers() {
  const registry = {};
  const userData = process.env.USERS || "";
  const lines = userData
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  lines.forEach((line) => {
    const parts = line.split(":").map((part) => part.trim());
    if (parts.length < 3) return;

    const username = parts[0];
    const password = parts[1];
    let roleCandidate = (parts[2] || "").toLowerCase();
    let pointer = 3;

    const record = {
      password,
      role: "student",
      grade: null,
      gradeAccess: [],
      allowedPages: ["all"],
      originalUsername: username,
      hasLeaderboardAccess: false,
    };

    if (ROLE_TYPES.includes(roleCandidate)) {
      record.role = roleCandidate;
      if (roleCandidate === "leadadmin") {
        record.hasLeaderboardAccess = true;
      }
    } else {
      const derivedGrade = normalizeGradeSlug(roleCandidate);
      if (derivedGrade) {
        record.role = "student";
        record.grade = derivedGrade;
        record.gradeAccess = [derivedGrade];
      } else {
        record.role = "student";
      }
    }

    if (
      (record.role === "student" || record.role === "teacher") &&
      parts[pointer]
    ) {
      const gradeSegment = parts[pointer];
      pointer += 1;

      if (record.role === "student") {
        const gradeSlug = normalizeGradeSlug(gradeSegment);
        if (gradeSlug) {
          record.grade = gradeSlug;
          record.gradeAccess = [gradeSlug];
        }
      } else {
        record.gradeAccess = gradeSegment
          .split("|")
          .map((g) => normalizeGradeSlug(g))
          .filter(Boolean);
      }
    }

    if (
      (record.role === "admin" || record.role === "leadadmin") &&
      record.gradeAccess.length === 0
    ) {
      record.gradeAccess = [...GRADE_SLUGS];
    }

    if (record.role === "teacher" && record.gradeAccess.length === 0) {
      record.gradeAccess = [...GRADE_SLUGS];
    }

    const allowedPages = parts
      .slice(pointer)
      .map((p) => p.trim())
      .filter(Boolean);
    if (allowedPages.length > 0) {
      record.allowedPages = allowedPages;
    } else if (record.role === "admin" && record.role !== "leadadmin") {
      record.allowedPages = ["form-editor", "user-approver", "gift-approver"];
    }

    if (record.role === "admin" && allowedPages.includes("leaderboard")) {
      record.hasLeaderboardAccess = true;
    }

    registry[username] = record;
    registry[username.toLowerCase()] = record;
  });

  return registry;
}

const users = parseUsers();

function getSessionUser(req) {
  if (!req.session || !req.session.username) return null;
  const envUser =
    users[req.session.username] || users[req.session.username.toLowerCase()];
  if (envUser) return envUser;
  if (req.session.role && req.session.role === "student") {
    return {
      originalUsername: req.session.username,
      role: req.session.role,
      grade: req.session.grade || null,
      gradeAccess:
        req.session.gradeAccess ||
        (req.session.grade ? [req.session.grade] : []),
      allowedPages: req.session.allowedPages || ["all"],
    };
  }
  return null;
}

function userHasGradeAccess(user, gradeSlug) {
  if (!user || !gradeSlug) return false;
  const normalized =
    gradeSlug === "all" ? "all" : normalizeGradeSlug(gradeSlug);
  if (!normalized) return false;

  if (user.role === "leadadmin" || user.role === "admin") {
    return true;
  }

  if (normalized === "all") {
    return true;
  }

  if (user.role === "teacher") {
    return user.gradeAccess && user.gradeAccess.includes(normalized);
  }

  if (user.role === "student") {
    const userGrade = user.grade || (user.gradeAccess && user.gradeAccess[0]);
    return normalizeGradeSlug(userGrade) === normalized;
  }

  return false;
}

function normalizeFormTarget(value) {
  if (!value) return "all";
  const normalized = value.toString().trim().toLowerCase();
  if (FORM_TARGETS.includes(normalized)) {
    return normalized;
  }
  const gradeSlug = normalizeGradeSlug(value);
  return gradeSlug || "all";
}

function getDefaultLandingPath(user) {
  if (!user) return "/login";
  if (user.role === "leadadmin" || user.role === "admin") {
    return "/admin/form-panel";
  }
  if (user.role === "teacher") {
    return "/admin/form-panel";
  }
  if (user.role === "student" && user.grade) {
    return `/grades/${user.grade}`;
  }
  return "/login";
}

function canUserAccessForm(user, form) {
  if (!form) return false;
  const allowedGrades = Array.isArray(form.allowedGrades)
    ? form.allowedGrades.map((g) => normalizeGradeSlug(g)).filter(Boolean)
    : [];

  if (allowedGrades.length > 0) {
    if (!user) return false;
    if (user.role === "admin" || user.role === "leadadmin") return true;
    if (user.role === "teacher") {
      return (
        allowedGrades.includes("teachers") ||
        allowedGrades.includes(user.grade) ||
        allowedGrades.includes("all")
      );
    }

    return allowedGrades.includes(user.grade);
  }

  const target = normalizeFormTarget(form.targetGrade || "all");

  if (target === "all") {
    return !!user;
  }

  if (target === "teachers") {
    return (
      !!user &&
      (user.role === "teacher" ||
        user.role === "admin" ||
        user.role === "leadadmin")
    );
  }

  if (target === "admins") {
    return !!user && (user.role === "admin" || user.role === "leadadmin");
  }

  return userHasGradeAccess(user, target);
}

async function getBanRecord(username) {
  if (!username) return null;
  const record = await BannedUser.findOne({ usernameLower: username.toLowerCase() });
  if (!record) return null;
  if (record.expiresAt && record.expiresAt < new Date()) return null;
  return record;
}

async function hasLeaderboardAccess(username) {
  if (!username) return false;

  const user = users[username] || users[username.toLowerCase()];
  if (user) {
    if (user.role === "leadadmin") return true;
    if (user.role === "admin" && user.hasLeaderboardAccess) return true;
  }

  const accessRecord = await LeaderboardAccess.findOne({
    username: username.toLowerCase(),
    hasLeaderboardAccess: true,
  });

  return !!accessRecord;
}

function isApiRequest(req) {
  return req.path.startsWith("/api/");
}

async function respondWithSessionReset(req, res, message) {
  const finalizeResponse = () => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    if (isApiRequest(req)) {
      res.status(401).json({
        success: false,
        message: message || "انتهت الجلسة. يرجى تسجيل الدخول مرة أخرى.",
      });
    } else {
      res.redirect("/login");
    }
  };

  if (req.session) {
    await new Promise((resolve) => {
      req.session.destroy((err) => {
        if (err) {
          console.error("[SESSION DESTROY ERROR]", err.message);
        }
        resolve();
      });
    });
  }

  finalizeResponse();
}

async function handleInvalidActiveSession(req, res, reason, activeRecord) {
  await sendWebhook("SECURITY", {
    embeds: [
      {
        title: "🚫 Session Validation Failed",
        color: 0xe74c3c,
        fields: [
          {
            name: "Username",
            value: req.session.username || "Unknown",
            inline: true,
          },
          { name: "Path", value: req.path, inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
          { name: "Reason", value: reason, inline: false },
          {
            name: "Request Session ID",
            value: req.sessionID
              ? req.sessionID.substring(0, 20) + "..."
              : "Unknown",
            inline: true,
          },
          {
            name: "Active Session ID",
            value: activeRecord?.sessionId
              ? activeRecord.sessionId.substring(0, 20) + "..."
              : "None",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  await respondWithSessionReset(
    req,
    res,
    "تم تسجيل الدخول من جهاز آخر. الرجاء تسجيل الدخول مجدداً."
  );
}

async function validateActiveSessionOwnership(req, res) {
  if (!req.session?.username) {
    return true;
  }

  const normalizedUsername = req.session.username.toLowerCase();
  const activeRecord = await ActiveSession.findOne({
    username: normalizedUsername,
    expiresAt: { $gt: new Date() },
  });

  if (!activeRecord) {
    await handleInvalidActiveSession(
      req,
      res,
      "Active session record missing",
      null
    );
    return false;
  }

  if (activeRecord.sessionId !== req.sessionID) {
    await handleInvalidActiveSession(
      req,
      res,
      "Session mismatch detected",
      activeRecord
    );
    return false;
  }

  const isPageView = !req.path.startsWith("/api/");
  await ActiveSession.updateOne(
    { _id: activeRecord._id },
    {
      $set: {
        lastSeenAt: new Date(),
        ...(isPageView ? { currentPath: req.path || "", currentMethod: req.method || "" } : {}),
      },
    }
  );

  return true;
}

async function requireAuth(req, res, next) {
  if (!req.session || !req.session.isAuthenticated) {
    return res.redirect("/login?redirect=" + encodeURIComponent(req.originalUrl));
  }

  const sessionValid = await validateActiveSessionOwnership(req, res);
  if (!sessionValid) return;

  const user = getSessionUser(req);
  if (user && user.role === 'student') {
    const allowedPaths = [
      '/grades', '/form', '/api/suggestions', '/api/user-info',
      '/api/gift-shop', '/api/forms/active', '/api/grades',
      '/logout', '/gift-shop'
    ];

    const path = req.path;
    const isAllowed = allowedPaths.some((allowed) => path.startsWith(allowed)) ||
      path === '/' || path.match(/^\/grades\/[^\/]+$/);

    if (!isAllowed) {
      await sendWebhook('SECURITY', {
        embeds: [{
          title: '🚫 Unauthorized Student Access',
          color: 0xe74c3c,
          fields: [
            { name: 'Username', value: req.session.username, inline: true },
            { name: 'Path', value: path, inline: true },
            { name: 'Role', value: 'student', inline: true },
            { name: 'IP', value: req.ip || 'unknown', inline: true }
          ],
          timestamp: new Date().toISOString()
        }]
      });
      return res.status(403).sendFile(require('path').join(__dirname, 'views/403.html'));
    }
  }
  next();
}

function requireRole(allowedRoles) {
  return async (req, res, next) => {
    const rbacMiddleware = rbacRequireRole(allowedRoles || []);
    return rbacMiddleware(req, res, async (err) => {
      if (err) {
        await sendWebhook('SECURITY', {
          embeds: [{
            title: '🚫 RBAC Access Denied',
            color: 0xe74c3c,
            fields: [
              { name: 'Username', value: req.session.username || 'Unknown', inline: true },
              { name: 'IP', value: req.ip || 'unknown', inline: true },
              { name: 'Path', value: req.path, inline: true },
              { name: 'Required Roles', value: allowedRoles ? allowedRoles.join(', ') : 'any', inline: true }
            ],
            timestamp: new Date().toISOString()
          }]
        });
        return;
      }
      next();
    });
  };
}

function hasSpecialRole(user, roleName) {
  if (!user) return false;
  if (user.role === "leadadmin") return true;
  if (
    user.role === "admin" &&
    user.allowedPages &&
    user.allowedPages.includes(roleName)
  ) {
    return true;
  }
  return false;
}

function requireSpecialRole(roleName) {
  return async (req, res, next) => {
    if (!req.session.isAuthenticated) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🔒 Special Role Check Failed",
            color: 0xf59e0b,
            fields: [
              { name: "Required Role", value: roleName, inline: true },
              { name: "Path", value: req.path, inline: true },
              { name: "Status", value: "Not authenticated", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(401).json({ error: "Authentication required" });
    }
    const user = getSessionUser(req);
    if (!user) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Invalid User for Special Role",
            color: 0xe74c3c,
            fields: [
              {
                name: "Username",
                value: req.session.username || "none",
                inline: true,
              },
              { name: "Required Role", value: roleName, inline: true },
              { name: "Path", value: req.path, inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).json({ error: "Access denied" });
    }
    if (hasSpecialRole(user, roleName) || user.role === "leadadmin") {
      return next();
    }
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Missing Special Role",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "User Role", value: user.role, inline: true },
            { name: "Required Role", value: roleName, inline: true },
            {
              name: "User Allowed Pages",
              value: user.allowedPages?.join(", ") || "none",
              inline: false,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res
      .status(403)
      .json({ error: "Access denied. You need the " + roleName + " role." });
  };
}

function sanitizeQuestions(rawQuestions = []) {
  if (!Array.isArray(rawQuestions) || rawQuestions.length === 0) {
    throw new Error("يجب إضافة سؤال واحد على الأقل.");
  }

  return rawQuestions.map((question, index) => {
    const questionText = (question.questionText || "").trim();
    const questionType =
      question.questionType === "true-false" ? "true-false" : "multiple-choice";
    const required = question.required === false ? false : true;
    const points = typeof question.points === "number" ? question.points : 10;

    if (!questionText) {
      throw new Error(`نص السؤال رقم ${index + 1} غير موجود.`);
    }

    let options = [];
    let correctAnswer = question.correctAnswer;
    let correctAnswerIndex =
      typeof question.correctAnswerIndex === "number"
        ? question.correctAnswerIndex
        : undefined;

    if (questionType === "true-false") {
      options = ["True", "False"];
      const normalizedAnswer = (question.correctAnswer || "")
        .toString()
        .toLowerCase();
      correctAnswer =
        normalizedAnswer === "true" || normalizedAnswer === "1"
          ? "True"
          : "False";
      correctAnswerIndex = correctAnswer === "True" ? 0 : 1;
    } else {
      options = (question.options || [])
        .map((opt) => (opt || "").trim())
        .filter(Boolean);
      if (options.length < 2) {
        throw new Error(`السؤال رقم ${index + 1} يحتاج إلى خيارين على الأقل.`);
      }

      if (typeof correctAnswerIndex !== "number") {
        const parsedAnswer = parseInt(question.correctAnswer, 10);
        if (!Number.isNaN(parsedAnswer)) {
          correctAnswerIndex = parsedAnswer;
        }
      }

      if (
        correctAnswerIndex === undefined ||
        correctAnswerIndex < 0 ||
        correctAnswerIndex >= options.length
      ) {
        throw new Error(`اختر إجابة صحيحة للسؤال رقم ${index + 1}.`);
      }

      correctAnswer = correctAnswerIndex;
    }

    return {
      questionText,
      questionType,
      options,
      correctAnswer,
      correctAnswerIndex,
      required,
      points,
    };
  });
}

function parseExpiryDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error("تاريخ انتهاء غير صالح");
  }
  return date;
}

function serializeForm(form) {
  return {
    _id: form._id ? String(form._id) : undefined,
    topic: form.topic,
    link: form.link,
    expiry: form.expiry,
    description: form.description,
    targetGrade: form.targetGrade,
    allowedGrades: Array.isArray(form.allowedGrades) ? form.allowedGrades : [],
    status: form.status,
    allowRetake: form.allowRetake,
    createdBy: form.createdBy,
    updatedBy: form.updatedBy,
    updatedAt: form.updatedAt,
    questions: form.questions,
  };
}

app.get("/", async (req, res) => {
  sendWebhook("USER", {
    embeds: [
      {
        title: "🏠 Homepage Accessed",
        color: 0x3498db,
        fields: [
          { name: "Path", value: "/", inline: true },
          { name: "Method", value: "GET", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "User Agent",
            value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
            inline: false,
          },
          {
            name: "Authenticated",
            value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
            inline: true,
          },
          {
            name: "Username",
            value: req.session.username || "Guest",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
  res.sendFile(path.join(__dirname, "views", "home.html"));
});

app.get("/login", async (req, res) => {
  await sendWebhook("USER", {
    embeds: [
      {
        title: "🔐 Login Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Path", value: "/login", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "User Agent",
            value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
            inline: false,
          },
          {
            name: "Already Authenticated",
            value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
            inline: true,
          },
          {
            name: "Current User",
            value: req.session.username || "None",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
  if (req.session.isAuthenticated) {
    const user = getSessionUser(req);
    if (user) {
      return res.redirect(getDefaultLandingPath(user));
    }
  }
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.get("/register", async (req, res) => {
  await sendWebhook("USER", {
    embeds: [
      {
        title: "📝 Registration Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Path", value: "/register", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "User Agent",
            value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
            inline: false,
          },
          {
            name: "Already Authenticated",
            value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
  if (req.session.isAuthenticated) {
    const user = getSessionUser(req);
    if (user) {
      return res.redirect(getDefaultLandingPath(user));
    }
  }
  res.sendFile(path.join(__dirname, "views", "register.html"));
});

app.get("/reset-password/:token", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "reset-password.html"));
});

app.get("/api/reset-password/validate/:token", async (req, res) => {
  try {
    const token = (req.params.token || "").trim();
    if (!token) {
      return res.json({ valid: false, message: "الرابط غير صالح" });
    }

    const localReset = await userRegistrationsStore.findResetLinkByToken(token);
    if (localReset && localReset.user && localReset.link) {
      return res.json({
        valid: true,
        username: localReset.user.username,
        requiresVerification: !localReset.link.verifiedAt,
      });
    }

    const now = new Date();
    const mongoUser = await UserRegistration.findOne({
      passwordResetLinks: {
        $elemMatch: {
          token,
          usedAt: null,
          supersededAt: null,
          expiresAt: { $gt: now },
        },
      },
    }).lean();

    if (mongoUser) {
      const link = (mongoUser.passwordResetLinks || []).find(
        (l) => l && l.token === token
      );
      return res.json({
        valid: true,
        username: mongoUser.username,
        requiresVerification: !(link && link.verifiedAt),
      });
    }

    return res.json({
      valid: false,
      message: "هذا الرابط غير صحيح أو منتهي الصلاحية",
    });
  } catch (err) {
    return res.json({ valid: false, message: "حدث خطأ أثناء التحقق من الرابط" });
  }
});

app.post("/api/verify-2fa", async (req, res) => {
  const { code } = req.body;
  const pending = req.session.pending2FA;

  if (!pending) {
    return res.status(401).json({ success: false, message: "لا توجد جلسة تحقق نشطة." });
  }

  if (new Date() > new Date(pending.expiresAt)) {
    delete req.session.pending2FA;
    return res.status(401).json({ success: false, message: "انتهت صلاحية الرمز. يرجى تسجيل الدخول مرة أخرى." });
  }

  if (code !== pending.code) {
    trackFailedAttempt(req.ip);
    return res.status(401).json({ success: false, message: "رمز التحقق غير صحيح." });
  }

  req.session.isAuthenticated = true;
  req.session.username = pending.username;
  req.session.role = pending.userData.role;
  req.session.allowedPages = pending.userData.allowedPages;
  req.session.grade = pending.userData.grade;
  req.session.gradeAccess = pending.userData.gradeAccess;
  req.session.hasLeaderboardAccess = pending.userData.hasLeaderboardAccess;
  req.session.displayName = pending.username;

  const { generateAccessToken, generateRefreshToken } = require('./src/utils/auth');
  const accessToken = generateAccessToken({
    _id: pending.id || pending.username, // Handle both mongo and local
    username: pending.username,
    role: pending.userData.role,
    grade: pending.userData.grade
  });
  const refreshToken = generateRefreshToken({ _id: pending.id || pending.username });

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  delete req.session.pending2FA;
  clearFailedAttempts(req.ip);

  await sendWebhook("SECURITY", {
    embeds: [
      {
        title: "✅ 2FA Verification Successful",
        color: 0x2ecc71,
        fields: [
          { name: "User", value: pending.username, inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true }
        ],
        timestamp: new Date().toISOString()
      }
    ]
  });

  res.json({ success: true, message: "تم التحقق بنجاح." });
});

app.post("/login", secureLoginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (
    !username ||
    !password ||
    typeof username !== "string" ||
    typeof password !== "string"
  ) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "❌ Invalid Login Data Format",
          color: 0xe74c3c,
          fields: [
            {
              name: "Username Provided",
              value: username ? "Yes" : "No",
              inline: true,
            },
            {
              name: "Password Provided",
              value: password ? "Yes" : "No",
              inline: true,
            },
            { name: "Username Type", value: typeof username, inline: true },
            { name: "Password Type", value: typeof password, inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    trackFailedAttempt(req.ip);
    return res
      .status(400)
      .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
  }

  const userAgent = req.headers["user-agent"] || "unknown";
  const normalizedUsername = username.toLowerCase().trim();

  await sendWebhook("USER", {
    embeds: [
      {
        title: "🔐 Login Attempt Initiated",
        color: 0xf59e0b,
        fields: [
          { name: "Username", value: username, inline: true },
          {
            name: "Normalized Username",
            value: normalizedUsername,
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "User Agent",
            value: userAgent.substring(0, 100),
            inline: false,
          },
          {
            name: "Timestamp",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  const isEmail = username.includes("@");
  const isPhone = /^01\d{9}$/.test(username.replace(/\D/g, ""));

  let user = users[username] || users[normalizedUsername];
  let isAdminUser = !!user;

  if (!user) {
    try {
      let registeredUser = null;
      if (isEmail) {
        registeredUser = await findUserByEmail(username);
      } else if (isPhone) {
        const cleanedPhone = username.replace(/\D/g, "");
        registeredUser = await findUserByPhone(cleanedPhone);
      } else {
        registeredUser = await findUserByUsername(normalizedUsername);
      }

      if (registeredUser) {
        if (registeredUser._isLocked) {
          const waitTime = Math.ceil((registeredUser.lockUntil - Date.now()) / 60000);
          return res.status(423).json({
            success: false,
            message: `تم قفل الحساب مؤقتاً بسبب محاولات دخول خاطئة متعددة. يرجى المحاولة مرة أخرى بعد ${waitTime} دقيقة.`
          });
        }

        if (registeredUser.approvalStatus === "pending") {
          const passwordMatch = await comparePassword(
            password,
            registeredUser.password
          );
          if (!passwordMatch) {
            await sendWebhook("SECURITY", {
              embeds: [
                {
                  title: "❌ Login Attempt - Wrong Password (Pending Account)",
                  color: 0xe74c3c,
                  fields: [
                    { name: "Username", value: username },
                    { name: "Error", value: "Wrong password" },
                    {
                      name: "Account Status",
                      value: "Pending approval",
                      inline: true,
                    },
                    {
                      name: "Time",
                      value: moment()
                        .tz("Africa/Cairo")
                        .format("YYYY-MM-DD HH:mm:ss"),
                    },
                    { name: "IP", value: req.ip || "unknown", inline: true },
                  ],
                  timestamp: new Date().toISOString(),
                },
              ],
            });
            trackFailedAttempt(req.ip);
            return res
              .status(401)
              .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
          }

          await sendWebhook("SECURITY", {
            embeds: [
              {
                title: "⚠️ Login Attempt - Pending Account",
                color: 0xf39c12,
                fields: [
                  { name: "Username", value: username },
                  { name: "Status", value: "Pending approval" },
                  {
                    name: "Name",
                    value: `${registeredUser.firstName} ${registeredUser.secondName}`,
                    inline: true,
                  },
                  { name: "Grade", value: registeredUser.grade, inline: true },
                  {
                    name: "Time",
                    value: moment()
                      .tz("Africa/Cairo")
                      .format("YYYY-MM-DD HH:mm:ss"),
                  },
                  { name: "IP", value: req.ip || "unknown", inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          return res.status(403).json({
            success: false,
            message:
              "حسابك في انتظار الموافقة. يرجى الانتظار حتى تتم مراجعة طلبك.",
          });
        }
        if (registeredUser.approvalStatus === "declined") {
          const passwordMatch = await comparePassword(
            password,
            registeredUser.password
          );
          if (!passwordMatch) {
            await sendWebhook("SECURITY", {
              embeds: [
                {
                  title: "❌ Login Attempt - Wrong Password (Declined Account)",
                  color: 0xe74c3c,
                  fields: [
                    { name: "Username", value: username },
                    { name: "Error", value: "Wrong password" },
                    { name: "Account Status", value: "Declined", inline: true },
                    {
                      name: "Time",
                      value: moment()
                        .tz("Africa/Cairo")
                        .format("YYYY-MM-DD HH:mm:ss"),
                    },
                    { name: "IP", value: req.ip || "unknown", inline: true },
                  ],
                  timestamp: new Date().toISOString(),
                },
              ],
            });
            trackFailedAttempt(req.ip);
            return res
              .status(401)
              .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
          }

          await sendWebhook("SECURITY", {
            embeds: [
              {
                title: "🚫 Login Attempt - Declined Account",
                color: 0xe74c3c,
                fields: [
                  { name: "Username", value: username },
                  { name: "Status", value: "Account declined" },
                  {
                    name: "Decline Reason",
                    value: registeredUser.reviewReason || "No reason",
                    inline: false,
                  },
                  {
                    name: "Declined By",
                    value: registeredUser.reviewedBy || "System",
                    inline: true,
                  },
                  {
                    name: "Time",
                    value: moment()
                      .tz("Africa/Cairo")
                      .format("YYYY-MM-DD HH:mm:ss"),
                  },
                  { name: "IP", value: req.ip || "unknown", inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          return res.status(403).json({
            success: false,
            message: "تم رفض طلب التسجيل الخاص بك. يرجى التواصل مع الإدارة.",
          });
        }

        const passwordMatch = await comparePassword(
          password,
          registeredUser.password
        );
        if (passwordMatch) {
          if (typeof registeredUser.updateOne === "function") {
            await registeredUser.updateOne({
              $set: { loginAttempts: 0 },
              $unset: { lockUntil: 1 },
            });
          } else if (!registeredUser._isLocal && registeredUser._id) {
            try {
              await UserRegistration.updateOne(
                { _id: registeredUser._id },
                { $set: { loginAttempts: 0 }, $unset: { lockUntil: 1 } }
              );
            } catch (err) {
              console.error("Failed to reset mongo loginAttempts/lockUntil:", err);
            }
          }
          if (
            registeredUser.verificationCode &&
            !registeredUser.verificationCodeVerified
          ) {
            const { verificationCode } = req.body;
            if (!verificationCode || verificationCode.length !== 6) {
              await sendWebhook("SECURITY", {
                embeds: [
                  {
                    title: "⚠️ Login Attempt - Invalid Verification Format",
                    color: 0xf39c12,
                    fields: [
                      { name: "Username", value: username },
                      {
                        name: "Error",
                        value: "Invalid verification code format",
                      },
                      {
                        name: "Code Provided",
                        value: verificationCode || "None",
                        inline: true,
                      },
                      {
                        name: "Code Length",
                        value: verificationCode?.length || 0,
                        inline: true,
                      },
                      {
                        name: "Time",
                        value: moment()
                          .tz("Africa/Cairo")
                          .format("YYYY-MM-DD HH:mm:ss"),
                      },
                      { name: "IP", value: req.ip || "unknown", inline: true },
                    ],
                    timestamp: new Date().toISOString(),
                  },
                ],
              });
              return res.status(403).json({
                success: false,
                requiresVerification: true,
                message: "البيانات المدخلة غير صحيحة",
              });
            }
            if (verificationCode !== registeredUser.verificationCode) {
              await sendWebhook("SECURITY", {
                embeds: [
                  {
                    title: "⚠️ Login Attempt - Wrong Verification Code",
                    color: 0xf39c12,
                    fields: [
                      { name: "Username", value: username },
                      { name: "Error", value: "Wrong verification code" },
                      {
                        name: "Expected Code",
                        value: registeredUser.verificationCode,
                        inline: true,
                      },
                      {
                        name: "Provided Code",
                        value: verificationCode,
                        inline: true,
                      },
                      {
                        name: "Time",
                        value: moment()
                          .tz("Africa/Cairo")
                          .format("YYYY-MM-DD HH:mm:ss"),
                      },
                      { name: "IP", value: req.ip || "unknown", inline: true },
                    ],
                    timestamp: new Date().toISOString(),
                  },
                ],
              });
              return res.status(403).json({
                success: false,
                requiresVerification: true,
                message: "البيانات المدخلة غير صحيحة",
              });
            }
            registeredUser.verificationCodeVerified = true;
            if (registeredUser._isLocal) {
              try {
                await localUserStore.adminUpdate(
                  registeredUser._id,
                  { verificationCodeVerified: true },
                  "carl"
                );
              } catch (err) {
                console.error("Failed to update local user verification:", err);
              }
            } else if (registeredUser && registeredUser._id) {
              try {
                await UserRegistration.updateOne(
                  { _id: registeredUser._id },
                  { $set: { verificationCodeVerified: true } }
                );
              } catch (err) {
                console.error("Failed to update mongo user verification:", err);
              }
            }

            await sendWebhook("USER", {
              embeds: [
                {
                  title: "✅ Verification Code Successfully Verified",
                  color: 0x10b981,
                  fields: [
                    { name: "Username", value: username, inline: true },
                    {
                      name: "Verification Code",
                      value: verificationCode,
                      inline: true,
                    },
                    {
                      name: "Verification Date",
                      value: new Date().toLocaleString(),
                      inline: true,
                    },
                    { name: "IP", value: req.ip || "unknown", inline: true },
                  ],
                  timestamp: new Date().toISOString(),
                },
              ],
            });
          }

          const derivedRole = registeredUser.role || "student";
          const gradeAccess =
            derivedRole === "admin" || derivedRole === "leadadmin"
              ? GRADE_SLUGS
              : [registeredUser.grade];

          let allowedPages = [];
          if (derivedRole === "admin" || derivedRole === "leadadmin") {
            const envUser =
              users[registeredUser.username] ||
              users[registeredUser.username.toLowerCase()];
            if (envUser && envUser.allowedPages) {
              allowedPages = envUser.allowedPages;
            } else {
              allowedPages = ["form-editor", "user-approver", "gift-approver"];
            }
          }

          registeredUser.lastLoginAt = new Date();
          if (registeredUser._isLocal) {
            try {
              await localUserStore.adminUpdate(
                registeredUser._id,
                { lastLoginAt: registeredUser.lastLoginAt },
                "carl"
              );
            } catch (err) {
              console.error("Failed to update local user lastLoginAt:", err);
            }
          } else if (registeredUser && registeredUser._id) {
            try {
              await UserRegistration.updateOne(
                { _id: registeredUser._id },
                { $set: { lastLoginAt: registeredUser.lastLoginAt } }
              );
            } catch (err) {
              console.error("Failed to update mongo user lastLoginAt:", err);
            }
          }

          user = {
            originalUsername: registeredUser.username,
            role: derivedRole,
            grade: registeredUser.grade,
            gradeAccess,
            allowedPages: allowedPages,
            hasLeaderboardAccess: await hasLeaderboardAccess(
              registeredUser.username
            ),
          };
        } else {
          await sendWebhook("SECURITY", {
            embeds: [
              {
                title: "❌ Login Attempt - Wrong Password",
                color: 0xe74c3c,
                fields: [
                  { name: "Username", value: username },
                  { name: "Error", value: "Wrong password" },
                  {
                    name: "Account Status",
                    value: registeredUser.approvalStatus,
                    inline: true,
                  },
                  { name: "User Type", value: "Registered User", inline: true },
                  {
                    name: "Time",
                    value: moment()
                      .tz("Africa/Cairo")
                      .format("YYYY-MM-DD HH:mm:ss"),
                  },
                  { name: "IP", value: req.ip || "unknown", inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          if (typeof registeredUser.incLoginAttempts === "function") {
            await registeredUser.incLoginAttempts();
          }
          trackFailedAttempt(req.ip);
          return res
            .status(401)
            .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
        }
      } else {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "❌ Login Attempt - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Username", value: username },
                { name: "Error", value: "User not found" },
                {
                  name: "Search Type",
                  value: isEmail ? "Email" : isPhone ? "Phone" : "Username",
                  inline: true,
                },
                {
                  name: "Time",
                  value: moment()
                    .tz("Africa/Cairo")
                    .format("YYYY-MM-DD HH:mm:ss"),
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        trackFailedAttempt(req.ip);
        return res
          .status(401)
          .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
      }
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Login Error - Database Query Failed",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "فشل التحقق من البيانات" });
    }
  }

  if (!user) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "❌ Login Attempt - Invalid User Object",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: username },
            { name: "Error", value: "Invalid user object" },
            {
              name: "User Type",
              value: isAdminUser ? "Admin User" : "Registered User",
              inline: true,
            },
            {
              name: "Time",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    trackFailedAttempt(req.ip);
    return res
      .status(401)
      .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
  }

  try {
    const banRecord = await getBanRecord(username);
    if (
      banRecord &&
      (banRecord.banType === "login" || banRecord.banType === "all")
    ) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Login Attempt - Banned User",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username },
              { name: "Ban Type", value: banRecord.banType },
              { name: "Reason", value: banRecord.reason || "No reason" },
              {
                name: "Banned By",
                value: banRecord.createdBy || "System",
                inline: true,
              },
              {
                name: "Ban Date",
                value: banRecord.createdAt.toLocaleString(),
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      let banMessage = "تم حظر هذا المستخدم من تسجيل الدخول.";
      if (banRecord.reason && banRecord.reason.trim()) {
        banMessage = `تم حظرك من تسجيل الدخول. السبب: ${banRecord.reason}`;
      }
      return res.status(403).json({
        success: false,
        message: banMessage,
      });
    }
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "⚠️ Ban Check Error",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: username },
            { name: "Error", value: error.message },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res
      .status(500)
      .json({ success: false, message: "فشل التحقق من الصلاحيات" });
  }

  if (isAdminUser) {
    const passwordMatch = await comparePassword(password, user.password || "");

    if (!passwordMatch) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "❌ Admin Login Attempt - Wrong Password",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username },
              { name: "User Role", value: user.role, inline: true },
              {
                name: "Password Hash Type",
                value: user.password?.startsWith("$2") ? "BCrypt" : "Plain",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      trackFailedAttempt(req.ip);
      return res
        .status(401)
        .json({ success: false, message: "البيانات المدخلة غير صحيحة" });
    }
  }

  if (user.twoFactorEnabled) {
    const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 5 * 60 * 1000);

    req.session.pending2FA = {
      username: user.originalUsername || username,
      code: twoFactorCode,
      expiresAt: expiry,
      userData: {
        role: user.role,
        allowedPages: user.allowedPages,
        grade: user.grade,
        gradeAccess: user.gradeAccess,
        hasLeaderboardAccess: user.hasLeaderboardAccess
      }
    };

    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🔐 2FA Code Generated",
          color: 0x3498db,
          fields: [
            { name: "User", value: username, inline: true },
            { name: "Code", value: `**${twoFactorCode}**`, inline: true },
            { name: "Expires", value: expiry.toLocaleTimeString(), inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true }
          ],
          timestamp: new Date().toISOString()
        }
      ]
    });

    return res.json({
      success: true,
      requires2FA: true,
      message: "يرجى إدخال رمز التحقق المكون من 6 أرقام."
    });
  }

  req.session.isAuthenticated = true;
  req.session.username = user.originalUsername || username;
  req.session.role = user.role;
  req.session.allowedPages = user.allowedPages;
  req.session.grade = user.grade || null;
  req.session.gradeAccess = user.gradeAccess || [];
  req.session.hasLeaderboardAccess = user.hasLeaderboardAccess || false;

  const accessToken = generateAccessToken({
    _id: user._id || (user.originalUsername || username),
    username: user.originalUsername || username,
    role: user.role,
    grade: user.grade
  });
  const refreshToken = generateRefreshToken({ _id: user._id || (user.originalUsername || username) });

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  clearFailedAttempts(req.ip);

  req.session.displayName = user.originalUsername || username;

  const parser = new UAParser();
  const deviceInfo = parser.setUA(userAgent).getResult();
  const device = `${deviceInfo.os.name || "Unknown OS"} (${deviceInfo.browser.name || "Unknown Browser"
    })`;

  const loginTime = moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss");

  const gradeLabel = user.grade
    ? GRADE_LABELS[user.grade]?.long || user.grade
    : "N/A";

  const sessionId = req.sessionID;
  const sessionExpiry = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000);

  let replacedSession = null;

  try {
    const previousSession = await ActiveSession.findOneAndUpdate(
      { username: normalizedUsername },
      {
        username: normalizedUsername,
        sessionId,
        userAgent: userAgent,
        ip: req.ip || "unknown",
        loginTime: new Date(),
        lastSeenAt: new Date(),
        expiresAt: sessionExpiry,
      },
      {
        upsert: true,
        new: false,
        setDefaultsOnInsert: true,
      }
    );

    if (
      previousSession &&
      previousSession.sessionId &&
      previousSession.sessionId !== sessionId
    ) {
      replacedSession = previousSession;
    }

    await ActiveSession.deleteMany({
      username: normalizedUsername,
      sessionId: { $ne: sessionId },
    });
  } catch (sessionError) {
    console.error("[SESSION ERROR]", sessionError.message);
  }

  if (replacedSession) {
    await sendWebhook("SECURITY", {
      content: `⚠️ **Multiple Login Detected - Logging Out Old Session**`,
      embeds: [
        {
          title: "User Logged In On Another Device - Force Logout",
          color: 0xf59e0b,
          fields: [
            {
              name: "Username",
              value: user.originalUsername || username,
              inline: true,
            },
            { name: "New Device", value: device, inline: true },
            {
              name: "Old Session IP",
              value: replacedSession.ip || "unknown",
              inline: true,
            },
            {
              name: "Old Session Device",
              value: replacedSession.userAgent?.substring(0, 100) || "Unknown",
              inline: false,
            },
            {
              name: "Old Session Login Time",
              value: replacedSession.loginTime
                ? replacedSession.loginTime.toLocaleString()
                : "Unknown",
              inline: true,
            },
            {
              name: "Old Session ID",
              value: replacedSession.sessionId
                ? replacedSession.sessionId.substring(0, 20) + "..."
                : "Unknown",
              inline: true,
            },
            {
              name: "Status",
              value: "Force logout old session, allowing new login",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    if (replacedSession.sessionId && replacedSession.sessionId !== sessionId) {
      await destroyStoredSession(req.sessionStore, replacedSession.sessionId);
    }
  }

  await sendWebhook("USER", {
    content: `🔐 **User Logged In Successfully**`,
    embeds: [
      {
        title: "✅ User Login",
        color: 0x1abc9c,
        fields: [
          {
            name: "Username",
            value: user.originalUsername || username,
            inline: true,
          },
          { name: "Role", value: user.role.toUpperCase(), inline: true },
          { name: "Grade", value: gradeLabel, inline: true },
          { name: "Device", value: device, inline: false },
          {
            name: "Browser",
            value: deviceInfo.browser.name || "Unknown",
            inline: true,
          },
          { name: "OS", value: deviceInfo.os.name || "Unknown", inline: true },
          { name: "Login Time", value: loginTime, inline: false },
          {
            name: "Grade Access",
            value: (user.gradeAccess || []).join(", ") || "None",
            inline: false,
          },
          {
            name: "Allowed Pages",
            value: (user.allowedPages || []).join(", ") || "All",
            inline: false,
          },
          {
            name: "Leaderboard Access",
            value: user.hasLeaderboardAccess ? "✅ Yes" : "❌ No",
            inline: false,
          },
          {
            name: "Session ID",
            value: sessionId.substring(0, 20) + "...",
            inline: false,
          },
          {
            name: "Session Expires",
            value: sessionExpiry.toLocaleString(),
            inline: false,
          },
          { name: "IP Address", value: req.ip || "unknown", inline: true },
          {
            name: "User Type",
            value: isAdminUser ? "Admin User" : "Registered User",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  const redirectParam = req.body.redirect;
  let redirectPath = getDefaultLandingPath(user);

  if (redirectParam && redirectParam.startsWith('/')) {
    // Basic safety check: ensure it returns to a valid local path
    // You might want to add more robust checks here (e.g. against open redirects)
    // For now, checks if user has access to this path would be ideal but complex to implement generic "canAccess(path)"
    // We will trust the path if it starts with / and assume middleware will catch unauthorized access on the target route itself.
    // However, we should avoid redirecting to /login again.
    if (redirectParam !== '/login' && redirectParam !== '/') {
      redirectPath = redirectParam;
    }
  }

  return res.status(200).json({
    success: true,
    message: "Authenticated",
    role: user.role,
    grade: user.grade || null,
    redirect: redirectPath,
    hasLeaderboardAccess: user.hasLeaderboardAccess || false,
  });
});

app.post("/logout", async (req, res) => {
  const username = req.session.username;
  const role = req.session.role;
  const grade = req.session.grade;
  const sessionId = req.sessionID;

  await sendWebhook("USER", {
    embeds: [
      {
        title: "🚪 Logout Request Received",
        color: 0x95a5a6,
        fields: [
          { name: "Username", value: username || "Unknown", inline: true },
          { name: "Role", value: role || "Unknown", inline: true },
          {
            name: "Session ID",
            value: sessionId?.substring(0, 20) + "..." || "Unknown",
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "Timestamp",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  try {
    if (username) {
      await ActiveSession.deleteMany({
        username: username.toLowerCase(),
      });
    }
  } catch (sessionError) {
    console.error("[SESSION CLEANUP ERROR]", sessionError.message);
  }

  const gradeLabel = grade ? GRADE_LABELS[grade]?.long || grade : "N/A";
  const logoutTime = moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss");

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  req.session.destroy(async (err) => {
    if (err) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Logout Session Destruction Error",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username || "Unknown", inline: true },
              { name: "Error", value: err.message, inline: false },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(500).json({ success: false, message: "Logout failed" });
    }

    await sendWebhook("USER", {
      content: `🚪 **User Logged Out**`,
      embeds: [
        {
          title: "User Logout",
          color: 0x95a5a6,
          fields: [
            { name: "Username", value: username || "Unknown", inline: true },
            {
              name: "Role",
              value: role ? role.toUpperCase() : "Unknown",
              inline: true,
            },
            { name: "Grade", value: gradeLabel, inline: true },
            { name: "Logout Time", value: logoutTime, inline: false },
            { name: "Session Cleared", value: "✅ Yes", inline: true },
            { name: "Active Session Removed", value: "✅ Yes", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json({ success: true });
  });
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many registration attempts. Try again later.",
  },
});

app.post("/api/register", registrationLimiter, spamBlocker, async (req, res) => {
  try {
    const { username, password, firstName, secondName, email, phone, grade } =
      req.body;

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📋 New Registration Attempt",
          color: 0x3498db,
          fields: [
            {
              name: "Username",
              value: username || "Not provided",
              inline: true,
            },
            { name: "Email", value: email || "Not provided", inline: true },
            { name: "Phone", value: phone || "Not provided", inline: true },
            { name: "Grade", value: grade || "Not provided", inline: true },
            {
              name: "Name",
              value:
                `${firstName || ""} ${secondName || ""}`.trim() ||
                "Not provided",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
            {
              name: "User Agent",
              value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
              inline: false,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    if (
      !username ||
      !password ||
      !firstName ||
      !secondName ||
      !email ||
      !phone ||
      !grade
    ) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Registration Failed - Missing Fields",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username ? "✅" : "❌", inline: true },
              { name: "Password", value: password ? "✅" : "❌", inline: true },
              {
                name: "First Name",
                value: firstName ? "✅" : "❌",
                inline: true,
              },
              {
                name: "Second Name",
                value: secondName ? "✅" : "❌",
                inline: true,
              },
              { name: "Email", value: email ? "✅" : "❌", inline: true },
              { name: "Phone", value: phone ? "✅" : "❌", inline: true },
              { name: "Grade", value: grade ? "✅" : "❌", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(400)
        .json({ success: false, message: "جميع الحقول مطلوبة" });
    }

    const existingUserByUsername = await findUserByUsername(username);
    if (existingUserByUsername) {
      return res.status(409).json({
        success: false,
        message: "Username already exists. Please choose another one.",
      });
    }

    const existingUserByEmail = await findUserByEmail(email);
    if (existingUserByEmail) {
      return res.status(409).json({
        success: false,
        message: "Email already exists. Please use another one.",
      });
    }

    const existingUserByPhone = await findUserByPhone(phone);
    if (existingUserByPhone) {
      return res.status(409).json({
        success: false,
        message: "Phone number already exists. Please use another one.",
      });
    }

    const existingUserByName = await findUserByName(firstName, secondName);
    if (existingUserByName) {
      return res.status(409).json({
        success: false,
        message: "A user with the same first and last name already exists.",
      });
    }

    if (!validateUsername(username)) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Registration Failed - Invalid Username",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: username, inline: true },
              {
                name: "Username Length",
                value: username.length.toString(),
                inline: true,
              },
              { name: "Validation Result", value: "Failed", inline: true },
              {
                name: "Expected",
                value:
                  "3-30 chars, Arabic/English letters, numbers, underscore, hyphen",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(400).json({
        success: false,
        message:
          "اسم المستخدم يجب أن يكون 3-30 حرف، ويمكن أن يحتوي على أحرف عربية وإنجليزية وأرقام وشرطة سفلية",
      });
    }

    const normalizedUsername = username.toLowerCase();
    const normalizedGrade = normalizeGradeSlug(grade);

    if (!normalizedGrade) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Registration Failed - Invalid Grade",
            color: 0xe74c3c,
            fields: [
              { name: "Grade Provided", value: grade, inline: true },
              { name: "Normalized Grade", value: "null", inline: true },
              {
                name: "Valid Grades",
                value: GRADE_SLUGS.join(", "),
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(400).json({ success: false, message: "الصف غير صالح" });
    }

    if (!validateEmail(email)) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Registration Failed - Invalid Email",
            color: 0xe74c3c,
            fields: [
              { name: "Email Provided", value: email, inline: true },
              { name: "Validation Result", value: "Failed", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(400)
        .json({ success: false, message: "البريد الإلكتروني غير صالح" });
    }

    if (!validatePhone(phone)) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Registration Failed - Invalid Phone",
            color: 0xe74c3c,
            fields: [
              { name: "Phone Provided", value: phone, inline: true },
              {
                name: "Cleaned Phone",
                value: phone.replace(/[\s-]/g, ""),
                inline: true,
              },
              { name: "Validation Result", value: "Failed", inline: true },
              {
                name: "Expected Format",
                value: "Egyptian phone number (+20 or 0 followed by 11 digits)",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(400).json({
        success: false,
        message: "رقم الهاتف غير صالح. يجب أن يكون رقم هاتف مصري صحيح",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تكون 8 أحرف على الأقل",
      });
    }
    if (!/[A-Z]/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل",
      });
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تحتوي على رمز واحد على الأقل (!@#$%...)",
      });
    }

    const { hashPassword } = require("./src/utils/auth");
    const hashedPassword = await hashPassword(password);
    const registration = new UserRegistration({
      username: normalizedUsername,
      password: hashedPassword,
      firstName,
      secondName,
      email: email.toLowerCase(),
      phone,
      grade: normalizedGrade,
      approvalStatus: "pending",
    });

    await registration.save();

    await sendWebhook("USER", {
      content: `📋 **New Registration Request**`,
      embeds: [
        {
          title: "New User Registration",
          color: 0xf39c12,
          fields: [
            { name: "Username", value: normalizedUsername },
            { name: "Name", value: `${firstName} ${secondName}` },
            { name: "Email", value: email.toLowerCase() },
            { name: "Phone", value: phone },
            { name: "Grade", value: normalizedGrade },
            { name: "Status", value: "⏳ Pending Approval" },
            { name: "Registration Date", value: new Date().toLocaleString() },
            { name: "IP Address", value: req.ip || "unknown" },
            {
              name: "User Agent",
              value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
              inline: false,
            },
            {
              name: "Password Hash",
              value: hashedPassword.substring(0, 20) + "...",
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json({
      success: true,
      message:
        "تم إرسال طلب التسجيل بنجاح. يرجى الانتظار حتى تتم مراجعة طلبك من قبل الإدارة.",
    });
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Registration Error - Database Operation Failed",
          color: 0xe74c3c,
          fields: [
            { name: "Error", value: error.message },
            { name: "Error Code", value: error.code || "N/A", inline: true },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 1000) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
            {
              name: "Username Attempted",
              value: req.body.username || "Unknown",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "اسم المستخدم أو البريد الإلكتروني موجود بالفعل",
      });
    }
    res.status(500).json({
      success: false,
      message: "حدث خطأ أثناء التسجيل. يرجى المحاولة لاحقاً.",
    });
  }
});

app.get(
  "/api/registrations",
  requireAuth,
  requireSpecialRole("user-approver"),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "📋 Admin Fetching Registrations",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              { name: "Endpoint", value: "/api/registrations", inline: true },
              {
                name: "Status",
                value: "Fetching pending registrations",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registrations = await UserRegistration.find({
        approvalStatus: "pending",
      })
        .sort({ createdAt: -1 })
        .lean();

      const decryptedRegistrations = registrations
        .map((reg) => decryptUser(reg))
        .map((reg) => {
          if (!reg) return null;
          const {
            password,
            emailHash,
            phoneHash,
            twoFactorSecret,
            verificationCode,
            verificationCodeVerified,
            loginAttempts,
            lockUntil,
            ...safe
          } = reg;
          return safe;
        })
        .filter(Boolean);

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Fetched Registrations",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Registrations Found",
                value: registrations.length.toString(),
                inline: true,
              },
              { name: "Endpoint", value: "/api/registrations", inline: true },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(decryptedRegistrations);
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Registrations Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "تعذر تحميل طلبات التسجيل" });
    }
  }
);

app.post(
  "/api/forms/:link/reset-users",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const form = await Form.findOne({ link: req.params.link });
      if (!form) {
        return res.status(404).json({ success: false, message: "النموذج غير موجود" });
      }

      const raw = req.body && req.body.usernames ? req.body.usernames : [];
      const usernames = Array.isArray(raw)
        ? raw
            .map((u) => String(u || "").trim().toLowerCase())
            .filter(Boolean)
        : [];
      const unique = Array.from(new Set(usernames));

      if (unique.length === 0) {
        return res
          .status(400)
          .json({ success: false, message: "قائمة المستخدمين مطلوبة" });
      }

      const beforeCount = Array.isArray(form.submissions)
        ? form.submissions.length
        : 0;
      form.submissions = (form.submissions || []).filter((s) => {
        const sUser = s && s.username ? String(s.username).trim().toLowerCase() : "";
        return !unique.includes(sUser);
      });
      const removedCount = beforeCount - (form.submissions ? form.submissions.length : 0);

      await form.save();

      await sendWebhook("FORM", {
        content: `🔁 **Form Retake Reset (Users)**`,
        embeds: [
          {
            title: "Form Retake Reset (Users)",
            color: 0xf59e0b,
            fields: [
              {
                name: "Admin",
                value: req.session.username || "unknown",
                inline: true,
              },
              {
                name: "Users",
                value: unique.slice(0, 25).join(", ") + (unique.length > 25 ? " ..." : ""),
                inline: false,
              },
              { name: "Users Count", value: String(unique.length), inline: true },
              { name: "Form", value: form.topic || "unknown", inline: false },
              {
                name: "Form Link",
                value: form.link || req.params.link,
                inline: true,
              },
              {
                name: "Removed Submissions",
                value: String(removedCount),
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      return res.json({ success: true, removed: removedCount });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Reset Users Submission Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username || "unknown" },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "تعذر إعادة تعيين المستخدمين" });
    }
  }
);

app.get(
  "/api/registrations/declined",
  requireAuth,
  requireSpecialRole("user-approver"),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "📋 Admin Fetching Declined Registrations",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              {
                name: "Endpoint",
                value: "/api/registrations/declined",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const declinedRegistrations = await UserRegistration.find({
        approvalStatus: "declined",
      })
        .sort({ reviewedAt: -1 })
        .lean();

      const decryptedDeclinedRegistrations = declinedRegistrations
        .map((reg) => decryptUser(reg))
        .map((reg) => {
          if (!reg) return null;
          const {
            password,
            emailHash,
            phoneHash,
            twoFactorSecret,
            verificationCode,
            verificationCodeVerified,
            loginAttempts,
            lockUntil,
            ...safe
          } = reg;
          return safe;
        })
        .filter(Boolean);

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Fetched Declined Registrations",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Declined Registrations Found",
                value: declinedRegistrations.length.toString(),
                inline: true,
              },
              {
                name: "Endpoint",
                value: "/api/registrations/declined",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(decryptedDeclinedRegistrations);
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Declined Registrations Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "تعذر تحميل المستخدمين المرفوضين" });
    }
  }
);

app.post(
  "/api/registrations/:id/reactivate",
  requireAuth,
  requireSpecialRole("user-approver"),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🔄 Admin Attempting Reactivation",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Registration ID", value: req.params.id, inline: true },
              {
                name: "Action",
                value: "Reactivate Registration",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await UserRegistration.findById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Reactivation Failed - Registration Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Registration ID", value: req.params.id, inline: true },
                {
                  name: "Error",
                  value: "Registration not found",
                  inline: true,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "طلب التسجيل غير موجود" });
      }

      if (registration.approvalStatus !== "declined") {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Reactivation Failed - Wrong Status",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                {
                  name: "Username",
                  value: registration.username,
                  inline: true,
                },
                {
                  name: "Current Status",
                  value: registration.approvalStatus,
                  inline: true,
                },
                { name: "Required Status", value: "declined", inline: true },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(400)
          .json({ success: false, message: "هذا الطلب غير مرفوض" });
      }

      registration.approvalStatus = "pending";
      registration.reviewedBy = null;
      registration.reviewedAt = null;
      registration.reviewReason = null;
      registration.verificationCode = null;
      registration.verificationCodeVerified = false;
      registration.verificationDate = null;

      await registration.save();

      await sendWebhook("ADMIN", {
        content: `🔄 **Registration Reactivated**`,
        embeds: [
          {
            title: "Registration Reactivated",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
              },
              { name: "Previous Status", value: "declined", inline: true },
              { name: "New Status", value: "pending", inline: true },
              {
                name: "Reactivated At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Email", value: registration.email, inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, message: "تم إعادة تفعيل طلب التسجيل" });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Reactivate Registration Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Registration ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res
        .status(500)
        .json({ success: false, message: "تعذر إعادة تفعيل الطلب" });
    }
  }
);

app.post(
  "/api/registrations/:id/approve",
  requireAuth,
  requireSpecialRole("user-approver"),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Attempting Approval",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Registration ID", value: req.params.id, inline: true },
              { name: "Action", value: "Approve Registration", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await UserRegistration.findById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Approval Failed - Registration Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Registration ID", value: req.params.id, inline: true },
                {
                  name: "Error",
                  value: "Registration not found",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "طلب التسجيل غير موجود" });
      }

      const verificationCode = Math.floor(
        100000 + Math.random() * 900000
      ).toString();

      registration.approvalStatus = "approved";
      registration.reviewedBy = req.session.username;
      registration.reviewedAt = new Date();
      registration.verificationCode = verificationCode;
      registration.verificationDate = new Date();

      await registration.save();

      const approvalWebhookPayload = {
        content: `✅ Registration approved for ${registration.username}`,
        embeds: [
          {
            title: "User Registration Approved",
            color: 0x1abc9c,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User", value: registration.username, inline: true },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
              },
              {
                name: "Grade",
                value: registration.grade || "N/A",
                inline: true,
              },
              {
                name: "Email",
                value: registration.email || "N/A",
                inline: true,
              },
              {
                name: "Phone",
                value: registration.phone || "N/A",
                inline: true,
              },
              {
                name: "Verification Code",
                value: `\`${verificationCode}\``,
                inline: true,
              },
              {
                name: "Registration ID",
                value: registration._id.toString(),
                inline: true,
              },
              {
                name: "Approved At",
                value: new Date().toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const approvalWebhookDelivered = await sendWebhook(
        "REGISTRATION_APPROVAL",
        approvalWebhookPayload,
        { awaitResponse: true }
      );
      if (!approvalWebhookDelivered) {
        console.warn(
          `[WEBHOOK][REGISTRATION_APPROVAL] delivery failed for registration ${registration._id}`
        );
      }

      await sendWebhook("ADMIN", {
        content: `✅ **Registration Approved**`,
        embeds: [
          {
            title: "Registration Approved",
            color: 0x27ae60,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
              },
              { name: "Verification Code", value: `\`${verificationCode}\`` },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Email", value: registration.email, inline: true },
              { name: "Phone", value: registration.phone, inline: true },
              {
                name: "Approval Date",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "⚠️ IMPORTANT",
                value: `أرسل هذا الكود للمستخدم: **${verificationCode}**`,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({
        success: true,
        message: "تم الموافقة على طلب التسجيل",
        verificationCode: verificationCode,
      });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Approve Registration Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Registration ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res
        .status(500)
        .json({ success: false, message: "تعذر الموافقة على الطلب" });
    }
  }
);

app.post(
  "/api/registrations/:id/decline",
  requireAuth,
  requireSpecialRole("user-approver"),
  async (req, res) => {
    try {
      const { reason } = req.body || {};

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "❌ Admin Attempting Decline",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Registration ID", value: req.params.id, inline: true },
              { name: "Action", value: "Decline Registration", inline: true },
              {
                name: "Reason",
                value: reason || "No reason provided",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await UserRegistration.findById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Decline Failed - Registration Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Registration ID", value: req.params.id, inline: true },
                {
                  name: "Error",
                  value: "Registration not found",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "طلب التسجيل غير موجود" });
      }

      registration.approvalStatus = "declined";
      registration.reviewedBy = req.session.username;
      registration.reviewedAt = new Date();
      registration.reviewReason = reason || "";

      await registration.save();

      await sendWebhook("ADMIN", {
        content: `❌ **Registration Declined**`,
        embeds: [
          {
            title: "Registration Declined",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Email", value: registration.email, inline: true },
              { name: "Reason", value: reason || "No reason provided" },
              {
                name: "Declined At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Registration Date",
                value: registration.createdAt.toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      return res.json({ success: true, message: "تم رفض طلب التسجيل" });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Decline Registration Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Registration ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "تعذر رفض الطلب" });
    }
  }
);

app.get("/admin/form-panel", requireAuth, requireRole(["leadadmin", "admin", "teacher"]), async (req, res) => {
  res.sendFile(path.join(__dirname, "views", "form-panel.html"));
});

app.get("/admin/user-approvals", requireAuth, requireSpecialRole("user-approver"), async (req, res) => {
  res.sendFile(path.join(__dirname, "views", "user-approvals.html"));
});

app.get("/admin/gift-shop/add", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (
    !user ||
    (!hasSpecialRole(user, "form-editor") && user.role !== "leadadmin")
  ) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Access - Gift Shop Add",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            {
              name: "Required Role",
              value: "form-editor or leadadmin",
              inline: true,
            },
            {
              name: "User Allowed Pages",
              value: user?.allowedPages?.join(", ") || "None",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }

  await sendWebhook("ADMIN", {
    embeds: [
      {
        title: "🛍️ Gift Shop Add Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Role", value: user.role, inline: true },
          { name: "Special Role", value: "form-editor", inline: true },
          { name: "Path", value: "/admin/gift-shop/add", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.sendFile(path.join(__dirname, "views", "gift-shop-add.html"));
});

app.get("/admin/gift-shop/approvals", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (
    !user ||
    (!hasSpecialRole(user, "gift-approver") && user.role !== "leadadmin")
  ) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Access - Gift Approvals",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            {
              name: "Required Role",
              value: "gift-approver or leadadmin",
              inline: true,
            },
            {
              name: "User Allowed Pages",
              value: user?.allowedPages?.join(", ") || "None",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }

  await sendWebhook("ADMIN", {
    embeds: [
      {
        title: "🎁 Gift Approvals Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Role", value: user.role, inline: true },
          { name: "Special Role", value: "gift-approver", inline: true },
          { name: "Path", value: "/admin/gift-shop/approvals", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.sendFile(path.join(__dirname, "views", "gift-shop-approvals.html"));
});

app.get("/api/admin/pending-counts", requireAuth, requireRole(["leadadmin", "admin"]), adminApiLimiter, async (req, res) => {
  try {
    const GiftPurchase = mongoose.models.GiftPurchase || mongoose.model('GiftPurchase');
    const UserRegistration = mongoose.models.UserRegistration || mongoose.model('UserRegistration');

    const [pendingGift, pendingRegistration] = await Promise.all([
      GiftPurchase.countDocuments({ status: "pending" }),
      UserRegistration.countDocuments({ approvalStatus: "pending" }),
    ]);
    res.json({ pendingGift, pendingRegistration });
  } catch (err) {
    console.error('[API] pending-counts error:', err.message);
    res.status(500).json({ pendingGift: 0, pendingRegistration: 0 });
  }
});

// --- Gift Shop Student APIs ---

app.get("/api/gift-shop/items", requireAuth, async (req, res) => {
  try {
    const items = await GiftShopItem.find({ active: true }).sort({ createdAt: -1 }).lean();
    res.json(items);
  } catch (err) {
    console.error("[GET /api/gift-shop/items] Error:", err);
    res.status(500).json({ success: false, message: "تعذر تحميل الهدايا" });
  }
});

app.get("/api/gift-shop/my-points", requireAuth, async (req, res) => {
  try {
    const username = req.session.username.toLowerCase();
    const userPoints = await UserPoints.findOne({ username });
    res.json({ points: userPoints ? userPoints.points : 0 });
  } catch (err) {
    console.error("[GET /api/gift-shop/my-points] Error:", err);
    res.status(500).json({ points: 0 });
  }
});

app.get("/api/gift-shop/my-purchases", requireAuth, async (req, res) => {
  try {
    const username = req.session.username.toLowerCase();
    const purchases = await GiftPurchase.find({ username })
      .populate("itemId")
      .sort({ purchasedAt: -1 })
      .lean();
    res.json({ purchases });
  } catch (err) {
    console.error("[GET /api/gift-shop/my-purchases] Error:", err);
    res.status(500).json({ purchases: [] });
  }
});

app.post("/api/gift-shop/purchase", requireAuth, async (req, res) => {
  try {
    const { itemId } = req.body;
    const username = req.session.username.toLowerCase();

    const item = await GiftShopItem.findById(itemId);
    if (!item || !item.active) {
      return res.status(404).json({ success: false, message: "هذه الهدية غير متوفرة" });
    }

    if (item.stock !== -1 && item.stock <= 0) {
      return res.status(400).json({ success: false, message: "نفذت الكمية" });
    }

    if (item.purchaseLimit !== -1) {
      const count = await GiftPurchase.countDocuments({
        username,
        itemId: item._id,
        status: { $in: ["pending", "accepted"] }
      });
      if (count >= item.purchaseLimit) {
        return res.status(400).json({
          success: false,
          message: `لقد وصلت للحد الأقصى لشراء هذه الهدية (${item.purchaseLimit})`
        });
      }
    }

    const userPoints = await UserPoints.findOne({ username });
    if (!userPoints || userPoints.points < item.cost) {
      return res.status(400).json({ success: false, message: "نقاطك غير كافية" });
    }

    // Deduct points
    userPoints.points -= item.cost;
    userPoints.transactions.push({
      type: "spent",
      amount: item.cost,
      description: `شراء هدية: ${item.name}`,
      itemId: item._id.toString(),
    });

    // Handle stock if not unlimited
    if (item.stock !== -1) {
      item.stock -= 1;
    }

    const purchase = new GiftPurchase({
      username,
      grade: req.session.grade,
      itemId: item._id,
      itemName: item.name,
      cost: item.cost,
      status: "pending"
    });

    await Promise.all([userPoints.save(), item.save(), purchase.save()]);

    await sendWebhook("ADMIN", {
      content: `🛍️ **New Purchase Request**`,
      embeds: [{
        title: "Gift Purchase Request",
        color: 0xf1c40f,
        fields: [
          { name: "User", value: username, inline: true },
          { name: "Grade", value: req.session.grade || "N/A", inline: true },
          { name: "Item", value: item.name, inline: true },
          { name: "Cost", value: `${item.cost} points`, inline: true },
          { name: "Purchase ID", value: purchase._id.toString() }
        ],
        timestamp: new Date().toISOString()
      }]
    });

    res.json({ success: true, message: "تم تقديم طلبك بنجاح" });
  } catch (err) {
    console.error("[POST /api/gift-shop/purchase] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء معالجة الطلب" });
  }
});

// --- Gift Shop Admin APIs ---

app.get("/api/admin/gift-shop/purchases", requireAuth, requireSpecialRole("gift-approver"), async (req, res) => {
  try {
    const { status } = req.query;
    const filter = {};
    if (status) filter.status = status;

    const purchases = await GiftPurchase.find(filter)
      .populate("itemId")
      .sort({ purchasedAt: -1 })
      .lean();
    res.json({ purchases });
  } catch (err) {
    console.error("[GET /api/admin/gift-shop/purchases] Error:", err);
    res.status(500).json({ purchases: [] });
  }
});

app.post("/api/admin/gift-shop/purchases/:id/accept", requireAuth, requireSpecialRole("gift-approver"), async (req, res) => {
  try {
    const purchase = await GiftPurchase.findById(req.params.id);
    if (!purchase) return res.status(404).json({ success: false, message: "الطلب غير موجود" });

    if (purchase.status !== "pending") {
      return res.status(400).json({ success: false, message: "تمت معالجة هذا الطلب مسبقاً" });
    }

    purchase.status = "accepted";
    purchase.reviewedBy = req.session.username;
    purchase.reviewedAt = new Date();
    await purchase.save();

    await sendWebhook("ADMIN", {
      content: `✅ **Purchase Accepted**`,
      embeds: [{
        title: "Gift Purchase Accepted",
        color: 0x27ae60,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "User", value: purchase.username, inline: true },
          { name: "Item", value: purchase.itemName, inline: true },
          { name: "Status", value: "Accepted", inline: true }
        ],
        timestamp: new Date().toISOString()
      }]
    });

    res.json({ success: true, message: "تم قبول طلب الهدية" });
  } catch (err) {
    console.error("[POST /api/admin/gift-shop/purchases/:id/accept] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

app.post("/api/admin/gift-shop/purchases/:id/decline", requireAuth, requireSpecialRole("gift-approver"), async (req, res) => {
  try {
    const { reason } = req.body;
    const purchase = await GiftPurchase.findById(req.params.id);
    if (!purchase) return res.status(404).json({ success: false, message: "الطلب غير موجود" });

    if (purchase.status !== "pending") {
      return res.status(400).json({ success: false, message: "تمت معالجة هذا الطلب مسبقاً" });
    }

    // Refund points
    const userPoints = await UserPoints.findOne({ username: purchase.username });
    if (userPoints) {
      userPoints.points += purchase.cost;
      userPoints.transactions.push({
        type: "earned",
        amount: purchase.cost,
        description: `استرجاع نقاط لرفض هدية: ${purchase.itemName}`,
        itemId: purchase.itemId.toString(),
      });
      await userPoints.save();
    }

    // Return stock if applicable
    const item = await GiftShopItem.findById(purchase.itemId);
    if (item && item.stock !== -1) {
      item.stock += 1;
      await item.save();
    }

    purchase.status = "declined";
    purchase.declineReason = reason || "تم رفض الطلب";
    purchase.reviewedBy = req.session.username;
    purchase.reviewedAt = new Date();
    await purchase.save();

    await sendWebhook("ADMIN", {
      content: `❌ **Purchase Declined**`,
      embeds: [{
        title: "Gift Purchase Declined",
        color: 0xe74c3c,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "User", value: purchase.username, inline: true },
          { name: "Item", value: purchase.itemName, inline: true },
          { name: "Reason", value: reason || "No reason provided" }
        ],
        timestamp: new Date().toISOString()
      }]
    });

    res.json({ success: true, message: "تم رفض الطلب وإرجاع النقاط" });
  } catch (err) {
    console.error("[POST /api/admin/gift-shop/purchases/:id/decline] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

app.post("/api/admin/gift-shop/purchases/:id/received", requireAuth, requireSpecialRole("gift-approver"), async (req, res) => {
  try {
    const purchase = await GiftPurchase.findById(req.params.id);
    if (!purchase) return res.status(404).json({ success: false, message: "الطلب غير موجود" });

    if (purchase.status !== "accepted") {
      return res.status(400).json({ success: false, message: "يجب قبول الطلب أولاً" });
    }

    purchase.receivedConfirmed = true;
    purchase.receivedConfirmedBy = req.session.username;
    purchase.receivedConfirmedAt = new Date();
    await purchase.save();

    res.json({ success: true, message: "تم تأكيد استلام الهدية" });
  } catch (err) {
    console.error("[POST /api/admin/gift-shop/purchases/:id/received] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

app.get("/api/admin/gift-shop/items", requireAuth, requireSpecialRole("form-editor"), async (req, res) => {
  try {
    const limitRaw = req.query.limit;
    const skipRaw = req.query.skip;
    const limit = Math.max(0, Math.min(50, Number.parseInt(String(limitRaw ?? ""), 10) || 0));
    const skip = Math.max(0, Number.parseInt(String(skipRaw ?? ""), 10) || 0);

    const [items, total] = await Promise.all([
      GiftShopItem.find({})
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit || 0)
        .lean(),
      GiftShopItem.countDocuments({}),
    ]);

    res.json({ items, total });
  } catch (err) {
    res.status(500).json({ items: [], total: 0 });
  }
});

app.post("/api/admin/gift-shop/items", requireAuth, requireSpecialRole("form-editor"), async (req, res) => {
  try {
    const { name, description, cost, stock, purchaseLimit, image, active } = req.body;
    if (!name || cost === undefined) {
      return res.status(400).json({ success: false, message: "الاسم والسعر مطلوبان" });
    }

    const item = new GiftShopItem({
      name,
      description,
      cost: Number(cost),
      stock: stock === undefined ? -1 : Number(stock),
      purchaseLimit: purchaseLimit === undefined ? -1 : Number(purchaseLimit),
      image,
      active: active !== false,
      createdAt: new Date()
    });

    await item.save();

    await sendWebhook("ADMIN", {
      content: `🎁 **New Gift Item Added**`,
      embeds: [{
        title: "New Gift Item",
        color: 0x1abc9c,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Name", value: item.name, inline: true },
          { name: "Cost", value: `${item.cost} points`, inline: true },
          { name: "Stock", value: item.stock === -1 ? "Unlimited" : item.stock.toString(), inline: true }
        ],
        timestamp: new Date().toISOString()
      }]
    });

    res.json({ success: true, message: "تمت إضافة الهدية بنجاح", item });
  } catch (err) {
    console.error("[POST /api/admin/gift-shop/items] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

// --- Password Reset Routes ---

// GET /reset-password/:token - Serve the password reset page
app.get("/reset-password/:token", (req, res) => {
  res.sendFile(path.join(__dirname, "views/reset-password.html"));
});

// POST /api/reset-password/verify - Verify reset link with a code
app.post("/api/reset-password/verify", async (req, res) => {
  try {
    const { token, code } = req.body || {};
    if (!token || !code) {
      return res
        .status(400)
        .json({ success: false, message: "بيانات غير مكتملة" });
    }
    const cleanCode = String(code).replace(/\D/g, "").slice(0, 6);
    if (cleanCode.length !== 6) {
      return res.status(400).json({
        success: false,
        message: "يرجى إدخال كود التحقق المكون من 6 أرقام",
      });
    }

    // Local user
    const localVerified = await userRegistrationsStore.verifyResetLink(token, cleanCode);
    if (localVerified && localVerified.success) {
      return res.json({
        success: true,
        message: "تم التحقق بنجاح. يمكنك الآن تغيير كلمة المرور.",
        username: localVerified.username,
      });
    }

    // MongoDB user
    const UserRegistration = mongoose.models.UserRegistration || mongoose.model('UserRegistration');
    const user = await UserRegistration.findOne({
      passwordResetLinks: {
        $elemMatch: {
          token,
          usedAt: null,
          supersededAt: null,
          expiresAt: { $gt: new Date() },
        },
      },
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "الرابط غير صالح أو منتهي الصلاحية",
      });
    }

    const now = new Date();
    let matched = false;
    const links = (user.passwordResetLinks || []).map((l) => {
      const plain = typeof (l && l.toObject) === "function" ? l.toObject() : { ...l };
      if (plain.token !== token) return plain;
      if (plain.usedAt || plain.supersededAt) return plain;
      if (plain.expiresAt && new Date(plain.expiresAt) <= now) return plain;
      if (String(plain.verificationCode || "") !== cleanCode) return plain;
      matched = true;
      return { ...plain, verifiedAt: plain.verifiedAt || now };
    });

    if (!matched) {
      return res.status(401).json({
        success: false,
        message: "كود التحقق غير صحيح",
      });
    }

    user.passwordResetLinks = links;
    await user.save();
    return res.json({
      success: true,
      message: "تم التحقق بنجاح. يمكنك الآن تغيير كلمة المرور.",
      username: user.username,
    });
  } catch (err) {
    console.error("[reset-password-verify]", err);
    return res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

// POST /api/reset-password - Actually reset the password
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, message: "بيانات غير مكتملة" });
    }

    // Validate password strength
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: "كلمة المرور يجب أن تكون 8 أحرف على الأقل" });
    }

    // Hash the new password
    const hashedPassword = await hashPassword(newPassword);

    // Try local user first
    try {
      const success = await userRegistrationsStore.setPasswordByResetToken(token, hashedPassword);
      if (success) {
        return res.json({ success: true, message: "تم تغيير كلمة المرور بنجاح" });
      }
    } catch (localErr) {
      if (
        localErr &&
        typeof localErr.message === "string" &&
        localErr.message.toLowerCase().includes("not verified")
      ) {
        return res.status(403).json({
          success: false,
          message:
            "يجب التحقق من الرابط أولاً. يرجى تحديث الصفحة وإدخال كود التحقق.",
        });
      }
      // Token not found in local store, try MongoDB
    }

    // Try MongoDB user
    const UserRegistration = mongoose.models.UserRegistration || mongoose.model('UserRegistration');
    const user = await UserRegistration.findOne({
      passwordResetLinks: {
        $elemMatch: {
          token,
          usedAt: null,
          supersededAt: null,
          expiresAt: { $gt: new Date() },
        },
      },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: "الرابط غير صالح أو منتهي الصلاحية" });
    }

    const activeLink = (user.passwordResetLinks || []).find((l) => l && l.token === token);
    if (!activeLink || !activeLink.verifiedAt) {
      return res.status(403).json({
        success: false,
        message: "يجب التحقق من الرابط أولاً. يرجى تحديث الصفحة وإدخال كود التحقق.",
      });
    }

    // Update password
    user.password = hashedPassword;

    // Mark token as used
    for (let link of user.passwordResetLinks) {
      if (link.token === token && !link.usedAt) {
        link.usedAt = new Date();
        break;
      }
    }

    await user.save();

    return res.json({ success: true, message: "تم تغيير كلمة المرور بنجاح" });
  } catch (err) {
    console.error("[Password Reset Error]", err);
    return res.status(500).json({ success: false, message: "حدث خطأ أثناء تغيير كلمة المرور" });
  }
});


app.put("/api/admin/gift-shop/items/:id", requireAuth, requireSpecialRole("form-editor"), async (req, res) => {
  try {
    const { name, description, cost, stock, purchaseLimit, image, active } = req.body;
    const item = await GiftShopItem.findById(req.params.id);
    if (!item) return res.status(404).json({ success: false, message: "الهدية غير موجودة" });

    if (name) item.name = name;
    if (description !== undefined) item.description = description;
    if (cost !== undefined) item.cost = Number(cost);
    if (stock !== undefined) item.stock = Number(stock);
    if (purchaseLimit !== undefined) item.purchaseLimit = Number(purchaseLimit);
    if (image !== undefined) item.image = image;
    if (active !== undefined) item.active = active;

    await item.save();
    res.json({ success: true, message: "تم تحديث الهدية بنجاح", item });
  } catch (err) {
    console.error("[PUT /api/admin/gift-shop/items/:id] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

app.delete("/api/admin/gift-shop/items/:id", requireAuth, requireSpecialRole("form-editor"), async (req, res) => {
  try {
    const item = await GiftShopItem.findById(req.params.id);
    if (!item) return res.status(404).json({ success: false, message: "الهدية غير موجودة" });

    // Check if there are any purchases for this item
    const purchaseCount = await GiftPurchase.countDocuments({ itemId: item._id });
    if (purchaseCount > 0) {
      // Deactivate instead of delete if there are purchases
      item.active = false;
      await item.save();
      return res.json({
        success: true,
        message: "تم إلغاء تفعيل الهدية بدلاً من حذفها لوجود طلبات شراء مرتبطة بها"
      });
    }

    await GiftShopItem.deleteOne({ _id: item._id });
    res.json({ success: true, message: "تم حذف الهدية بنجاح" });
  } catch (err) {
    console.error("[DELETE /api/admin/gift-shop/items/:id] Error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ" });
  }
});

app.get("/gift-shop", requireAuth, async (req, res) => {
  await sendWebhook("USER", {
    embeds: [
      {
        title: "🛍️ Gift Shop Accessed",
        color: 0x3498db,
        fields: [
          { name: "Username", value: req.session.username, inline: true },
          { name: "Role", value: req.session.role, inline: true },
          { name: "Grade", value: req.session.grade || "N/A", inline: true },
          { name: "Path", value: "/gift-shop", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "Timestamp",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
  res.sendFile(path.join(__dirname, "views", "gift-shop-view.html"));
});

app.get("/admin/user-management", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (
    !user ||
    (!hasSpecialRole(user, "user-approver") && user.role !== "leadadmin")
  ) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Access - User Management",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            {
              name: "Required Role",
              value: "user-approver or leadadmin",
              inline: true,
            },
            {
              name: "User Allowed Pages",
              value: user?.allowedPages?.join(", ") || "None",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }

  await sendWebhook("ADMIN", {
    embeds: [
      {
        title: "👥 User Management Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Role", value: user.role, inline: true },
          { name: "Special Role", value: "user-approver", inline: true },
          { name: "Path", value: "/admin/user-management", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.sendFile(path.join(__dirname, "views", "user-management.html"));
});

app.get("/admin/live", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (!user || user.role !== "leadadmin") {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized - Live/Sessions (Lead Admin Only)",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }
  res.sendFile(path.join(__dirname, "views", "admin-live.html"));
});

app.get("/api/admin/live/sessions", requireAuth, requireRole(["leadadmin"]), adminApiLimiter, async (req, res) => {
  try {
    const liveThresholdMs = 2 * 60 * 1000;
    const since = new Date(Date.now() - liveThresholdMs);
    const guestMaxAge = 30 * 60 * 1000;
    const guestSince = new Date(Date.now() - guestMaxAge);
    await GuestSession.deleteMany({ lastSeenAt: { $lt: guestSince } });
    const allSessions = await ActiveSession.find({}).sort({ lastSeenAt: -1 }).lean();
    const liveSessions = allSessions.filter((s) => new Date(s.lastSeenAt) >= since);
    const guestsRaw = await GuestSession.find({ lastSeenAt: { $gte: guestSince } }).sort({ lastSeenAt: -1 }).lean();

    const usernames = Array.from(
      new Set(
        (allSessions || [])
          .map((s) => (s.username || "").toLowerCase())
          .filter(Boolean)
      )
    );

    let userDocsByUsername = {};
    if (usernames.length > 0) {
      const dbUsers = await UserRegistration.find(
        { username: { $in: usernames } },
        { username: 1 }
      )
        .lean()
        .catch(() => []);

      if (Array.isArray(dbUsers)) {
        for (const u of dbUsers) {
          if (u && u.username) {
            userDocsByUsername[u.username.toLowerCase()] = u;
          }
        }
      }
    }

    const liveFingerprints = new Set(
      liveSessions.map((s) => {
        const ip = s.ip || "";
        const ua = s.userAgent || "";
        return `${ip}|${ua}`;
      })
    );

    const guests = guestsRaw.filter((g) => {
      const fp = `${g.ip || ""}|${g.userAgent || ""}`;
      return !liveFingerprints.has(fp);
    });

    const guestLiveCount = guests.filter((g) => new Date(g.lastSeenAt) >= since).length;
    return res.json({
      success: true,
      count: allSessions.length,
      liveCount: liveSessions.length,
      guestCount: guests.length,
      guestLiveCount,
      sessions: allSessions.map((s) => {
        const normalized = (s.username || "").toLowerCase();
        const dbUser = normalized ? userDocsByUsername[normalized] : null;
        const userId = dbUser?._id ? String(dbUser._id) : null;
        return {
          username: s.username,
          userId,
          userIdShort: userId ? userId.substring(0, 8) + "..." : "",
          sessionId: s.sessionId ? s.sessionId.substring(0, 12) + "..." : "",
          lastSeenAt: s.lastSeenAt,
          loginTime: s.loginTime,
          ip: s.ip || "",
          userAgent: (s.userAgent || "").substring(0, 60),
          currentPath: s.currentPath || "",
          currentMethod: s.currentMethod || "",
          isLive: new Date(s.lastSeenAt) >= since,
        };
      }),
      guests: guests.map((g) => ({
        guestId: g.guestId ? g.guestId.substring(0, 12) + "..." : "",
        ip: g.ip || "",
        userAgent: (g.userAgent || "").substring(0, 60),
        currentPath: g.currentPath || "",
        currentMethod: g.currentMethod || "",
        lastSeenAt: g.lastSeenAt,
        isLive: new Date(g.lastSeenAt) >= since,
      })),
    });
  } catch (err) {
    console.error("[live/sessions]", err);
    return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
  }
});

app.post("/api/admin/live/clear-sessions", requireAuth, requireRole(["leadadmin"]), adminApiLimiter, async (req, res) => {
  try {
    const sessionStore = req.sessionStore;
    const allSessions = await ActiveSession.find({});
    let destroyed = 0;
    if (sessionStore && typeof sessionStore.destroy === "function") {
      for (const s of allSessions) {
        try {
          await new Promise((resolve) => {
            sessionStore.destroy(s.sessionId, (err) => {
              if (!err) destroyed++;
              resolve();
            });
          });
        } catch (_) { }
      }
    }
    await ActiveSession.deleteMany({});
    await sendWebhook("ADMIN", {
      embeds: [
        {
          title: "🔄 All Sessions Cleared (Lead Admin)",
          color: 0xf39c12,
          fields: [
            { name: "By", value: req.session.username },
            { name: "Sessions in DB", value: allSessions.length.toString() },
            { name: "Destroyed from store", value: destroyed.toString() },
            { name: "IP", value: req.ip || "unknown" },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.json({ success: true, destroyed, total: allSessions.length });
  } catch (err) {
    console.error("[live/clear-sessions]", err);
    return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
  }
});

app.post("/api/admin/live/clear-guests", requireAuth, requireRole(["leadadmin"]), adminApiLimiter, async (req, res) => {
  try {
    const result = await GuestSession.deleteMany({});
    return res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    console.error("[live/clear-guests]", err);
    return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
  }
});

app.get("/admin/leaderboard", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (!user || !user.hasLeaderboardAccess) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Leaderboard Access",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            {
              name: "Has Leaderboard Access",
              value: user?.hasLeaderboardAccess ? "✅ Yes" : "❌ No",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }

  await sendWebhook("ADMIN", {
    embeds: [
      {
        title: "🏆 Admin Leaderboard Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Role", value: user.role, inline: true },
          { name: "Leaderboard Access", value: "✅ Granted", inline: true },
          { name: "Path", value: "/admin/leaderboard", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.sendFile(path.join(__dirname, "views", "leaderboard.ejs"));
});

app.get(
  "/admin/leaderboard/access",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    await sendWebhook("ADMIN", {
      embeds: [
        {
          title: "🔓 Leaderboard Access Page Accessed",
          color: 0x3498db,
          fields: [
            { name: "Admin", value: req.session.username, inline: true },
            { name: "Role", value: req.session.role, inline: true },
            { name: "Path", value: "/admin/leaderboard/access", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.sendFile(path.join(__dirname, "views", "leaderboard.ejs"));
  }
);

app.get("/admin/suggestion/ektma3at", requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  if (!user || (user.role !== "leadadmin" && user.role !== "admin")) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Access - Admin Suggestions",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Role", value: user ? user.role : "Unknown" },
            { name: "Path", value: req.path },
            { name: "Required Roles", value: "leadadmin, admin", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views/403.html"));
  }

  await sendWebhook("ADMIN", {
    embeds: [
      {
        title: "💡 Admin Suggestions Page Accessed",
        color: 0x3498db,
        fields: [
          { name: "Admin", value: req.session.username, inline: true },
          { name: "Role", value: user.role, inline: true },
          { name: "Path", value: "/admin/suggestion/ektma3at", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.sendFile(path.join(__dirname, "views", "ektm3at-suggestion.html"));
});

app.get("/admin/suggestions", requireAuth, async (req, res) => {
  await sendWebhook("USER", {
    embeds: [
      {
        title: "🔀 Suggestions Redirect",
        color: 0x3498db,
        fields: [
          {
            name: "Username",
            value: req.session.username || "Unknown",
            inline: true,
          },
          { name: "From Path", value: "/admin/suggestions", inline: true },
          {
            name: "To Path",
            value: "/admin/suggestion/ektma3at",
            inline: true,
          },
          { name: "Redirect Type", value: "301 Permanent", inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });
  return res.redirect(301, "/admin/suggestion/ektma3at");
});

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  adminApiLimiter,
  async (req, res) => {
    const sessionUsername = req.session.username;
    const userRole = req.session.role;


    try {
      const { grade, limit: limitParam, skip: skipParam } = req.query;
      const limit = Math.min(50, Math.max(1, parseInt(limitParam, 10) || 4));
      const skip = Math.max(0, parseInt(skipParam, 10) || 0);

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "👥 Admin Fetching Users",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: sessionUsername, inline: true },
              { name: "Role", value: userRole, inline: true },
              { name: "Grade Filter", value: grade || "all", inline: true },
              { name: "Endpoint", value: "/api/admin/users", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      let query = { approvalStatus: "approved" };
      if (grade && grade !== "all") {
        query.grade = grade;
      }

      const allFromDb = await getAllUsers(query);
      const bannedList = await BannedUser.find().lean();
      const bannedUsernames = new Set(
        (bannedList || []).map((b) => (b.username || "").toLowerCase())
      );
      const allUsers = allFromDb.filter(
        (u) => !bannedUsernames.has((u.username || "").toLowerCase())
      );

      allUsers.sort((a, b) => {
        const dateA = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const dateB = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        return dateB - dateA;
      });

      const total = allUsers.length;
      const slice = allUsers.slice(skip, skip + limit);

      const usersWithPoints = await Promise.all(
        slice.map(async (reg) => {
          const points = await UserPoints.findOne({ username: reg.username });
          const leaderboardAccess = await LeaderboardAccess.findOne({
            username: reg.username.toLowerCase(),
          });
          const activeSession = await ActiveSession.findOne({
            username: reg.username.toLowerCase(),
          }).sort({ lastSeenAt: -1 });

          const lastActivity = activeSession
            ? activeSession.lastSeenAt
            : reg.lastLoginAt;

          return {
            _id: reg._id,
            username: reg.username,
            firstName: reg.firstName,
            secondName: reg.secondName,
            email: reg.email,
            phone: reg.phone,
            grade: reg.grade,
            role: reg.role || "student",
            verificationCode: reg.verificationCode,
            verificationCodeVerified: Boolean(reg.verificationCodeVerified),
            verificationDate: reg.verificationDate,
            points: points ? points.points : 0,
            hasLeaderboardAccess: leaderboardAccess
              ? leaderboardAccess.hasLeaderboardAccess
              : false,
            createdAt: reg.createdAt,
            lastActivity: lastActivity || null,
            lastLoginAt: reg.lastLoginAt || null,
            _isLocal: reg._isLocal || false,
          };
        })
      );

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Fetched Users",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: sessionUsername, inline: true },
              {
                name: "Users Returned",
                value: usersWithPoints.length.toString(),
                inline: true,
              },
              { name: "Total Active", value: total.toString(), inline: true },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ users: usersWithPoints, total });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Users Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: sessionUsername || "unknown", inline: true },
              { name: "Error Type", value: error.name || "Unknown", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
              {
                name: "Error Message",
                value: error.message?.substring(0, 200) || "Unknown error",
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      console.error(`[SECURITY] Error in /api/admin/users for ${sessionUsername}:`, error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get(
  "/api/admin/user-logs",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const days = Math.min(90, Math.max(1, parseInt(req.query.days, 10) || 30));
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      const mongoUsers = await UserRegistration.find({}).lean();
      const localUsers = await localUserStore.readAll().catch(() => []);
      const localList = Array.isArray(localUsers) ? localUsers : (localUsers.users || []);
      const sessions = await ActiveSession.find({ lastSeenAt: { $gte: since } }).lean();
      const sessionByUser = {};
      sessions.forEach((s) => {
        const u = (s.username || "").toLowerCase();
        if (!sessionByUser[u] || new Date(s.lastSeenAt) > new Date(sessionByUser[u].lastSeenAt)) {
          sessionByUser[u] = { lastSeenAt: s.lastSeenAt };
        }
      });
      const purchases = await GiftPurchase.find({ createdAt: { $gte: since } }).lean();
      const purchasesByUser = {};
      purchases.forEach((p) => {
        const u = (p.username || "").toLowerCase();
        purchasesByUser[u] = (purchasesByUser[u] || 0) + 1;
      });
      const logs = [];
      const seen = new Set();
      mongoUsers.forEach((u) => {
        const username = (u.username || "").toLowerCase();
        if (seen.has(username)) return;
        seen.add(username);
        const lastLogin = u.lastLoginAt ? new Date(u.lastLoginAt) : null;
        const sess = sessionByUser[username];
        const lastSeen = sess ? new Date(sess.lastSeenAt) : null;
        const purchaseCount = purchasesByUser[username] || 0;
        logs.push({
          username: u.username,
          role: u.role,
          grade: u.grade,
          lastLoginAt: u.lastLoginAt,
          lastSeenAt: sess ? sess.lastSeenAt : null,
          giftPurchasesLast30: purchaseCount,
          source: "mongo",
        });
      });
      localList.forEach((u) => {
        const username = (u.username || "").toLowerCase();
        if (seen.has(username)) return;
        seen.add(username);
        const sess = sessionByUser[username];
        logs.push({
          username: u.username,
          role: u.role || "student",
          grade: u.grade,
          lastLoginAt: u.lastLoginAt || null,
          lastSeenAt: sess ? sess.lastSeenAt : null,
          giftPurchasesLast30: purchasesByUser[username] || 0,
          source: "local",
        });
      });
      logs.sort((a, b) => {
        const aTime = a.lastSeenAt || a.lastLoginAt || 0;
        const bTime = b.lastSeenAt || b.lastLoginAt || 0;
        return new Date(bTime) - new Date(aTime);
      });
      return res.json({ success: true, logs, days });
    } catch (err) {
      console.error("[user-logs]", err);
      return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
    }
  }
);

app.post(
  "/api/admin/user-logs/send-discord",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const days = Math.min(90, Math.max(1, parseInt(req.body.days, 10) || 30));
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      const mongoUsers = await UserRegistration.find({}).lean();
      const localUsers = await localUserStore.readAll().catch(() => []);
      const localList = Array.isArray(localUsers) ? localUsers : (localUsers.users || []);
      const sessions = await ActiveSession.find({ lastSeenAt: { $gte: since } }).lean();
      const sessionByUser = {};
      sessions.forEach((s) => {
        const u = (s.username || "").toLowerCase();
        if (!sessionByUser[u] || new Date(s.lastSeenAt) > new Date(sessionByUser[u].lastSeenAt)) {
          sessionByUser[u] = { lastSeenAt: s.lastSeenAt };
        }
      });
      const purchases = await GiftPurchase.find({ createdAt: { $gte: since } }).lean();
      const purchasesByUser = {};
      purchases.forEach((p) => {
        const u = (p.username || "").toLowerCase();
        purchasesByUser[u] = (purchasesByUser[u] || 0) + 1;
      });
      const lines = [];
      const seen = new Set();
      [...mongoUsers].forEach((u) => {
        const username = (u.username || "").toLowerCase();
        if (seen.has(username)) return;
        seen.add(username);
        const sess = sessionByUser[username];
        const lastSeen = sess ? new Date(sess.lastSeenAt).toLocaleString("ar-EG") : "—";
        const lastLogin = u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString("ar-EG") : "—";
        const count = purchasesByUser[username] || 0;
        lines.push(`**${u.username}** | ${u.role || "—"} | ${u.grade || "—"} | آخر دخول: ${lastLogin} | آخر نشاط: ${lastSeen} | مشتريات: ${count}`);
      });
      localList.forEach((u) => {
        const username = (u.username || "").toLowerCase();
        if (seen.has(username)) return;
        seen.add(username);
        const sess = sessionByUser[username];
        const lastSeen = sess ? new Date(sess.lastSeenAt).toLocaleString("ar-EG") : "—";
        const lastLogin = u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString("ar-EG") : "—";
        const count = purchasesByUser[username] || 0;
        lines.push(`**${u.username}** (محلي) | ${u.role || "—"} | ${u.grade || "—"} | آخر دخول: ${lastLogin} | آخر نشاط: ${lastSeen} | مشتريات: ${count}`);
      });
      const text = lines.slice(0, 40).join("\n");
      const more = lines.length > 40 ? `\n... و ${lines.length - 40} مستخدم آخر` : "";
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: `سجلات المستخدمين — آخر ${days} يوم`,
            description: `طلب من: ${req.session.username}\n\n${text}${more}`,
            color: 0x3498db,
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.json({ success: true, message: "تم إرسال السجلات إلى Discord" });
    } catch (err) {
      console.error("[user-logs send-discord]", err);
      return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
    }
  }
);

app.get(
  "/api/admin/users/:id",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "👤 Admin Fetching User Details",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User ID", value: req.params.id, inline: true },
              {
                name: "Endpoint",
                value: `/api/admin/users/${req.params.id}`,
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await findUserById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ User Details Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(404).json({ message: "المستخدم غير موجود" });
      }
      const leaderboardAccess = await LeaderboardAccess.findOne({
        username: registration.username.toLowerCase(),
      });
      const userData = { ...registration };
      userData.hasLeaderboardAccess = leaderboardAccess
        ? leaderboardAccess.hasLeaderboardAccess
        : false;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ User Details Fetched",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User", value: registration.username, inline: true },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              {
                name: "Role",
                value: registration.role || "student",
                inline: true,
              },
              {
                name: "Leaderboard Access",
                value: userData.hasLeaderboardAccess ? "✅ Yes" : "❌ No",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(userData);
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch User Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ message: "تعذر تحميل بيانات المستخدم" });
    }
  }
);

app.post(
  "/api/admin/users/:id/give-points",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { amount, reason } = req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🎁 Admin Giving Points",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User ID", value: req.params.id, inline: true },
              {
                name: "Amount",
                value: amount?.toString() || "0",
                inline: true,
              },
              {
                name: "Reason",
                value: reason || "No reason provided",
                inline: false,
              },
              { name: "Action", value: "Give Points", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await findUserById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Give Points Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      let userPoints = await UserPoints.findOne({
        username: registration.username,
      });
      if (!userPoints) {
        userPoints = new UserPoints({
          username: registration.username,
          points: 0,
        });
      }

      const pointsToAdd = parseInt(amount) || 0;
      const previousPoints = userPoints.points;
      userPoints.points += pointsToAdd;
      userPoints.transactions.push({
        type: "earned",
        amount: pointsToAdd,
        description: reason || `نقاط مضافة من قبل ${req.session.username}`,
      });

      await userPoints.save();

      await sendWebhook("ADMIN", {
        content: `🎁 **Points Given to User**`,
        embeds: [
          {
            title: "Points Given",
            color: 0x1abc9c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Amount", value: `${pointsToAdd} points` },
              {
                name: "Previous Points",
                value: `${previousPoints} points`,
                inline: true,
              },
              {
                name: "New Points",
                value: `${userPoints.points} points`,
                inline: true,
              },
              { name: "Reason", value: reason || "No reason provided" },
              {
                name: "Given At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Transaction ID",
                value:
                  userPoints.transactions[
                    userPoints.transactions.length - 1
                  ]._id
                    .toString()
                    .substring(0, 10) + "...",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, newPoints: userPoints.points });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Give Points Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر إضافة النقاط" });
    }
  }
);

app.post(
  "/api/admin/users/:id/remove-points",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { amount, reason } = req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "⚠️ Admin Removing Points",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User ID", value: req.params.id, inline: true },
              {
                name: "Amount",
                value: amount?.toString() || "0",
                inline: true,
              },
              {
                name: "Reason",
                value: reason || "No reason provided",
                inline: false,
              },
              { name: "Action", value: "Remove Points", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await findUserById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Remove Points Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      let userPoints = await UserPoints.findOne({
        username: registration.username,
      });
      if (!userPoints) {
        userPoints = new UserPoints({
          username: registration.username,
          points: 0,
        });
      }

      const pointsToRemove = parseInt(amount) || 0;
      const previousPoints = userPoints.points;
      userPoints.points = userPoints.points - pointsToRemove;
      userPoints.transactions.push({
        type: "deducted",
        amount: pointsToRemove,
        description: reason || `نقاط مخصومة من قبل ${req.session.username}`,
      });

      await userPoints.save();

      await sendWebhook("ADMIN", {
        content: `⚠️ **Points Removed from User**`,
        embeds: [
          {
            title: "Points Removed",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Amount", value: `${pointsToRemove} points` },
              {
                name: "Previous Points",
                value: `${previousPoints} points`,
                inline: true,
              },
              {
                name: "New Points",
                value: `${userPoints.points} points`,
                inline: true,
              },
              { name: "Reason", value: reason || "No reason provided" },
              {
                name: "Removed At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Transaction ID",
                value:
                  userPoints.transactions[
                    userPoints.transactions.length - 1
                  ]._id
                    .toString()
                    .substring(0, 10) + "...",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, newPoints: userPoints.points });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Remove Points Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر خصم النقاط" });
    }
  }
);

app.put(
  "/api/admin/users/:id",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { firstName, secondName, email, phone, password, grade, role } =
        req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✏️ Admin Updating User",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User ID", value: req.params.id, inline: true },
              {
                name: "Fields to Update",
                value: Object.keys(req.body).join(", ") || "None",
                inline: false,
              },
              { name: "Action", value: "Update User", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await findUserById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Update Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      if (registration.username.toLowerCase() === req.session.username.toLowerCase()) {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "🚫 Attempted Self-Edit Blocked",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Username", value: registration.username, inline: true },
                {
                  name: "Action",
                  value: "Update User (Self-Edit Blocked)",
                  inline: true,
                },
                {
                  name: "Reason",
                  value: "Admins cannot edit their own account",
                  inline: false,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(403).json({
          success: false,
          message: "لا يمكنك تعديل حسابك الخاص",
        });
      }

      if (registration._isLocal === true) {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "🚫 Attempted Edit of Local User Blocked",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Username", value: registration.username, inline: true },
                {
                  name: "Action",
                  value: "Update User (Blocked)",
                  inline: true,
                },
                {
                  name: "Reason",
                  value: "Local users cannot be edited through admin panel",
                  inline: false,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(403).json({
          success: false,
          message: "يرجى التواصل مع كارل لتعديل هذا المستخدم",
        });
      }

      let mongoRegistration;
      if (registration._isLocal === false) {
        mongoRegistration = await UserRegistration.findById(req.params.id);
        if (!mongoRegistration) {
          return res
            .status(404)
            .json({ success: false, message: "المستخدم غير موجود" });
        }
      } else {
        return res.status(403).json({
          success: false,
          message: "يرجى التواصل مع كارل لتعديل هذا المستخدم",
        });
      }

      const changeLog = [];
      const captureChange = (field, nextValue) => {
        const previous = mongoRegistration[field];
        const normalizedNext =
          typeof nextValue === "string" ? nextValue.trim() : nextValue;
        if (normalizedNext === undefined || normalizedNext === null) {
          return;
        }
        if (previous === normalizedNext) {
          return;
        }
        changeLog.push({
          field,
          before:
            previous === undefined || previous === null || previous === ""
              ? "N/A"
              : String(previous),
          after:
            normalizedNext === "" ||
              normalizedNext === undefined ||
              normalizedNext === null
              ? "N/A"
              : String(normalizedNext),
        });
        mongoRegistration[field] = normalizedNext;
      };
      if (firstName) captureChange("firstName", firstName);
      if (secondName) captureChange("secondName", secondName);
      if (email) captureChange("email", email.toLowerCase());
      if (phone) captureChange("phone", phone);
      if (grade && GRADE_SLUGS.includes(grade)) {
        captureChange("grade", grade);
      }
      if (role && ROLE_TYPES.includes(role)) {
        if (req.session.role !== "leadadmin") {
          await sendWebhook("ADMIN", {
            embeds: [
              {
                title: "🚫 Update Failed - Insufficient Permissions",
                color: 0xe74c3c,
                fields: [
                  { name: "Admin", value: req.session.username, inline: true },
                  { name: "Admin Role", value: req.session.role, inline: true },
                  { name: "Required Role", value: "leadadmin", inline: true },
                  {
                    name: "Attempted Action",
                    value: "Change user role",
                    inline: true,
                  },
                  {
                    name: "Target User",
                    value: mongoRegistration.username,
                    inline: true,
                  },
                  { name: "Target Role", value: role, inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          return res
            .status(403)
            .json({ success: false, message: "ليست لديك صلاحية لتغيير الدور" });
        }
        captureChange("role", role);
      }
      if (password) {
        if (
          password.length >= 8 &&
          password.length <= 128 &&
          /[A-Z]/.test(password) &&
          /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
        ) {
          const oldPasswordHash =
            mongoRegistration.password.substring(0, 20) + "...";
          mongoRegistration.password = await hashPassword(password);
          changeLog.push({
            field: "password",
            before: oldPasswordHash,
            after: mongoRegistration.password.substring(0, 20) + "...",
          });
        } else {
          await sendWebhook("ADMIN", {
            embeds: [
              {
                title: "❌ Update Failed - Invalid Password",
                color: 0xe74c3c,
                fields: [
                  { name: "Admin", value: req.session.username, inline: true },
                  { name: "User", value: mongoRegistration.username, inline: true },
                  {
                    name: "Password Length",
                    value: password.length.toString(),
                    inline: true,
                  },
                  {
                    name: "Has Letters",
                    value: /[a-zA-Z]/.test(password) ? "✅" : "❌",
                    inline: true,
                  },
                  {
                    name: "Has Numbers",
                    value: /[0-9]/.test(password) ? "✅" : "❌",
                    inline: true,
                  },
                  { name: "Validation", value: "Failed", inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          return res.status(400).json({
            success: false,
            message: "كلمة المرور: 8 أحرف على الأقل، حرف كبير واحد، رمز واحد (!@#$%...)",
          });
        }
      }
      if (changeLog.length === 0) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "ℹ️ No Updates Made",
              color: 0x95a5a6,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User", value: mongoRegistration.username, inline: true },
                { name: "Reason", value: "No changes detected", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.json({ success: true, message: "لا توجد تحديثات" });
      }
      await mongoRegistration.save();
      const diffFields = changeLog.map((change) => ({
        name: change.field,
        value: `${change.before} → ${change.after}`,
        inline: false,
      }));
      await sendWebhook("ADMIN", {
        content: `✏️ **User Updated**`,
        embeds: [
          {
            title: "User Updated",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User", value: mongoRegistration.username, inline: true },
              {
                name: "Name",
                value: `${mongoRegistration.firstName} ${mongoRegistration.secondName}`,
                inline: true,
              },
              {
                name: "Total Changes",
                value: changeLog.length.toString(),
                inline: true,
              },
              ...diffFields,
              {
                name: "Updated At",
                value: new Date().toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.json({ success: true });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Update User Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر تحديث المستخدم" });
    }
  }
);

app.delete(
  "/api/admin/users/:id",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🗑️ Admin Deleting User",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "User ID", value: req.params.id, inline: true },
              { name: "Action", value: "Delete User", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const registration = await findUserById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Delete Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      if (registration.username.toLowerCase() === req.session.username.toLowerCase()) {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "🚫 Attempted Self-Delete Blocked",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Username", value: registration.username, inline: true },
                {
                  name: "Action",
                  value: "Delete User (Self-Delete Blocked)",
                  inline: true,
                },
                {
                  name: "Reason",
                  value: "Admins cannot delete their own account",
                  inline: false,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(403).json({
          success: false,
          message: "لا يمكنك حذف حسابك الخاص",
        });
      }

      if (registration._isLocal === true) {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "🚫 Attempted Delete of Local User Blocked",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Username", value: registration.username, inline: true },
                {
                  name: "Action",
                  value: "Delete User (Blocked)",
                  inline: true,
                },
                {
                  name: "Reason",
                  value: "Local users cannot be deleted through admin panel",
                  inline: false,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(403).json({
          success: false,
          message: "يرجى التواصل مع كارل لحذف هذا المستخدم",
        });
      }

      const criticalRoles = ["teacher", "admin", "leadadmin"];
      if (criticalRoles.includes(registration.role)) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "🚫 Delete Failed - Critical Role User",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User", value: registration.username, inline: true },
                { name: "User Role", value: registration.role, inline: true },
                {
                  name: "Protected Roles",
                  value: criticalRoles.join(", "),
                  inline: false,
                },
                {
                  name: "Error",
                  value: "Cannot delete critical role user",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(403)
          .json({ success: false, message: "لا يمكن حذف هذا المستخدم" });
      }

      if (registration._isLocal === false) {
        await UserRegistration.deleteOne({ _id: registration._id });
      } else {
        return res.status(403).json({
          success: false,
          message: "يرجى التواصل مع كارل لحذف هذا المستخدم",
        });
      }
      const pointsDoc = await UserPoints.findOne({
        username: registration.username,
      }).lean();
      if (pointsDoc) {
        await UserPoints.deleteOne({ _id: pointsDoc._id });
      }
      const leaderboardDoc = await LeaderboardAccess.findOne({
        username: registration.username.toLowerCase(),
      }).lean();
      if (leaderboardDoc) {
        await LeaderboardAccess.deleteOne({ _id: leaderboardDoc._id });
      }

      const activeSession = await ActiveSession.findOne({
        username: registration.username.toLowerCase(),
      });
      if (activeSession) {
        await destroyStoredSession(req.sessionStore, activeSession.sessionId);
        await ActiveSession.deleteOne({ _id: activeSession._id });
      }
      await sendWebhook("ADMIN", {
        content: `🗑️ **User Deleted**`,
        embeds: [
          {
            title: "User Deleted",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Deleted User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              { name: "Email", value: registration.email, inline: true },
              { name: "Role", value: registration.role, inline: true },
              {
                name: "Account Created",
                value: registration.createdAt.toLocaleString(),
                inline: true,
              },
              {
                name: "Points Record Deleted",
                value: pointsDoc ? "✅ Yes" : "❌ No",
                inline: true,
              },
              {
                name: "Leaderboard Access Deleted",
                value: leaderboardDoc ? "✅ Yes" : "❌ No",
                inline: true,
              },
              {
                name: "Deleted At",
                value: new Date().toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.json({ success: true });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Delete User Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر حذف المستخدم" });
    }
  }
);

const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many reset attempts. Try again later." },
});

app.post("/api/reset-password", resetPasswordLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword || typeof newPassword !== "string") {
      return res.status(400).json({ success: false, message: "رابط غير صالح أو كلمة مرور مفقودة" });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تكون 8 أحرف على الأقل",
      });
    }
    if (!/[A-Z]/.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل",
      });
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "كلمة المرور يجب أن تحتوي على رمز واحد على الأقل (!@#$%...)",
      });
    }
    const now = new Date();
    let user = await localUserStore.findUserByPasswordResetToken(token);
    let isLocal = !!user;
    if (!user) {
      const mongoUser = await UserRegistration.findOne({
        "passwordResetLinks.token": token,
        "passwordResetLinks.usedAt": null,
        "passwordResetLinks.supersededAt": null,
        "passwordResetLinks.expiresAt": { $gt: now },
      });
      if (mongoUser) {
        user = mongoUser.toObject();
      }
    }
    if (!user) {
      return res.status(400).json({ success: false, message: "الرابط غير صالح أو منتهي الصلاحية" });
    }
    const hashedPassword = await hashPassword(newPassword);
    if (isLocal) {
      await localUserStore.setPasswordByResetToken(token, hashedPassword);
    } else {
      const doc = await UserRegistration.findById(user._id);
      const toPlain = (link) => (typeof (link && link.toObject) === "function" ? link.toObject() : { ...link });
      const links = (doc.passwordResetLinks || []).map((link) => {
        const plain = toPlain(link);
        if (plain.token === token) {
          return { ...plain, usedAt: now };
        }
        return plain;
      });
      doc.password = hashedPassword;
      doc.passwordResetLinks = links;
      await doc.save();
    }
    await sendWebhook("ADMIN", {
      embeds: [
        {
          title: "🔐 Password Reset Completed",
          color: 0x27ae60,
          fields: [
            { name: "Username", value: user.username, inline: true },
            { name: "Name", value: `${user.firstName || ""} ${user.secondName || ""}`, inline: true },
            { name: "Source", value: isLocal ? "Local" : "MongoDB", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
            { name: "Time", value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"), inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.json({ success: true, message: "تم تغيير كلمة المرور بنجاح" });
  } catch (err) {
    console.error("[reset-password]", err);
    return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
  }
});

app.get(
  "/api/admin/users/:id/password-reset-links",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const userId = req.params.id;
      const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;
      let links = [];
      const localUser = await localUserStore.findById(userId);
      if (localUser) {
        links = await localUserStore.getPasswordResetLinks(userId);
      } else {
        const mongoUser = await UserRegistration.findById(userId).lean();
        if (mongoUser) {
          links = (mongoUser.passwordResetLinks || []).map((l) => ({
            token: l.token,
            verificationCode: l.verificationCode,
            verifiedAt: l.verifiedAt,
            expiresAt: l.expiresAt,
            createdAt: l.createdAt,
            createdBy: l.createdBy,
            usedAt: l.usedAt,
            supersededAt: l.supersededAt,
          }));
        }
      }
      const linkList = links.map((l) => ({
        ...l,
        url: `${baseUrl}/reset-password/${l.token}`,
        active: !l.usedAt && !l.supersededAt && l.expiresAt && new Date(l.expiresAt) > new Date(),
      }));
      return res.json({ success: true, links: linkList });
    } catch (err) {
      console.error("[password-reset-links]", err);
      return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
    }
  }
);

app.post(
  "/api/admin/users/:id/password-reset-link",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const userId = req.params.id;
      const adminUsername = (req.session && req.session.username) || "";
      const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      let linkUrl = null;
      let createdBy = adminUsername;
      let targetUsername = "";
      let isLocal = false;
      let verificationCode = null;
      const localUser = await localUserStore.findById(userId);
      if (localUser) {
        isLocal = true;
        targetUsername = localUser.username;
        const result = await localUserStore.createPasswordResetLink(userId, adminUsername);
        linkUrl = `${baseUrl}/reset-password/${result.token}`;
        verificationCode = result.verificationCode;
      } else {
        const mongoUser = await UserRegistration.findById(userId);
        if (!mongoUser) {
          return res.status(404).json({ success: false, message: "المستخدم غير موجود" });
        }
        targetUsername = mongoUser.username;
        const token = crypto.randomBytes(24).toString("hex");
        verificationCode = String(Math.floor(100000 + Math.random() * 900000));
        const links = (mongoUser.passwordResetLinks || []).map((l) => {
          const prev = typeof (l && l.toObject) === "function" ? l.toObject() : { ...l };
          return { ...prev, supersededAt: prev.supersededAt || new Date() };
        });
        links.push({
          token,
          verificationCode,
          verifiedAt: null,
          expiresAt,
          createdAt: new Date(),
          createdBy: adminUsername,
          usedAt: null,
          supersededAt: null,
        });
        await UserRegistration.updateOne(
          { _id: userId },
          { $set: { passwordResetLinks: links } }
        );
        linkUrl = `${baseUrl}/reset-password/${token}`;
      }
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🔗 Password Reset Link Generated",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: adminUsername, inline: true },
              { name: "Target User", value: targetUsername, inline: true },
              { name: "Expires", value: expiresAt.toISOString(), inline: true },
              { name: "Link", value: linkUrl ? `\`${linkUrl}\`` : "N/A", inline: false },
              { name: "Source", value: isLocal ? "Local" : "MongoDB", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.json({
        success: true,
        link: linkUrl,
        verificationCode,
        expiresAt: isLocal ? expiresAt.toISOString() : expiresAt.toISOString(),
        message: "تم إنشاء رابط تغيير كلمة المرور (صالح 7 أيام). الرابط السابق لم يعد صالحاً.",
      });
    } catch (err) {
      console.error("[password-reset-link]", err);
      return res.status(500).json({ success: false, message: err.message || "حدث خطأ" });
    }
  }
);

app.post(
  "/api/admin/users/:id/logout-all",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const registration = await UserRegistration.findById(req.params.id);
      if (!registration) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Logout All Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User ID", value: req.params.id, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      const activeSessions = await ActiveSession.find({
        username: registration.username.toLowerCase(),
      });

      const sessionStore = req.sessionStore;
      const destroyedSessions = [];

      if (sessionStore && sessionStore.destroy) {
        for (const session of activeSessions) {
          try {
            await new Promise((resolve, reject) => {
              sessionStore.destroy(session.sessionId, (err) => {
                if (err) {
                  console.error(
                    `[SESSION DESTROY ERROR] ${session.sessionId}:`,
                    err.message
                  );
                  reject(err);
                } else {
                  destroyedSessions.push(session.sessionId);
                  resolve();
                }
              });
            });
          } catch (sessionError) {
            console.error(
              `[SESSION DESTROY ERROR] ${session.sessionId}:`,
              sessionError.message
            );
          }
        }
      }

      const deletedSessions = await ActiveSession.deleteMany({
        username: registration.username.toLowerCase(),
      });

      const forms = await Form.find({});
      for (const form of forms) {
      }

      await sendWebhook("ADMIN", {
        content: `🚪 **Logged Out All User Sessions**`,
        embeds: [
          {
            title: "All User Sessions Logged Out",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Target User", value: registration.username },
              {
                name: "Name",
                value: `${registration.firstName} ${registration.secondName}`,
                inline: true,
              },
              { name: "Grade", value: registration.grade, inline: true },
              {
                name: "Active Sessions Found",
                value: activeSessions.length.toString(),
                inline: true,
              },
              {
                name: "Sessions Destroyed from Store",
                value: destroyedSessions.length.toString(),
                inline: true,
              },
              {
                name: "Database Records Removed",
                value: deletedSessions.deletedCount.toString(),
                inline: true,
              },
              {
                name: "Action",
                value: "Force Logout All Sessions",
                inline: true,
              },
              {
                name: "Logged Out At",
                value: new Date().toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({
        success: true,
        message: `تم تسجيل الخروج من جميع جلسات المستخدم (${deletedSessions.deletedCount} جلسة)`,
        sessionsRemoved: deletedSessions.deletedCount,
        sessionsDestroyed: destroyedSessions.length,
      });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Logout All Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "User ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res
        .status(500)
        .json({ success: false, message: "تعذر تسجيل الخروج من جميع الجلسات" });
    }
  }
);

app.get(
  "/api/admin/leaderboard/access",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🔓 Admin Fetching Leaderboard Access",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              {
                name: "Endpoint",
                value: "/api/admin/leaderboard/access",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const accessRecords = await LeaderboardAccess.find().sort({
        username: 1,
      });

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Leaderboard Access Fetched",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Records Found",
                value: accessRecords.length.toString(),
                inline: true,
              },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(accessRecords);
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Leaderboard Access Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "تعذر تحميل بيانات صلاحيات لوحة الصدارة" });
    }
  }
);

app.post(
  "/api/admin/leaderboard/access",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { username, hasLeaderboardAccess } = req.body;

      if (!username) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Leaderboard Access Update Failed - Missing Username",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Error", value: "Username is required", inline: true },
                {
                  name: "Access Action",
                  value: hasLeaderboardAccess ? "Grant" : "Revoke",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(400)
          .json({ success: false, message: "اسم المستخدم مطلوب" });
      }

      const normalizedUsername = username.toLowerCase();
      const user = await UserRegistration.findOne({
        username: normalizedUsername,
      });
      if (!user) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Leaderboard Access Update Failed - User Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Username", value: username, inline: true },
                { name: "Error", value: "User not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "المستخدم غير موجود" });
      }

      if (user.role === "student") {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Leaderboard Access Update Failed - Student Role",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "User", value: username, inline: true },
                { name: "User Role", value: user.role, inline: true },
                {
                  name: "Error",
                  value: "Cannot grant leaderboard access to students",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({
          success: false,
          message: "لا يمكن منح صلاحيات لوحة الصدارة للطلاب",
        });
      }

      let accessRecord = await LeaderboardAccess.findOne({
        username: normalizedUsername,
      });

      if (hasLeaderboardAccess) {
        if (!accessRecord) {
          accessRecord = new LeaderboardAccess({
            username: normalizedUsername,
            role: user.role,
            hasLeaderboardAccess: true,
            grantedBy: req.session.username,
            grantedAt: new Date(),
          });
        } else {
          accessRecord.hasLeaderboardAccess = true;
          accessRecord.grantedBy = req.session.username;
          accessRecord.grantedAt = new Date();
        }
        await accessRecord.save();

        await sendWebhook("ADMIN", {
          content: `🔓 **Leaderboard Access Granted**`,
          embeds: [
            {
              title: "Leaderboard Access Granted",
              color: 0x27ae60,
              fields: [
                { name: "Admin", value: req.session.username },
                { name: "User", value: username },
                {
                  name: "Name",
                  value: `${user.firstName} ${user.secondName}`,
                  inline: true,
                },
                { name: "Role", value: user.role },
                { name: "Access", value: "Granted" },
                {
                  name: "Granted At",
                  value: new Date().toLocaleString(),
                  inline: true,
                },
                {
                  name: "Previous Status",
                  value: accessRecord ? "Had Access" : "No Access",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });

        res.json({
          success: true,
          message: "تم منح صلاحيات لوحة الصدارة للمستخدم",
        });
      } else {
        if (accessRecord) {
          await LeaderboardAccess.deleteOne({ _id: accessRecord._id });
          await sendWebhook("ADMIN", {
            content: `🔒 **Leaderboard Access Revoked**`,
            embeds: [
              {
                title: "Leaderboard Access Revoked",
                color: 0xe74c3c,
                fields: [
                  { name: "Admin", value: req.session.username },
                  { name: "User", value: username },
                  {
                    name: "Name",
                    value: `${user.firstName} ${user.secondName}`,
                    inline: true,
                  },
                  { name: "Role", value: user.role },
                  { name: "Access", value: "Revoked" },
                  {
                    name: "Revoked At",
                    value: new Date().toLocaleString(),
                    inline: true,
                  },
                  {
                    name: "Previous Access Since",
                    value: accessRecord.grantedAt.toLocaleString(),
                    inline: true,
                  },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
        } else {
          await sendWebhook("ADMIN", {
            embeds: [
              {
                title: "ℹ️ Leaderboard Access Revoke - No Record Found",
                color: 0x95a5a6,
                fields: [
                  { name: "Admin", value: req.session.username, inline: true },
                  { name: "User", value: username, inline: true },
                  {
                    name: "Status",
                    value: "No access record to revoke",
                    inline: true,
                  },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
        }
        res.json({
          success: true,
          message: "تم إزالة صلاحيات لوحة الصدارة من المستخدم",
        });
      }
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Update Leaderboard Access Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Username", value: req.body.username || "Unknown" },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res
        .status(500)
        .json({ success: false, message: "تعذر تحديث صلاحيات لوحة الصدارة" });
    }
  }
);

app.get("/api/user-info", async (req, res) => {
  await sendWebhook("USER", {
    embeds: [
      {
        title: "👤 User Info Request",
        color: 0x3498db,
        fields: [
          { name: "Endpoint", value: "/api/user-info", inline: true },
          { name: "Method", value: "GET", inline: true },
          {
            name: "Authenticated",
            value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
            inline: true,
          },
          {
            name: "Username",
            value: req.session.username || "Guest",
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "User Agent",
            value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
            inline: false,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  if (req.session.isAuthenticated) {
    const user = getSessionUser(req);
    const allowedPages = user
      ? user.allowedPages
      : req.session.allowedPages || [];
    const leaderboardAccess = req.session.hasLeaderboardAccess || false;

    res.json({
      isAuthenticated: true,
      username: req.session.username,
      role: req.session.role,
      grade: req.session.grade || (user && user.grade) || null,
      gradeAccess: user ? user.gradeAccess : req.session.gradeAccess || [],
      allowedPages: allowedPages,
      hasLeaderboardAccess: leaderboardAccess,
      hasFormEditorRole:
        user &&
        (user.role === "leadadmin" ||
          (user.role === "admin" && allowedPages.includes("form-editor"))),
      hasUserApproverRole:
        user &&
        (user.role === "leadadmin" ||
          (user.role === "admin" && allowedPages.includes("user-approver"))),
      hasGiftApproverRole:
        user &&
        (user.role === "leadadmin" ||
          (user.role === "admin" && allowedPages.includes("gift-approver"))),
      landing: getDefaultLandingPath(user),
    });
  } else {
    res.json({ isAuthenticated: false });
  }
});

app.get("/api/announcements/:page", async (req, res) => {
  try {
    const { page } = req.params;

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📢 Announcements Request",
          color: 0x3498db,
          fields: [
            {
              name: "Endpoint",
              value: `/api/announcements/${page}`,
              inline: true,
            },
            { name: "Page", value: page, inline: true },
            {
              name: "Authenticated",
              value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    const announcements = await Announcement.find({ page })
      .sort({ timestamp: -1 })
      .limit(10);

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Announcements Fetched",
          color: 0x10b981,
          fields: [
            { name: "Page", value: page, inline: true },
            {
              name: "Announcements Found",
              value: announcements.length.toString(),
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json(announcements);
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Fetch Announcements Error",
          color: 0xe74c3c,
          fields: [
            { name: "Page", value: req.params.page },
            { name: "Error", value: error.message },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({ error: "Failed to fetch announcements" });
  }
});

app.post(
  "/api/announcements",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { page, title, content, priority } = req.body;

      if (!page || !title || !content) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Create Announcement Failed - Missing Fields",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Page", value: page || "Missing", inline: true },
                { name: "Title", value: title ? "✅" : "❌", inline: true },
                { name: "Content", value: content ? "✅" : "❌", inline: true },
                {
                  name: "Error",
                  value: "Missing required fields",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({ error: "Missing required fields" });
      }

      const announcement = new Announcement({
        page,
        title,
        content,
        author: req.session.username,
        priority: priority || "normal",
      });

      await announcement.save();

      await sendWebhook("ADMIN", {
        content: `📢 **New Announcement Created**`,
        embeds: [
          {
            title: "Announcement Created",
            color: 0x1abc9c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Page", value: page, inline: true },
              { name: "Title", value: title, inline: true },
              { name: "Priority", value: priority || "normal", inline: true },
              {
                name: "Content Preview",
                value:
                  content.substring(0, 200) +
                  (content.length > 200 ? "..." : ""),
                inline: false,
              },
              {
                name: "Created At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Announcement ID",
                value: announcement._id.toString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, announcement });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Create Announcement Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Page", value: req.body.page || "Unknown" },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "Failed to create announcement" });
    }
  }
);

app.delete(
  "/api/announcements/:id",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🗑️ Admin Deleting Announcement",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Announcement ID", value: req.params.id, inline: true },
              { name: "Action", value: "Delete Announcement", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const announcement = await Announcement.findById(req.params.id);
      if (!announcement) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Delete Announcement Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Announcement ID", value: req.params.id, inline: true },
                {
                  name: "Error",
                  value: "Announcement not found",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ success: false, message: "الإعلان غير موجود" });
      }
      await Announcement.deleteOne({ _id: announcement._id });

      await sendWebhook("ADMIN", {
        content: `🗑️ **Announcement Deleted**`,
        embeds: [
          {
            title: "Announcement Deleted",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Announcement Title", value: announcement.title },
              { name: "Page", value: announcement.page, inline: true },
              { name: "Author", value: announcement.author, inline: true },
              { name: "Priority", value: announcement.priority, inline: true },
              {
                name: "Created Date",
                value: announcement.timestamp.toLocaleString(),
                inline: true,
              },
              {
                name: "Deleted At",
                value: new Date().toLocaleString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Delete Announcement Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Announcement ID", value: req.params.id },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "Failed to delete announcement" });
    }
  }
);

app.get("/api/page-content/:page", async (req, res) => {
  try {
    const { page } = req.params;

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📄 Page Content Request",
          color: 0x3498db,
          fields: [
            {
              name: "Endpoint",
              value: `/api/page-content/${page}`,
              inline: true,
            },
            { name: "Page", value: page, inline: true },
            {
              name: "Authenticated",
              value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    let pageContent = await PageContent.findOne({ page });
    if (!pageContent) {
      pageContent = new PageContent({ page, content: "" });
      await pageContent.save();

      await sendWebhook("USER", {
        embeds: [
          {
            title: "🆕 Page Content Created",
            color: 0x10b981,
            fields: [
              { name: "Page", value: page, inline: true },
              { name: "Status", value: "New page created", inline: true },
              {
                name: "Username",
                value: req.session.username || "Guest",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
    } else {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "✅ Page Content Fetched",
            color: 0x10b981,
            fields: [
              { name: "Page", value: page, inline: true },
              {
                name: "Last Edited",
                value: pageContent.lastEdited.toLocaleString(),
                inline: true,
              },
              {
                name: "Edited By",
                value: pageContent.editedBy || "System",
                inline: true,
              },
              {
                name: "Content Length",
                value: `${pageContent.content.length} characters`,
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
    }

    res.json(pageContent);
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Fetch Page Content Error",
          color: 0xe74c3c,
          fields: [
            { name: "Page", value: req.params.page },
            { name: "Error", value: error.message },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({ error: "Failed to fetch page content" });
  }
});

app.put(
  "/api/page-content/:page",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { page } = req.params;
      const { content } = req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✏️ Admin Updating Page Content",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Page", value: page, inline: true },
              {
                name: "Content Length",
                value: content?.length.toString() || "0",
                inline: true,
              },
              { name: "Action", value: "Update Page Content", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      let pageContent = await PageContent.findOne({ page });
      const previousContent = pageContent ? pageContent.content : "";
      const previousEditedBy = pageContent ? pageContent.editedBy : "System";
      const previousEditDate = pageContent
        ? pageContent.lastEdited
        : new Date();

      if (pageContent) {
        pageContent.content = content;
        pageContent.lastEdited = new Date();
        pageContent.editedBy = req.session.username;
      } else {
        pageContent = new PageContent({
          page,
          content,
          editedBy: req.session.username,
        });
      }

      await pageContent.save();

      await sendWebhook("ADMIN", {
        content: `✏️ **Page Content Updated**`,
        embeds: [
          {
            title: "Page Content Updated",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Page", value: page },
              {
                name: "Previous Editor",
                value: previousEditedBy,
                inline: true,
              },
              { name: "New Editor", value: req.session.username, inline: true },
              {
                name: "Previous Edit Date",
                value: previousEditDate.toLocaleString(),
                inline: true,
              },
              {
                name: "New Edit Date",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Previous Content Length",
                value: `${previousContent.length} characters`,
                inline: true,
              },
              {
                name: "New Content Length",
                value: `${content.length} characters`,
                inline: true,
              },
              {
                name: "Content Preview",
                value:
                  content.substring(0, 200) +
                  (content.length > 200 ? "..." : ""),
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, pageContent });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Update Page Content Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Page", value: req.params.page },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ error: "Failed to update page content" });
    }
  }
);


GRADE_SLUGS.forEach((slug) => {
  app.get(`/${slug}`, requireAuth, async (req, res) => {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "🔀 Grade Slug Redirect",
          color: 0x3498db,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Grade Slug", value: slug, inline: true },
            { name: "From Path", value: `/${slug}`, inline: true },
            { name: "To Path", value: `/grades/${slug}`, inline: true },
            { name: "Redirect Type", value: "302 Temporary", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.redirect(`/grades/${slug}`);
  });
});

app.get("/grades/:gradeSlug", requireAuth, async (req, res) => {
  const normalizedSlug = normalizeGradeSlug(req.params.gradeSlug);
  if (!normalizedSlug) {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "❌ Grade Page - Invalid Slug",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            {
              name: "Requested Slug",
              value: req.params.gradeSlug,
              inline: true,
            },
            { name: "Normalized Slug", value: "null", inline: true },
            {
              name: "Valid Slugs",
              value: GRADE_SLUGS.join(", "),
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(404).sendFile(path.join(__dirname, "views", "404.html"));
  }

  const user = getSessionUser(req);
  if (!userHasGradeAccess(user, normalizedSlug)) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "🚫 Unauthorized Grade Access",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "User Role", value: user?.role || "Unknown", inline: true },
            { name: "User Grade", value: user?.grade || "None", inline: true },
            { name: "Requested Grade", value: normalizedSlug, inline: true },
            {
              name: "User Grade Access",
              value: user?.gradeAccess?.join(", ") || "None",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).sendFile(path.join(__dirname, "views", "403.html"));
  }

  await sendWebhook("USER", {
    embeds: [
      {
        title: "📚 Grade Dashboard Accessed",
        color: 0x3498db,
        fields: [
          { name: "Username", value: req.session.username, inline: true },
          { name: "User Role", value: user.role, inline: true },
          { name: "Grade Slug", value: normalizedSlug, inline: true },
          {
            name: "Grade Label",
            value: GRADE_LABELS[normalizedSlug]?.short || normalizedSlug,
            inline: true,
          },
          { name: "Path", value: `/grades/${normalizedSlug}`, inline: true },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  res.render("grade-dashboard", {
    gradeSlug: normalizedSlug,
    gradeMeta: gradeBlueprints[normalizedSlug] || {},
    gradeLabel: GRADE_LABELS[normalizedSlug] || {},
    user: {
      username: req.session.username,
      role: req.session.role,
      grade: req.session.grade || null,
    },
  });
});

app.get(
  "/grades/:gradeSlug/suggestion/ektm3at",
  requireAuth,
  async (req, res) => {
    const normalizedSlug = normalizeGradeSlug(req.params.gradeSlug);
    if (!normalizedSlug) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Grade Suggestion Page - Invalid Slug",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "Requested Slug",
                value: req.params.gradeSlug,
                inline: true,
              },
              { name: "Normalized Slug", value: "null", inline: true },
              { name: "Page", value: "Suggestion Ektm3at", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(404)
        .sendFile(path.join(__dirname, "views", "404.html"));
    }

    const user = getSessionUser(req);
    if (!userHasGradeAccess(user, normalizedSlug)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Unauthorized Grade Suggestion Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              { name: "Requested Grade", value: normalizedSlug, inline: true },
              { name: "Page", value: "Grade Suggestion Ektm3at", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(403)
        .sendFile(path.join(__dirname, "views", "403.html"));
    }

    await sendWebhook("USER", {
      embeds: [
        {
          title: "💡 Grade Suggestion Page Accessed",
          color: 0x3498db,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Grade Slug", value: normalizedSlug, inline: true },
            {
              name: "Grade Label",
              value: GRADE_LABELS[normalizedSlug]?.short || normalizedSlug,
              inline: true,
            },
            { name: "Page", value: "Ektm3at Suggestion", inline: true },
            {
              name: "Path",
              value: `/grades/${normalizedSlug}/suggestion/ektm3at`,
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.render("ektm3at-suggestion", {
      gradeSlug: normalizedSlug,
      gradeLabel: GRADE_LABELS[normalizedSlug] || {},
      gradeMeta: gradeBlueprints[normalizedSlug] || {},
      user: {
        username: req.session.username,
        role: req.session.role,
        grade: req.session.grade || null,
      },
    });
  }
);

app.post(
  "/api/suggestions",
  requireAuth,
  submissionLimiter,
  async (req, res) => {
    try {
      const user = getSessionUser(req);
      if (!user) {
        await sendWebhook("SECURITY", {
          embeds: [
            {
              title: "❌ Suggestion Submission - No User",
              color: 0xe74c3c,
              fields: [
                { name: "Endpoint", value: "/api/suggestions", inline: true },
                { name: "Method", value: "POST", inline: true },
                {
                  name: "Error",
                  value: "User not found in session",
                  inline: true,
                },
                { name: "IP", value: req.ip || "unknown", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(401).json({ success: false, message: "غير مصرح" });
      }

      const { text, category } = req.body;
      const suggestionText = (text || "").trim();

      await sendWebhook("USER", {
        embeds: [
          {
            title: "💡 New Suggestion Attempt",
            color: 0xf59e0b,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Role", value: user.role, inline: true },
              { name: "Grade", value: user.grade || "N/A", inline: true },
              { name: "Category", value: category || "meeting", inline: true },
              {
                name: "Text Length",
                value: suggestionText.length.toString(),
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      if (suggestionText.length < 5) {
        await sendWebhook("USER", {
          embeds: [
            {
              title: "❌ Suggestion Submission - Too Short",
              color: 0xe74c3c,
              fields: [
                { name: "Username", value: req.session.username, inline: true },
                {
                  name: "Text Length",
                  value: suggestionText.length.toString(),
                  inline: true,
                },
                { name: "Minimum Required", value: "5", inline: true },
                {
                  name: "Category",
                  value: category || "meeting",
                  inline: true,
                },
                { name: "Error", value: "Text too short", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(400)
          .json({ success: false, message: "اكتب اقتراحاً أوضح." });
      }
      if (suggestionText.length > 600) {
        await sendWebhook("USER", {
          embeds: [
            {
              title: "❌ Suggestion Submission - Too Long",
              color: 0xe74c3c,
              fields: [
                { name: "Username", value: req.session.username, inline: true },
                {
                  name: "Text Length",
                  value: suggestionText.length.toString(),
                  inline: true,
                },
                { name: "Maximum Allowed", value: "600", inline: true },
                {
                  name: "Category",
                  value: category || "meeting",
                  inline: true,
                },
                { name: "Error", value: "Text too long", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(400)
          .json({ success: false, message: "الحد الأقصى 600 حرف." });
      }

      const normalizedCategory = category || "meeting";
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 7);

      const recent = await Suggestion.findOne({
        username: (req.session.username || "").toLowerCase(),
        category: normalizedCategory,
        createdAt: { $gte: cutoff },
      });

      if (recent) {
        const duplicateEmbed = {
          title: "⏰ Suggestion Submission - Rate Limited",
          color: 0xf59e0b,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Category", value: normalizedCategory, inline: true },
            {
              name: "Last Submission",
              value: recent.createdAt.toLocaleString(),
              inline: true,
            },
            {
              name: "Time Since Last",
              value: `${Math.floor(
                (new Date() - recent.createdAt) / (1000 * 60 * 60 * 24)
              )} days`,
              inline: true,
            },
            {
              name: "Limit",
              value: "1 suggestion per week per category",
              inline: false,
            },
            { name: "Error", value: "Rate limited", inline: true },
            {
              name: "Attempted Text",
              value: suggestionText.substring(0, 1024) || "No text",
              inline: false,
            },
          ],
          timestamp: new Date().toISOString(),
        };

        await sendWebhook("USER", { embeds: [duplicateEmbed] });
        await sendWebhook("SUGGESTION", {
          content: "♻️ Duplicate suggestion attempt blocked",
          embeds: [
            {
              ...duplicateEmbed,
              title: "♻️ Duplicate Suggestion Attempt",
            },
          ],
        });
        return res.status(429).json({
          success: false,
          message: "يمكنك إرسال اقتراح واحد فقط كل أسبوع لنفس القسم.",
        });
      }

      let displayName = req.session.displayName || req.session.username || "";
      try {
        const profile = await UserRegistration.findOne({
          username: (req.session.username || "").toLowerCase(),
        });
        if (profile) {
          displayName = `${profile.firstName} ${profile.secondName}`.trim();
        }
      } catch (err) {
        console.error("[SUGGESTION PROFILE ERROR]", err.message);
      }

      const userGrade = user.grade || req.session.grade || null;
      const gradeLabel = userGrade
        ? GRADE_LABELS[userGrade]?.long || userGrade
        : "N/A";

      const saved = await Suggestion.create({
        username: (req.session.username || "").toLowerCase(),
        displayName,
        grade: userGrade,
        category: normalizedCategory,
        text: suggestionText,
      });

      const suggestionPayload = {
        content: `💡 **New Suggestion Submitted**`,
        embeds: [
          {
            title: "New Suggestion",
            color: 0x9b59b6,
            fields: [
              { name: "Display Name", value: displayName, inline: true },
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "Role",
                value: user.role ? user.role.toUpperCase() : "STUDENT",
                inline: true,
              },
              { name: "Grade", value: gradeLabel, inline: true },
              { name: "Category", value: normalizedCategory, inline: true },
              {
                name: "Submitted At",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
              {
                name: "Suggestion ID",
                value: saved._id.toString(),
                inline: true,
              },
              {
                name: "Text Length",
                value: `${suggestionText.length} characters`,
                inline: true,
              },
              {
                name: "Suggestion",
                value: suggestionText.substring(0, 1024) || "No text",
                inline: false,
              },
              { name: "IP Address", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      };

      const suggestionLogged = await sendWebhook(
        "SUGGESTION",
        suggestionPayload,
        {
          awaitResponse: true,
        }
      );
      if (!suggestionLogged) {
        await sendWebhook("USER", suggestionPayload);
      }

      return res.json({ success: true, suggestion: saved });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Suggestion Error",
            color: 0xe74c3c,
            fields: [
              { name: "User", value: req.session.username || "Unknown" },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "تعذر حفظ الاقتراح" });
    }
  }
);

app.get(
  "/api/suggestions",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { category = "all", grade = "all", search = "" } = req.query;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "💡 Admin Fetching Suggestions",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              { name: "Category Filter", value: category, inline: true },
              { name: "Grade Filter", value: grade, inline: true },
              { name: "Search Term", value: search || "None", inline: true },
              { name: "Endpoint", value: "/api/suggestions", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const query = {};
      if (category !== "all") {
        query.category = category;
      }
      if (grade !== "all") {
        const normalized = normalizeGradeSlug(grade);
        if (normalized) {
          query.grade = normalized;
        }
      }
      if (search) {
        const regex = new RegExp(search.trim(), "i");
        query.$or = [
          { displayName: regex },
          { username: regex },
          { text: regex },
        ];
      }

      const suggestions = await Suggestion.find(query)
        .sort({ createdAt: -1 })
        .limit(500);

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Fetched Suggestions",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Suggestions Found",
                value: suggestions.length.toString(),
                inline: true,
              },
              { name: "Category Filter", value: category, inline: true },
              { name: "Grade Filter", value: grade, inline: true },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      return res.json({ success: true, suggestions });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Suggestions Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "تعذر تحميل الاقتراحات" });
    }
  }
);

app.post("/api/nady", spamBlocker, async (req, res) => {
  const { description } = req.body;
  const userId = crypto
    .createHash("sha256")
    .update(req.headers["user-agent"] + req.ip)
    .digest("hex");

  await sendWebhook("USER", {
    embeds: [
      {
        title: "🌟 Nady Suggestion Attempt",
        color: 0xf59e0b,
        fields: [
          { name: "Endpoint", value: "/api/nady", inline: true },
          {
            name: "Description Length",
            value: description?.length.toString() || "0",
            inline: true,
          },
          {
            name: "User Hash",
            value: userId.substring(0, 16) + "...",
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  if (!description) {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "❌ Nady Suggestion Failed - Missing Description",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/nady", inline: true },
            { name: "Error", value: "Description is required", inline: true },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(400).json({ message: "All fields are required." });
  }

  const embed = {
    embeds: [
      {
        title: "🌟 اقتراح جديد!",
        color: 0x1abc9c,
        fields: [
          {
            name: "📝 الوصف",
            value: description || "لم يتم تقديم وصف.",
            inline: false,
          },
          {
            name: "👤 رقم المستخدم",
            value: userId || "مستخدم غير معروف",
            inline: true,
          },
          {
            name: "📊 وصف الطول",
            value: `${description.length} حرف`,
            inline: true,
          },
          {
            name: "🕐 الوقت",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
          { name: "Category", value: "nady", inline: true },
        ],
      },
    ],
  };

  try {
    const delivered = await sendWebhook("SUGGESTION", embed, {
      awaitResponse: true,
    });
    if (delivered) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "✅ Nady Suggestion Sent Successfully",
            color: 0x10b981,
            fields: [
              { name: "Endpoint", value: "/api/nady", inline: true },
              {
                name: "Description Length",
                value: description.length.toString(),
                inline: true,
              },
              {
                name: "User Hash",
                value: userId.substring(0, 16) + "...",
                inline: true,
              },
              {
                name: "Webhook Delivery",
                value: "Success",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(200)
        .json({ message: "لقد انتهيت و تم إرسال اقتراحك بنجاح" });
    }
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "⚠️ Nady Suggestion Delivery Failed",
          color: 0xf59e0b,
          fields: [
            { name: "Endpoint", value: "/api/nady", inline: true },
            {
              name: "Description Length",
              value: description.length.toString(),
              inline: true,
            },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(500).json({ message: "Failed to submit request." });
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Nady Suggestion Error",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/nady", inline: true },
            { name: "Error", value: error.message, inline: false },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    console.error("Nady submission error:", error);
    return res.status(500).json({ message: "Error submitting request." });
  }
});

app.post("/api/trip", spamBlocker, async (req, res) => {
  const { description } = req.body;
  const userId = crypto
    .createHash("sha256")
    .update(req.headers["user-agent"] + req.ip)
    .digest("hex");

  await sendWebhook("USER", {
    embeds: [
      {
        title: "✈️ Trip Suggestion Attempt",
        color: 0xf59e0b,
        fields: [
          { name: "Endpoint", value: "/api/trip", inline: true },
          {
            name: "Description Length",
            value: description?.length.toString() || "0",
            inline: true,
          },
          {
            name: "User Hash",
            value: userId.substring(0, 16) + "...",
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  if (!description) {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "❌ Trip Suggestion Failed - Missing Description",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/trip", inline: true },
            { name: "Error", value: "Description is required", inline: true },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(400).json({ message: "All fields are required." });
  }

  const embed = {
    embeds: [
      {
        title: "🌟 اقتراح جديد!",
        color: 0x1abc9c,
        fields: [
          {
            name: "📝 الوصف",
            value: description || "لم يتم تقديم وصف.",
            inline: false,
          },
          {
            name: "👤 رقم المستخدم",
            value: userId || "مستخدم غير معروف",
            inline: true,
          },
          {
            name: "📊 وصف الطول",
            value: `${description.length} حرف`,
            inline: true,
          },
          {
            name: "🕐 الوقت",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
          { name: "Category", value: "trip", inline: true },
        ],
      },
    ],
  };

  try {
    const delivered = await sendWebhook("SUGGESTION", embed, {
      awaitResponse: true,
    });
    if (delivered) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "✅ Trip Suggestion Sent Successfully",
            color: 0x10b981,
            fields: [
              { name: "Endpoint", value: "/api/trip", inline: true },
              {
                name: "Description Length",
                value: description.length.toString(),
                inline: true,
              },
              {
                name: "User Hash",
                value: userId.substring(0, 16) + "...",
                inline: true,
              },
              {
                name: "Webhook Delivery",
                value: "Success",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(200)
        .json({ message: "لقد انتهيت و تم إرسال اقتراحك بنجاح" });
    }
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "⚠️ Trip Suggestion Delivery Failed",
          color: 0xf59e0b,
          fields: [
            { name: "Endpoint", value: "/api/trip", inline: true },
            {
              name: "Description Length",
              value: description.length.toString(),
              inline: true,
            },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(500).json({ message: "Failed to submit request." });
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Trip Suggestion Error",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/trip", inline: true },
            { name: "Error", value: error.message, inline: false },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    console.error("Trip submission error:", error);
    return res.status(500).json({ message: "Error submitting request." });
  }
});

app.post("/api/ektmaa", spamBlocker, async (req, res) => {
  const { description } = req.body;
  const userId = crypto
    .createHash("sha256")
    .update(req.headers["user-agent"] + req.ip)
    .digest("hex");

  await sendWebhook("USER", {
    embeds: [
      {
        title: "🤝 Ektmaa Suggestion Attempt",
        color: 0xf59e0b,
        fields: [
          { name: "Endpoint", value: "/api/ektmaa", inline: true },
          {
            name: "Description Length",
            value: description?.length.toString() || "0",
            inline: true,
          },
          {
            name: "User Hash",
            value: userId.substring(0, 16) + "...",
            inline: true,
          },
          { name: "IP", value: req.ip || "unknown", inline: true },
          {
            name: "Webhook URL",
            value: webhookURL ? "✅ Set" : "❌ Missing",
            inline: true,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  if (!description) {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "❌ Ektmaa Suggestion Failed - Missing Description",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/ektmaa", inline: true },
            { name: "Error", value: "Description is required", inline: true },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(400).json({ message: "All fields are required." });
  }

  const embed = {
    embeds: [
      {
        title: "🌟 اقتراح جديد!",
        color: 0x1abc9c,
        fields: [
          {
            name: "📝 الوصف",
            value: description || "لم يتم تقديم وصف.",
            inline: false,
          },
          {
            name: "👤 رقم المستخدم",
            value: userId || "مستخدم غير معروف",
            inline: true,
          },
          {
            name: "📊 وصف الطول",
            value: `${description.length} حرف`,
            inline: true,
          },
          {
            name: "🕐 الوقت",
            value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
            inline: true,
          },
        ],
      },
    ],
  };

  try {
    const delivered = await sendWebhook("SUGGESTION", {
      ...embed,
      embeds: (embed.embeds || []).map((e) => ({
        ...e,
        fields: [
          { name: "Category", value: "ektmaa", inline: true },
          ...(e.fields || []),
        ],
      })),
    }, { awaitResponse: true });
    if (delivered) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "✅ Ektmaa Suggestion Sent Successfully",
            color: 0x10b981,
            fields: [
              { name: "Endpoint", value: "/api/ektmaa", inline: true },
              {
                name: "Description Length",
                value: description.length.toString(),
                inline: true,
              },
              {
                name: "User Hash",
                value: userId.substring(0, 16) + "...",
                inline: true,
              },
              {
                name: "Webhook Delivery",
                value: "Success",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(200)
        .json({ message: "لقد انتهيت و تم إرسال اقتراحك بنجاح" });
    }
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "⚠️ Ektmaa Suggestion Delivery Failed",
          color: 0xf59e0b,
          fields: [
            { name: "Endpoint", value: "/api/ektmaa", inline: true },
            {
              name: "Description Length",
              value: description.length.toString(),
              inline: true,
            },
            {
              name: "Webhook Configured",
              value: webhookURL ? "✅ Yes" : "❌ No",
              inline: true,
            },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(500).json({ message: "Failed to submit request." });
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Ektmaa Suggestion Error",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/ektmaa", inline: true },
            { name: "Error", value: error.message, inline: false },
            {
              name: "User Hash",
              value: userId.substring(0, 16) + "...",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    console.error("Ektmaa submission error:", error);
    return res.status(500).json({ message: "Error submitting request." });
  }
});

app.get("/api/forms/active", async (req, res) => {
  try {
    const user = req.session.isAuthenticated ? getSessionUser(req) : null;
    const now = new Date();

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📋 Active Forms Request",
          color: 0x3498db,
          fields: [
            { name: "Endpoint", value: "/api/forms/active", inline: true },
            {
              name: "Authenticated",
              value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
            { name: "User Role", value: user?.role || "Guest", inline: true },
            { name: "User Grade", value: user?.grade || "N/A", inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    const query = {
      status: "published",
      $and: [
        {
          $or: [{ expiry: null }, { expiry: { $gt: now } }],
        },
      ],
    };

    const candidateForms = await Form.find(query).sort({ updatedAt: -1 }).limit(50);
    const forms = candidateForms.filter((form) => canUserAccessForm(user, form));

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Active Forms Fetched",
          color: 0x10b981,
          fields: [
            { name: "Endpoint", value: "/api/forms/active", inline: true },
            {
              name: "Forms Found",
              value: forms.length.toString(),
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
            {
              name: "Query Conditions",
              value: JSON.stringify(query.$and).substring(0, 200) + "...",
              inline: false,
            },
            {
              name: "Timestamp",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json(
      forms.map((form) => ({
        id: form.link,
        topic: form.topic,
        description: form.description || "",
        link: form.link,
        expiry: form.expiry,
        updatedAt: form.updatedAt,
        allowRetake: form.allowRetake,
        targetGrade: form.targetGrade,
        allowedGrades: Array.isArray(form.allowedGrades) ? form.allowedGrades : (form.targetGrade === "all" ? [] : [form.targetGrade]),
      }))
    );
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Fetch Active Forms Error",
          color: 0xe74c3c,
          fields: [
            { name: "Endpoint", value: "/api/forms/active" },
            { name: "Error", value: error.message },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({ message: "تعذر تحميل النماذج" });
  }
});

app.get("/api/forms/active/:gradeSlug", requireAuth, async (req, res) => {
  try {
    const gradeSlug = normalizeGradeSlug(req.params.gradeSlug);

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📋 Grade Active Forms Request",
          color: 0x3498db,
          fields: [
            {
              name: "Endpoint",
              value: `/api/forms/active/${req.params.gradeSlug}`,
              inline: true,
            },
            {
              name: "Requested Grade",
              value: req.params.gradeSlug,
              inline: true,
            },
            {
              name: "Normalized Grade",
              value: gradeSlug || "Invalid",
              inline: true,
            },
            { name: "Username", value: req.session.username, inline: true },
            { name: "User Role", value: req.session.role, inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    if (!gradeSlug) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Grade Forms - Invalid Grade Slug",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "Requested Grade",
                value: req.params.gradeSlug,
                inline: true,
              },
              { name: "Normalized Grade", value: "null", inline: true },
              {
                name: "Valid Grades",
                value: GRADE_SLUGS.join(", "),
                inline: false,
              },
              { name: "Error", value: "Grade not found", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(404).json({ message: "الصف غير موجود" });
    }

    const user = getSessionUser(req);
    if (!userHasGradeAccess(user, gradeSlug)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Unauthorized Grade Forms Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              {
                name: "User Grade",
                value: user?.grade || "None",
                inline: true,
              },
              { name: "Requested Grade", value: gradeSlug, inline: true },
              {
                name: "User Grade Access",
                value: user?.gradeAccess?.join(", ") || "None",
                inline: false,
              },
              { name: "Error", value: "No grade access", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(403)
        .json({ message: "غير مصرح لك بالاطلاع على هذه النماذج" });
    }

    const now = new Date();
    const candidateForms = await Form.find({
      status: "published",
      $and: [
        {
          $or: [{ expiry: null }, { expiry: { $gt: now } }],
        },
      ],
    }).sort({ updatedAt: -1 });

    const forms = candidateForms.filter((form) => {
      if (!canUserAccessForm(user, form)) return false;
      const allowedGrades = Array.isArray(form.allowedGrades)
        ? form.allowedGrades.map((g) => normalizeGradeSlug(g)).filter(Boolean)
        : [];
      if (allowedGrades.length > 0) {
        return allowedGrades.includes(gradeSlug);
      }
      const target = normalizeFormTarget(form.targetGrade || "all");
      return target === "all" || target === gradeSlug;
    });

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Grade Forms Fetched",
          color: 0x10b981,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Grade", value: gradeSlug, inline: true },
            {
              name: "Forms Found",
              value: forms.length.toString(),
              inline: true,
            },
            {
              name: "Grade Label",
              value: GRADE_LABELS[gradeSlug]?.short || gradeSlug,
              inline: true,
            },
            {
              name: "Timestamp",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json(
      forms.map((form) => ({
        id: form.link,
        topic: form.topic,
        title: form.topic,
        description: form.description || "",
        link: form.link,
        expiry: form.expiry,
        deadline: form.expiry,
        updatedAt: form.updatedAt,
        allowRetake: form.allowRetake,
        targetGrade: form.targetGrade,
        status: "active",
      }))
    );
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Fetch Grade Forms Error",
          color: 0xe74c3c,
          fields: [
            { name: "User", value: req.session.username },
            { name: "Grade", value: req.params.gradeSlug },
            { name: "Error", value: error.message },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({ message: "تعذر تحميل النماذج الخاصة بالصف" });
  }
});

app.get("/api/grades/:gradeSlug/forms", requireAuth, async (req, res) => {
  try {
    const gradeSlug = normalizeGradeSlug(req.params.gradeSlug);

    await sendWebhook("USER", {
      embeds: [
        {
          title: "📋 Grade Forms Request",
          color: 0x3498db,
          fields: [
            {
              name: "Endpoint",
              value: `/api/grades/${req.params.gradeSlug}/forms`,
              inline: true,
            },
            {
              name: "Requested Grade",
              value: req.params.gradeSlug,
              inline: true,
            },
            {
              name: "Normalized Grade",
              value: gradeSlug || "Invalid",
              inline: true,
            },
            { name: "Username", value: req.session.username, inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    if (!gradeSlug) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Grade Forms - Invalid Slug",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "Requested Grade",
                value: req.params.gradeSlug,
                inline: true,
              },
              { name: "Error", value: "Grade not found", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(404).json({ message: "الصف غير موجود" });
    }

    const user = getSessionUser(req);
    if (!userHasGradeAccess(user, gradeSlug)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Unauthorized Grade Forms Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              { name: "Requested Grade", value: gradeSlug, inline: true },
              { name: "Error", value: "No access to this grade", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(403)
        .json({ message: "غير مصرح لك بالاطلاع على هذه النماذج" });
    }

    const now = new Date();
    const forms = await Form.find({
      status: "published",
      $and: [
        {
          $or: [{ targetGrade: "all" }, { targetGrade: gradeSlug }],
        },
        {
          $or: [{ expiry: null }, { expiry: { $gt: now } }],
        },
      ],
    }).sort({ updatedAt: -1 });

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Grade Forms Fetched",
          color: 0x10b981,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Grade", value: gradeSlug, inline: true },
            {
              name: "Forms Found",
              value: forms.length.toString(),
              inline: true,
            },
            {
              name: "Timestamp",
              value: moment().tz("Africa/Cairo").format("YYYY-MM-DD HH:mm:ss"),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.json(
      forms.map((form) => ({
        topic: form.topic,
        description: form.description,
        link: form.link,
        expiry: form.expiry,
        updatedAt: form.updatedAt,
        allowRetake: form.allowRetake,
        targetGrade: form.targetGrade,
      }))
    );
  } catch (error) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Fetch Grade Forms Error",
          color: 0xe74c3c,
          fields: [
            { name: "User", value: req.session.username },
            { name: "Grade", value: req.params.gradeSlug },
            { name: "Error", value: error.message },
            {
              name: "Stack Trace",
              value: error.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({ message: "تعذر تحميل النماذج الخاصة بالصف" });
  }
});

app.get(
  "/api/forms",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "📋 Admin Fetching All Forms",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              { name: "Endpoint", value: "/api/forms", inline: true },
              { name: "Action", value: "Fetch all forms", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const now = new Date();
      const allForms = await Form.find().sort({ updatedAt: -1 });

      const activeForms = [];
      const expiredForms = [];

      allForms.forEach((form) => {
        const isExpired = form.expiry && new Date(form.expiry) < now;
        if (isExpired) {
          expiredForms.push(serializeForm(form));
        } else {
          activeForms.push(serializeForm(form));
        }
      });

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Fetched All Forms",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Total Forms",
                value: allForms.length.toString(),
                inline: true,
              },
              {
                name: "Active Forms",
                value: activeForms.length.toString(),
                inline: true,
              },
              {
                name: "Expired Forms",
                value: expiredForms.length.toString(),
                inline: true,
              },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({
        active: activeForms,
        expired: expiredForms,
      });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Forms Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ message: "تعذر تحميل النماذج" });
    }
  }
);

app.post(
  "/api/forms",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const {
        topic,
        expiry,
        questions,
        description,
        targetGrade,
        allowedGrades,
        status,
        allowRetake,
      } = req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "📝 Admin Creating Form",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Topic", value: topic || "Not provided", inline: true },
              {
                name: "Target Grade",
                value: targetGrade || "all",
                inline: true,
              },
              {
                name: "Questions Count",
                value: questions?.length.toString() || "0",
                inline: true,
              },
              { name: "Action", value: "Create Form", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const expiryDate = parseExpiryDate(expiry);

      if (!topic) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Create Form Failed - Missing Topic",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Error", value: "Topic is required", inline: true },
                {
                  name: "Target Grade",
                  value: targetGrade || "all",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({ message: "يرجى إدخال اسم للنموذج" });
      }

      const existingForm = await Form.findOne({ topic: topic.trim() });
      if (existingForm) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Create Form Failed - Duplicate Topic",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Topic", value: topic, inline: true },
                {
                  name: "Existing Form Link",
                  value: existingForm.link,
                  inline: true,
                },
                {
                  name: "Existing Form Status",
                  value: existingForm.status,
                  inline: true,
                },
                { name: "Error", value: "Duplicate topic", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(400)
          .json({ message: "يوجد نموذج بنفس الاسم بالفعل" });
      }

      const sanitizedQuestions = sanitizeQuestions(questions);
      const normalizedStatus = "published";
      const normalizedTarget = normalizeFormTarget(targetGrade);
      const normalizedAllowedGrades = Array.isArray(allowedGrades)
        ? allowedGrades.map((g) => normalizeGradeSlug(g)).filter(Boolean)
        : [];
      const link = uuidv4();

      const newForm = new Form({
        topic: topic.trim(),
        expiry: expiryDate,
        description: description || "",
        targetGrade: normalizedTarget,
        allowedGrades: normalizedAllowedGrades,
        status: normalizedStatus,
        allowRetake: Boolean(allowRetake),
        questions: sanitizedQuestions,
        link,
        createdBy: req.session.username,
        updatedBy: req.session.username,
        updatedAt: new Date(),
      });

      await newForm.save();

      const user = getSessionUser(req);
      const gradeLabel =
        GRADE_LABELS[newForm.targetGrade]?.long || newForm.targetGrade;

      await sendWebhook("FORM", {
        content: `📝 **New Form Created**`,
        embeds: [
          {
            title: "Form Created",
            color: 0x1abc9c,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Role",
                value: user ? user.role.toUpperCase() : "ADMIN",
                inline: true,
              },
              { name: "Form Name", value: newForm.topic, inline: true },
              {
                name: "Target Grade",
                value: gradeLabel || newForm.targetGrade,
                inline: true,
              },
              { name: "Status", value: newForm.status, inline: true },
              {
                name: "Questions Count",
                value: `${newForm.questions.length}`,
                inline: true,
              },
              {
                name: "Total Points",
                value: `${newForm.questions.reduce(
                  (sum, q) => sum + (q.points || 10),
                  0
                )}`,
                inline: true,
              },
              {
                name: "Form Link",
                value: `${req.protocol}://${req.get("host")}/form/${newForm.link
                  }`,
                inline: false,
              },
              {
                name: "Expiry Date",
                value: newForm.expiry
                  ? new Date(newForm.expiry).toLocaleString("ar-EG")
                  : "No expiry",
                inline: true,
              },
              {
                name: "Created At",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
              { name: "Form ID", value: newForm._id.toString(), inline: true },
              {
                name: "Questions Types",
                value: newForm.questions.map((q) => q.questionType).join(", "),
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({
        success: true,
        form: serializeForm(newForm),
        shareUrl: `${req.protocol}://${req.get("host")}/form/${link}`,
      });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Create Form Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Topic", value: req.body.topic || "Unknown" },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(400).json({
        success: false,
        message: error.message || "تعذر إنشاء النموذج",
      });
    }
  }
);

app.get(
  "/api/forms/:link",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "📋 Admin Fetching Form Details",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Form Link", value: req.params.link, inline: true },
              {
                name: "Endpoint",
                value: `/api/forms/${req.params.link}`,
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      let form = await Form.findOne({ link: req.params.link });
      if (!form && mongoose.Types.ObjectId.isValid(req.params.link)) {
        form = await Form.findById(req.params.link);
      }
      if (!form) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Fetch Form Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Form Link", value: req.params.link, inline: true },
                { name: "Error", value: "Form not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(404).json({ message: "النموذج غير موجود" });
      }

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Form Details Fetched",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: form.link, inline: true },
              { name: "Status", value: form.status, inline: true },
              {
                name: "Questions",
                value: form.questions.length.toString(),
                inline: true,
              },
              {
                name: "Submissions",
                value: form.submissions.length.toString(),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(serializeForm(form));
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Form Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ message: "تعذر تحميل النموذج" });
    }
  }
);

app.put(
  "/api/forms/:link",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const {
        topic,
        expiry,
        questions,
        description,
        targetGrade,
        allowedGrades,
        status,
        allowRetake,
      } = req.body;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✏️ Admin Updating Form",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Form Link", value: req.params.link, inline: true },
              { name: "Topic", value: topic || "No change", inline: true },
              {
                name: "Questions Count",
                value: questions?.length.toString() || "No change",
                inline: true,
              },
              { name: "Action", value: "Update Form", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const form = await Form.findOne({ link: req.params.link });
      if (!form) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Update Form Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Form Link", value: req.params.link, inline: true },
                { name: "Error", value: "Form not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(404).json({ message: "النموذج غير موجود" });
      }

      const expiryDate = parseExpiryDate(expiry);

      if (topic && topic.trim() !== form.topic) {
        const duplicate = await Form.findOne({ topic: topic.trim() });
        if (duplicate) {
          await sendWebhook("ADMIN", {
            embeds: [
              {
                title: "❌ Update Form Failed - Duplicate Topic",
                color: 0xe74c3c,
                fields: [
                  { name: "Admin", value: req.session.username, inline: true },
                  { name: "Form Link", value: req.params.link, inline: true },
                  { name: "New Topic", value: topic, inline: true },
                  {
                    name: "Existing Form Link",
                    value: duplicate.link,
                    inline: true,
                  },
                  { name: "Error", value: "Duplicate topic", inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          });
          return res.status(400).json({ message: "يوجد نموذج آخر بنفس الاسم" });
        }
        form.topic = topic.trim();
      }

      if (typeof description === "string") form.description = description;
      if (targetGrade) form.targetGrade = normalizeFormTarget(targetGrade);
      if (Array.isArray(allowedGrades)) {
        form.allowedGrades = allowedGrades
          .map((g) => normalizeGradeSlug(g))
          .filter(Boolean);
      }
      form.status = "published";
      if (typeof allowRetake !== "undefined") {
        form.allowRetake = Boolean(allowRetake);
      }
      if (expiry !== undefined) {
        form.expiry = expiryDate;
      }

      if (questions && questions.length > 0) {
        form.questions = sanitizeQuestions(questions);
      }

      form.updatedBy = req.session.username;
      form.updatedAt = new Date();

      await form.save();

      const wasExpired = form.expiry && new Date(form.expiry) < new Date();
      const isNowActive = expiryDate && new Date(expiryDate) > new Date();
      if (wasExpired && isNowActive) {
        await sendWebhook("FORM", {
          content: `🔄 **Form Reactivated**`,
          embeds: [
            {
              title: "Form Reactivated",
              color: 0x27ae60,
              fields: [
                { name: "Admin", value: req.session.username },
                { name: "Form", value: form.topic },
                { name: "Form Link", value: form.link, inline: true },
                {
                  name: "New Expiry",
                  value: expiryDate
                    ? new Date(expiryDate).toLocaleString("ar-EG")
                    : "No expiry",
                },
                { name: "Previous Status", value: "expired", inline: true },
                { name: "New Status", value: "published", inline: true },
                {
                  name: "Reactivated At",
                  value: new Date().toLocaleString(),
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
      }

      const updateUser = getSessionUser(req);
      await sendWebhook("FORM", {
        content: `✏️ **Form Updated**`,
        embeds: [
          {
            title: "Form Updated",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Role",
                value: updateUser ? updateUser.role.toUpperCase() : "ADMIN",
                inline: true,
              },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: form.link, inline: true },
              { name: "Status", value: form.status, inline: true },
              {
                name: "Questions Count",
                value: form.questions.length.toString(),
                inline: true,
              },
              { name: "Target Grade", value: form.targetGrade, inline: true },
              {
                name: "Updated At",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
              { name: "Form ID", value: form._id.toString(), inline: true },
              { name: "Previous Editor", value: form.updatedBy, inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, form: serializeForm(form) });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Update Form Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(400).json({
        success: false,
        message: error.message || "تعذر تحديث النموذج",
      });
    }
  }
);

app.post(
  "/api/forms/:link/reset-user",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const form = await Form.findOne({ link: req.params.link });
      if (!form) {
        return res.status(404).json({ success: false, message: "النموذج غير موجود" });
      }

      const rawUsername = req.body && req.body.username ? String(req.body.username) : "";
      const username = rawUsername.trim().toLowerCase();
      if (!username) {
        return res
          .status(400)
          .json({ success: false, message: "اسم المستخدم مطلوب" });
      }

      const beforeCount = Array.isArray(form.submissions)
        ? form.submissions.length
        : 0;
      form.submissions = (form.submissions || []).filter((s) => {
        const sUser = s && s.username ? String(s.username).trim().toLowerCase() : "";
        return sUser !== username;
      });
      const removedCount = beforeCount - (form.submissions ? form.submissions.length : 0);

      await form.save();

      await sendWebhook("FORM", {
        content: `🔁 **Form Retake Reset (User)**`,
        embeds: [
          {
            title: "Form Retake Reset",
            color: 0xf59e0b,
            fields: [
              {
                name: "Admin",
                value: req.session.username || "unknown",
                inline: true,
              },
              { name: "Username", value: username, inline: true },
              { name: "Form", value: form.topic || "unknown", inline: false },
              {
                name: "Form Link",
                value: form.link || req.params.link,
                inline: true,
              },
              {
                name: "Removed Submissions",
                value: String(removedCount),
                inline: true,
              },
              {
                name: "Allow Retake",
                value: form.allowRetake ? "✅ Yes" : "❌ No",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      return res.json({ success: true, removed: removedCount });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Reset User Submission Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username || "unknown" },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res
        .status(500)
        .json({ success: false, message: "تعذر إعادة تعيين المستخدم" });
    }
  }
);

app.delete(
  "/api/forms/:link",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { link } = req.params;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🗑️ Admin Deleting Form",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Form Link", value: link, inline: true },
              { name: "Action", value: "Delete Form", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      let form = await Form.findOne({ link });
      if (!form && mongoose.Types.ObjectId.isValid(link)) {
        form = await Form.findById(link);
      }
      if (!form) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Delete Form Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Form Link", value: link, inline: true },
                { name: "Error", value: "Form not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(404).json({ message: "النموذج غير موجود" });
      }

      await Form.deleteOne({ _id: form._id });

      const deleteUser = getSessionUser(req);
      await sendWebhook("FORM", {
        content: `🗑️ **Form Deleted**`,
        embeds: [
          {
            title: "Form Deleted",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Role",
                value: deleteUser ? deleteUser.role.toUpperCase() : "ADMIN",
                inline: true,
              },
              { name: "Form Name", value: form.topic, inline: true },
              { name: "Form Link", value: link, inline: true },
              {
                name: "Questions Count",
                value: form.questions.length.toString(),
                inline: true,
              },
              {
                name: "Submissions Count",
                value: form.submissions.length.toString(),
                inline: true,
              },
              {
                name: "Deleted At",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
              { name: "Form ID", value: form._id.toString(), inline: true },
              {
                name: "Created By",
                value: form.createdBy || "Unknown",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, message: "تم حذف النموذج نهائيًا." });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Delete Form Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر حذف النموذج" });
    }
  }
);

app.post(
  "/api/forms/:link/deactivate",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { link } = req.params;

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "⏸️ Admin Deactivating Form",
            color: 0xf1c40f,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Form Link", value: link, inline: true },
              { name: "Action", value: "Deactivate Form", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      let form = await Form.findOne({ link });
      if (!form && mongoose.Types.ObjectId.isValid(link)) {
        form = await Form.findById(link);
      }
      if (!form) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Deactivate Form Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Form Link", value: link, inline: true },
                { name: "Error", value: "Form not found", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(404).json({ message: "النموذج غير موجود" });
      }

      const oldDate = new Date("2000-01-01T00:00:00Z");
      form.status = "expired";
      form.allowRetake = false;
      form.expiry = oldDate;
      form.updatedBy = req.session.username;
      form.updatedAt = new Date();
      await form.save();

      const deactivateUser = getSessionUser(req);
      await sendWebhook("FORM", {
        content: `⏸️ **Form Deactivated**`,
        embeds: [
          {
            title: "Form Deactivated",
            color: 0xf1c40f,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Role",
                value: deactivateUser
                  ? deactivateUser.role.toUpperCase()
                  : "ADMIN",
                inline: true,
              },
              { name: "Form Name", value: form.topic, inline: true },
              { name: "Form Link", value: link, inline: true },
              {
                name: "Expiry Set To",
                value: oldDate.toLocaleString(),
                inline: true,
              },
              {
                name: "Questions Count",
                value: form.questions.length.toString(),
                inline: true,
              },
              {
                name: "Updated At",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, message: "تم تعطيل النموذج بنجاح." });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Deactivate Form Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Form Link", value: req.params.link },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ success: false, message: "تعذر تعطيل النموذج" });
    }
  }
);

app.get(
  "/api/banned-users",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "🚫 Admin Fetching Banned Users",
            color: 0x3498db,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Role", value: req.session.role, inline: true },
              { name: "Endpoint", value: "/api/banned-users", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const bans = await BannedUser.find().sort({ createdAt: -1 });

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Banned Users Fetched",
            color: 0x10b981,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              {
                name: "Bans Found",
                value: bans.length.toString(),
                inline: true,
              },
              {
                name: "Timestamp",
                value: moment()
                  .tz("Africa/Cairo")
                  .format("YYYY-MM-DD HH:mm:ss"),
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json(bans);
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Fetch Banned Users Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(500).json({ message: "تعذر تحميل القائمة" });
    }
  }
);

app.post(
  "/api/banned-users",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const { username, banType, reason, duration, days } = req.body;
      const normalized = username.toLowerCase();

      if (!normalized) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Ban User Failed - Missing Username",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Ban Type", value: banType || "all", inline: true },
                { name: "Reason", value: reason || "No reason", inline: true },
                { name: "Error", value: "Username is required", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({ message: "يرجى إدخال اسم المستخدم" });
      }

      const allowedBanTypes = ["login", "forms", "all"];
      const selectedBanType = allowedBanTypes.includes(banType)
        ? banType
        : "all";

      const existingBan = await BannedUser.findOne({
        usernameLower: normalized,
      });
      const isUpdate = !!existingBan;

      const isPermanent = duration === "permanent" || (duration !== "temporary" && days == null);
      const numDays = duration === "temporary" && days != null ? Math.max(1, parseInt(days, 10) || 1) : null;
      const expiresAt = isPermanent ? null : (numDays ? new Date(Date.now() + numDays * 24 * 60 * 60 * 1000) : null);

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: isUpdate ? "⚠️ Admin Updating Ban" : "🚫 Admin Creating Ban",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Username", value: username, inline: true },
              { name: "Ban Type", value: selectedBanType, inline: true },
              {
                name: "Reason",
                value: reason || "No reason provided",
                inline: false,
              },
              {
                name: "Action",
                value: isUpdate ? "Update Ban" : "Create Ban",
                inline: true,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      const ban = await BannedUser.findOneAndUpdate(
        { usernameLower: normalized },
        {
          username: username.trim(),
          usernameLower: normalized,
          banType: selectedBanType,
          reason: reason || "",
          expiresAt,
          createdBy: req.session.username,
          createdAt: new Date(),
        },
        { new: true, upsert: true, setDefaultsOnInsert: true }
      );

      await sendWebhook("SECURITY", {
        content: isUpdate ? `🔄 **User Ban Updated**` : `🚫 **User Banned**`,
        embeds: [
          {
            title: isUpdate ? "User Ban Updated" : "User Banned",
            color: isUpdate ? 0xf39c12 : 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Banned User", value: username },
              { name: "Ban Type", value: selectedBanType },
              { name: "Reason", value: reason || "No reason provided" },
              {
                name: "Action",
                value: isUpdate ? "Updated" : "Created",
                inline: true,
              },
              {
                name: "Previous Ban Type",
                value: isUpdate ? existingBan.banType : "None",
                inline: true,
              },
              {
                name: "Previous Reason",
                value: isUpdate ? existingBan.reason : "None",
                inline: true,
              },
              {
                name: "Banned At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              { name: "Ban ID", value: ban._id.toString(), inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true, ban });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Ban User Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Username", value: req.body.username || "Unknown" },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res.status(400).json({ success: false, message: "تعذر حفظ قرار الحظر" });
    }
  }
);

app.delete(
  "/api/banned-users/:username",
  requireAuth,
  requireRole(["admin", "leadadmin"]),
  async (req, res) => {
    try {
      const normalized = req.params.username.toLowerCase();

      await sendWebhook("ADMIN", {
        embeds: [
          {
            title: "✅ Admin Unbanning User",
            color: 0xf59e0b,
            fields: [
              { name: "Admin", value: req.session.username, inline: true },
              { name: "Username", value: req.params.username, inline: true },
              { name: "Normalized", value: normalized, inline: true },
              { name: "Action", value: "Unban User", inline: true },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      if (!normalized) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Unban Failed - Invalid Username",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Username", value: req.params.username, inline: true },
                { name: "Error", value: "Invalid username", inline: true },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({ message: "اسم المستخدم غير صالح" });
      }
      const banRecord = await BannedUser.findOne({ usernameLower: normalized });
      if (!banRecord) {
        await sendWebhook("ADMIN", {
          embeds: [
            {
              title: "❌ Unban Failed - Not Found",
              color: 0xe74c3c,
              fields: [
                { name: "Admin", value: req.session.username, inline: true },
                { name: "Username", value: req.params.username, inline: true },
                {
                  name: "Error",
                  value: "User not found in ban list",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res
          .status(404)
          .json({ message: "المستخدم غير موجود في قائمة الحظر" });
      }
      await BannedUser.deleteOne({ _id: banRecord._id });
      await sendWebhook("SECURITY", {
        content: `✅ **User Unbanned**`,
        embeds: [
          {
            title: "User Unbanned",
            color: 0x27ae60,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Unbanned User", value: req.params.username },
              {
                name: "Previous Ban Type",
                value: banRecord.banType,
                inline: true,
              },
              {
                name: "Previous Reason",
                value: banRecord.reason || "No reason",
                inline: true,
              },
              {
                name: "Banned By",
                value: banRecord.createdBy || "System",
                inline: true,
              },
              {
                name: "Banned Date",
                value: banRecord.createdAt.toLocaleString(),
                inline: true,
              },
              {
                name: "Unbanned At",
                value: new Date().toLocaleString(),
                inline: true,
              },
              {
                name: "Ban Duration",
                value: `${Math.floor(
                  (new Date() - banRecord.createdAt) / (1000 * 60 * 60 * 24)
                )} days`,
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });

      res.json({ success: true });
    } catch (error) {
      await sendWebhook("ERROR", {
        embeds: [
          {
            title: "❌ Unban User Error",
            color: 0xe74c3c,
            fields: [
              { name: "Admin", value: req.session.username },
              { name: "Username", value: req.params.username },
              { name: "Error", value: error.message },
              {
                name: "Stack Trace",
                value: error.stack?.substring(0, 500) || "No stack",
                inline: false,
              },
              { name: "IP", value: req.ip || "unknown", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      res
        .status(500)
        .json({ success: false, message: "تعذر إزالة المستخدم من الحظر" });
    }
  }
);

app.get("/form/:link", requireAuth, async (req, res) => {
  try {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "📄 Form Access Attempt",
          color: 0x3498db,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Role", value: req.session.role, inline: true },
            { name: "Form Link", value: req.params.link, inline: true },
            { name: "Path", value: `/form/${req.params.link}`, inline: true },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    const form = await Form.findOne({ link: req.params.link });
    if (!form) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Form Not Found",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form Link", value: req.params.link, inline: true },
              { name: "Error", value: "Form not found", inline: true },
              { name: "Redirect", value: "/404.html", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(404).redirect("/404.html");
    }

    const user = getSessionUser(req);
    const isAdminViewer =
      user && (user.role === "admin" || user.role === "leadadmin");
    if (form.status === "draft" && !isAdminViewer) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "🚫 Draft Form Access Denied",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: form.link, inline: true },
              { name: "Form Status", value: "draft", inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              {
                name: "Required Role",
                value: "admin or leadadmin",
                inline: true,
              },
              {
                name: "Error",
                value: "Draft form access denied",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).redirect("/404.html");
    }
    if (form.status === "expired" && !isAdminViewer) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "🕒 Expired Form Access Denied",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: form.link, inline: true },
              { name: "Form Status", value: "expired", inline: true },
              {
                name: "Expiry Date",
                value: form.expiry?.toLocaleString() || "No expiry",
                inline: true,
              },
              {
                name: "Error",
                value: "Expired form access denied",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).redirect("/404.html");
    }

    if (!canUserAccessForm(user, form)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Unauthorized Form Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              {
                name: "User Grade",
                value: user?.grade || "None",
                inline: true,
              },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Target", value: form.targetGrade, inline: true },
              { name: "Form Status", value: form.status, inline: true },
              { name: "Error", value: "No form access", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).redirect("/404.html");
    }

    const currentTime = new Date();
    if (form.expiry && currentTime > form.expiry) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "🕒 Form Expired",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: form.link, inline: true },
              {
                name: "Expiry Date",
                value: form.expiry.toLocaleString(),
                inline: true,
              },
              {
                name: "Current Time",
                value: currentTime.toLocaleString(),
                inline: true,
              },
              { name: "Error", value: "Form expired", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).redirect("/404.html");
    }

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Form Accessed Successfully",
          color: 0x10b981,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Form", value: form.topic, inline: true },
            { name: "Form Link", value: form.link, inline: true },
            { name: "Form Status", value: form.status, inline: true },
            {
              name: "Questions",
              value: form.questions.length.toString(),
              inline: true,
            },
            { name: "Target Grade", value: form.targetGrade, inline: true },
            {
              name: "Expiry Date",
              value: form.expiry?.toLocaleString() || "No expiry",
              inline: true,
            },
            {
              name: "Access Time",
              value: currentTime.toLocaleString(),
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.render("form", {
      form,
      sessionUser: {
        username: req.session.username,
        role: req.session.role,
        grade: req.session.grade || null,
      },
    });
  } catch (err) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Render Form Error",
          color: 0xe74c3c,
          fields: [
            { name: "Form Link", value: req.params.link },
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Error", value: err.message },
            {
              name: "Stack Trace",
              value: err.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    if (req.accepts("html")) {
      return res.status(500).sendFile(path.join(__dirname, "views/500.html"));
    }
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/form/:link", requireAuth, submissionLimiter, async (req, res) => {
  const formLink = req.params.link;
  const { deviceId, ...answers } = req.body;
  const userIp = req.ip || "unknown";
  const sessionUser = getSessionUser(req);

  await sendWebhook("USER", {
    embeds: [
      {
        title: "📝 Form Submission Attempt",
        color: 0xf59e0b,
        fields: [
          { name: "Username", value: req.session.username, inline: true },
          { name: "Form Link", value: formLink, inline: true },
          {
            name: "Device ID",
            value: deviceId?.substring(0, 20) + "..." || "Missing",
            inline: true,
          },
          {
            name: "Answers Count",
            value: Object.keys(answers).length.toString(),
            inline: true,
          },
          { name: "IP", value: userIp, inline: true },
          {
            name: "User Agent",
            value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
            inline: false,
          },
        ],
        timestamp: new Date().toISOString(),
      },
    ],
  });

  if (!sessionUser) {
    await sendWebhook("SECURITY", {
      embeds: [
        {
          title: "❌ Form Submission - No Session User",
          color: 0xe74c3c,
          fields: [
            { name: "Form Link", value: formLink, inline: true },
            {
              name: "Device ID",
              value: deviceId?.substring(0, 20) + "..." || "Missing",
              inline: true,
            },
            { name: "IP", value: userIp, inline: true },
            {
              name: "Error",
              value: "Session expired or invalid",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(403).json({
      success: false,
      message: "الجلسة انتهت. يرجى تسجيل الدخول مرة أخرى.",
    });
  }

  if (!deviceId || typeof deviceId !== "string") {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "❌ Form Submission - Invalid Device ID",
          color: 0xe74c3c,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Form Link", value: formLink, inline: true },
            { name: "Device ID Type", value: typeof deviceId, inline: true },
            {
              name: "Device ID Value",
              value: deviceId || "null",
              inline: true,
            },
            {
              name: "Error",
              value: "Invalid or missing device ID",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    return res.status(400).json({
      success: false,
      message: "الجهاز غير صالح أو غير موجود. يرجى المحاولة مرة أخرى.",
    });
  }

  try {
    const form = await Form.findOne({ link: formLink });
    if (!form) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Form Submission - Form Not Found",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form Link", value: formLink, inline: true },
              { name: "Error", value: "Form not found", inline: true },
              { name: "Redirect", value: "/404.html", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(404).redirect("/404.html");
    }

    if (!canUserAccessForm(sessionUser, form)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Form Submission - No Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "User Role", value: sessionUser.role, inline: true },
              {
                name: "User Grade",
                value: sessionUser.grade || "None",
                inline: true,
              },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Target", value: form.targetGrade, inline: true },
              { name: "Error", value: "No form access", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).json({
        success: false,
        message: "ليست لديك صلاحية لحل هذا النموذج.",
      });
    }

    const isAdminViewer =
      req.session &&
      (req.session.role === "admin" || req.session.role === "leadadmin");
    if (form.status === "draft" && !isAdminViewer) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "🚫 Form Submission - Draft Form",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Status", value: "draft", inline: true },
              {
                name: "Error",
                value: "Draft form not available",
                inline: true,
              },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).json({
        success: false,
        message: "هذا النموذج غير متاح حالياً.",
      });
    }
    if (form.status === "expired" && !isAdminViewer) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "🕒 Form Submission - Expired Form",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Status", value: "expired", inline: true },
              {
                name: "Expiry Date",
                value: form.expiry?.toLocaleString() || "No expiry",
                inline: true,
              },
              { name: "Error", value: "Form expired", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).json({
        success: false,
        message: "انتهت صلاحية هذا النموذج.",
      });
    }

    const banRecord = await getBanRecord(
      req.session.username || (sessionUser && sessionUser.originalUsername)
    );
    if (
      banRecord &&
      (banRecord.banType === "forms" || banRecord.banType === "all")
    ) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Form Submission - Banned User",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Ban Type", value: banRecord.banType, inline: true },
              {
                name: "Ban Reason",
                value: banRecord.reason || "No reason",
                inline: true,
              },
              {
                name: "Banned By",
                value: banRecord.createdBy || "System",
                inline: true,
              },
              { name: "Error", value: "User banned from forms", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      let banMessage = "تم حظرك من إرسال النماذج.";
      if (banRecord.reason && banRecord.reason.trim()) {
        banMessage = `تم حظرك من إرسال النماذج. السبب: ${banRecord.reason}`;
      }
      return res.status(403).json({
        success: false,
        message: banMessage,
      });
    }

    if (
      req.session.submittedForms &&
      req.session.submittedForms.includes(formLink) &&
      !form.allowRetake
    ) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "⚠️ Form Submission - Already Submitted",
            color: 0xf59e0b,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Link", value: formLink, inline: true },
              {
                name: "Allow Retake",
                value: form.allowRetake ? "✅ Yes" : "❌ No",
                inline: true,
              },
              { name: "Error", value: "Already submitted", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(400).json({
        success: false,
        message: "لقد قمت بإرسال هذا النموذج من قبل.",
      });
    }

    if (!form.allowRetake) {
      const existingSubmission = form.submissions.find(
        (submission) =>
          submission.deviceId === deviceId || submission.ip === userIp
      );

      if (existingSubmission) {
        await sendWebhook("USER", {
          embeds: [
            {
              title: "⚠️ Form Submission - Duplicate Device/IP",
              color: 0xf59e0b,
              fields: [
                { name: "Username", value: req.session.username, inline: true },
                { name: "Form", value: form.topic, inline: true },
                {
                  name: "Device ID",
                  value: deviceId.substring(0, 20) + "...",
                  inline: true,
                },
                { name: "IP", value: userIp, inline: true },
                {
                  name: "Existing Submission Time",
                  value: existingSubmission.submissionTime.toLocaleString(),
                  inline: true,
                },
                {
                  name: "Error",
                  value: "Duplicate device/IP submission",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
        return res.status(400).json({
          success: false,
          message: ".لقد قمت بإرسال هذا النموذج مسبقًا",
        });
      }
    }

    const answerDetails = form.questions.map((question, index) => {
      const rawAnswer = answers[`q${index}`];
      const normalizedUserAnswer = formatAnswerValue(rawAnswer, "").trim();
      const userAnswer = normalizedUserAnswer || "لم يتم الإجابة";
      let correctAnswerRaw = "";

      if (question.questionType === "true-false") {
        correctAnswerRaw = question.correctAnswer || "";
      } else {
        const answerIndex =
          typeof question.correctAnswerIndex === "number"
            ? question.correctAnswerIndex
            : typeof question.correctAnswer === "number"
              ? question.correctAnswer
              : null;

        if (
          typeof answerIndex === "number" &&
          Array.isArray(question.options)
        ) {
          correctAnswerRaw = question.options[answerIndex] || "";
        } else if (typeof question.correctAnswer === "string") {
          correctAnswerRaw = question.correctAnswer;
        }
      }

      const normalizedCorrectAnswer = formatAnswerValue(
        correctAnswerRaw,
        ""
      ).trim();
      const correctAnswer = normalizedCorrectAnswer || "غير محدد";
      const questionPoints =
        typeof question.points === "number" ? question.points : 10;
      const isCorrect =
        normalizedUserAnswer &&
        normalizedCorrectAnswer &&
        normalizedUserAnswer === normalizedCorrectAnswer;
      const pointsAwarded = isCorrect ? questionPoints : 0;

      return {
        questionNumber: index + 1,
        questionText: question.questionText || "",
        userAnswer,
        correctAnswer,
        isCorrect: Boolean(isCorrect),
        pointsAwarded,
      };
    });

    const score = answerDetails.filter((detail) => detail.isCorrect).length;
    const pointsEarned = answerDetails.reduce(
      (total, detail) => total + detail.pointsAwarded,
      0
    );

    const submissionUsername =
      req.session.username ||
      (sessionUser && (sessionUser.username || sessionUser.originalUsername)) ||
      "غير معروف";
    form.submissions.push({
      username: submissionUsername,
      grade:
        req.session.grade || (sessionUser && sessionUser.grade) || "غير محدد",
      score: score,
      deviceId,
      ip: userIp,
      submissionTime: new Date(),
    });

    await form.save();

    if (pointsEarned > 0 && sessionUser && sessionUser.role === "student") {
      try {
        let userPoints = await UserPoints.findOne({
          username: req.session.username.toLowerCase(),
        });
        if (!userPoints) {
          userPoints = new UserPoints({
            username: req.session.username.toLowerCase(),
            points: 0,
          });
        }

        const previousPoints = userPoints.points;
        userPoints.points += pointsEarned;
        userPoints.transactions.push({
          type: "earned",
          amount: pointsEarned,
          description: `إجابة صحيحة على نموذج: ${form.topic}`,
          formLink: formLink,
        });

        await userPoints.save();

        await sendWebhook("USER", {
          embeds: [
            {
              title: "🎁 Points Awarded for Form",
              color: 0x1abc9c,
              fields: [
                { name: "Username", value: req.session.username, inline: true },
                { name: "Form", value: form.topic, inline: true },
                {
                  name: "Points Earned",
                  value: pointsEarned.toString(),
                  inline: true,
                },
                {
                  name: "Previous Points",
                  value: previousPoints.toString(),
                  inline: true,
                },
                {
                  name: "New Points",
                  value: userPoints.points.toString(),
                  inline: true,
                },
                { name: "Transaction Type", value: "earned", inline: true },
                {
                  name: "Transaction ID",
                  value:
                    userPoints.transactions[
                      userPoints.transactions.length - 1
                    ]._id
                      .toString()
                      .substring(0, 10) + "...",
                  inline: true,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
      } catch (error) {
        await sendWebhook("ERROR", {
          embeds: [
            {
              title: "❌ Award Points Error",
              color: 0xe74c3c,
              fields: [
                { name: "User", value: req.session.username },
                { name: "Form", value: form.topic },
                { name: "Points Attempted", value: pointsEarned.toString() },
                { name: "Error", value: error.message },
                {
                  name: "Stack Trace",
                  value: error.stack?.substring(0, 500) || "No stack",
                  inline: false,
                },
              ],
              timestamp: new Date().toISOString(),
            },
          ],
        });
      }
    }

    if (!form.allowRetake) {
      req.session.submittedForms = req.session.submittedForms || [];
      req.session.submittedForms.push(formLink);
    }

    const totalQuestions = form.questions.length;
    const percentage =
      totalQuestions > 0 ? Math.round((score / totalQuestions) * 100) : 0;

    const parser = new UAParser();
    const userAgent = req.headers["user-agent"];
    const deviceInfo = parser.setUA(userAgent).getResult();
    const device = `${deviceInfo.os.name || "Unknown OS"} (${deviceInfo.browser.name || "Unknown Browser"
      })`;

    const submissionTime = moment()
      .tz("Africa/Cairo")
      .format("YYYY-MM-DD HH:mm:ss");
    const userGrade =
      req.session.grade || (sessionUser && sessionUser.grade) || null;
    const gradeLabel = userGrade
      ? GRADE_LABELS[userGrade]?.long || userGrade
      : "غير محدد";
    const userRole = req.session.role || "student";

    const formEmbed = {
      title: "Form Submission Report",
      color: pointsEarned > 0 ? 0x10b981 : 0x6366f1,
      fields: [
        {
          name: "👤 User Information",
          value: `**Username:** ${req.session.username
            }\n**Grade:** ${gradeLabel}\n**Role:** ${userRole.toUpperCase()}`,
          inline: true,
        },
        {
          name: "📋 Form Information",
          value: `**Topic:** ${form.topic}\n**Target Grade:** ${GRADE_LABELS[form.targetGrade]?.long || form.targetGrade
            }\n**Questions:** ${totalQuestions}`,
          inline: true,
        },
        {
          name: "📊 Results",
          value: `**Score:** ${score}/${totalQuestions}\n**Percentage:** ${percentage}%\n**Points:** 🎁 ${pointsEarned}`,
          inline: false,
        },
        {
          name: "🕐 Submission Details",
          value: `**Time:** ${submissionTime}\n**Device:** ${device}\n**IP:** ${userIp}\n**Device ID:** ${deviceId.substring(
            0,
            20
          )}...`,
          inline: false,
        },
        {
          name: "📈 Additional Info",
          value: `**Form Link:** ${formLink}\n**Form ID:** ${form._id.toString()}\n**Submission ID:** ${form.submissions[
            form.submissions.length - 1
          ]._id
            .toString()
            .substring(0, 10)}...\n**Allow Retake:** ${form.allowRetake ? "✅ Yes" : "❌ No"
            }\n**Total Submissions:** ${form.submissions.length}`,
          inline: false,
        },
      ],
      footer: {
        text: `Form: ${formLink}`,
      },
      timestamp: new Date().toISOString(),
    };

    const remainingFieldSlots = Math.max(0, 25 - formEmbed.fields.length);
    if (remainingFieldSlots > 0 && answerDetails.length) {
      const detailsToInclude = Math.min(
        remainingFieldSlots,
        answerDetails.length
      );
      const detailFields = [];

      for (let i = 0; i < detailsToInclude; i++) {
        const detail = answerDetails[i];
        detailFields.push({
          name: `س${detail.questionNumber}: ${truncateValue(
            detail.questionText || "سؤال بدون عنوان",
            100
          )}`,
          value: `اختيار الطالب: ${detail.userAnswer}\nالإجابة الصحيحة: ${detail.correctAnswer
            }\nالحالة: ${detail.isCorrect ? "✅ صحيح" : "❌ خطأ"
            }\nالنقاط المكتسبة: ${detail.pointsAwarded}`,
          inline: false,
        });
      }

      if (answerDetails.length > detailsToInclude && detailFields.length) {
        const lastField = detailFields[detailFields.length - 1];
        lastField.value += `\n\n... يوجد ${answerDetails.length - detailsToInclude
          } سؤال إضافي لم يتم عرضها بسبب قيود ديسكورد.`;
      }

      formEmbed.fields.push(...detailFields);
    }

    await sendWebhook("FORM", {
      content: `📝 **New Form Submission**`,
      embeds: [formEmbed],
    });

    const pointsMessage =
      pointsEarned > 0 ? ` لقد ربحت ${pointsEarned} نقطة!` : "";
    res.json({
      success: true,
      message: `لقد انتهيت و تم إرسال النموذج بنجاح!${pointsMessage}`,
      pointsEarned: pointsEarned,
    });
  } catch (err) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Form Submission Error",
          color: 0xe74c3c,
          fields: [
            { name: "User", value: req.session.username },
            { name: "Form Link", value: formLink },
            { name: "Error", value: err.message },
            {
              name: "Stack Trace",
              value: err.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    res.status(500).json({
      success: false,
      message: "حدث خطأ أثناء تقديم النموذج. يرجى المحاولة لاحقًا.",
    });
  }
});

app.get("/form/:link/leaderboard", requireAuth, async (req, res) => {
  try {
    await sendWebhook("USER", {
      embeds: [
        {
          title: "🏆 Form Leaderboard Access",
          color: 0x3498db,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Form Link", value: req.params.link, inline: true },
            {
              name: "Path",
              value: `/form/${req.params.link}/leaderboard`,
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    const form = await Form.findOne({ link: req.params.link });
    if (!form) {
      await sendWebhook("USER", {
        embeds: [
          {
            title: "❌ Form Leaderboard - Form Not Found",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              { name: "Form Link", value: req.params.link, inline: true },
              { name: "Error", value: "Form not found", inline: true },
              { name: "Redirect", value: "/404.html", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(404).redirect("/404.html");
    }

    const user = getSessionUser(req);
    if (!canUserAccessForm(user, form)) {
      await sendWebhook("SECURITY", {
        embeds: [
          {
            title: "🚫 Form Leaderboard - No Access",
            color: 0xe74c3c,
            fields: [
              { name: "Username", value: req.session.username, inline: true },
              {
                name: "User Role",
                value: user?.role || "Unknown",
                inline: true,
              },
              { name: "Form", value: form.topic, inline: true },
              { name: "Form Target", value: form.targetGrade, inline: true },
              { name: "Error", value: "No form access", inline: true },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      });
      return res.status(403).redirect("/404.html");
    }

    const sortedSubmissions = form.submissions.sort((a, b) => b.score - a.score);

    const leaderboardBase = await Promise.all(
      sortedSubmissions.map(async (submission) => {
        const user = await UserRegistration.findOne({
          username: submission.username.toLowerCase(),
        });
        const fullName = user
          ? `${user.firstName} ${user.secondName}`.trim()
          : submission.username;

        return {
          username: submission.username,
          name: fullName,
          grade: submission.grade || "غير محدد",
          score: submission.score,
          totalQuestions: form.questions.length,
          submissionTime: submission.submissionTime.toLocaleString("en-US", {
            timeZone: "Africa/Cairo",
          }),
          submissionDate: submission.submissionTime,
        };
      })
    );

    const leaderboard = leaderboardBase.map((entry, index, arr) => {
      if (index === 0) {
        return { ...entry, rank: 1 };
      }

      const prev = arr[index - 1];
      const rank = entry.score === prev.score ? prev.rank : index + 1;
      return { ...entry, rank };
    });

    await sendWebhook("USER", {
      embeds: [
        {
          title: "✅ Form Leaderboard Fetched",
          color: 0x10b981,
          fields: [
            { name: "Username", value: req.session.username, inline: true },
            { name: "Form", value: form.topic, inline: true },
            { name: "Form Link", value: form.link, inline: true },
            {
              name: "Submissions Count",
              value: form.submissions.length.toString(),
              inline: true,
            },
            {
              name: "Leaderboard Entries",
              value: leaderboard.length.toString(),
              inline: true,
            },
            {
              name: "Top Score",
              value:
                leaderboard.length > 0 ? leaderboard[0].score.toString() : "0",
              inline: true,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });

    res.render("leaderboard", { form, leaderboard });
  } catch (err) {
    await sendWebhook("ERROR", {
      embeds: [
        {
          title: "❌ Leaderboard Error",
          color: 0xe74c3c,
          fields: [
            { name: "Form Link", value: req.params.link },
            { name: "Username", value: req.session.username || "Unknown" },
            { name: "Error", value: err.message },
            {
              name: "Stack Trace",
              value: err.stack?.substring(0, 500) || "No stack",
              inline: false,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
    if (req.accepts("html")) {
      return res.status(500).sendFile(path.join(__dirname, "views/500.html"));
    }
    res.status(500).json({ error: "Server error" });
  }
});

app.use(async (req, res) => {
  try {
    sendWebhook("USER", {
      embeds: [
        {
          title: "❌ 404 Not Found",
          color: 0xe74c3c,
          fields: [
            { name: "Path", value: req.path, inline: true },
            { name: "Method", value: req.method, inline: true },
            {
              name: "Authenticated",
              value: req.session.isAuthenticated ? "✅ Yes" : "❌ No",
              inline: true,
            },
            {
              name: "Username",
              value: req.session.username || "Guest",
              inline: true,
            },
            { name: "IP", value: req.ip || "unknown", inline: true },
            {
              name: "User Agent",
              value: req.headers["user-agent"]?.substring(0, 100) || "unknown",
              inline: false,
            },
          ],
          timestamp: new Date().toISOString(),
        },
      ],
    });
  } catch (err) {
    console.error("[404 WEBHOOK ERROR]", err.message);
  }

  if (req.accepts("html")) {
    res.status(404).sendFile(path.join(__dirname, "views/404.html"));
  } else {
    res.status(404).json({ error: "Resource not found" });
  }
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log("\x1b[33m%s\x1b[0m", "┌───────────────────────────────────────┐");
  console.log("\x1b[33m%s\x1b[0m", "│  👑 Made by Carl                      │");
  console.log("\x1b[33m%s\x1b[0m", "│  🟢 Server is online                  │");
  console.log("\x1b[33m%s\x1b[0m", "│  🔗 MongoDB is connected              │");
  console.log(
    "\x1b[33m%s\x1b[0m",
    `│  ⚓ Working on port: ${PORT}             │`
  );
  console.log("\x1b[33m%s\x1b[0m", "└───────────────────────────────────────┘");
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;