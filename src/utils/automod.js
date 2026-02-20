const mongoose = require('mongoose');

// More logical patterns - only blocking actual SQL injection and XSS attempts
const MALICIOUS_PATTERNS = [
    // SQL Injection patterns - only match when in context of SQL commands
    /(\bSELECT\b.*\bFROM\b)|(\bINSERT\b.*\bINTO\b)|(\bUPDATE\b.*\bSET\b)|(\bDELETE\b.*\bFROM\b)|(\bDROP\b.*\bTABLE\b)|(\bUNION\b.*\bSELECT\b)/i,

    // XSS patterns - actual script tags and event handlers
    /(<script[^>]*>.*?<\/script>)|(<iframe)|(<embed)|(<object)/i,
    /(javascript\s*:)|(on\w+\s*=\s*['"][^'"]*['"])/i,

    // Path traversal - only block multiple instances
    /(\.\.\/.*\.\.\/)|(\.\.\\.\.)/i,

    // Command injection - actual dangerous commands
    /(;\s*(rm|cat|curl|wget|nc|bash)\s+)/i
];

const spamTracker = new Map();

const COOLDOWN_MS = 30000;
const SPAM_THRESHOLD = 5;
const AUTO_BAN_DURATION_DAYS = 3;

function isMalicious(input) {
    if (!input) return false;
    const searchStr = typeof input === 'string' ? input : JSON.stringify(input);
    return MALICIOUS_PATTERNS.some(regex => regex.test(searchStr));
}

function maliciousFilter(req, res, next) {
    const toCheck = [req.body, req.query, req.params];

    for (const obj of toCheck) {
        if (isMalicious(obj)) {
            console.error(`[AUTOMOD] Malicious request blocked from IP: ${req.ip} - Path: ${req.path}`);

            if (global.sendWebhook) {
                global.sendWebhook("SECURITY", {
                    important: true,
                    embeds: [{
                        title: "🚨 نظام الحماية: تم رصد محاولة اختراق",
                        color: 0xe74c3c,
                        fields: [
                            { name: "العنوان الرقمي (IP)", value: req.ip, inline: true },
                            { name: "المسار", value: req.path, inline: true },
                            { name: "الطريقة", value: req.method, inline: true },
                            { name: "البيانات المرسلة", value: JSON.stringify(obj).substring(0, 500) }
                        ],
                        timestamp: new Date().toISOString()
                    }]
                });
            }

            return res.status(403).json({
                success: false,
                message: "تم حظر طلبك من قبل النظام الأمني. إذا كنت تعتقد أن هذا خطأ، يرجى الاتصال بالإدارة."
            });
        }
    }
    next();
}

async function spamBlocker(req, res, next) {
    const key = req.session?.username || req.ip;
    const now = Date.now();
    const record = spamTracker.get(key) || { count: 0, lastAction: 0, triggerCount: 0 };

    if (now - record.lastAction < COOLDOWN_MS) {
        record.triggerCount++;
        spamTracker.set(key, record);

        if (record.triggerCount >= SPAM_THRESHOLD) {
            return await autoBanUser(req, res, key, "حظر تلقائي: محاولات متكررة رغم فترة الانتظار (سبام).");
        }

        const waitSeconds = Math.ceil((COOLDOWN_MS - (now - record.lastAction)) / 1000);
        return res.status(429).json({
            success: false,
            message: `يرجى الانتظار ${waitSeconds} ثانية قبل المحاولة مرة أخرى.`
        });
    }

    record.lastAction = now;
    spamTracker.set(key, record);
    next();
}

async function autoBanUser(req, res, target, reason) {
    const BannedUser = mongoose.model('BannedUser');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + AUTO_BAN_DURATION_DAYS);

    try {
        await BannedUser.findOneAndUpdate(
            { usernameLower: target.toLowerCase() },
            {
                username: target,
                usernameLower: target.toLowerCase(),
                banType: "all",
                reason: reason,
                expiresAt: expiresAt,
                createdBy: "النظام التلقائي",
                createdAt: new Date()
            },
            { upsert: true }
        );

        if (global.sendWebhook) {
            global.sendWebhook("SECURITY", {
                important: true,
                embeds: [{
                    title: "🔨 النظام التلقائي: تم تطبيق حظر لمدة 3 أيام",
                    color: 0xe74c3c,
                    fields: [
                        { name: "المستخدم المستهدف", value: target, inline: true },
                        { name: "السبب", value: reason, inline: true },
                        { name: "تاريخ انتهاء الحظر", value: expiresAt.toLocaleString("ar-EG"), inline: true },
                        { name: "العنوان الرقمي (IP)", value: req.ip, inline: true }
                    ],
                    timestamp: new Date().toISOString()
                }]
            });
        }

        if (req.session && req.session.username && req.session.username.toLowerCase() === target.toLowerCase()) {
            req.session.destroy();
        }

        return res.status(403).json({
            success: false,
            message: `تم حظرك لمدة ${AUTO_BAN_DURATION_DAYS} أيام. السبب: ${reason}`
        });

    } catch (err) {
        console.error("[AUTOMOD] Error issuing auto-ban:", err);
        return res.status(500).json({ success: false, message: "خطأ داخلي في النظام أثناء المراجعة الأمنية." });
    }
}

module.exports = {
    maliciousFilter,
    spamBlocker,
    autoBanUser
};
