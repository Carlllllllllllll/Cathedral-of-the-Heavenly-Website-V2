const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (ENCRYPTION_KEY) {
    // If it's a 64-char hex string, it's 32 bytes
    if (ENCRYPTION_KEY.length === 64 && /^[0-9a-fA-F]+$/.test(ENCRYPTION_KEY)) {
        ENCRYPTION_KEY = Buffer.from(ENCRYPTION_KEY, 'hex');
    } else {
        // Otherwise, hash it to get exactly 32 bytes
        ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
    }
} else {
    console.warn('[ENCRYPTION] No ENCRYPTION_KEY found in env, using random key. DATA WILL NOT BE PERSISTENT ACROSS RESTARTS!');
    ENCRYPTION_KEY = crypto.randomBytes(32);
}

function encrypt(text) {
    if (!text) return null;

    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    } catch (error) {
        console.error('[ENCRYPTION] Error encrypting data:', error);
        throw new Error('Encryption failed');
    }
}

function decrypt(ciphertext) {
    if (!ciphertext || typeof ciphertext !== 'string' || !ciphertext.includes(':')) {
        return null;
    }

    try {
        const [iv, encryptedData, authTag] = ciphertext.split(':');

        const decipher = crypto.createDecipheriv(
            ALGORITHM,
            ENCRYPTION_KEY,
            Buffer.from(iv, 'hex')
        );

        decipher.setAuthTag(Buffer.from(authTag, 'hex'));

        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('[ENCRYPTION] Error decrypting data:', error);
        throw new Error('Decryption failed');
    }
}

function encryptFields(obj, fields) {
    const encrypted = { ...obj };

    fields.forEach(field => {
        if (obj[field]) {
            encrypted[field] = encrypt(obj[field].toString());
        }
    });

    return encrypted;
}

function decryptFields(obj, fields) {
    const decrypted = { ...obj };

    fields.forEach(field => {
        if (obj[field] && typeof obj[field] === 'string' && obj[field].includes(':')) {
            try {
                decrypted[field] = decrypt(obj[field]);
            } catch (error) {
                console.error(`[ENCRYPTION] Failed to decrypt field: ${field}`);
                decrypted[field] = null;
            }
        }
    });

    return decrypted;
}

function hash(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function verifyHash(value, hashedValue) {
    return hash(value) === hashedValue;
}

function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

module.exports = {
    encrypt,
    decrypt,
    encryptFields,
    decryptFields,
    hash,
    verifyHash,
    generateToken,
};
