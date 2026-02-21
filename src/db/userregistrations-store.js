const fs = require("fs");
const fsPromises = require("fs").promises;
const path = require("path");
const crypto = require("crypto");
const { sanitizeString, sanitizePayload } = require("../utils/security");
const { logSecurityEvent } = require("../utils/security");
const { encryptFields, decryptFields, hash } = require("../utils/encryption");

class SecureUserRegistrationsStore {
  constructor() {
    this.dbDir = path.join(__dirname);
    this.filePath = path.join(this.dbDir, "userregistrations.json");
    this.lockFilePath = path.join(this.dbDir, "userregistrations.lock");
    this.maxFileSize = 50 * 1024 * 1024;
    this.writeQueue = [];
    this.isWriting = false;
    this.lastWriteTime = 0;
    this.minWriteInterval = 100; 
    this.ensureDirectory();
    this.initializeFile();
    this.migrateLocalUsersEncryption().catch((err) => {
      console.error("[LOCAL USERS] Encryption migration failed:", err && err.message ? err.message : err);
    });
  }

  getSensitiveFields() {
    return ["firstName", "secondName", "email", "phone"];
  }

  isEncryptedValue(val) {
    return typeof val === "string" && val.includes(":");
  }

  computeHashes(user) {
    const normalizedEmail = (user.email || "").toString().toLowerCase().trim();
    const normalizedPhone = (user.phone || "").toString().trim();
    return {
      emailHash: normalizedEmail ? hash(normalizedEmail) : null,
      phoneHash: normalizedPhone ? hash(normalizedPhone) : null,
    };
  }

  encryptUserForStorage(user) {
    const fields = this.getSensitiveFields();
    const encrypted = encryptFields(user, fields);
    const hashes = this.computeHashes(user);
    return { ...encrypted, ...hashes };
  }

  decryptUserFromStorage(user) {
    const fields = this.getSensitiveFields();
    return decryptFields(user, fields);
  }

  async migrateLocalUsersEncryption() {
    if (!process.env.ENCRYPTION_KEY) return;

    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) return;

    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);
      if (!data || !Array.isArray(data.users)) return;

      let changed = false;
      const fields = this.getSensitiveFields();

      const migratedUsers = data.users.map((u) => {
        if (!u || typeof u !== "object") return u;

        const hasAnyPlaintext = fields.some((f) => u[f] && !this.isEncryptedValue(u[f]));
        const hashes = this.computeHashes(u);
        const needsHashes = (hashes.emailHash && !u.emailHash) || (hashes.phoneHash && !u.phoneHash);

        if (!hasAnyPlaintext && !needsHashes) return u;

        changed = true;
        const encrypted = hasAnyPlaintext ? this.encryptUserForStorage(u) : { ...u, ...hashes };
        return encrypted;
      });

      if (!changed) return;

      data.users = migratedUsers;
      if (data._metadata) {
        data._metadata.lastModified = new Date().toISOString();
        data._metadata.totalUsers = Array.isArray(data.users) ? data.users.length : 0;
        data._metadata.checksum = this.calculateChecksum(data.users);
      }
      await this.writeFileSecure(JSON.stringify(data, null, 2));
    } finally {
      await this.releaseLockAsync();
    }
  }

  ensureDirectory() {
    if (!fs.existsSync(this.dbDir)) {
      fs.mkdirSync(this.dbDir, { recursive: true, mode: 0o700 });
    }
    try {
      fs.chmodSync(this.dbDir, 0o700);
    } catch (err) {
      console.error("Warning: Could not set directory permissions:", err.message);
    }
  }

  initializeFile() {
    if (!fs.existsSync(this.filePath)) {
      const initialData = {
        _metadata: {
          version: "1.0",
          createdAt: new Date().toISOString(),
          lastModified: new Date().toISOString(),
          totalUsers: 0,
          checksum: null,
        },
        users: [],
      };
      this.writeFileSyncSecure(JSON.stringify(initialData, null, 2));
    } else {

      this.verifyFileIntegrity();
    }
  }

  verifyFileIntegrity() {
    try {
      const content = fs.readFileSync(this.filePath, "utf8");
      if (content.length > this.maxFileSize) {
        throw new Error("File size exceeds maximum allowed size");
      }
      const data = JSON.parse(content);
      if (!data._metadata || !Array.isArray(data.users)) {
        throw new Error("Invalid file structure");
      }

      if (data._metadata.checksum) {
        const calculatedChecksum = this.calculateChecksum(data.users);
        if (calculatedChecksum !== data._metadata.checksum) {
          throw new Error("File integrity check failed - checksum mismatch");
        }
      }
    } catch (error) {
      console.error("File integrity verification failed:", error.message);

      this.createEmergencyBackup();
      throw error;
    }
  }

  calculateChecksum(data) {
    const hash = crypto.createHash("sha256");
    hash.update(JSON.stringify(data));
    return hash.digest("hex");
  }

  createEmergencyBackup() {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupPath = path.join(this.dbDir, `userregistrations.backup.${timestamp}.json`);
      if (fs.existsSync(this.filePath)) {
        fs.copyFileSync(this.filePath, backupPath);
      }
    } catch (err) {
      console.error("Failed to create emergency backup:", err.message);
    }
  }

  acquireLock() {
    const maxAttempts = 50;
    let attempts = 0;
    while (attempts < maxAttempts) {
      try {
        if (!fs.existsSync(this.lockFilePath)) {
          fs.writeFileSync(this.lockFilePath, process.pid.toString(), { flag: "wx" });
          return true;
        }

        const lockStats = fs.statSync(this.lockFilePath);
        const lockAge = Date.now() - lockStats.mtimeMs;
        if (lockAge > 30000) {

          try {
            fs.unlinkSync(this.lockFilePath);
            fs.writeFileSync(this.lockFilePath, process.pid.toString(), { flag: "wx" });
            return true;
          } catch (e) {

          }
        }
        attempts++;

        const waitTime = Math.min(10 * attempts, 100);

        const start = Date.now();
        while (Date.now() - start < waitTime) {

        }
      } catch (err) {
        attempts++;
        if (attempts >= maxAttempts) {
          throw new Error("Could not acquire file lock after multiple attempts");
        }
      }
    }
    return false;
  }

  async acquireLockAsync() {
    const maxAttempts = 50;
    let attempts = 0;
    while (attempts < maxAttempts) {
      try {
        try {
          await fsPromises.access(this.lockFilePath);

          const lockStats = await fsPromises.stat(this.lockFilePath);
          const lockAge = Date.now() - lockStats.mtimeMs;
          if (lockAge > 30000) {

            try {
              await fsPromises.unlink(this.lockFilePath);
            } catch (e) {

            }
          } else {

            attempts++;
            await new Promise((resolve) => setTimeout(resolve, Math.min(10 * attempts, 100)));
            continue;
          }
        } catch (err) {

        }

        try {
          await fsPromises.writeFile(this.lockFilePath, process.pid.toString(), { flag: "wx" });
          return true;
        } catch (e) {

          attempts++;
          await new Promise((resolve) => setTimeout(resolve, Math.min(10 * attempts, 100)));
        }
      } catch (err) {
        attempts++;
        if (attempts >= maxAttempts) {
          throw new Error("Could not acquire file lock after multiple attempts");
        }
        await new Promise((resolve) => setTimeout(resolve, Math.min(10 * attempts, 100)));
      }
    }
    return false;
  }

  releaseLock() {
    try {
      if (fs.existsSync(this.lockFilePath)) {
        fs.unlinkSync(this.lockFilePath);
      }
    } catch (err) {
      console.error("Error releasing lock:", err.message);
    }
  }

  async releaseLockAsync() {
    try {
      await fsPromises.unlink(this.lockFilePath).catch(() => {

      });
    } catch (err) {
      console.error("Error releasing lock:", err.message);
    }
  }

  writeFileSyncSecure(content) {

    if (typeof content !== "string") {
      throw new Error("Content must be a string");
    }
    if (content.length > this.maxFileSize) {
      throw new Error("Content exceeds maximum file size");
    }

    try {
      JSON.parse(content);
    } catch (err) {
      throw new Error("Invalid JSON content");
    }

    const tempPath = this.filePath + ".tmp";
    const backupPath = this.filePath + ".bak";

    try {

      if (fs.existsSync(this.filePath)) {
        fs.copyFileSync(this.filePath, backupPath);
      }

      fs.writeFileSync(tempPath, content, {
        encoding: "utf8",
        mode: 0o600, 

        flag: "w",
      });

      fs.renameSync(tempPath, this.filePath);

      try {
        fs.chmodSync(this.filePath, 0o600);
      } catch (err) {
        console.error("Warning: Could not set file permissions:", err.message);
      }

      if (fs.existsSync(backupPath)) {
        setTimeout(() => {
          try {
            fs.unlinkSync(backupPath);
          } catch (e) {}
        }, 5000);
      }
    } catch (error) {

      if (fs.existsSync(backupPath)) {
        try {
          fs.copyFileSync(backupPath, this.filePath);
        } catch (e) {
          console.error("Failed to restore from backup:", e.message);
        }
      }
      throw error;
    }
  }

  async writeFileSecure(content) {

    if (typeof content !== "string") {
      throw new Error("Content must be a string");
    }
    if (content.length > this.maxFileSize) {
      throw new Error("Content exceeds maximum file size");
    }

    try {
      JSON.parse(content);
    } catch (err) {
      throw new Error("Invalid JSON content");
    }

    const tempPath = this.filePath + ".tmp";
    const backupPath = this.filePath + ".bak";

    try {

      try {
        await fsPromises.access(this.filePath);
        await fsPromises.copyFile(this.filePath, backupPath);
      } catch (err) {

      }

      await fsPromises.writeFile(tempPath, content, {
        encoding: "utf8",
        mode: 0o600, 

        flag: "w",
      });

      await fsPromises.rename(tempPath, this.filePath);

      try {
        await fsPromises.chmod(this.filePath, 0o600);
      } catch (err) {
        console.error("Warning: Could not set file permissions:", err.message);
      }

      fsPromises.unlink(backupPath).catch(() => {

      });
    } catch (error) {

      try {
        await fsPromises.access(backupPath);
        await fsPromises.copyFile(backupPath, this.filePath);
      } catch (e) {
        console.error("Failed to restore from backup:", e.message);
      }
      throw error;
    }
  }

  sanitizeUser(user) {
    if (!user || typeof user !== "object") {
      throw new Error("User must be an object");
    }

    const sanitized = {
      _id: user._id || this.generateId(),
      username: sanitizeString((user.username || "").toString().toLowerCase().trim(), {
        maxLength: 60,
        stripHtml: true,
      }),
      password: user.password ? sanitizeString(user.password.toString(), {
        maxLength: 200,
        stripHtml: false,
      }) : undefined,
      firstName: sanitizeString((user.firstName || "").toString().trim(), {
        maxLength: 100,
        stripHtml: true,
      }),
      secondName: sanitizeString((user.secondName || "").toString().trim(), {
        maxLength: 100,
        stripHtml: true,
      }),
      email: sanitizeString((user.email || "").toString().toLowerCase().trim(), {
        maxLength: 200,
        stripHtml: true,
      }),
      phone: sanitizeString((user.phone || "").toString().trim(), {
        maxLength: 20,
        stripHtml: true,
      }),
      grade: sanitizeString((user.grade || "").toString().trim(), {
        maxLength: 50,
        stripHtml: true,
      }),
      role: sanitizeString((user.role || "student").toString().trim(), {
        maxLength: 50,
        stripHtml: true,
      }),
      approvalStatus: ["pending", "approved", "declined"].includes(user.approvalStatus)
        ? user.approvalStatus
        : "pending",
      verificationCode: user.verificationCode
        ? sanitizeString(user.verificationCode.toString(), {
            maxLength: 20,
            stripHtml: false,
          })
        : null,
      verificationCodeVerified: Boolean(user.verificationCodeVerified),
      verificationDate: user.verificationDate
        ? new Date(user.verificationDate).toISOString()
        : null,
      lastLoginAt: user.lastLoginAt
        ? new Date(user.lastLoginAt).toISOString()
        : null,
      createdAt: user.createdAt
        ? new Date(user.createdAt).toISOString()
        : new Date().toISOString(),
      reviewedBy: user.reviewedBy
        ? sanitizeString(user.reviewedBy.toString(), {
            maxLength: 60,
            stripHtml: true,
          })
        : undefined,
      reviewedAt: user.reviewedAt
        ? new Date(user.reviewedAt).toISOString()
        : undefined,
      reviewReason: user.reviewReason
        ? sanitizeString(user.reviewReason.toString(), {
            maxLength: 500,
            stripHtml: true,
          })
        : undefined,
      _isLocal: true,
      passwordResetLinks: Array.isArray(user.passwordResetLinks)
        ? user.passwordResetLinks.map((link) => ({
            token: link.token,
            expiresAt: link.expiresAt ? new Date(link.expiresAt).toISOString() : null,
            createdAt: link.createdAt ? new Date(link.createdAt).toISOString() : null,
            createdBy: link.createdBy ? sanitizeString(link.createdBy.toString(), { maxLength: 60, stripHtml: true }) : null,
            usedAt: link.usedAt ? new Date(link.usedAt).toISOString() : null,
            supersededAt: link.supersededAt ? new Date(link.supersededAt).toISOString() : null,
          }))
        : [],
    };

    const hashes = this.computeHashes(sanitized);
    sanitized.emailHash = hashes.emailHash;
    sanitized.phoneHash = hashes.phoneHash;

    if (!sanitized.username || sanitized.username.length < 3) {
      throw new Error("Username must be at least 3 characters");
    }
    if (!sanitized.email || !sanitized.email.includes("@")) {
      throw new Error("Invalid email address");
    }
    if (!sanitized.firstName || sanitized.firstName.length < 1) {
      throw new Error("First name is required");
    }

    return sanitized;
  }

  generateId() {
    return crypto.randomBytes(12).toString("hex");
  }

  async readAll() {
    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for read operation");
    }

    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);

      if (!data._metadata || !Array.isArray(data.users)) {
        throw new Error("Invalid file structure");
      }

      return data.users.map((user) => {
        const decrypted = this.decryptUserFromStorage(user);
        return {
          ...decrypted,
          _isLocal: true,
        };
      });
    } finally {
      await this.releaseLockAsync();
    }
  }

  async findById(id) {
    const users = await this.readAll();
    return users.find((u) => u._id === id) || null;
  }

  async findByUsername(username) {
    const normalized = sanitizeString((username || "").toString().toLowerCase().trim(), {
      maxLength: 60,
      stripHtml: true,
    });
    const users = await this.readAll();
    return users.find((u) => u.username === normalized) || null;
  }

  async findByEmail(email) {
    const normalized = sanitizeString((email || "").toString().toLowerCase().trim(), {
      maxLength: 200,
      stripHtml: true,
    });
    const emailHash = normalized ? hash(normalized) : null;
    const users = await this.readAll();
    return users.find((u) => (u.emailHash || null) === emailHash) || null;
  }

  async findByPhone(phone) {
    const normalized = sanitizeString((phone || "").toString().trim(), {
      maxLength: 20,
      stripHtml: true,
    });
    const phoneHash = normalized ? hash(normalized) : null;
    const users = await this.readAll();
    return users.find((u) => (u.phoneHash || null) === phoneHash) || null;
  }

  async findByName(firstName, secondName) {
    const normalizedFirstName = sanitizeString((firstName || "").toString().toLowerCase().trim(), {
      maxLength: 100,
      stripHtml: true,
    });
    const normalizedSecondName = sanitizeString((secondName || "").toString().toLowerCase().trim(), {
        maxLength: 100,
        stripHtml: true,
      });
    const users = await this.readAll();
    return users.find((u) => u.firstName.toLowerCase() === normalizedFirstName && u.secondName.toLowerCase() === normalizedSecondName) || null;
  }

  async find(query = {}) {
    const users = await this.readAll();

    if (!query || Object.keys(query).length === 0) {
      return users;
    }

    return users.filter((user) => {
      for (const [key, value] of Object.entries(query)) {
        if (key === "_id" && user._id !== value) {
          return false;
        }
        if (key === "username" && user.username !== value.toLowerCase()) {
          return false;
        }
        if (key === "email" && user.email !== value.toLowerCase()) {
          return false;
        }
        if (key === "approvalStatus" && user.approvalStatus !== value) {
          return false;
        }
        if (key === "role" && user.role !== value) {
          return false;
        }
        if (key === "grade" && user.grade !== value) {
          return false;
        }
      }
      return true;
    });
  }

  async create(userData) {
    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for write operation");
    }

    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);

      if (!data._metadata || !Array.isArray(data.users)) {
        throw new Error("Invalid file structure");
      }

      const sanitized = this.sanitizeUser(userData);
      const stored = this.encryptUserForStorage(sanitized);
      const existing = data.users.find(
        (u) => u.username === sanitized.username || (stored.emailHash && u.emailHash === stored.emailHash)
      );

      if (existing) {
        throw new Error("User with this username or email already exists");
      }

      data.users.push(stored);
      data._metadata.totalUsers = data.users.length;
      data._metadata.lastModified = new Date().toISOString();
      data._metadata.checksum = this.calculateChecksum(data.users);

      const jsonContent = JSON.stringify(data, null, 2);
      await this.writeFileSecure(jsonContent);

      await logSecurityEvent("user_action", [
        {
          name: "Action",
          value: "Local User Created",
          inline: true,
        },
        {
          name: "Username",
          value: sanitized.username,
          inline: true,
        },
      ]);

      return sanitized;
    } finally {
      await this.releaseLockAsync();
    }
  }

  async update(id, updateData) {

    throw new Error("Local users cannot be updated. Please contact carl to edit this user.");
  }

  async delete(id) {

    throw new Error("Local users cannot be deleted. Please contact carl to delete this user.");
  }

  async count(query = {}) {
    const users = await this.find(query);
    return users.length;
  }

  async adminUpdate(id, updateData, adminUsername) {

    if (!adminUsername || adminUsername.toLowerCase() !== "carl") {
      throw new Error("Unauthorized: Only carl can modify local users");
    }

    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for write operation");
    }

    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);

      const userIndex = data.users.findIndex((u) => u._id === id);
      if (userIndex === -1) {
        throw new Error("User not found");
      }

      const existingUser = data.users[userIndex];
      const existingDecrypted = this.decryptUserFromStorage(existingUser);
      const sanitizedUpdate = this.sanitizeUser({
        ...existingDecrypted,
        ...updateData,
      });
      const storedUpdate = this.encryptUserForStorage(sanitizedUpdate);

      data.users[userIndex] = { ...existingUser, ...storedUpdate };
      data._metadata.lastModified = new Date().toISOString();
      data._metadata.checksum = this.calculateChecksum(data.users);

      const jsonContent = JSON.stringify(data, null, 2);
      await this.writeFileSecure(jsonContent);

      await logSecurityEvent("admin_action", [
        {
          name: "Action",
          value: "Local User Updated (Admin)",
          inline: true,
        },
        {
          name: "Admin",
          value: adminUsername,
          inline: true,
        },
        {
          name: "Username",
          value: sanitizedUpdate.username,
          inline: true,
        },
      ]);

      return sanitizedUpdate;
    } finally {
      await this.releaseLockAsync();
    }
  }

  async createPasswordResetLink(userId, adminUsername) {
    if (!adminUsername) {
      throw new Error("Unauthorized: Admin username required to create password reset links for local users");
    }
    const token = crypto.randomBytes(24).toString("hex");
    const verificationCode = String(Math.floor(100000 + Math.random() * 900000));
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for write operation");
    }
    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);
      const userIndex = data.users.findIndex((u) => u._id === userId);
      if (userIndex === -1) {
        throw new Error("User not found");
      }
      const user = data.users[userIndex];
      const links = Array.isArray(user.passwordResetLinks) ? user.passwordResetLinks : [];
      const updatedLinks = links.map((l) => ({
        ...l,
        supersededAt: l.supersededAt || now.toISOString(),
      }));
      updatedLinks.push({
        token,
        verificationCode,
        verifiedAt: null,
        expiresAt: expiresAt.toISOString(),
        createdAt: now.toISOString(),
        createdBy: adminUsername,
        usedAt: null,
        supersededAt: null,
      });
      data.users[userIndex] = { ...user, passwordResetLinks: updatedLinks };
      data._metadata.lastModified = now.toISOString();
      data._metadata.checksum = this.calculateChecksum(data.users);
      await this.writeFileSecure(JSON.stringify(data, null, 2));
      return {
        token,
        verificationCode,
        expiresAt: expiresAt.toISOString(),
        createdAt: now.toISOString(),
        createdBy: adminUsername,
        links: updatedLinks,
      };
    } finally {
      await this.releaseLockAsync();
    }
  }

  async getPasswordResetLinks(userId) {
    const user = await this.findById(userId);
    return (user && user.passwordResetLinks) ? user.passwordResetLinks : [];
  }

  async findUserByPasswordResetToken(token) {
    if (!token || typeof token !== "string") return null;
    const users = await this.readAll();
    const now = new Date();
    for (const user of users) {
      const links = user.passwordResetLinks || [];
      for (const link of links) {
        if (link.token !== token) continue;
        if (link.usedAt) continue;
        if (link.supersededAt) continue;
        const exp = link.expiresAt ? new Date(link.expiresAt) : null;
        if (!exp || exp <= now) continue;
        return user;
      }
    }
    return null;
  }

  async findResetLinkByToken(token) {
    if (!token || typeof token !== "string") return null;
    const users = await this.readAll();
    const now = new Date();
    for (const user of users) {
      const links = user.passwordResetLinks || [];
      for (const link of links) {
        if (!link || link.token !== token) continue;
        if (link.usedAt) continue;
        if (link.supersededAt) continue;
        const exp = link.expiresAt ? new Date(link.expiresAt) : null;
        if (!exp || exp <= now) continue;
        return { user, link };
      }
    }
    return null;
  }

  async verifyResetLink(token, code) {
    const cleanToken = typeof token === "string" ? token.trim() : "";
    const cleanCode = String(code || "").replace(/\D/g, "").slice(0, 6);
    if (!cleanToken || cleanCode.length !== 6) {
      return { success: false };
    }

    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for write operation");
    }
    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);
      const nowIso = new Date().toISOString();
      let foundUser = null;
      let matched = false;

      for (let i = 0; i < data.users.length; i++) {
        const user = data.users[i];
        const links = user.passwordResetLinks || [];
        const updatedLinks = links.map((l) => {
          if (!l || l.token !== cleanToken) return l;
          if (l.usedAt || l.supersededAt) return l;
          const exp = l.expiresAt ? new Date(l.expiresAt) : null;
          if (!exp || exp <= new Date()) return l;
          if (String(l.verificationCode || "") !== cleanCode) return l;
          matched = true;
          foundUser = user;
          return { ...l, verifiedAt: l.verifiedAt || nowIso };
        });

        if (matched) {
          data.users[i] = { ...user, passwordResetLinks: updatedLinks };
          break;
        }
      }

      if (!matched || !foundUser) {
        return { success: false };
      }

      data._metadata.lastModified = nowIso;
      data._metadata.checksum = this.calculateChecksum(data.users);
      await this.writeFileSecure(JSON.stringify(data, null, 2));
      return { success: true, username: foundUser.username };
    } finally {
      await this.releaseLockAsync();
    }
  }

  async setPasswordByResetToken(token, hashedPassword) {
    const lockAcquired = await this.acquireLockAsync();
    if (!lockAcquired) {
      throw new Error("Could not acquire lock for write operation");
    }
    try {
      const content = await fsPromises.readFile(this.filePath, "utf8");
      const data = JSON.parse(content);
      const now = new Date().toISOString();
      let found = false;
      for (let i = 0; i < data.users.length; i++) {
        const user = data.users[i];
        const links = user.passwordResetLinks || [];
        for (let j = 0; j < links.length; j++) {
          if (links[j].token === token && !links[j].usedAt && !links[j].supersededAt) {
            const exp = links[j].expiresAt ? new Date(links[j].expiresAt) : null;
            if (exp && exp > new Date()) {
              if (!links[j].verifiedAt) {
                throw new Error("Reset link not verified");
              }
              links[j].usedAt = now;
              data.users[i] = {
                ...user,
                password: hashedPassword,
                passwordResetLinks: links,
              };
              found = true;
              break;
            }
          }
        }
        if (found) break;
      }
      if (!found) {
        throw new Error("Invalid or expired reset token");
      }
      data._metadata.lastModified = now;
      data._metadata.checksum = this.calculateChecksum(data.users);
      await this.writeFileSecure(JSON.stringify(data, null, 2));
      return true;
    } finally {
      await this.releaseLockAsync();
    }
  }
}

module.exports = new SecureUserRegistrationsStore();

