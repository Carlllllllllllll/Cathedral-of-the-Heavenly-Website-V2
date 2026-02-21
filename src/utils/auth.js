const jwt = require("jsonwebtoken");

const bcrypt = require("bcrypt");

let argon2;

try {
  argon2 = require("argon2");
} catch (e) {}

const JWT_SECRET = process.env.JWT_SECRET || "fallback_jwt_secret_998877";

const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "fallback_refresh_secret_112233";

const ACCESS_TOKEN_EXPIRY = "15m";

const REFRESH_TOKEN_EXPIRY = "7d";

async function hashPassword(password) {
  if (argon2) {
    return await argon2.hash(password, {
      type: argon2.argon2id,

      memoryCost: 2 ** 16,

      timeCost: 3,

      parallelism: 1,
    });
  }

  return await bcrypt.hash(password, 12);
}

async function comparePassword(password, hashedPassword) {
  if (argon2 && hashedPassword.startsWith("$argon2")) {
    try {
      return await argon2.verify(hashedPassword, password);
    } catch (e) {
      return false;
    }
  }

  return await bcrypt.compare(password, hashedPassword);
}

function generateAccessToken(user) {
  return jwt.sign(
    {
      id: user._id,

      username: user.username,

      role: user.role,

      grade: user.grade,
    },

    JWT_SECRET,

    { expiresIn: ACCESS_TOKEN_EXPIRY },
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user._id },

    JWT_REFRESH_SECRET,

    { expiresIn: REFRESH_TOKEN_EXPIRY },
  );
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = {
  hashPassword,

  comparePassword,

  generateAccessToken,

  generateRefreshToken,

  verifyAccessToken,

  verifyRefreshToken,
};
