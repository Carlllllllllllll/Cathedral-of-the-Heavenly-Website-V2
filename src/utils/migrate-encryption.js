const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const { encryptFields, hash } = require("./encryption");

dotenv.config();

async function migrate() {
  console.log("🚀 Starting Database Encryption Migration...");

  try {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    console.log("✅ Connected to MongoDB");

    const UserRegistration =
      mongoose.models.UserRegistration ||
      mongoose.model(
        "UserRegistration",
        new mongoose.Schema(
          {
            firstName: String,
            secondName: String,
            email: String,
            emailHash: String,
            phone: String,
            phoneHash: String,
            username: String,
          },
          { strict: false },
        ),
      );

    const users = await UserRegistration.find({});
    console.log(`📊 Found ${users.length} users to process.`);

    let migratedCount = 0;
    let skippedCount = 0;
    let errorCount = 0;

    for (const user of users) {
      const isEncrypted = (val) =>
        typeof val === "string" && val.split(":").length === 3;

      if (isEncrypted(user.firstName)) {
        skippedCount++;
        continue;
      }

      if (user.firstName === "[object Object]") {
        console.warn(
          `[!] Warning: user ${user.username} has corrupted data [object Object]. Skipping to avoid further issues.`,
        );
        errorCount++;
        continue;
      }

      try {
        user.emailHash = hash((user.email || "").toLowerCase());
        user.phoneHash = hash((user.phone || "").trim());

        const fieldsToEncrypt = ["firstName", "secondName", "email", "phone"];
        const userData = user.toObject();
        const encryptedData = encryptFields(userData, fieldsToEncrypt);

        fieldsToEncrypt.forEach((field) => {
          if (userData[field]) {
            user[field] = encryptedData[field];
          }
        });

        await user.save();
        migratedCount++;
      } catch (err) {
        console.error(
          `❌ Failed to migrate user ${user.username}:`,
          err.message,
        );
        errorCount++;
      }
    }

    console.log(`\n🎉 Migration Complete!`);
    console.log(`✅ Migrated: ${migratedCount}`);
    console.log(`⏩ Skipped: ${skippedCount}`);
    console.log(`❌ Errors/Corrupted: ${errorCount}`);
  } catch (error) {
    console.error("❌ Migration Error:", error);
  } finally {
    if (require.main === module) {
      await mongoose.disconnect();
    }
  }
}

if (require.main === module) {
  migrate();
}

module.exports = migrate;
