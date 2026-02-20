function sanitizeId(value) {
  if (!value) {
    return "";
  }
  const normalized = value.toString().replace(/[^0-9]/g, "");
  return normalized;
}

function getOwnerId() {
  const fallback = "1126336222206365696";
  const configured = sanitizeId(process.env.DISCORD_OWNER_ID);
  return configured || fallback;
}

function getOwnerMention() {
  const ownerId = getOwnerId();
  return ownerId ? `<@${ownerId}>` : "";
}

function appendOwnerMention(content) {
  const mention = getOwnerMention();
  if (!mention) {
    return content || "";
  }
  if (!content || !content.includes(mention)) {
    return content ? `${content} ${mention}`.trim() : mention;
  }
  return content;
}

module.exports = {
  getOwnerMention,
  appendOwnerMention,
};
