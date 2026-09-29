const crypto = require("crypto");

const users = new Map();

function hash(password, salt) {
  return crypto.scryptSync(password, salt, 64);
}

function verifyPassword(username, password) {
  const user = users.get(String(username));
  if (!user) {
    return false;
  }
  return crypto.timingSafeEqual(hash(String(password), user.salt), user.hash);
}

module.exports = { verifyPassword };
