const express = require("express");
const { verifyPassword } = require("./users");

const app = express();
app.use(express.urlencoded({ extended: false }));

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
// Addresses tracked at once: past this, the one seen longest ago is dropped.
const MAX_TRACKED = 10000;
const attempts = new Map();

function tooManyAttempts(key) {
  const now = Date.now();
  const recent = (attempts.get(key) || []).filter((time) => now - time < WINDOW_MS);
  recent.push(now);
  // The limit only needs the latest few.
  recent.splice(0, recent.length - (MAX_ATTEMPTS + 1));
  // Re-inserted, so the map stays in order of when each address was last seen.
  attempts.delete(key);
  attempts.set(key, recent);
  if (attempts.size > MAX_TRACKED) {
    attempts.delete(attempts.keys().next().value);
  }
  return recent.length > MAX_ATTEMPTS;
}

function login(req, res) {
  if (tooManyAttempts(req.ip)) {
    return res.status(429).send("Too many attempts, try again later");
  }
  if (!verifyPassword(req.body.username, req.body.password)) {
    return res.status(401).send("Invalid credentials");
  }
  req.session.user = req.body.username;
  res.redirect("/");
}

app.post("/login", login);

module.exports = app;
