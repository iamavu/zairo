const express = require("express");
const { verifyPassword } = require("./users");

const app = express();
app.use(express.urlencoded({ extended: false }));

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const attempts = new Map();

function tooManyAttempts(key) {
  const now = Date.now();
  const recent = (attempts.get(key) || []).filter((time) => now - time < WINDOW_MS);
  recent.push(now);
  attempts.set(key, recent);
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
