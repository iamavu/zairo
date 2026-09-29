const express = require("express");
const { verifyPassword } = require("./users");

const app = express();
app.use(express.urlencoded({ extended: false }));

function safeNext(next) {
  return typeof next === "string" && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

function finishLogin(req, res) {
  if (!verifyPassword(req.body.username, req.body.password)) {
    return res.status(401).send("Invalid credentials");
  }
  req.session.user = req.body.username;
  res.redirect(safeNext(req.query.next));
}

app.post("/login", finishLogin);

module.exports = app;
