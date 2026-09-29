const express = require("express");
const { verifyPassword } = require("./users");

const app = express();
app.use(express.urlencoded({ extended: false }));

function login(req, res) {
  if (!verifyPassword(req.body.username, req.body.password)) {
    return res.status(401).send("Invalid credentials");
  }
  req.session.user = req.body.username;
  res.redirect("/");
}

app.post("/login", login);

module.exports = app;
