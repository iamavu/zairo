const express = require("express");

const app = express();

function logRequests(req, res, next) {
  const started = process.hrtime.bigint();
  res.on("finish", () => {
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    console.log(`${req.method} ${req.path} ${res.statusCode} ${ms.toFixed(1)}ms`);
  });
  next();
}

function listItems(req, res) {
  res.json({ items: [] });
}

app.use(logRequests);
app.get("/items", listItems);
app.listen(3000);
