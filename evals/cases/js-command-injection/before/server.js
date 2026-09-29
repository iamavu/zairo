const express = require("express");
const { execFile } = require("child_process");

const app = express();
const HOST_RE = /^[a-z0-9.-]{1,253}$/i;

function ping(req, res) {
  const host = String(req.query.host || "");
  if (!HOST_RE.test(host)) {
    return res.status(400).json({ error: "bad host" });
  }
  execFile("ping", ["-c", "1", host], (err, stdout) => {
    res.json({ ok: !err, output: stdout });
  });
}

app.get("/ping", ping);
app.listen(3000);
