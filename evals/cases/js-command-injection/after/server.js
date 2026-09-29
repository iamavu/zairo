const express = require("express");
const { exec } = require("child_process");

const app = express();

function ping(req, res) {
  const host = String(req.query.host || "");
  const count = req.query.count || 1;
  exec(`ping -c ${count} ${host}`, (err, stdout) => {
    res.json({ ok: !err, output: stdout });
  });
}

app.get("/ping", ping);
app.listen(3000);
