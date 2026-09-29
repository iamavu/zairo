const express = require("express");

const app = express();

function listItems(req, res) {
  res.json({ items: [] });
}

app.get("/items", listItems);
app.listen(3000);
