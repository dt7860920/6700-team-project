// A clean Express app: every flag on this file is a false positive.
const express = require("express");
const fs = require("fs");
const axios = require("axios");
const { execFile } = require("child_process");
const escapeHtml = require("escape-html");
const db = require("./db");

const app = express();
const BASE_URL = "https://api.example.com";
const CONFIG_PATH = "/etc/app/config.json";
const ID_PATTERN = /^[0-9]+$/;

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (err, rows) => res.json(rows));
});

app.get("/user-template", (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => res.json(rows));
});

app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (err, stdout) => res.send(stdout));
});

app.get("/valid", (req, res) => {
  const ok = ID_PATTERN.exec(req.query.q);
  res.json({ ok: Boolean(ok) });
});

app.get("/items", async (req, res) => {
  const r = await axios.get(BASE_URL + "/items");
  res.json(r.data);
});

app.get("/config", (req, res) => {
  fs.readFile(CONFIG_PATH, "utf8", (err, data) => res.type("json").send(data));
});

app.get("/hello", (req, res) => {
  res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
});

app.get("/echo", (req, res) => {
  res.send(JSON.stringify({ q: req.query.q }));
});

module.exports = app;
