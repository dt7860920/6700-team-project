// Planted vulnerabilities in an Express app. ``// VULN: CWE-x`` marks every intended sink line.
// The pre-existing regex fallback is Python-only, so every JS case is a ``regex-miss``.
const express = require("express");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const serialize = require("node-serialize");
const child_process = require("child_process");
const { exec, execSync } = require("child_process");
const { findUser, readUpload } = require("./lib");
const db = require("./db");

const app = express();
const pool = db.pool;

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => { // VULN: CWE-89 regex-miss
    res.json(rows);
  });
});

app.get("/user/:name", (req, res) => {
  pool.query(`SELECT * FROM users WHERE name = '${req.params.name}'`).then((rows) => { // VULN: CWE-89 regex-miss
    res.json(rows);
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";
  db.connection.query(sql, (err, rows) => res.json(rows)); // VULN: CWE-89 regex-miss
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, stdout) => res.send(stdout)); // VULN: CWE-78 regex-miss
});

app.get("/ls", (req, res) => {
  const dir = req.query.dir;
  const out = execSync(`ls -la ${dir}`); // VULN: CWE-78 regex-miss
  res.type("text").send(out);
});

app.post("/calc", (req, res) => {
  res.json({ result: eval(req.body.expr) }); // VULN: CWE-95 regex-miss
});

app.get("/fn", (req, res) => {
  const f = new Function("return " + req.query.code); // VULN: CWE-95 regex-miss
  res.json(f());
});

app.get("/files/:name", (req, res) => {
  fs.readFile(path.join(__dirname, "files", req.params.name), "utf8", (err, data) => { // VULN: CWE-22 regex-miss
    res.send(data);
  });
});

app.get("/static", (req, res) => {
  res.sendFile(req.query.file); // VULN: CWE-22 regex-miss
});

app.post("/proxy", async (req, res) => {
  const r = await axios.get(req.body.url); // VULN: CWE-918 regex-miss
  res.send(r.data);
});

app.get("/fetch", async (req, res) => {
  const r = await fetch(req.query.target); // VULN: CWE-918 regex-miss
  res.send(await r.text());
});

app.get("/profile", (req, res) => {
  const profile = serialize.unserialize(req.cookies.profile); // VULN: CWE-502 regex-miss
  res.json(profile);
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>"); // VULN: CWE-79 regex-miss
});

function runHandler(req, res) {
  child_process.exec(req.body.cmd, (err, out) => res.send(out)); // VULN: CWE-78 regex-miss
}
app.post("/run", runHandler);

app.get("/closure", (req, res) => {
  db.connect((err) => {
    db.query("SELECT * FROM items WHERE q = '" + req.query.q + "'", (e, rows) => res.json(rows)); // VULN: CWE-89 regex-miss
  });
});

app.get("/find", (req, res) => {
  // one hop into lib.findUser
  res.json(findUser(req.query.name));
});

app.get("/upload/:f", (req, res) => {
  res.send(readUpload(req.params.f));
});

module.exports = app;
