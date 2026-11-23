// A deliberately-vulnerable Express app with an OS-command-injection sink (CWE-78) behind a
// route handler. Used to exercise framework detection and the supertest scaffold; the
// dynamic sink oracle is Python-only for now, so a JS finding is reported as 'skipped',
// never proven. Kept here so detection + scaffolding have a realistic JS target.
const express = require("express");
const { execSync } = require("child_process");

const app = express();

app.get("/run", (req, res) => {
  const host = req.query.host || "localhost";
  // VULNERABLE (CWE-78): host is concatenated into a shell command string.
  const out = execSync("ping -c 1 " + host).toString();
  res.send(out);
});

module.exports = app;
