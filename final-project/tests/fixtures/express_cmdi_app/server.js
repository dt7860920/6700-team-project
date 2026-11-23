'use strict';
// Deliberately vulnerable Express fixture for the JS/TS verification oracle's real-jail
// tests. The sinks sit behind the application's OWN entry point - an import-time secret
// and a header-based precondition - exactly like the Python framework fixtures
// (tests/fixtures/flask_sqli_app, fastapi_cmd_app): a from-scratch script that never
// requires this module, or that calls the dangerous function itself, must NOT prove
// anything; only driving the real route does.

const express = require('express');
const { execSync, spawnSync } = require('child_process');

// Import-time precondition: the app refuses to even load without its deployment secret -
// the real-app failure mode (module-level code the jail does not satisfy on its own).
const APP_SECRET = process.env.APP_SECRET;
if (!APP_SECRET) {
  throw new Error('APP_SECRET must be set before requiring this module');
}

const app = express();

function requireApiKey(req, res, next) {
  if (req.headers['x-api-key'] !== APP_SECRET) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
}

// VULN (CWE-78, command injection): the "host" query parameter is interpolated into a
// shell command string. Reachable only through this route, behind requireApiKey.
app.get('/diagnose', requireApiKey, (req, res) => {
  const host = String(req.query.host || '');
  const output = execSync(`ping -c 1 ${host}`).toString(); // VULN-CMDI
  res.type('text/plain').send(output);
});

// The SAFE sibling: the same intent, but the argument reaches the child process as its OWN
// argv entry (no shell), so it can never be a command-injection sink - the planted
// false-positive the verifier must NOT prove.
app.get('/diagnose-safe', requireApiKey, (req, res) => {
  const host = String(req.query.host || '');
  const result = spawnSync('ping', ['-c', '1', host]); // SAFE: argv form, no shell
  res.type('text/plain').send(result.stdout ? result.stdout.toString() : '');
});

// VULN (CWE-94, code injection): the "expr" query parameter is eval'd.
app.get('/calc', requireApiKey, (req, res) => {
  const expr = String(req.query.expr || '0');
  const result = eval(expr); // VULN-EVAL
  res.json({ result: String(result) });
});

module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`listening on ${port}`);
  });
}
