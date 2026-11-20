// Helpers whose sinks are reachable only through their callers in express_app.js (one hop).
const fs = require("fs");
const path = require("path");
const db = require("./db");

const UPLOADS = "/srv/uploads";

function findUser(name) {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'"); // VULN: CWE-89 regex-miss
}

function readUpload(name) {
  return fs.readFileSync(path.join(UPLOADS, name), "utf8"); // VULN: CWE-22 regex-miss
}

function loadBlob(blob) {
  // no caller passes attacker data: reported at the "param" tier only
  return require("node-serialize").unserialize(blob); // VULN: CWE-502 regex-miss
}

module.exports = { findUser, readUpload, loadBlob };
