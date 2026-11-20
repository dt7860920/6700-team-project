// An AWS Lambda handler: every member of ``event`` is attacker input.
const { execSync } = require("child_process");
const http = require("http");

exports.handler = async (event) => {
  const cmd = event.queryStringParameters.cmd;
  const out = execSync(cmd).toString(); // VULN: CWE-78 regex-miss
  const body = JSON.parse(event.body);
  return { statusCode: 200, body: JSON.stringify({ out, body }) };
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  http.get(url.searchParams.get("target"), (upstream) => upstream.pipe(res)); // VULN: CWE-918 regex-miss
});

server.listen(8080);
