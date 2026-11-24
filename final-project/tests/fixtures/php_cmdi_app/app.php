<?php
// Deliberately vulnerable procedural PHP fixture for the PHP sink oracle's real-jail tests.
// The sinks sit behind the application's OWN entry point - an include-time secret and an
// API-key precondition - exactly like the express_cmdi_app JS fixture
// (tests/fixtures/express_cmdi_app). A from-scratch script that never requires this file, or
// that calls system() itself, must NOT prove anything; only driving handle() does.

$APP_SECRET = getenv('APP_SECRET');
if (!$APP_SECRET) {
    // Include-time precondition: the app refuses to load without its deployment secret -
    // the real-app failure mode (top-level code the jail does not satisfy on its own).
    throw new RuntimeException('APP_SECRET must be set before including this app');
}

function require_api_key(array $req): void
{
    global $APP_SECRET;
    if (($req['api_key'] ?? null) !== $APP_SECRET) {
        throw new RuntimeException('unauthorized');
    }
}

function handle(array $req)
{
    $path = (string) ($req['path'] ?? '');
    $args = (array) ($req['args'] ?? []);
    if ($path === '/diagnose') {
        require_api_key($req);
        $host = (string) ($args['host'] ?? '');
        // VULN (CWE-78, command injection): the "host" parameter is interpolated into a shell
        // command string. Reachable only through this route, behind require_api_key.
        return system('ping -c 1 ' . $host); // VULN-CMDI
    }
    if ($path === '/diagnose-safe') {
        require_api_key($req);
        $host = (string) ($args['host'] ?? '');
        // SAFE sibling: the argv (array) form of proc_open never spawns a shell, so the host
        // can never be a command-injection sink - the planted false positive.
        $proc = proc_open(['ping', '-c', '1', $host], [], $pipes); // SAFE: argv form, no shell
        if (is_resource($proc)) {
            proc_close($proc);
        }
        return '';
    }
    throw new RuntimeException('not found: ' . $path);
}
