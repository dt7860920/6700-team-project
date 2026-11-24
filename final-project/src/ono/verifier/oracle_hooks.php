<?php
// In-jail PHP sink oracle: runs a read-only PoC INSIDE the sandbox and reports whether a
// verifier-chosen canary reached the flagged sink.
//
// This is the PHP sibling of ono/verifier/_oracle.py and ono/verifier/oracle_hooks.js. The
// verifier ships this file's *source text* into the jail (.ono/oracle.php) next to the PoC
// the prover wrote (.ono/poc.php) and runs:
//
//     php .ono/oracle.php '<json config>'
//
// The config names the finding's CWE, sink `file` + line range, the canary string and the
// PoC path - EXACTLY the same shape the Python and JS oracles take (see oracle_php.py). The
// oracle:
//
// 1. hooks the handful of PHP builtins that are the dangerous call for one of the families
//    this oracle proves, using the `uopz` PECL extension (uopz_set_hook): a PHP builtin such
//    as system()/shell_exec()/unserialize()/mysqli_query() cannot be redefined in pure PHP,
//    so uopz installs a closure that runs ON ENTRY to the real function, observes its
//    arguments, and lets the original proceed unchanged;
// 2. exposes the canary to the PoC as getenv('ONO_PAYLOAD') - the PoC must put it wherever
//    attacker input enters and drive the target code;
// 3. requires the PoC file (so its top-level code runs once, like Python's runpy / Node's
//    require of the entry module);
// 4. prints ONE line `ONO_ORACLE_RESULT <json>` describing every hit: which sink fired,
//    whether the canary was in the DANGEROUS argument, and the in-repo call stack at that
//    moment.
//
// A hit counts as the finding being real only if (a) its CWE matches the finding and (b) the
// finding's sink file:line (within a small tolerance) is on the stack when the sink fired -
// the PoC calling system($canary) itself therefore proves nothing; the target code must be
// the one reaching the sink. This is the identical integrity contract as the Python and JS
// oracles (see _oracle.py's module docstring). The prover NEVER receives the canary.
//
// What "unsanitized" means for each family (mirrors the Python/JS oracles):
//   command injection (CWE-78)   the canary appears in a SHELL command string
//                                (system/exec/shell_exec/passthru/popen, or proc_open with a
//                                string command); proc_open with an ARRAY command (argv, no
//                                shell) is the safe, parameterised shape and does not fire
//   code injection (CWE-95)      the canary appears in source handed to assert() or
//                                create_function()
//   SQL injection (CWE-89)       the canary appears in the SQL TEXT passed to
//                                mysqli_query/pg_query/PDO::query/PDO::exec/... (a bound
//                                parameter placeholder never reaches it)
//   path traversal (CWE-22)      the canary appears in a path opened/written/removed that
//                                still carries a ".." segment
//   unsafe deserialization (502) the canary appears in a blob handed to unserialize()
//   SSRF (CWE-918)               the canary appears in the URL a curl request is pointed at
//                                (curl_setopt CURLOPT_URL) or in a URL fetched by
//                                file_get_contents()
//   reflected output (CWE-79)    the canary appears in a formatted string written to output
//                                by printf()/vprintf()
//
// LANGUAGE-CONSTRUCT LIMITATION (documented, honest): `eval`, `include`/`require`,
// `echo`/`print` and the backtick operator are PHP language CONSTRUCTS, not functions, so
// uopz_set_hook cannot intercept them. The php_frontend lowers them into synthetic calls for
// STATIC matching only; at runtime they cannot be observed by this oracle. A finding whose
// sink is purely one of those constructs (notably CWE-98 file inclusion, and the eval/echo
// members of CWE-95/CWE-79) therefore stays honestly UNPROVEN (rung <= 2), never falsely
// failed - the same posture the JS oracle takes for pure-ESM targets. The FUNCTION-form
// members of every family (shell_exec, assert, create_function, printf, ... ) ARE hooked.
//
// FALLBACK WHEN uopz IS UNAVAILABLE: if the `uopz` extension is not loaded the oracle emits a
// single ok=false result naming the missing extension (the finding stays rung <= 2, never a
// crash). A pure-PHP fallback can shadow a NAMESPACED call to a builtin (e.g. a call to
// `system()` from inside `namespace App;` resolves `App\system` first, which a same-named
// function defined in that namespace can shadow) - but it cannot touch an unqualified call in
// the global namespace, which is the common case, so uopz is the primary and intended
// mechanism here.

declare(strict_types=1);

const RESULT_MARKER = 'ONO_ORACLE_RESULT ';
const PAYLOAD_ENV = 'ONO_PAYLOAD';
const MAX_HITS = 50;
const MAX_STACK = 12;
const PREVIEW_CHARS = 240;
const TAIL_CHARS = 2000;
const CANARY_CORE_LEN = 19; // "ONO" + 16 hex chars (see oracle.py's new_canary)

// CWE families: a hit of one member proves a finding labelled with any other member. Mirrors
// _oracle.py's CWE_FAMILIES (a CWE number means the same thing in any language), plus CWE-98
// (PHP file inclusion), which heads no shared family. Only the families this oracle
// instruments (or honestly cannot, for the language-construct ones) are listed.
const CWE_FAMILIES = [
    'CWE-78' => ['CWE-78', 'CWE-77', 'CWE-88'],      // command injection
    'CWE-94' => ['CWE-94', 'CWE-95', 'CWE-96'],      // code injection (assert/create_function)
    'CWE-89' => ['CWE-89'],                          // SQL injection
    'CWE-98' => ['CWE-98'],                          // file inclusion (language construct only)
    'CWE-22' => ['CWE-22', 'CWE-23', 'CWE-36'],      // path traversal
    'CWE-918' => ['CWE-918'],                        // SSRF
    'CWE-502' => ['CWE-502', 'CWE-20'],              // unsafe deserialization
    'CWE-79' => ['CWE-79', 'CWE-80'],                // reflected unescaped output
];

const SHELLS = ['sh', 'bash', 'dash', 'zsh', 'ash', 'ksh'];
const CURLOPT_URL_VALUE = 10002; // CURLOPT_URL numeric value (curl may not be loaded)

function ono_family_of(string $cwe): array
{
    foreach (CWE_FAMILIES as $members) {
        if (in_array($cwe, $members, true)) {
            return $members;
        }
    }
    return [$cwe];
}

/**
 * Everything a hook needs: the canary, the sink to match and the hits so far.
 */
class OnoOracleState
{
    public string $canary;
    public string $core;
    public string $sinkFile;
    public int $lineStart;
    public int $lineEnd;
    public int $tolerance;
    public string $root;
    public string $pocFile;
    /** @var array<int, array<string, mixed>> */
    public array $hits = [];
    public bool $truncated = false;
    public bool $active = false; // hooks only record while the PoC runs

    public function __construct(array $config, string $root)
    {
        $this->canary = (string) ($config['canary'] ?? '');
        $this->core = substr($this->canary, 0, CANARY_CORE_LEN);
        $sink = str_replace('\\', '/', (string) ($config['sink_file'] ?? ''));
        $this->sinkFile = preg_replace('#^\./#', '', $sink) ?? $sink;
        $this->lineStart = (int) ($config['line_start'] ?? 1);
        $this->lineEnd = (int) ($config['line_end'] ?? $this->lineStart);
        $this->tolerance = (int) ($config['tolerance'] ?? 3);
        $this->root = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $poc = (string) ($config['poc'] ?? '');
        $this->pocFile = $this->normalize($poc);
    }

    private function normalize(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        if ($path !== '' && $path[0] !== '/') {
            $path = $this->root . $path;
        }
        $real = @realpath($path);
        return $real !== false ? str_replace('\\', '/', $real) : $path;
    }

    /** In-repo frames, innermost first; the oracle and the PoC are labelled, not hidden. */
    public function repoStack(): array
    {
        $frames = [];
        $raw = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, MAX_STACK + 8);
        foreach ($raw as $frame) {
            if (count($frames) >= MAX_STACK) {
                break;
            }
            $file = isset($frame['file']) ? str_replace('\\', '/', (string) $frame['file']) : '';
            $line = isset($frame['line']) ? (int) $frame['line'] : 0;
            if ($file === '') {
                continue;
            }
            if (strpos($file, $this->root) !== 0) {
                continue;
            }
            $rel = substr($file, strlen($this->root));
            if (strpos($rel, '.ono/oracle') === 0) {
                continue; // the oracle's own frames are noise
            }
            $frames[] = [
                'file' => $rel,
                'line' => $line,
                'func' => (string) ($frame['function'] ?? '<main>'),
            ];
        }
        return $frames;
    }

    public function atSink(array $stack, bool $innermostOnly = false): bool
    {
        $lo = $this->lineStart - $this->tolerance;
        $hi = $this->lineEnd + $this->tolerance;
        $frames = array_values(array_filter($stack, static fn($f) => !OnoOracleState::isPoc($f['file'])));
        if ($innermostOnly) {
            $frames = array_slice($frames, 0, 1);
            $lo = $this->lineStart;
            $hi = $this->lineEnd;
        }
        foreach ($frames as $f) {
            if ($f['file'] === $this->sinkFile && $f['line'] >= $lo && $f['line'] <= $hi) {
                return true;
            }
        }
        return false;
    }

    public function record(string $cwe, string $kind, $argument, bool $tainted): void
    {
        if (!$this->active) {
            return;
        }
        $stack = $this->repoStack();
        $located = $this->atSink($stack, !$tainted);
        if (!$tainted && !$located) {
            return;
        }
        if (count($this->hits) >= MAX_HITS) {
            $this->truncated = true;
            return;
        }
        $this->hits[] = [
            'cwe' => $cwe,
            'kind' => $kind,
            'tainted' => $tainted,
            'at_sink' => $tainted && $located,
            'argument' => $this->preview($argument),
            'stack' => $stack,
        ];
    }

    public function contains($value): bool
    {
        if ($this->core === '') {
            return false;
        }
        if (is_string($value)) {
            return strpos($value, $this->core) !== false;
        }
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                if ((is_string($k) && strpos($k, $this->core) !== false) || $this->contains($v)) {
                    return true;
                }
            }
            return false;
        }
        if (is_object($value)) {
            if (method_exists($value, '__toString')) {
                return strpos((string) $value, $this->core) !== false;
            }
            return false;
        }
        if ($value === null || is_bool($value) || is_int($value) || is_float($value)) {
            return false;
        }
        return strpos((string) $value, $this->core) !== false;
    }

    private function preview($value): string
    {
        try {
            if (is_string($value)) {
                $text = $value;
            } elseif (is_array($value) || is_object($value)) {
                $text = json_encode($value);
                if ($text === false) {
                    $text = '<unserializable>';
                }
            } else {
                $text = var_export($value, true);
            }
        } catch (\Throwable $e) {
            $text = '<unprintable>';
        }
        $text = str_replace($this->canary, '<PAYLOAD>', (string) $text);
        if ($this->core !== '') {
            $text = str_replace($this->core, '<PAYLOAD>', $text);
        }
        return substr($text, 0, PREVIEW_CHARS);
    }

    public static function isPoc(string $rel): bool
    {
        return strpos($rel, '.ono/') === 0;
    }
}

// ---------------------------------------------------------------------------
// Hooks (all via uopz_set_hook: a closure that runs on entry to the real builtin)
// ---------------------------------------------------------------------------

function ono_is_shell_like($executable): bool
{
    if (!is_string($executable)) {
        return false;
    }
    $base = basename(str_replace('\\', '/', $executable));
    return in_array($base, SHELLS, true);
}

/** Install a uopz hook on a global function; returns true if it was installed. */
function ono_hook(string $function, \Closure $hook, array &$installed): bool
{
    if (!function_exists('uopz_set_hook') || !function_exists($function)) {
        return false;
    }
    try {
        if (uopz_set_hook($function, $hook)) {
            $installed[] = $function;
            return true;
        }
    } catch (\Throwable $e) {
        // one builtin's refusal to be hooked must never break the others
    }
    return false;
}

/** Install a uopz hook on a class method; best-effort (the class/method may not exist). */
function ono_hook_method(string $class, string $method, \Closure $hook, array &$installed): bool
{
    if (!function_exists('uopz_set_hook') || !class_exists($class) || !method_exists($class, $method)) {
        return false;
    }
    try {
        if (uopz_set_hook($class, $method, $hook)) {
            $installed[] = "$class::$method";
            return true;
        }
    } catch (\Throwable $e) {
    }
    return false;
}

function ono_install_command(OnoOracleState $state, array &$installed): void
{
    foreach (['system', 'exec', 'shell_exec', 'passthru', 'popen'] as $fn) {
        ono_hook($fn, function () use ($state, $fn) {
            $args = func_get_args();
            $cmd = $args[0] ?? '';
            $state->record('CWE-78', $fn, $cmd, $state->contains($cmd));
        }, $installed);
    }
    // proc_open: a STRING command runs through a shell (dangerous); an ARRAY command is argv,
    // never parsed by a shell - the safe, parameterised shape, recorded untainted (so the
    // "ran but not in the dangerous argument" signal is available to a false-positive finding).
    ono_hook('proc_open', function () use ($state) {
        $args = func_get_args();
        $cmd = $args[0] ?? '';
        if (is_array($cmd)) {
            $joined = implode(' ', array_map(static fn($p) => is_scalar($p) ? (string) $p : '', $cmd));
            if ($state->contains($joined)) {
                $state->record('CWE-78', 'proc_open(argv)', $joined, false);
            }
        } else {
            $state->record('CWE-78', 'proc_open(shell)', $cmd, $state->contains($cmd));
        }
    }, $installed);
}

function ono_install_code(OnoOracleState $state, array &$installed): void
{
    // `eval` is a language construct - NOT hookable (see the limitation note). The function
    // forms of code injection ARE: assert() (a string argument is eval'd) and create_function().
    ono_hook('assert', function () use ($state) {
        $args = func_get_args();
        $code = $args[0] ?? null;
        if (is_string($code)) {
            $state->record('CWE-95', 'assert', $code, $state->contains($code));
        }
    }, $installed);
    ono_hook('create_function', function () use ($state) {
        $args = func_get_args();
        $body = $args[1] ?? ($args[0] ?? '');
        $state->record('CWE-95', 'create_function', $body, $state->contains($body));
    }, $installed);
}

function ono_install_sql(OnoOracleState $state, array &$installed): void
{
    // Procedural drivers. The SQL text is the dangerous argument; for the procedural forms a
    // canary anywhere in a string argument means it reached the query text (these functions
    // take no bound parameters - prepared statements use a separate bind call).
    $procedural = [
        'mysqli_query' => 1, // mysqli_query($link, $query)
        'mysql_query' => 0,  // mysql_query($query [, $link])
        'pg_query' => 'any', // pg_query($query) or pg_query($conn, $query)
        'pg_send_query' => 'any',
        'sqlite_query' => 'any',
    ];
    foreach ($procedural as $fn => $argIndex) {
        ono_hook($fn, function () use ($state, $fn, $argIndex) {
            $args = func_get_args();
            if ($argIndex === 'any') {
                foreach ($args as $a) {
                    if (is_string($a) && $state->contains($a)) {
                        $state->record('CWE-89', $fn, $a, true);
                        return;
                    }
                }
                return;
            }
            $sql = $args[$argIndex] ?? null;
            if (is_string($sql)) {
                $state->record('CWE-89', $fn, $sql, $state->contains($sql));
            }
        }, $installed);
    }
    // PDO / mysqli object methods: the SQL text is the first positional.
    foreach ([['PDO', 'query'], ['PDO', 'exec'], ['mysqli', 'query'], ['SQLite3', 'query'], ['SQLite3', 'exec']] as [$cls, $m]) {
        ono_hook_method($cls, $m, function () use ($state, $cls, $m) {
            $args = func_get_args();
            $sql = $args[0] ?? null;
            if (is_string($sql)) {
                $state->record('CWE-89', "$cls::$m", $sql, $state->contains($sql));
            }
        }, $installed);
    }
}

function ono_install_path(OnoOracleState $state, array &$installed): void
{
    foreach (['fopen', 'file_get_contents', 'file_put_contents', 'readfile', 'fpassthru', 'unlink'] as $fn) {
        ono_hook($fn, function () use ($state, $fn) {
            $args = func_get_args();
            $path = $args[0] ?? '';
            if (!is_string($path) || !$state->contains($path)) {
                return;
            }
            // SSRF double-duty: a tainted URL fetched by file_get_contents is CWE-918, not
            // CWE-22; a filesystem path carrying ".." is traversal.
            if (preg_match('#^\s*[a-z][a-z0-9+.\-]*://#i', $path)) {
                $state->record('CWE-918', $fn, $path, true);
                return;
            }
            $segments = explode('/', str_replace('\\', '/', $path));
            $traversal = in_array('..', $segments, true);
            $state->record('CWE-22', $fn, $path, $traversal);
        }, $installed);
    }
}

function ono_install_deserialization(OnoOracleState $state, array &$installed): void
{
    ono_hook('unserialize', function () use ($state) {
        $args = func_get_args();
        $blob = $args[0] ?? '';
        $state->record('CWE-502', 'unserialize', $blob, $state->contains($blob));
    }, $installed);
}

function ono_install_ssrf(OnoOracleState $state, array &$installed): void
{
    // curl_setopt($ch, CURLOPT_URL, $url): the canary in the URL option is the SSRF sink.
    ono_hook('curl_setopt', function () use ($state) {
        $args = func_get_args();
        $option = $args[1] ?? null;
        $value = $args[2] ?? null;
        $urlOpt = defined('CURLOPT_URL') ? CURLOPT_URL : CURLOPT_URL_VALUE;
        if ($option === $urlOpt && is_string($value) && $state->contains($value)) {
            $state->record('CWE-918', 'curl_setopt(CURLOPT_URL)', $value, true);
        }
    }, $installed);
}

function ono_install_output(OnoOracleState $state, array &$installed): void
{
    // `echo`/`print` are language constructs (not hookable); printf()/vprintf() ARE functions.
    foreach (['printf', 'vprintf'] as $fn) {
        ono_hook($fn, function () use ($state, $fn) {
            $args = func_get_args();
            foreach ($args as $a) {
                if ($state->contains($a)) {
                    $state->record('CWE-79', $fn, $a, true);
                    return;
                }
            }
        }, $installed);
    }
}

function ono_install_hooks(OnoOracleState $state): array
{
    $installed = [];
    foreach ([
        'ono_install_command',
        'ono_install_code',
        'ono_install_sql',
        'ono_install_path',
        'ono_install_deserialization',
        'ono_install_ssrf',
        'ono_install_output',
    ] as $installer) {
        try {
            $installer($state, $installed);
        } catch (\Throwable $e) {
            // one family's hook failing must never break the others
        }
    }
    return $installed;
}

// ---------------------------------------------------------------------------
// Running the PoC
//
// The PoC is required at the SCRIPT'S GLOBAL SCOPE (an `if` / `try` block creates no scope in
// PHP), not from inside a function - so a target whose top-level code sets globals the rest of
// it reads (`$APP_SECRET` + `global $APP_SECRET`, a common procedural shape) behaves exactly
// as it would when run directly. This is PHP's equivalent of the JS oracle compiling the PoC
// at the repository root (requirePocAtRoot) and Python's runpy at the root.
// ---------------------------------------------------------------------------

function ono_emit(array $result): void
{
    // Leading newline so a stray byte left on stdout (e.g. an app's own output flushed at a
    // fatal shutdown) cannot glue itself to the marker and break the parser's line scan.
    fwrite(STDOUT, "\n" . RESULT_MARKER . json_encode($result, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR) . "\n");
}

function ono_emit_once(array $result): void
{
    if (!empty($GLOBALS['ono_emitted'])) {
        return;
    }
    $GLOBALS['ono_emitted'] = true;
    ono_emit($result);
}

/** Backstop: a true fatal (OOM, timeout, undefined construct) bypasses the try/catch below -
 *  this still emits ONE result line so the host never sees a silent, marker-less run. */
function ono_shutdown(): void
{
    if (!empty($GLOBALS['ono_emitted'])) {
        return;
    }
    $err = error_get_last();
    $detail = is_array($err) && isset($err['message']) ? $err['message'] : 'the PoC terminated without a result';
    ono_emit_once(['ok' => false, 'error' => 'the oracle did not finish: ' . $detail]);
}

/** Parse argv/config, install hooks, prepare the jail; ['fail'=>...] or the ready state. */
function ono_setup(array $argv): array
{
    $args = array_slice($argv, 1);
    if (count($args) < 1) {
        return ['fail' => ['ok' => false, 'error' => 'usage: <json>']];
    }
    $config = json_decode($args[0], true);
    if (!is_array($config)) {
        return ['fail' => ['ok' => false, 'error' => 'the oracle config was not valid JSON']];
    }
    if (!extension_loaded('uopz')) {
        return ['fail' => ['ok' => false, 'error' => 'the uopz extension is not loaded in this '
            . 'PHP runtime; the PHP sink oracle cannot hook builtins without it (build the php '
            . 'jail image: pecl install uopz && docker-php-ext-enable uopz)']];
    }
    $root = getcwd() !== false ? getcwd() : '.';
    $state = new OnoOracleState($config, $root);
    putenv(PAYLOAD_ENV . '=' . $state->canary);
    $_ENV[PAYLOAD_ENV] = $state->canary;
    $_SERVER[PAYLOAD_ENV] = $state->canary;
    $installed = ono_install_hooks($state);
    @chdir($root);
    // Both an unqualified `include 'app.php'` and an explicit `./app.php` from the PoC resolve
    // against this (the workspace root).
    set_include_path($root . PATH_SEPARATOR . get_include_path());
    return ['state' => $state, 'config' => $config, 'installed' => $installed];
}

/** Turn the recorded hits into the shared ONO_ORACLE_RESULT document. */
function ono_build_result(
    OnoOracleState $state,
    array $config,
    array $installed,
    int $pocExit,
    string $pocError,
    string $pocStdout,
    float $durationMs
): array {
    $accepted = ono_family_of((string) ($config['cwe'] ?? ''));
    $relevant = array_values(array_filter($state->hits, static fn($h) => in_array($h['cwe'], $accepted, true)));
    $fired = false;
    foreach ($relevant as $h) {
        if ($h['at_sink']) {
            $fired = true;
            break;
        }
    }
    $reachedElsewhere = array_values(array_filter($relevant, static fn($h) => $h['tainted'] && !$h['at_sink']));
    $untaintedAtSink = false;
    if (!$fired) {
        foreach ($relevant as $h) {
            if (!$h['tainted']) {
                $untaintedAtSink = true;
                break;
            }
        }
    }
    return [
        'ok' => true,
        'fired' => $fired,
        'reached_elsewhere' => $reachedElsewhere,
        'untainted_at_sink' => $untaintedAtSink,
        'hits' => $state->hits,
        'hits_truncated' => $state->truncated,
        'hooks' => $installed,
        'poc_exit' => $pocExit,
        'poc_error' => $pocError,
        'poc_stdout' => substr($pocStdout, -TAIL_CHARS),
        'poc_stderr' => '',
        'duration_ms' => $durationMs,
    ];
}

// --- main (deliberately at the script's global scope; `if`/`try` add no scope) -------------
if (PHP_SAPI === 'cli' && isset($argv)) {
    $GLOBALS['ono_emitted'] = false;
    register_shutdown_function('ono_shutdown');
    $ono_setup = ono_setup($argv);
    if (isset($ono_setup['fail'])) {
        ono_emit_once($ono_setup['fail']);
    } else {
        /** @var OnoOracleState $ono_state */
        $ono_state = $ono_setup['state'];
        $ono_poc_error = '';
        $ono_poc_exit = 0;
        $ono_started = microtime(true);
        ob_start();
        $ono_state->active = true;
        try {
            require $ono_state->pocFile;
        } catch (\Throwable $ono_e) {
            $ono_poc_exit = 1;
            // Python's traceback puts the message LAST; the shared host-side oracle.py takes
            // the LAST line for the short summary and the TAIL for the full one. Match that:
            // the stack trace first, then the "Type: message" line last.
            $ono_poc_error = substr(
                $ono_e->getTraceAsString() . "\n" . get_class($ono_e) . ': ' . $ono_e->getMessage(),
                -TAIL_CHARS
            );
        }
        $ono_state->active = false;
        $ono_captured = ob_get_clean();
        $ono_poc_stdout = $ono_captured === false ? '' : $ono_captured;
        $ono_duration = (microtime(true) - $ono_started) * 1000.0;
        ono_emit_once(ono_build_result(
            $ono_state,
            $ono_setup['config'],
            $ono_setup['installed'],
            $ono_poc_exit,
            $ono_poc_error,
            (string) $ono_poc_stdout,
            $ono_duration
        ));
    }
}
