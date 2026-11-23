// In-jail Node sink oracle: runs a read-only PoC INSIDE the sandbox and reports whether a
// verifier-chosen canary reached the flagged sink.
//
// This is the JS/TS sibling of ono/verifier/_oracle.py. The verifier ships this file's
// *source text* into the jail (.ono/oracle.js) next to the PoC the prover wrote (.ono/poc.js)
// and runs:
//
//     node .ono/oracle.js '<json config>'
//
// The config names the finding's CWE, sink `file` + line range, the canary string and the
// PoC path - EXACTLY the same shape the Python oracle takes (see oracle_js.py). The oracle:
//
// 1. monkey-patches the handful of Node built-ins (and, best-effort, optional third-party
//    packages already resolvable via NODE_PATH) that are the dangerous call for one of the
//    families this oracle proves: child_process (command injection), eval/Function/vm (code
//    injection), a SQL driver's query/execute (SQL injection), fs/path (path traversal /
//    external control of file name), http/https/fetch (SSRF), node-serialize (unsafe
//    deserialization);
// 2. exposes the canary to the PoC as `process.env.ONO_PAYLOAD` - the PoC must put it wherever
//    attacker input enters and drive the target code;
// 3. requires the PoC file (so module-level code in it runs once, like Python's runpy);
// 4. prints ONE line `ONO_ORACLE_RESULT <json>` describing every hit: which sink fired,
//    whether the canary was in the DANGEROUS argument, and the in-repo call stack at that
//    moment.
//
// A hit counts as the finding being real only if (a) its CWE matches the finding and (b) the
// finding's sink file:line (within a small tolerance) is on the stack when the sink fired -
// the PoC calling child_process.exec(canary) itself therefore proves nothing; the target
// code must be the one reaching the sink. This is the identical integrity contract as the
// Python oracle (see _oracle.py's module docstring).
//
// What "unsanitized" means for each family (mirrors _oracle.py's docstring):
//   command injection   the canary appears in a SHELL command string (exec/execSync, or
//                        spawn/execFile with {shell: true}); the argv-array form without a
//                        shell does not fire (that is the safe, parameterised shape)
//   code injection       the canary appears in source handed to eval / new Function / vm.*
//   SQL injection        the canary appears in the SQL TEXT passed to query()/execute()/
//                        prepare() (a bound parameter placeholder never reaches it)
//   path traversal       the canary appears in a path opened/written/removed that still
//                        carries a ".." segment
//   file-name control    the canary appears in a path whose DIRECTORY component (not just the
//                        leaf) is attacker-controlled, or that traverses with ".."
//   SSRF                 the canary appears in the host/URL an outbound http(s)/fetch request
//                        is made to
//   unsafe deserialization  the canary appears in a blob handed to node-serialize's
//                        unserialize() (which itself calls eval - the eval hook is the
//                        general-purpose backstop for this family)
//
// Node-builtins only for the hooks that must always be available (child_process, vm, fs,
// path, http, https); third-party drivers (mysql2, pg, sqlite3, better-sqlite3,
// node-serialize) are wrapped only if `require` resolves them - a target that declares none
// of them simply gets no SQL/deserialization hook, and that finding stays honestly unproven,
// never falsely failed. CommonJS only (the oracle and the PoC are both run with `require`);
// a target that is pure ESM is a known limitation (see the PR description).

'use strict';

const RESULT_MARKER = 'ONO_ORACLE_RESULT ';
const PAYLOAD_ENV = 'ONO_PAYLOAD';
const MAX_HITS = 50;
const MAX_STACK = 12;
const PREVIEW_CHARS = 240;
const TAIL_CHARS = 2000;
const CANARY_CORE_LEN = 19; // "ONO" + 16 hex chars (see oracle.py's new_canary)

// CWE families: a hit of one member proves a finding labelled with any other member. Mirrors
// _oracle.py's CWE_FAMILIES exactly (a CWE number means the same thing in any language) -
// only the families this oracle actually instruments are listed.
const CWE_FAMILIES = {
  'CWE-78': new Set(['CWE-78', 'CWE-77', 'CWE-88']),
  'CWE-94': new Set(['CWE-94', 'CWE-95', 'CWE-96']),
  'CWE-89': new Set(['CWE-89']),
  'CWE-22': new Set(['CWE-22', 'CWE-23', 'CWE-36']),
  'CWE-73': new Set(['CWE-73']),
  'CWE-918': new Set(['CWE-918']),
  'CWE-502': new Set(['CWE-502', 'CWE-20']),
};

function familyOf(cwe) {
  for (const members of Object.values(CWE_FAMILIES)) {
    if (members.has(cwe)) return members;
  }
  return new Set([cwe]);
}

const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ash', 'ksh']);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

class State {
  constructor(config, root) {
    this.canary = String(config.canary);
    this.core = this.canary.slice(0, CANARY_CORE_LEN);
    this.sinkFile = String(config.sink_file).replace(/\\/g, '/').replace(/^\.\//, '');
    this.lineStart = Number(config.line_start || 1);
    this.lineEnd = Number(config.line_end || this.lineStart);
    this.tolerance = Number(config.tolerance != null ? config.tolerance : 3);
    this.root = root.replace(/\/+$/, '') + '/';
    this.pocFile = require('path').resolve(String(config.poc));
    this.hits = [];
    this.truncated = false;
    this.active = false; // hooks only record while the PoC runs
  }

  // -- stack --------------------------------------------------------------
  repoStack() {
    // One extra frame for this function itself; Error.prepareStackTrace is the default V8
    // formatter, so `.stack` is "Error\n    at fn (/abs/path:L:C)\n    at ...".
    const raw = new Error().stack || '';
    const lines = raw.split('\n').slice(1); // drop the "Error" header line
    const frames = [];
    const re = /at\s+(?:([^(]+?)\s+\()?(.*?):(\d+):(\d+)\)?\s*$/;
    for (const line of lines) {
      if (frames.length >= MAX_STACK) break;
      const m = re.exec(line.trim());
      if (!m) continue;
      const func = (m[1] || '<anonymous>').trim();
      const file = m[2];
      const lineNo = parseInt(m[3], 10);
      if (!file || file.startsWith('node:') || file.includes('internal/')) continue;
      let abspath;
      try {
        abspath = require('path').resolve(file);
      } catch {
        continue;
      }
      if (!abspath.startsWith(this.root)) continue;
      const rel = abspath.slice(this.root.length);
      if (rel.startsWith('.ono/oracle')) continue; // the oracle's own frames are noise
      frames.push({ file: rel, line: lineNo, func });
    }
    return frames;
  }

  atSink(stack, { innermostOnly = false } = {}) {
    let lo = this.lineStart - this.tolerance;
    let hi = this.lineEnd + this.tolerance;
    let frames = stack.filter((f) => !isPoc(f.file));
    if (innermostOnly) {
      frames = frames.slice(0, 1);
      lo = this.lineStart;
      hi = this.lineEnd;
    }
    return frames.some((f) => f.file === this.sinkFile && f.line >= lo && f.line <= hi);
  }

  // -- recording ------------------------------------------------------------
  record(cwe, kind, argument, tainted) {
    if (!this.active) return;
    const stack = this.repoStack();
    const located = this.atSink(stack, { innermostOnly: !tainted });
    if (!tainted && !located) return;
    if (this.hits.length >= MAX_HITS) {
      this.truncated = true;
      return;
    }
    this.hits.push({
      cwe,
      kind,
      tainted,
      at_sink: tainted && located,
      argument: preview(argument, this.canary),
      stack,
    });
  }

  contains(value) {
    return this._contains(value, this.core);
  }

  _contains(value, needle) {
    try {
      if (value == null) return false;
      if (typeof value === 'string') return value.includes(needle);
      if (Buffer.isBuffer(value)) return value.toString('utf8').includes(needle);
      if (Array.isArray(value)) return value.some((v) => this._contains(v, needle));
      if (typeof value === 'object') {
        return Object.keys(value).some(
          (k) => this._contains(k, needle) || this._contains(value[k], needle)
        );
      }
      return String(value).includes(needle);
    } catch {
      return false;
    }
  }
}

const POC_ENTRY_NAME = '.ono-poc-entry.js';
// The PoC is compiled with a FAKE filename directly at the workspace root (see
// requirePocAtRoot) so its own `require('./app')`-style relative requires resolve against
// the repository root, not `.ono/` - both this synthetic name and the real `.ono/poc.js`
// staging path are "the PoC", never counted as the flagged sink.

function isPoc(rel) {
  return rel.startsWith('.ono/') || rel === POC_ENTRY_NAME;
}

function preview(value, canary) {
  let text;
  try {
    if (Buffer.isBuffer(value)) text = value.toString('utf8');
    else if (typeof value === 'string') text = value;
    else text = JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (typeof text !== 'string') text = String(text);
  const core = canary.slice(0, CANARY_CORE_LEN);
  text = text.split(canary).join('<PAYLOAD>').split(core).join('<PAYLOAD>');
  return text.slice(0, PREVIEW_CHARS);
}

function tryRequire(name) {
  try {
    return require(name);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

function isShellLike(executable) {
  try {
    const base = String(executable).split('/').pop();
    return SHELLS.has(base);
  } catch {
    return false;
  }
}

function installChildProcess(state, installed) {
  const cp = require('child_process');
  for (const name of ['exec', 'execSync']) {
    const original = cp[name];
    cp[name] = function (command, ...rest) {
      state.record('CWE-78', `child_process.${name}`, command, state.contains(command));
      return original.call(this, command, ...rest);
    };
  }
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync']) {
    const original = cp[name];
    if (typeof original !== 'function') continue;
    cp[name] = function (file, ...rest) {
      // Node signature: (file, args?, options?) - args/options are both optional.
      let args = rest[0];
      let options = rest[1];
      if (!Array.isArray(args)) {
        options = args;
        args = [];
      }
      options = options && typeof options === 'object' ? options : {};
      const usesShell = Boolean(options.shell) || isShellLike(file);
      if (usesShell) {
        const command = [file, ...(Array.isArray(args) ? args : [])].join(' ');
        state.record('CWE-78', `child_process.${name}(shell)`, command, state.contains(command));
      } else {
        // argv form: each argument reaches the child as its OWN argument, never parsed by a
        // shell - the safe shape. Record it untainted (if it is at the sink) so the "ran but
        // not in the dangerous argument" signal is available to a false-positive finding.
        const joined = [file, ...(Array.isArray(args) ? args : [])].join(' ');
        if (state.contains(joined)) {
          state.record('CWE-78', `child_process.${name}(argv)`, joined, false);
        }
      }
      return original.apply(this, rest.length ? [file, ...rest] : [file]);
    };
  }
  installed.push('child_process');
}

function installEvalLike(state, installed) {
  const vm = require('vm');
  const originalEval = global.eval;
  // eslint-disable-next-line no-eval
  global.eval = function (code) {
    if (typeof code === 'string') {
      state.record('CWE-94', 'eval', code, state.contains(code));
    }
    return originalEval(code);
  };

  const OriginalFunction = global.Function;
  const FunctionProxy = new Proxy(OriginalFunction, {
    construct(target, args) {
      const body = args.length ? args[args.length - 1] : '';
      if (typeof body === 'string') {
        state.record('CWE-94', 'new Function', body, state.contains(body));
      }
      return new target(...args);
    },
    apply(target, thisArg, args) {
      const body = args.length ? args[args.length - 1] : '';
      if (typeof body === 'string') {
        state.record('CWE-94', 'Function()', body, state.contains(body));
      }
      return target.apply(thisArg, args);
    },
  });
  global.Function = FunctionProxy;

  for (const name of ['runInThisContext', 'runInNewContext', 'runInContext']) {
    const original = vm[name];
    if (typeof original !== 'function') continue;
    vm[name] = function (code, ...rest) {
      if (typeof code === 'string') {
        state.record('CWE-94', `vm.${name}`, code, state.contains(code));
      }
      return original.call(this, code, ...rest);
    };
  }
  const OriginalScript = vm.Script;
  if (typeof OriginalScript === 'function') {
    vm.Script = new Proxy(OriginalScript, {
      construct(target, args) {
        const code = args.length ? args[0] : '';
        if (typeof code === 'string') {
          state.record('CWE-94', 'vm.Script', code, state.contains(code));
        }
        return new target(...args);
      },
    });
  }
  if (typeof vm.compileFunction === 'function') {
    const original = vm.compileFunction;
    vm.compileFunction = function (code, ...rest) {
      if (typeof code === 'string') {
        state.record('CWE-94', 'vm.compileFunction', code, state.contains(code));
      }
      return original.call(this, code, ...rest);
    };
  }
  installed.push('eval', 'Function', 'vm');
}

function recordPath(state, kind, rawPath, mode) {
  let text;
  try {
    text = Buffer.isBuffer(rawPath) ? rawPath.toString('utf8') : String(rawPath);
  } catch {
    return;
  }
  if (!state.contains(text)) return;
  const normalized = text.replace(/\\/g, '/');
  const segments = normalized.split('/');
  const traversal = segments.includes('..');
  state.record('CWE-22', kind, text, traversal);
  const inDirectory = segments.slice(0, -1).some((seg) => state.contains(seg));
  const writing = /[wax+]/.test(mode || 'r');
  state.record('CWE-73', `${kind}(${writing ? 'write' : 'read'})`, text, traversal || inDirectory);
}

function installPathModule(state, installed) {
  // path.join()/path.resolve() NORMALIZE their result (unlike Python's os.path.join, which
  // is naive concatenation) - a ".." in the attacker-controlled INPUT segment is resolved
  // away before the joined string ever reaches fs.*, so checking the fs.* argument alone
  // (recordPath, below) misses the single most common Node traversal idiom:
  // fs.readFileSync(path.join(BASE, userInput)). Catch it here, at the join/resolve call
  // itself, where the raw (pre-normalization) segment still carries the ".." - and this
  // runs inside the SAME call as the fs.* sink, so the stack location matches either way.
  const path = require('path');
  for (const name of ['join', 'resolve']) {
    const original = path[name];
    if (typeof original !== 'function') continue;
    path[name] = function (...segments) {
      for (const seg of segments) {
        if (typeof seg !== 'string' || !state.contains(seg)) continue;
        const parts = seg.replace(/\\/g, '/').split('/');
        const traversal = parts.includes('..');
        state.record('CWE-22', `path.${name}`, seg, traversal);
        const inDirectory = parts.slice(0, -1).some((p) => state.contains(p));
        state.record('CWE-73', `path.${name}`, seg, traversal || inDirectory);
      }
      return original.apply(this, segments);
    };
  }
  installed.push('path');
}

function installFs(state, installed) {
  const fs = require('fs');
  const readers = [
    'readFile',
    'readFileSync',
    'createReadStream',
    'open',
    'openSync',
    'stat',
    'statSync',
  ];
  const writers = [
    'writeFile',
    'writeFileSync',
    'appendFile',
    'appendFileSync',
    'createWriteStream',
    'unlink',
    'unlinkSync',
  ];
  for (const name of readers) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function (p, ...rest) {
      recordPath(state, `fs.${name}`, p, 'r');
      return original.call(this, p, ...rest);
    };
  }
  for (const name of writers) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function (p, ...rest) {
      recordPath(state, `fs.${name}`, p, 'w');
      return original.call(this, p, ...rest);
    };
  }
  for (const name of ['rename', 'renameSync']) {
    const original = fs[name];
    if (typeof original !== 'function') continue;
    fs[name] = function (src, dst, ...rest) {
      recordPath(state, `fs.${name}`, src, 'w');
      recordPath(state, `fs.${name}`, dst, 'w');
      return original.call(this, src, dst, ...rest);
    };
  }
  installed.push('fs');
}

function hostOf(target) {
  if (target == null) return null;
  if (typeof target === 'string') {
    try {
      return new URL(target).hostname;
    } catch {
      return target; // not a well-formed URL: fall back to the whole string
    }
  }
  if (typeof target === 'object') {
    return target.hostname || target.host || null;
  }
  return null;
}

function installHttp(state, installed) {
  for (const modName of ['http', 'https']) {
    const mod = require(modName);
    for (const name of ['request', 'get']) {
      const original = mod[name];
      if (typeof original !== 'function') continue;
      mod[name] = function (target, ...rest) {
        const host = hostOf(target);
        const whole = typeof target === 'string' ? target : host;
        state.record('CWE-918', `${modName}.${name}`, whole, state.contains(String(whole || '')));
        return original.call(this, target, ...rest);
      };
    }
  }
  if (typeof global.fetch === 'function') {
    const original = global.fetch;
    global.fetch = function (target, ...rest) {
      const url = target && typeof target === 'object' && 'url' in target ? target.url : target;
      state.record('CWE-918', 'fetch', url, state.contains(String(url || '')));
      return original.call(this, target, ...rest);
    };
  }
  installed.push('http', 'https');
}

function wrapQueryLike(obj, methods, state, label) {
  if (!obj) return;
  for (const name of methods) {
    const original = obj[name];
    if (typeof original !== 'function') continue;
    obj[name] = function (sql, ...rest) {
      if (typeof sql === 'string') {
        state.record('CWE-89', `${label}.${name}`, sql, state.contains(sql));
      }
      return original.apply(this, [sql, ...rest]);
    };
  }
}

function installSql(state, installed) {
  const mysql2 = tryRequire('mysql2') || tryRequire('mysql2/promise');
  if (mysql2) {
    for (const factory of ['createConnection', 'createPool']) {
      const original = mysql2[factory];
      if (typeof original !== 'function') continue;
      mysql2[factory] = function (...args) {
        const result = original.apply(this, args);
        const wrap = (obj) => wrapQueryLike(obj, ['query', 'execute'], state, `mysql2.${factory}`);
        if (result && typeof result.then === 'function') {
          result.then(wrap).catch(() => {});
        } else {
          wrap(result);
        }
        return result;
      };
    }
    installed.push('mysql2');
  }
  const mysql = tryRequire('mysql');
  if (mysql) {
    for (const factory of ['createConnection', 'createPool']) {
      const original = mysql[factory];
      if (typeof original !== 'function') continue;
      mysql[factory] = function (...args) {
        const result = original.apply(this, args);
        wrapQueryLike(result, ['query'], state, `mysql.${factory}`);
        return result;
      };
    }
    installed.push('mysql');
  }
  const pg = tryRequire('pg');
  if (pg) {
    for (const clsName of ['Client', 'Pool']) {
      const cls = pg[clsName];
      if (cls && cls.prototype) wrapQueryLike(cls.prototype, ['query'], state, `pg.${clsName}`);
    }
    installed.push('pg');
  }
  const sqlite3 = tryRequire('sqlite3');
  if (sqlite3 && sqlite3.Database && sqlite3.Database.prototype) {
    wrapQueryLike(
      sqlite3.Database.prototype,
      ['run', 'get', 'all', 'each', 'exec', 'prepare'],
      state,
      'sqlite3.Database'
    );
    installed.push('sqlite3');
  }
  const betterSqlite3 = tryRequire('better-sqlite3');
  if (betterSqlite3 && betterSqlite3.prototype) {
    wrapQueryLike(betterSqlite3.prototype, ['prepare', 'exec'], state, 'better-sqlite3');
    installed.push('better-sqlite3');
  }
}

function installDeserialization(state, installed) {
  const nodeSerialize = tryRequire('node-serialize');
  if (nodeSerialize && typeof nodeSerialize.unserialize === 'function') {
    const original = nodeSerialize.unserialize;
    nodeSerialize.unserialize = function (data, ...rest) {
      state.record('CWE-502', 'node-serialize.unserialize', data, state.contains(data));
      return original.call(this, data, ...rest);
    };
    installed.push('node-serialize');
  }
}

function installHooks(state) {
  const installed = [];
  const installers = [
    installChildProcess,
    installEvalLike,
    installPathModule,
    installFs,
    installHttp,
    installSql,
    installDeserialization,
  ];
  for (const installer of installers) {
    try {
      installer(state, installed);
    } catch {
      // one hook's absence/oddity must never break the others
    }
  }
  return installed;
}

// ---------------------------------------------------------------------------
// Running the PoC
// ---------------------------------------------------------------------------

function requirePocAtRoot(pocFile, root) {
  // The PoC is staged at `.ono/poc.js` (next to this oracle, matching the Python oracle's
  // layout and the staging/cleanup commands in oracle_js.py), but the prover writes it as
  // if it lived at the repository ROOT - `require('./app')`, exactly like the scaffold in
  // ono/agents/scaffolds.py shows. A plain `require(pocFile)` would resolve those relative
  // requires against `.ono/`, not the root, and break every realistic PoC. Compiling it
  // through Node's own Module machinery with a FAKE filename AT the root makes its
  // `require`, `__filename` and `__dirname` behave exactly as if it were written there.
  const Module = require('module');
  const path = require('path');
  const fs = require('fs');
  const fakePath = path.join(root, POC_ENTRY_NAME);
  const source = fs.readFileSync(pocFile, 'utf8');
  const mod = new Module(fakePath, null);
  mod.filename = fakePath;
  mod.paths = Module._nodeModulePaths(root);
  Module._cache[fakePath] = mod;
  try {
    mod._compile(source, fakePath);
  } finally {
    delete Module._cache[fakePath];
  }
  return mod.exports;
}

// A real PoC rarely reaches the sink synchronously: driving an Express/Nest/Next route is
// itself async (app.listen's callback, the outbound http.get, the server receiving and
// routing the request, THEN the handler calling the dangerous function) - several event-loop
// ticks deep. Unlike Python (one synchronous script, done when it returns), a Node script's
// top-level `require()` only *schedules* that work; it returns long before any of it has
// run. So the result is computed and printed from `process.on('beforeExit', ...)` - emitted
// once the event loop has genuinely drained (every timer/socket/pending callback finished),
// which is the correct generalisation of "the script is done" to asynchronous Node code. A
// PoC that never closes what it opens (forgets `server.close()`) hangs here exactly as it
// would hang in production; the OUTER `timeout -s KILL` wrapper the jail already runs every
// command under (see sandbox.py's `run()`) is the backstop, surfaced as `timed_out`, not a
// crash. Hits recorded by hooks firing on ANY later tick (not just the synchronous one) are
// captured because `state.active` is only turned off inside `finalize`, not at the end of
// the synchronous `require()` call.
function runOracle(config, root) {
  const state = new State(config, root);
  process.env[PAYLOAD_ENV] = state.canary;
  const extraPaths = Array.isArray(config.node_path) ? config.node_path : [];
  for (const extra of extraPaths) {
    if (typeof extra === 'string' && require('fs').existsSync(extra)) {
      // require() resolves relative to the requiring module's own paths; module.paths is
      // mutated per-module, so the cleanest global addition is NODE_PATH itself re-parsed by
      // Module._initPaths at startup. That already ran, so append to the resolver's global
      // paths array that every subsequent require() (ours and the PoC's) consults.
      require('module').globalPaths.push(extra);
    }
  }
  const installedHooks = installHooks(state);
  process.chdir(root);

  const chunks = { stdout: [], stderr: [] };
  const realWrite = { stdout: process.stdout.write, stderr: process.stderr.write };
  process.stdout.write = (chunk) => {
    chunks.stdout.push(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
    return true;
  };
  process.stderr.write = (chunk) => {
    chunks.stderr.push(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
    return true;
  };

  let pocError = '';
  let pocExit = 0;
  let finished = false;
  const started = process.hrtime.bigint();

  return new Promise((resolve) => {
    function finalize() {
      if (finished) return;
      finished = true;
      state.active = false;
      process.stdout.write = realWrite.stdout;
      process.stderr.write = realWrite.stderr;
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      const accepted = familyOf(String(config.cwe || ''));
      const relevant = state.hits.filter((h) => accepted.has(h.cwe));
      const fired = relevant.some((h) => h.at_sink);
      resolve({
        ok: true,
        fired,
        reached_elsewhere: relevant.filter((h) => h.tainted && !h.at_sink),
        untainted_at_sink: !fired && relevant.some((h) => !h.tainted),
        hits: state.hits,
        hits_truncated: state.truncated,
        hooks: installedHooks,
        poc_exit: pocExit,
        poc_error: pocError,
        poc_stdout: chunks.stdout.join('').slice(-TAIL_CHARS),
        poc_stderr: chunks.stderr.join('').slice(-TAIL_CHARS),
        duration_ms: durationMs,
      });
    }

    function onUncaught(err) {
      pocExit = 1;
      // Python's traceback puts the message LAST (frames, then "ExceptionType: message"),
      // which is why the host-side oracle.py (shared by both languages, blind to which one
      // produced poc_error) always takes the LAST line for the short summary and the TAIL
      // for the full one. Node's `.stack` is the opposite (message FIRST) - reorder it here,
      // frames then message, so the SAME shared logic picks the real message either way.
      const raw = err && err.stack ? err.stack : String(err);
      const lines = raw.split('\n');
      const reordered = lines.length > 1 ? `${lines.slice(1).join('\n')}\n${lines[0]}` : raw;
      pocError = reordered.slice(-TAIL_CHARS);
      finalize();
    }

    process.once('uncaughtException', onUncaught);
    process.once('unhandledRejection', onUncaught);
    process.once('beforeExit', finalize);

    state.active = true;
    try {
      requirePocAtRoot(state.pocFile, root);
    } catch (err) {
      onUncaught(err); // a SYNCHRONOUS top-level throw: nothing async was ever scheduled
    }
  });
}

function main(argv, root) {
  if (!argv.length) {
    process.stdout.write(RESULT_MARKER + JSON.stringify({ ok: false, error: 'usage: <json>' }) + '\n');
    return;
  }
  let config;
  try {
    config = JSON.parse(argv[0]);
  } catch (err) {
    const msg = `${err && err.name ? err.name : 'Error'}: ${err && err.message ? err.message : err}`;
    process.stdout.write(RESULT_MARKER + JSON.stringify({ ok: false, error: msg }) + '\n');
    return;
  }
  Promise.resolve(runOracle(config, root || process.cwd()))
    .catch((err) => ({
      ok: false,
      error: `${err && err.name ? err.name : 'Error'}: ${err && err.message ? err.message : err}`,
    }))
    .then((result) => {
      process.stdout.write(RESULT_MARKER + JSON.stringify(result) + '\n');
    });
}

if (require.main === module) {
  main(process.argv.slice(2), process.cwd());
}

module.exports = { main, runOracle, State, RESULT_MARKER };
