# Executor deployment hardening

How to run the sandbox Executor with the smallest blast radius the current design allows.
This is the operator-side companion to the code-level jail (`src/ono/executor/sandbox.py`);
it covers the four review findings that are deployment decisions rather than code:

| Finding | Issue | What this page gives you | Default compose changed? |
|---|---|---|---|
| H1 Executor holds the host Docker socket as root | #92 | threat model + an **optional** docker-socket-proxy override | no (opt-in override file) |
| H2 no user-namespace remapping | #93 | how to enable `userns-remap` and verify the jails under it | no (daemon setting) |
| M1 single static bearer token | #94 | rotation procedure, `.env` hygiene, why the internal network is load-bearing | no |
| M2 seccomp | #95 | the shipped hardened profile (on by default), how to validate / disable / replace it | no |

Nothing here is forced: the stock `docker compose up` behaves exactly as before.

---

## 1. The blast radius, stated plainly (H1, #92)

`compose.yml` mounts `/var/run/docker.sock` into the Executor and runs it as `user: "0:0"`.
**Holding the Docker socket is equivalent to root on the host.** The Executor's own
`cap_drop: ALL` / `read_only` / `no-new-privileges` constrain the *process*, not what it can
do *through the socket* (`docker run --privileged -v /:/host ...` is one API call away).
So any RCE, SSRF or path bug in the Executor API is a host compromise.

What already stands between an attacker and that socket:

* **Network.** The Executor has no `ports:` block and sits only on the `internal` network
  (`internal: true` - no route in or out). The only thing that can open a TCP connection to
  it is the `app` container. **This is load-bearing.** Never add `ports:` to the executor,
  never put it on `default`, and treat a compromise of the `app` container as a compromise of
  the Executor's attack surface.
* **Auth.** Every route but `/health` needs `Authorization: Bearer <EXECUTOR_TOKEN>`
  (constant-time compared, >= 16 chars enforced at boot).
* **Surface.** ~10 routes, every input validated (scan-id pattern, path confinement, archive
  member validation, byte caps on uploads and JSON bodies), nothing untrusted executes in the
  Executor process - only inside the jails, which never see the socket.

### 1a. Optional: a read-limited docker-socket-proxy (`compose.socket-proxy.yml`)

An override file puts an HAProxy-based allow-list
([tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)) between
the Executor and the daemon, and removes the socket from the Executor entirely:

```bash
cd final-project
docker compose -f compose.yml -f compose.socket-proxy.yml up -d --build
# or
make compose-up-proxied
```

What changes with the override (and only with it):

| | default `compose.yml` | with `compose.socket-proxy.yml` |
|---|---|---|
| socket mount | raw `/var/run/docker.sock` in the Executor | mounted **read-only into the proxy only** |
| Executor user | root (`0:0`) | the image's unprivileged `ono` user |
| Docker API reachable | all of it | `containers`, `exec`, `images`, `start`, `_ping`, `version` + POST/DELETE on those; everything else 403 |
| network | `internal` | `internal` + a dedicated `docker-api` internal network shared only with the proxy |

Be honest about what it buys: an attacker who owns the Executor can still **create and start
arbitrary containers** through the allowed calls (that is the Executor's job), including ones
with host bind-mounts or `--privileged` if they craft the request themselves. The proxy
removes the *other* ~90% of the API (volumes, networks, build, swarm, system, plugins,
commit, events, stop/kill of unrelated containers) and lets the Executor drop root. It is a
real reduction, not isolation. Rootless Docker or a dedicated VM for the daemon remain the
stronger answers if the deployment can afford them.

**Validate before relying on it.** The allow-list above was checked by running the whole
real-jail suite *through* the proxy (every API call the Executor makes: create, start, exec
create/start/inspect with the hijacked stream, inspect, list by label, pull, force-remove):

```bash
# 1. a throw-away proxy on loopback, same env as the override file
docker run -d --name ono-proxy-check -p 127.0.0.1:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CONTAINERS=1 -e EXEC=1 -e IMAGES=1 -e POST=1 -e ALLOW_START=1 \
  tecnativa/docker-socket-proxy:0.3.0
# 2. the jail test-suite, talking to the daemon only via the proxy
DOCKER_HOST=tcp://127.0.0.1:2375 ONO_DOCKER_TESTS=1 uv run pytest -m docker -q tests/test_executor_docker.py
docker rm -f ono-proxy-check
```

Expect all tests to pass; a 403 from the proxy surfaces as `SandboxError: ... 403 Forbidden`
and names the path to add. For reference, this is the complete set of API paths the
Executor used during that run (all allowed by the env above; the exec stream upgrade is
the `101`): `POST /containers/create`, `POST /containers/{id}/start`,
`GET /containers/{id}/json`, `GET /containers/json?filters=...`, `DELETE /containers/{id}`,
`POST /containers/{id}/exec`, `POST /exec/{id}/start` (101 Upgrade), `GET /exec/{id}/json`,
`GET /images/{name}/json`, `POST /images/create`, `GET /version`, `GET /_ping`. Re-run this on *your* daemon version before switching production
to the override, and after any Docker/proxy upgrade.

Known limits of the override: `docker compose` >= 2.24 is needed for the `!reset` tag that
removes the socket mount; the Executor's `/health` reports `docker: false` if the proxy is
not up yet (it recovers - `depends_on` only orders start-up).

---

## 2. User-namespace remapping (H2, #93)

The jails run as uid 10001 (exec) / 10002 (PID 1), but without `userns-remap` those are the
**same real uids on the host**: a container escape lands as host uid 10001, not as an
unprivileged uid in a throw-away range. Enabling remapping on the daemon is the biggest
remaining isolation win and needs no code change.

On the host (Jetstream2 Ubuntu):

```bash
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "userns-remap": "default"
}
EOF
sudo systemctl restart docker
```

Consequences to plan for:

* Docker creates a `dockremap` user/subordinate range and **re-pulls every image** into a
  per-namespace storage root (`/var/lib/docker/<uid>.<gid>/`): the first `compose up` is a
  cold start.
* The Executor's socket mount keeps working (the socket is a bind mount; remapping affects
  the processes *inside* containers, and the daemon itself still runs as root). With the
  socket-proxy override, same thing for the proxy.
* Anything that bind-mounts host paths needs ownership in the remapped range; the default
  stack mounts nothing writable from the host (tmpfs only), so nothing to fix. The optional
  observability profile mounts config files read-only - fine.
* `--userns=host` is the per-container escape hatch; the Executor never passes it, so the
  jails are always remapped once the daemon is.

Verify after enabling (from the box):

```bash
docker run --rm python:3.13-slim cat /proc/self/uid_map     # should NOT read "0 0 4294967295"
# then one jail through the Executor and the real-jail suite:
ONO_DOCKER_TESTS=1 uv run pytest -m docker -q tests/test_executor_docker.py
```

Status: **not validated by the authors** - Docker Desktop (where the suite was run) does not
expose `userns-remap`. The jail flags are compatible with it (no host bind mounts, no
`--userns=host`, non-root uids), but run the suite on the remapped daemon before trusting it.

---

## 3. The bearer token (M1, #94)

All Executor authorization is one shared secret. It has no expiry, so treat it as a
credential whose compromise is equivalent to a compromise of the Executor (and, without the
proxy, the host). Practically:

* **Generate** it with `openssl rand -hex 32` (the Executor refuses anything under 16 chars;
  use 64). Store it only in `.env` with `chmod 600 .env`, owned by the deploy user. It is a
  `SecretStr` in `Settings`: never logged, never returned by any endpoint, not in `/info`.
* **Rotate** on a schedule (quarterly is reasonable) and immediately on any suspicion, any
  team change, or any exposure of `.env`/shell history. Rotation is a restart of both services,
  so do it between scans (an Executor restart destroys every live sandbox - in-flight scans
  fail and are reported as failed, nothing is left dangling):

  ```bash
  cd final-project
  NEW=$(openssl rand -hex 32)
  sed -i.bak "s/^EXECUTOR_TOKEN=.*/EXECUTOR_TOKEN=${NEW}/" .env && rm .env.bak
  docker compose up -d --no-deps --force-recreate executor app     # both read the new token
  curl -fsS localhost:8080/health
  ```

  The old token stops working the moment the Executor container is recreated; there is no
  grace window (two valid tokens at once is not supported - keep the rotation to one command).
* **Scope.** The token is only load-bearing *inside* the internal network: an attacker who can
  present it must already be able to open a TCP connection to `executor:8081`, which only the
  `app` container can. The network isolation is the first wall and the token the second; do
  not weaken either (no `ports:` on the Executor, do not set `EXECUTOR_HOST` to a routable
  address outside Compose).
* mTLS between app and Executor would add a third factor; it is not implemented. If you need
  it, terminate TLS in a sidecar on the `internal` network rather than teaching the Executor
  about certificates - keep the privileged process tiny.

---

## 4. Seccomp (M2, #95)

The jails run under a **hardened seccomp profile by default** (`SANDBOX_SECCOMP_PROFILE=hardened`),
shipped as `src/ono/executor/seccomp-hardened.json`. It is Docker's default profile (moby
v28.3.3) minus syscall groups a Python/npm test runner never needs:

* `ptrace`, `process_vm_readv/writev` (the default allows ptrace on kernels >= 4.8);
* `personality`, `modify_ldt`;
* Linux AIO (`io_setup`, `io_submit`, ...), System V IPC (`shm*`, `sem*`, `msg*`, `ipc`),
  POSIX message queues (`mq_*`);
* `memfd_secret`, `name_to_handle_at`, `fanotify_mark`, `vmsplice`, `remap_file_pages`,
  `sync`, `syncfs`, `socketcall`;
* `socket()` restricted to `AF_UNIX`, `AF_INET`, `AF_INET6` (no netlink / packet / vsock
  families reach the kernel, even though the jail has no network anyway).

Everything capability-gated in Docker's default is left in place (inert under `cap_drop: ALL`,
correct if a cap is ever added). `no-new-privileges` is always set alongside it.

How it was validated (and how to re-validate on your daemon): the entire real-jail suite runs
under the profile, plus a dedicated test that checks the kernel reports `Seccomp: 2`, that
`ptrace`/`personality`/`AF_NETLINK` fail with EPERM, and that the in-jail helper
(`python3 -I -S`), `tar` extraction, reads, grep, patching, subprocesses, `run_tests` and
`reset` all still work:

```bash
ONO_DOCKER_TESTS=1 ONO_SANDBOX_SECCOMP=hardened       uv run pytest -m docker -q tests/test_executor_docker.py
ONO_DOCKER_TESTS=1 ONO_SANDBOX_SECCOMP=docker-default uv run pytest -m docker -q tests/test_executor_docker.py
```

Caveat: the authors validated on Docker Desktop (Linux VM, **arm64**). The dropped syscalls
are architecture-independent in meaning, but run the suite once on the x86_64 production
host. If a target's test-suite needs something the profile blocks, you will see
`Operation not permitted` in `run()` output; then either:

* fall back to Docker's default: `SANDBOX_SECCOMP_PROFILE=docker-default`;
* or ship your own: `SANDBOX_SECCOMP_PROFILE=/path/to/profile.json` (moby format; the
  Executor validates it is JSON with `defaultAction` + `syscalls` at boot and passes the
  *contents* to the daemon - the Engine API does not read files).

---

## 5. Related operational knobs from the same review

* **`SANDBOX_SNAPSHOT_DIR`** (#96): uploads are streamed to disk and each live sandbox's
  reset snapshot is a file, not process memory. Retained bytes are bounded by
  `SANDBOX_MAX_ACTIVE x MAX_CLONE_MB` and reported by the Executor's `/health` as
  `snapshot_bytes`. In Compose the Executor's `/tmp` is a **tmpfs** (RAM-backed, bounded by the
  tmpfs size); for a real disk, add a volume and set `SANDBOX_SNAPSHOT_DIR` to it, or size the
  tmpfs (`tmpfs: - /tmp:size=2g`).
* **`EXECUTOR_MAX_BODY_MB`** (#98, default 16): byte cap on every non-upload request body,
  enforced before parsing; the archive upload keeps its own `MAX_CLONE_MB` cap.
