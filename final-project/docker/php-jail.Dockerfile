# The PHP verification-jail image (runtime=php; see ono.executor.sandbox.select_image).
#
# A scan with any PHP finding runs its whole verify stage in one jail started from this
# image. It must carry, together:
#   * php 8.x                 - to run the target's code and the prover's PoC
#   * the `uopz` PECL extension - the runtime sink oracle (ono/verifier/oracle_hooks.php)
#     hooks PHP builtins (system, shell_exec, unserialize, mysqli_query, ...) through
#     uopz_set_hook; a PHP builtin cannot be redefined in pure PHP, so without uopz the
#     oracle cannot observe a sink and every PHP finding stays rung <= 2
#   * python3                 - the in-jail read/tree/grep guest helper (ono/executor/_guest.py)
#     ALWAYS runs as `python3`, regardless of the target's language, so every jail image needs it
#   * git                     - parity with the other jail images (patch/tree operations)
#
# NO composer here: dependency provisioning for PHP is a deliberate follow-up (target
# procedural / dependency-light PHP first), so the jail only needs the runtime, not a
# package manager.
#
# Build (on the Executor host) and tag it to match the sandbox_image_php setting default:
#
#     docker build -f docker/php-jail.Dockerfile -t ono-php-jail:local .
#
# The jail runs this image read-only, as a non-root uid, with no network, dropped
# capabilities and a seccomp profile (see ono/executor/sandbox.py's jail_kwargs) - exactly
# like the python and node jail images. Nothing below installs a daemon or opens a port.

FROM php:8.3-cli

# uopz from PECL, then enable it for the CLI SAPI (docker-php-ext-enable drops the
# zend_extension/extension line into the conf.d directory the php binary reads).
# python3 + git are the cross-language jail requirements above. Keep the layer slim.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 git; \
    pecl install uopz; \
    docker-php-ext-enable uopz; \
    php -m | grep -qi uopz; \
    python3 --version; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/pear;

# A sanity default; the Executor overrides the command with `sleep infinity` when it starts
# the jail, and every exec runs as the sandbox uid (see sandbox.py).
CMD ["php", "-v"]
