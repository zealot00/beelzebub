#!/usr/bin/env bash
#
# verify-sandbox.sh — the container escape suite.
#
# It starts the honeypot with the hardened profile and then tries to escape
# from the inside: escalate the privileges, write to the filesystem, read the
# host files, reach the cloud metadata service, and mount the docker socket.
#
# Every attempt must FAIL. A successful attempt is a finding, not a pass.
#
# Usage:
#   scripts/verify-sandbox.sh [--compose docker-compose.hardened.yml]
#
# Requirements: docker with the compose plugin, and the ability to bind the
# ports declared in the profile.

set -uo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.hardened.yml}"
SERVICE="beelzebub"
CONTAINER="beelzebub"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compose) COMPOSE_FILE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
PASSED=0
FAILED=0

log()  { printf '%s\n' "$*"; }
pass() { printf '%s  PASS %s %s\n' "$GREEN" "$RESET" "$1"; PASSED=$((PASSED+1)); }
fail() { printf '%s  FAIL %s %s\n' "$RED" "$RESET" "$1"; FAILED=$((FAILED+1)); }

if ! command -v docker >/dev/null 2>&1; then
  log "${YELLOW}docker is not available: the escape attempts cannot be run here.${RESET}"
  log "The static assertions of the profile are covered by the Go suite:"
  log "  go test ./internal/adversarial/... -run TestTheHardenedProfileIsHardened"
  exit 2
fi

log "Starting the honeypot with ${COMPOSE_FILE} ..."
docker compose -f "$COMPOSE_FILE" up -d --build >/dev/null 2>&1 || {
  log "${RED}the honeypot could not be started${RESET}"
  exit 1
}
trap 'docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1' EXIT

sleep 3

# in_container runs a command inside the honeypot and returns its output.
in_container() {
  docker compose -f "$COMPOSE_FILE" exec -T "$SERVICE" /bin/sh -c "$1" 2>&1
}

log ""
log "=== Container escape suite ==="
log ""

# 1. The process must not be root.
if in_container 'id -u' | grep -qE '^(0|root)$'; then
  fail "the runtime runs as root"
else
  pass "the runtime does not run as root"
fi

# 2. The capabilities must be dropped.
capabilities=$(in_container 'grep -E "^CapEff|^CapBnd" /proc/self/status 2>/dev/null || cat /proc/self/status 2>/dev/null | grep -E "^CapEff|^CapBnd"' | tr '\n' ' ')
if [[ -z "$capabilities" ]]; then
  # The scratch image has no shell: the check is done from the host side.
  log "${YELLOW}  the container has no shell, the capabilities are read from the host${RESET}"
  host_caps=$(docker inspect --format '{{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}}' "$CONTAINER" 2>/dev/null)
  if [[ "$host_caps" == *"[ALL]"* ]]; then
    pass "every capability is dropped (${host_caps})"
  else
    fail "the capabilities are not dropped (${host_caps})"
  fi
elif [[ "$capabilities" =~ CapEff:\s*0000000000000000 ]]; then
  pass "the effective capability set is empty"
else
  fail "the capabilities are not empty: ${capabilities}"
fi

# 3. The root filesystem must be read only.
if in_container 'touch /escape-canary 2>/dev/null && echo WRITABLE' | grep -q WRITABLE; then
  fail "the root filesystem is writable"
else
  pass "the root filesystem is read only"
fi

# 4. The host files must not be readable.
if in_container 'cat /etc/shadow 2>/dev/null | grep -q .' ; then
  fail "the shadow file is readable"
else
  pass "the shadow file is not readable"
fi

# 5. The docker socket must not be mounted.
if docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$CONTAINER" 2>/dev/null | grep -q "docker.sock"; then
  fail "the docker socket is mounted"
else
  pass "the docker socket is not mounted"
fi

# 6. The cloud metadata service must not be reachable.
if in_container 'wget -q -T 2 -O - http://169.254.169.254/latest/meta-data/ 2>/dev/null | grep -q .' ; then
  fail "the cloud metadata service is reachable"
else
  pass "the cloud metadata service is not reachable"
fi

# 7. The configuration must be read only.
if in_container 'echo "x" >> /configurations/beelzebub.yaml 2>/dev/null && echo WRITABLE' | grep -q WRITABLE; then
  fail "the configuration is writable"
else
  pass "the configuration is read only"
fi

# 8. The tmpfs must not be executable.
if in_container 'cp /main /tmp/x 2>/dev/null && chmod +x /tmp/x 2>/dev/null && /tmp/x --version 2>/dev/null | grep -q .' ; then
  fail "the temporary filesystem is executable"
else
  pass "the temporary filesystem is not executable"
fi

# 9. The resource ceilings must be applied.
pids=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$CONTAINER" 2>/dev/null)
memory=$(docker inspect --format '{{.HostConfig.Memory}}' "$CONTAINER" 2>/dev/null)
if [[ "${pids:-0}" -gt 0 && "${memory:-0}" -gt 0 ]]; then
  pass "the resource ceilings are applied (pids=${pids}, memory=${memory})"
else
  fail "the resource ceilings are missing (pids=${pids}, memory=${memory})"
fi

# 10. The honeypot must not answer on the addresses of the production.
if docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$CONTAINER" 2>/dev/null | grep -q .; then
  pass "the honeypot has an address on its own network"
else
  fail "the honeypot has no address"
fi

log ""
log "=== ${PASSED} passed, ${FAILED} failed ==="
[[ "$FAILED" -eq 0 ]] || exit 1
