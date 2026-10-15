#!/bin/sh
# Refuse to remove imagegate while dockerd is configured to use it: with the
# plugin gone, dockerd rejects every API call. Upgrades are let through.
# dpkg and rpm abort the removal when this fails; apk warns but proceeds.
set -e

case "$1" in
  upgrade|1|2) exit 0 ;;   # deb upgrade / rpm upgrade (instances left)
esac
# apk calls pre-deinstall without arguments, rpm with 0, deb with "remove".

if [ -z "${IMAGEGATE_FORCE_REMOVE:-}" ] && grep -qs '"imagegate"' /etc/docker/daemon.json; then
  cat >&2 <<'MSG'
imagegate: refusing to remove while /etc/docker/daemon.json enables it.
Removing it now would make dockerd reject every API call. First remove
"imagegate" from "authorization-plugins" and restart docker, or set
IMAGEGATE_FORCE_REMOVE=1 to remove anyway.
MSG
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now imagegate-health.timer imagegate.service >/dev/null 2>&1 || true
elif command -v rc-update >/dev/null 2>&1; then
  rc-service imagegate stop >/dev/null 2>&1 || true
  rc-update del imagegate default >/dev/null 2>&1 || true
fi
