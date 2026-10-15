#!/bin/sh
# Install or upgrade. Never touches dockerd's configuration: enabling the
# plugin is a deliberate step (see the runbook).
set -e

# dpkg re-runs postinst when a removal is aborted (see preremove.sh).
case "$1" in abort-remove|abort-upgrade|abort-deconfigure) exit 0 ;; esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  if systemctl is-active --quiet imagegate; then
    # Upgrade: dockerd rejects API calls for the second or so this takes.
    systemctl try-restart imagegate || true
    exit 0
  fi
  systemctl enable imagegate.service imagegate-health.timer >/dev/null 2>&1 || true
elif command -v rc-update >/dev/null 2>&1 && [ -x /etc/init.d/imagegate ]; then
  if rc-service imagegate status >/dev/null 2>&1; then
    rc-service imagegate restart || true
    exit 0
  fi
  rc-update add imagegate default >/dev/null 2>&1 || true
fi

cat <<'MSG'
imagegate is installed. The policy at /etc/imagegate/policy.yaml starts in
audit mode. Next steps:
  1. Edit /etc/imagegate/policy.yaml, then run: imagegate validate
  2. Start the service (systemctl start imagegate, or rc-service imagegate
     start), then run: imagegate health
  3. Read /usr/share/doc/imagegate/runbook.md (lockout recovery)
  4. Add {"authorization-plugins": ["imagegate"]} to /etc/docker/daemon.json
     (example: /usr/share/imagegate/daemon.json) and restart docker
MSG
