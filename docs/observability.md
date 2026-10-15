# Observability

Every decision produces one structured audit record and updates a small set
of Prometheus metrics. Audit mode depends on both to show what enforcement
would break.

## Audit records

One JSON line per decision on stdout, which systemd sends to journald:

```json
{"ts":"2026-10-14T19:20:03Z","decision":"deny","mode":"enforce","reason":"NO_SBOM",
 "image":"ghcr.io/acme/api:1.4.2","digest":"sha256:3f9c…","rule":"internal",
 "signer":"ci-main","cache":"miss","latencyMs":842,"endpoint":"containers/create",
 "user":"","policyHash":"9b1e…","enforced":true,"detail":"no SPDX or CycloneDX attestation signed by identity \"ci-main\""}
```

| Field | Meaning |
| --- | --- |
| `decision` | `allow` or `deny`: the verdict, even when not enforced |
| `enforced` | `false` when a deny was only logged (audit mode, or `failClosed: false`) |
| `reason` | A [reason code](runbook.md#reason-codes) |
| `signer` | The policy identity that produced the accepted signature |
| `cache` | `hit`, `miss`, or empty when no lookup happened |
| `endpoint` | `containers/create`, `containers/start`, `containers/restart` or `warm` |
| `user` | Set only when dockerd uses TLS client-certificate auth; empty on the Unix socket |
| `ticket`, `severity` | On override use: the ticket and `"high"` |

Operational logs (policy loads, errors, override use) go to stderr as JSON
through `log/slog`. imagegate never logs registry credentials or full
certificates.

## Metrics

Served on `127.0.0.1:9732/metrics`, localhost only.

| Metric | Type | Labels |
| --- | --- | --- |
| `imagegate_decisions_total` | counter | `decision`, `reason`, `rule`, `mode` |
| `imagegate_verify_duration_seconds` | histogram | `stage` (`resolve`, `signature`, `sbom`) |
| `imagegate_cache_requests_total` | counter | `result` (`hit`, `miss`) |
| `imagegate_upstream_errors_total` | counter | `target` (`registry`, `tuf`, `dockerd`) |
| `imagegate_overrides_active` | gauge | — |
| `imagegate_policy_reload_errors_total` | counter | — |

`/healthz` returns 200 once a valid policy is loaded.

## Suggested alerts

```yaml
groups:
  - name: imagegate
    rules:
      - alert: ImagegateOverrideUsed
        expr: increase(imagegate_decisions_total{reason="OVERRIDE"}[5m]) > 0
      - alert: ImagegateUpstreamErrors
        expr: |
          sum(rate(imagegate_upstream_errors_total[10m]))
            / sum(rate(imagegate_decisions_total[10m])) > 0.05
        for: 10m
      - alert: ImagegatePolicyReloadFailed
        expr: increase(imagegate_policy_reload_errors_total[15m]) > 0
```

Also alert when the `imagegate-health` systemd timer fails.
