# Beszel network_monitors IDOR — PoC reproduction guide

Two self-contained Go tests prove the finding end-to-end against the **real** Beszel hub
(no mocking of the code under test). Both use Beszel's own `//go:build testing` harness.

- `beszel-network-monitor-idor_test.go` — **the IDOR**: a low-priv user reassigns a monitor to a system they don't own (API layer).
- `beszel-network-monitor-idor-dispatch_test.go` — **the impact**: the injected monitor is pushed to the victim's agent to probe an attacker-chosen target.

## Setup (≈2 min)

```bash
git clone https://github.com/henrygd/beszel && cd beszel
git checkout v0.21.0                      # or current main

# the hub embeds a built frontend; create a placeholder so the test build compiles
mkdir -p internal/site/dist && echo '<!doctype html><title>poc</title>' > internal/site/dist/index.html

# drop the PoCs into the packages whose test harness they reuse
cp /path/to/beszel-network-monitor-idor_test.go          internal/alerts/nm_idor_poc_test.go
cp /path/to/beszel-network-monitor-idor-dispatch_test.go internal/hub/systems/nm_idor_dispatch_poc_test.go
```

## Run

```bash
# Test 1 — the IDOR (SHARE_ALL_SYSTEMS defaults to false)
go test -tags testing -run TestNetworkMonitorSystemAccessIDOR_PoC ./internal/alerts/ -v

# Test 2 — the downstream impact (attacker's probe reaches the victim's agent)
go test -tags testing -run TestNetworkMonitorIDOR_ReachesVictimAgent_PoC ./internal/hub/systems/ -v
```

## Expected output (what proves the bug)

Test 1 — the assertion encodes the *secure* expectation (no monitor on the victim's system),
so its **FAIL is the proof** that the reassignment succeeded:
```
attacker created monitor <id> on own system <A>
PATCH {system: victimSystem} -> HTTP 200:
>>> IDOR CONFIRMED: attacker placed a monitor on victim system <B>
    (target="169.254.169.254" protocol="tcp" port=80) — attacker is NOT a member of that system
--- FAIL: TestNetworkMonitorSystemAccessIDOR_PoC
    SECURE EXPECTATION: no monitor should exist on the victim's system
```

Test 2 — **PASS** confirms the victim's connected agent is instructed to run the attacker's probe:
```
>>> IMPACT CONFIRMED: victim agent for system <B> was instructed to probe
    "169.254.169.254" (tcp:80) — an attacker-controlled target injected via the network_monitors IDOR
--- PASS: TestNetworkMonitorIDOR_ReachesVictimAgent_PoC
```

## Why this proves direct, clear security impact

- **Proven, not theorized:** both steps run against the real hub code paths (collection rules, the
  `OnRecordUpdateRequest` hook, and the agent sync path). The connecting query
  `GetMonitorConfigsForSystem` (`WHERE system=? AND enabled=true`) has no owner filter — confirmed by reading it.
- **Control comparison:** the identical reassignment on the `alerts` collection returns HTTP 404 (the
  project's own `alerts_access_test.go` asserts "the system of an existing alert is immutable through the API"),
  proving the missing `@request.body.system:changed = false` guard is specific to `network_monitors`.
- **Honest impact boundary:** after reassignment the attacker loses read access to the record, so this is a
  **blind** cross-tenant write — integrity tampering with another tenant's monitoring plus forcing the victim's
  agent to emit attacker-chosen network probes. It is **not** a results-exfiltrating SSRF; do not claim the
  attacker reads internal responses.

## One-line fix
Add the guard the `alerts` collection already uses, in `internal/hub/collections.go`:
```go
systemScopedUpdateRule := systemScopedWriteRule + " && @request.body.system:changed = false"
// apply as the network_monitors `update` rule
```
