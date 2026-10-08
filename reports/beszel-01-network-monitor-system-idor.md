# Cross-tenant IDOR: a network monitor can be reassigned to a system the user does not own (`network_monitors`)

| | |
|---|---|
| **Product** | Beszel (henrygd/beszel) |
| **Affected version** | 0.21.0 (latest; feature introduced in 0.20.0) |
| **Component** | `network_monitors` collection update rule (`internal/hub/collections.go`) + update hook (`internal/hub/network_monitors.go`) |
| **Vulnerability class** | CWE-639 Authorization Bypass Through User-Controlled Key (IDOR) / CWE-863 Incorrect Authorization |
| **Authentication** | Authenticated, low-privilege (any non-`readonly` user who owns at least one system) |
| **Severity** | Low–Medium (CVSS 3.1 ~5.0 — `AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:L`; AC:H because the victim's 15-char system ID must be known, mirroring the scoring of the prior Beszel IDOR CVE-2026-40077) |

---

## 1. Summary

Beszel's `alerts` collection was hardened (fix for CVE-2026-94382) so that an alert's `system` relation is **immutable through the API** — its update rule contains `@request.body.system:changed = false && @request.body.user:changed = false`, and `alerts_access_test.go` explicitly asserts "The system of an existing alert is immutable through the API."

The `network_monitors` collection — a newer feature (agent version gate `MinVersionNetworkMonitors = 0.20.0`) — uses the same system-scoped write rule **but is missing that `system:changed = false` guard.** PocketBase evaluates an update rule against the record's **stored** `system` relation, so a user who legitimately owns a monitor on their own system A can `PATCH` its `system` to a victim's system B that the attacker does not own. The reassignment is accepted, and Beszel's update hook then persists (and syncs to the victim's agent) a monitor on system B via an internal `app.Save`, which bypasses collection rules entirely.

Result: an authenticated low-privilege user can create/modify network monitors on systems belonging to other tenants.

## 2. Direct security impact (proven)

- **Cross-tenant integrity violation.** The attacker injects or modifies a network-probe configuration on another tenant's system — tampering with the victim's monitoring. Because the monitor ID is a deterministic hash of `(system, target, protocol, port/server)`, an attacker who targets the same tuple as an existing victim monitor can collide its ID and overwrite/disrupt it (availability impact on the victim's monitoring).
- **Weaponizing the victim's agent as a network probe.** The monitor's `target`/`protocol`/`port`/`server` are attacker-controlled. Once the monitor lives on the victim's system, Beszel pushes it to the **victim's agent**, which then performs the attacker-chosen TCP/HTTP/DNS/ICMP probe against an attacker-chosen target on the **victim's private network** (e.g. `169.254.169.254`, internal hosts/ports) — a blind SSRF/port-scan pivot through infrastructure the attacker does not control.
- Low privilege, no victim interaction.

This is the same authorization-bypass class Beszel has already accepted and assigned CVEs for (CVE-2026-40077, CVE-2026-94382), extended to a newer endpoint with added integrity/availability impact.

## 3. Root cause (exact code)

Secure sibling — `alerts` update rule (`internal/hub/collections.go`):
```go
alertsUpdateRule := alertsOwnerRule + " && @request.body.user:changed = false && @request.body.system:changed = false"
```

Vulnerable — `network_monitors` rules (`internal/hub/collections.go:111`): the same `systemScopedWriteRule` is applied to `update` with **no** `system:changed = false` guard:
```go
systemScopedWriteRule := systemScopedReadRule + " && @request.auth.role != \"readonly\""
// systemScopedReadRule = `@request.auth.id != "" && system.users.id ?= @request.auth.id`
applyCollectionRules(app, []string{"network_monitors"}, collectionRules{
    list:   &systemScopedReadRule,
    view:   &systemScopedReadRule,
    create: &systemScopedWriteRule,
    update: &systemScopedWriteRule,   // <-- stored system is checked; body may still change `system`
    delete: &systemScopedWriteRule,
})
```

The update request-hook then propagates the attacker-chosen system via a rule-bypassing `app.Save` (`internal/hub/network_monitors.go:60`):
```go
hub.OnRecordUpdateRequest("network_monitors").BindFunc(func(e *core.RecordRequestEvent) error {
    systemID := e.Record.GetString("system")                 // = victim system B (from request body)
    ID := generateMonitorID(systemID, *monitorConfigFromRecord(e.Record))
    if ID != e.Record.Id {
        newRecord := copyMonitorToNewRecord(e.Record, ID)    // copies system = B
        if err := e.App.Save(newRecord); err != nil { ... }  // app.Save bypasses collection rules
        if err := e.App.Delete(e.Record); err != nil { ... }
        return nil
    }
    ...
    hub.upsertNetworkMonitor(e.Record, runNow)               // pushes probe config to system B's agent
})
```

## 4. Proof of Concept (verified, runs against the real hub)

The PoC is a Go test (`beszel-network-monitor-idor_test.go`) built on Beszel's own test harness, mirroring `alerts_access_test.go`. It creates two users (attacker, victim) each owning a system, has the attacker create a monitor on their own system, then `PATCH`es the monitor's `system` to the victim's system, and checks the database.

Run:
```
# place the file at internal/alerts/nm_idor_poc_test.go in a beszel checkout
# (needs a placeholder internal/site/dist/index.html so the frontend embed compiles)
go test -tags testing -run TestNetworkMonitorSystemAccessIDOR_PoC ./internal/alerts/ -v
```

Actual output against Beszel 0.21.0 (`SHARE_ALL_SYSTEMS=false`):
```
=== RUN   TestNetworkMonitorSystemAccessIDOR_PoC
    attacker created monitor 457f9a19 on own system cazc4i9di9l615j
    PATCH {system: victimSystem} -> HTTP 200:
    >>> IDOR CONFIRMED: attacker placed a monitor on victim system 7w4kvfb83tg8qhk
        (target="169.254.169.254" protocol="tcp" port=80) — attacker is NOT a member of that system
--- FAIL: TestNetworkMonitorSystemAccessIDOR_PoC (0.48s)
        SECURE EXPECTATION: no monitor should exist on the victim's system
```
The test asserts the *secure* expectation (no monitor on the victim's system); its failure is the proof that the IDOR succeeds. The identical operation against the `alerts` collection returns HTTP 404 (asserted by the project's own `alerts_access_test.go`), confirming the missing guard is specific to `network_monitors`.

## 5. Remediation

Add the same guard the `alerts` collection uses, so an existing monitor's `system` cannot be changed through the API:
```go
systemScopedUpdateRule := systemScopedWriteRule + " && @request.body.system:changed = false"
applyCollectionRules(app, []string{"network_monitors"}, collectionRules{
    list:   &systemScopedReadRule,
    view:   &systemScopedReadRule,
    create: &systemScopedWriteRule,
    update: &systemScopedUpdateRule,   // <-- system is now immutable through the API
    delete: &systemScopedWriteRule,
})
```
(Optionally also re-validate system membership inside the `OnRecordUpdateRequest` hook before the rule-bypassing `app.Save`, as defense in depth, and add a regression test mirroring the alerts one.)

## 6. Scope & duplicate verification

- **In scope** per `SECURITY.md` criterion 1 ("puts users or user data at risk") — cross-tenant tampering and abuse of another tenant's agent.
- **Latest supported version:** 0.21.0 (latest release); feature added in 0.20.0.
- **Not a duplicate.** Checked the 4 published advisories, NVD/OSV/GitLab/Wiz CVE databases, and the repo's issues/PRs:
  - CVE-2026-40077 / GHSA-5f5r-95pg-xrpm — **read** IDOR in `api.go` endpoints, fixed 0.18.7 (those now enforce `system.HasUser`; verified).
  - CVE-2026-94382 / GHSA-759g-ch5m-2gch — alerts IDOR, fixed 0.19.0 (the collection that *received* the `system:changed` guard this one lacks).
  - CVE-2026-27734 (Docker path traversal, 0.18.4) and the OAuth role-escalation advisory are unrelated.
  - No advisory, CVE, or issue references `network_monitors` authorization. Novel.

## 7. Reporting
Private GitHub advisory at `https://github.com/henrygd/beszel/security/advisories/new`, or email `henrygd` per `SECURITY.md`. A fork with the one-line rule fix can be attached.
