# Homarr — Unauthenticated information disclosure via public tRPC procedures (2 instances)

**Target:** homarr-labs/homarr
**Version:** 2.2.0 (current `master`, commit `eb1d449`)
**Class:** Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)
**Severity:** Low–Moderate (per instance; CVSS 3.1 ~5.3 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
**Auth required:** None.

Both issues are the same root cause as the previously fixed **GHSA-m4vc-4prp-cvp7** (unauthenticated integration-metadata leak): a `publicProcedure` returns data that should be gated/stripped for anonymous callers. They are different endpoints not covered by that advisory, and each is demonstrably inconsistent with sibling code that *does* restrict anonymous output — evidence of oversight, not intent.

---

## Finding 1 — `board.getAllBoards` leaks board creators' email to anonymous users

**Component:** `packages/api/src/router/board.ts:338` (`publicProcedure`), also REST `GET /api/boards`
**Precondition:** instance has ≥1 **public** board (a first-class Homarr feature).

`getAllBoards` is unauthenticated and, for anonymous callers, returns all public boards with the creator object **including `email`**:

- DB query selects `creator: { id, name, image, email }` (`board.ts:~371`).
- Output schema `boardSummarySchema.creator` permits `email` (`packages/validation/src/board.ts:156`), so tRPC does not strip it.
- Anonymous WHERE: `getAccessibleBoardsWhere(undefined, undefined, [])` → `or(isPublic=true, creatorId="", …)` (`board.ts:2896`) → returns all public boards.

The sibling `board.getPublicBoards` (also public) deliberately returns only `id, name, logoImageUrl` — no creator, no email — proving the project knows to minimise anonymous output.

**Impact:** unauthenticated harvesting of the email of every public-board creator (usually the admin) → targeted phishing / credential-stuffing against the account that controls the dashboard and its stored secrets.

**PoC (no auth):**
```
GET /api/trpc/board.getAllBoards?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D
# or: GET /api/boards
```
Response includes `"creator": { "...", "email": "admin@example.com" }` for public boards.

**Fix:** remove `email` from `boardSummarySchema.creator`, or only include `creator.email` when `ctx.session?.user` is present (match the minimal shape of `getPublicBoards` for anonymous callers).

---

## Finding 2 — `searchEngine.getDefaultSearchEngine` leaks an integration's internal URL to anonymous users

**Component:** `packages/api/src/router/search-engine/search-engine-router.ts:73` (`publicProcedure`)
**Precondition:** the server's default search engine is **integration-backed** (`type: "fromIntegration"`). Admins can set any configured engine as the default.

`getDefaultSearchEngine` is unauthenticated. For an anonymous caller (`ctx.session?.user.id` undefined) it falls through to the **server default** search engine and returns it joined with `integration: { kind, url, id }` — with **no restriction on engine type and no `.output()` schema** to strip the integration:

```ts
getDefaultSearchEngine: publicProcedure.query(async ({ ctx }) => {
  const userDefaultId = ctx.session?.user.id ? (...) : null;   // null for anon
  ...
  const serverDefault = await ctx.db.query.searchEngines.findFirst({
    where: eq(searchEngines.id, searchSettings.defaultSearchEngineId),
    with: { integration: { columns: { kind: true, url: true, id: true } } },  // url returned to anon
  });
  if (serverDefault) return serverDefault;   // no type restriction, no output filter
});
```

This is directly inconsistent with the sibling public procedures `search` and `catalog`, which **explicitly** restrict anonymous callers to generic engines:

```ts
// search / catalog:
where: ctx.session?.user ? undefined : eq(searchEngines.type, "generic"),
// comment: "Public dashboards have no session: restrict anonymous users to generic ... engines"
```

`getDefaultSearchEngine` is missing that same guard, so it is the one anonymous path that exposes an integration-backed engine — including the integration's configured `url` (typically an internal/private service URL), its `kind` (what software is running), and `id`.

**Impact:** unauthenticated disclosure of an internal integration URL and the integrated service type — internal-network reconnaissance and fingerprinting, the same data class as the patched GHSA-m4vc-4prp-cvp7.

**PoC (no auth):**
```
GET /api/trpc/searchEngine.getDefaultSearchEngine?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D
```
When the default engine is integration-backed, the response includes `"integration": { "kind": "...", "url": "http://internal-host:port", "id": "..." }`.

**Fix:** apply the same anonymous guard the siblings use — for anonymous callers, either refuse to return an integration-backed default, or strip the `integration` object (and/or add an `.output()` schema that omits `integration.url` when unauthenticated).

---

## Verification note

Both findings were verified by static analysis of the shipped 2.2.0 code paths (procedure auth level, DB column selection, anonymous WHERE/type filters, and absence of output-schema stripping). I did not stand up a live instance (requires a DB + full build); the maintainers' triager can confirm each instantly with the unauthenticated requests above (Finding 1 needs a public board; Finding 2 needs an integration-backed default search engine).

## Scope & prior-art check (verified)

**In scope.** Homarr's `SECURITY.md` treats something as a vulnerability if it "puts users or user data at risk" (criterion 1). Finding 1 exposes user PII (email); Finding 2 exposes instance/integration data (internal URL + service type). Both fit. Report channel: GitHub private advisory, or `homarr-labs@proton.me`.

**Supported version.** Audited against **v2.2.0**, which is the latest stable release (tags top out at v2.2.0) — the only version the policy supports. Both vulnerable code paths also still exist on the unreleased `dev` HEAD (not an in-progress fix).

**Not a duplicate.** Checked: all 9 published GitHub advisories; the CVE/advisory databases (NVD, OSV, GitHub Advisory DB); and the repo's issues/PRs (semantic + keyword). Neither endpoint appears.
- The only documented unauthenticated info-disclosure is **CVE-2026-27796 / GHSA-m4vc-4prp-cvp7** — the `integration.all` endpoint, a *different* procedure, patched back in **1.54.0**.
- Related issues #6608 (integration management-page authz), #6557 (custom-widget UNAUTHORIZED functional bug), #2076 (old private-board access) do **not** cover either of these.

**Severity precedent (strengthens Finding 2).** CVE-2026-27796 — the *same data class* (unauthenticated disclosure of an integration's internal URL + service type) via a different endpoint — was assigned **CVSS 5.3 (Medium)**. Finding 2 exposes the same category of data, so a comparable rating is reasonable. Finding 1 (email only) is likely Low.

## Reporting path
Per Homarr `SECURITY.md` (private GitHub advisory, or `homarr-labs@proton.me`). Both share one root cause and can be filed as a single advisory with two instances. Not yet reported — submission left to you.
