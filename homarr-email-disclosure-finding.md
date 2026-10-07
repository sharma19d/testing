# Homarr — Unauthenticated disclosure of board creators' email addresses via `board.getAllBoards`

**Target:** homarr-labs/homarr
**Version:** 2.2.0 (current `master`, commit `eb1d449`)
**Component:** tRPC `board.getAllBoards` (`publicProcedure`) — `packages/api/src/router/board.ts:338`; also mapped to REST `GET /api/boards`
**Class:** Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) — unauthenticated PII disclosure
**Severity:** Low–Moderate (CVSS 3.1 ~5.3, `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
**Auth required:** None.
**Precondition:** The instance has at least one **public** board (a first-class Homarr feature for shared/landing dashboards).

---

## Summary

`board.getAllBoards` is a `publicProcedure` (no authentication). For an anonymous caller it returns every **public** board, and each board object includes its **creator's email address** (plus id, name, avatar URL). An unauthenticated remote attacker can therefore harvest the email addresses of all users who created public boards — typically the instance administrator.

A sibling endpoint, `board.getPublicBoards` (also public), deliberately returns only `id`, `name`, `logoImageUrl` — no creator and no email. That contrast shows the project knows to minimise data exposed to anonymous callers, so the creator email in `getAllBoards` is an oversight rather than an intended disclosure.

This is the same *class* as the previously fixed GHSA-m4vc-4prp-cvp7 (unauthenticated integration-metadata disclosure), but a different endpoint and different data, and is not covered by any existing advisory.

---

## Root cause (code-verified)

`packages/api/src/router/board.ts:338`
```ts
getAllBoards: publicProcedure            // <-- no auth
  .input(z.void())
  .output(z.array(boardSummarySchema))   // <-- schema permits creator.email (does not strip it)
  .query(async ({ ctx }) => {
    const userId = ctx.session?.user.id;                       // undefined for anon
    const { boardIds, currentUser, groupMemberships } = await getBoardAccessContextAsync(ctx.db, userId);
    const dbBoards = await ctx.db.query.boards.findMany({
      columns: { id: true, name: true, logoImageUrl: true, isPublic: true },
      with: {
        creator: { columns: { id: true, name: true, image: true, email: true } },  // <-- email selected
        ...
      },
      where: getAccessibleBoardsWhere(
        ctx.session?.user.permissions.includes("board-view-all"),  // undefined for anon
        userId, boardIds),
    });
    return dbBoards.map((board) => ({ ...board, isHome: ..., isMobileHome: ... }));
  }),
```

Output schema (`packages/validation/src/board.ts:156`) — `email` is an allowed field, so tRPC does **not** strip it:
```ts
export const boardSummarySchema = z.object({
  id: z.string(), name: z.string(), logoImageUrl: z.string().nullable(), isPublic: z.boolean(),
  creator: z.object({ id: z.string(), name: z.string().nullable(),
                      image: z.string().nullable(), email: z.string().nullable() }).nullable(),
  ...
});
```

Anonymous WHERE clause (`packages/api/src/router/board.ts:2896`): for anon, `canViewAll` is `undefined`, `userId` is `undefined`, `boardIds` is `[]`, so:
```ts
getAccessibleBoardsWhere(undefined, undefined, []) =>
  or( eq(boards.isPublic, true), eq(boards.creatorId, ""), undefined )
```
→ returns **all public boards**, each joined with `creator.email`.

Verified statically end-to-end: public procedure → anon returns public boards → DB query selects `creator.email` → output schema allows `email` → value reaches the unauthenticated caller.

---

## Proof of concept

Unauthenticated request against any Homarr instance that has ≥1 public board (no session cookie / token):

tRPC transport:
```
GET /api/trpc/board.getAllBoards?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D
Host: <homarr-host>
```
or the REST mapping:
```
GET /api/boards
Host: <homarr-host>
```

Response (abridged) — note `creator.email` for a public board, returned with no authentication:
```json
[
  {
    "id": "…",
    "name": "Home",
    "isPublic": true,
    "creator": { "id": "…", "name": "admin", "image": null, "email": "admin@example.com" },
    "isHome": true, "isMobileHome": false,
    "userPermissions": [], "groupPermissions": []
  }
]
```

> Verification note: this was confirmed by static analysis of the shipped 2.2.0 code paths (procedure auth level, DB column selection, and output-schema pass-through). I did not stand up a live instance (requires a DB + full build); the maintainers' triager can confirm instantly with the request above against any instance that has a public board.

---

## Impact

Unauthenticated harvesting of registered users' email addresses — in practice the administrator's, since the admin usually owns the public/home board. Email + display name enables targeted phishing and credential-stuffing against the very account that controls the dashboard and its stored integration secrets.

---

## Suggested fix

Drop `email` from the anonymous response. Either:
- remove `email` from `boardSummarySchema.creator` (if no authenticated caller needs it there), or
- select/return `creator.email` only when `ctx.session?.user` is present (mirror the minimal shape of `getPublicBoards` for anonymous callers).

---

## Reporting path

Per Homarr's `SECURITY.md` (private advisory on GitHub). Not yet reported — leaving submission to you.
