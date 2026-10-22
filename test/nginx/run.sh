#!/usr/bin/env bash
# Replay every 8G fixture request through real nginx (Docker) and compare with the JavaScript matcher.
#   bash test/nginx/run.sh                      nginx:1.27, every case must agree
#   bash test/nginx/run.sh --image nginx:1.30   another nginx
#   bash test/nginx/run.sh --break uri          a deliberately wrong $uri (no decoding, no merging): must fail
#   bash test/nginx/run.sh --break pcre         patterns run as plain JavaScript, untranslated: must fail
#   bash test/nginx/run.sh --verbose            print every case
set -euo pipefail
cd "$(dirname "$0")/../.."
exec node test/nginx/harness.ts "$@"
