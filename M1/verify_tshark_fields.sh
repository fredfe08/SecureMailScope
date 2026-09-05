#!/usr/bin/env bash
set -u
exec python3 -m securemailscope_m1.cli verify-fields "$@"
