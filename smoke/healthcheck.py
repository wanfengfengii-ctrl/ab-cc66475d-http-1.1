#!/usr/bin/env python3
"""Container healthcheck probe. Exits 0 only when the API answers healthy."""

from __future__ import annotations

import json
import os
import sys
import urllib.request

port = os.environ.get("PORT", "8080")
try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{port}/healthz", timeout=3
    ) as resp:
        ok = resp.status == 200 and json.load(resp).get("status") == "ok"
except Exception:  # noqa: BLE001 - any failure means unhealthy
    ok = False
sys.exit(0 if ok else 1)
