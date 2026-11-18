#!/usr/bin/env python3
"""Dump only the PAC rewrite rules (id/mask/value) from tools/nopac/rewrite_rules.json
into a small JSON that the CI checker can use to classify instructions in the
built kernel.  Non-PAC ISA entries are not relevant here."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "..", "tools", "nopac", "rewrite_rules.json")
DST = os.path.join(HERE, "pac_rules.json")

with open(SRC, "r", encoding="utf-8") as f:
    data = json.load(f)

rules = []
for r in data.get("rules", data.get("pac", [])):
    m = r.get("match")
    if not m or "mask" not in m or "value" not in m:
        continue
    rules.append({
        "id": r["id"],
        "class": r.get("class", "PAC"),
        "mask": int(m["mask"], 16) if isinstance(m["mask"], str) else m["mask"],
        "value": int(m["value"], 16) if isinstance(m["value"], str) else m["value"],
        "emit": r.get("emit"),
        "note": r.get("note", ""),
    })

with open(DST, "w", encoding="utf-8") as f:
    json.dump({"rules": rules}, f, indent=1)
print("wrote %s with %d rules" % (DST, len(rules)))
for r in rules:
    print("  %-14s mask=%08x value=%08x emit=%s" % (r["id"], r["mask"], r["value"], r["emit"]))
