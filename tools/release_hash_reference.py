#!/usr/bin/env python3
"""Reference implementation of the CloakPipe Agent Release manifest hash.

Independent of the Rust crate (crates/cloakpipe-release/src/canonical.rs) and
standard-library only, so a third party can recompute a release hash without
trusting CloakPipe code. CI asserts both implementations agree.

Usage: release_hash_reference.py MANIFEST.json   (JSON input; convert YAML first)
"""
import hashlib
import json
import sys
import unicodedata

HASH_DOMAIN = b"cloakpipe.dev/agent-release/v1"


def canonical_view(m):
    s = m["spec"]
    refs = lambda xs: [x["ref"] for x in xs]
    return {
        "apiVersion": m["apiVersion"],
        "kind": m["kind"],
        "agent": m["metadata"]["agent"],  # version and labels are excluded
        "spec": {
            "code": {"repository": s["code"]["repository"], "commit": s["code"]["commit"]},
            "prompts": refs(s["prompts"]),  # ordered
            "model": s["model"]["ref"],
            "parameters": s.get("parameters", {}),
            "tools": sorted(refs(s.get("tools", []))),
            "mcpServers": sorted(refs(s.get("mcpServers", []))),
            "retrieval": s["retrieval"]["ref"] if s.get("retrieval") else None,
            "policies": sorted(refs(s.get("policies", []))),
            "runtime": {"image": s["runtime"]["image"], "region": s["runtime"]["region"]},
            "dependencies": sorted(s.get("dependencies", []), key=lambda d: (d["name"], d["version"])),
            "featureFlags": s.get("featureFlags", {}),
        },
    }


def nfc(v):
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, list):
        return [nfc(x) for x in v]
    if isinstance(v, dict):
        return {nfc(k): nfc(x) for k, x in v.items()}
    return v


def jcs(v):
    """RFC 8785 subset: sorted keys, no whitespace, UTF-8. Integral floats are
    written as integers, matching ECMAScript number serialisation."""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def manifest_hash(manifest):
    body = jcs(nfc(canonical_view(manifest))).encode("utf-8")
    return "sha256:" + hashlib.sha256(HASH_DOMAIN + b"\n" + body).hexdigest()


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        print(manifest_hash(json.load(f)))
