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

# The hash domain follows the manifest's apiVersion namespace: manifests
# issued under the legacy cloakpipe.dev namespace keep their original domain,
# so their hashes stay valid. Any other apiVersion uses the current domain
# (validation rejects unsupported versions).
HASH_DOMAIN = b"cloakpipe.co/agent-release/v1"
LEGACY_API_VERSION = "cloakpipe.dev/v1alpha1"
LEGACY_HASH_DOMAIN = b"cloakpipe.dev/agent-release/v1"


def hash_domain(manifest):
    return LEGACY_HASH_DOMAIN if manifest.get("apiVersion") == LEGACY_API_VERSION else HASH_DOMAIN


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


def es_number(x):
    """ECMAScript Number::toString, as RFC 8785 requires for every number."""
    x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    mantissa, _, exp = repr(abs(x)).partition("e")  # repr is shortest round-trip
    int_part, _, frac_part = mantissa.partition(".")
    digits = int_part + frac_part
    point = len(int_part) + int(exp or 0)  # decimal point sits after `point` digits
    lead = len(digits) - len(digits.lstrip("0"))
    digits = digits.strip("0")
    k, n = len(digits), point - lead  # value = 0.<digits> * 10^n
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def jcs(v):
    """RFC 8785: sorted keys (UTF-16 order), no whitespace, UTF-8 strings,
    ECMAScript number formatting."""
    if isinstance(v, bool) or v is None:
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return es_number(v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)


def manifest_hash(manifest):
    body = jcs(nfc(canonical_view(manifest))).encode("utf-8")
    return "sha256:" + hashlib.sha256(hash_domain(manifest) + b"\n" + body).hexdigest()


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        print(manifest_hash(json.load(f)))
