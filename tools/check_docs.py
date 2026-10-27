#!/usr/bin/env python3
"""Keep the README, docs/ and examples/ honest: every command they show must
exist, and the walkthroughs must actually run.

    python3 tools/check_docs.py --bin target/debug
    python3 tools/check_docs.py --self-test

`--bin` is the directory holding the `cloakpipe` and `cloakpipe-verify`
binaries (a default build: anything feature-gated belongs in docs/legacy/,
which is not checked). Python 3.8+, stdlib only.

What it checks, over README.md, docs/*.md (not docs/legacy/) and
examples/*/README.md:

1. Commands exist. In every ```bash / ```sh / ```console code block (in
   console blocks, only the `$ ` lines), in every inline code span that
   starts with `cloakpipe `, and in MCP host config snippets (a JSON block
   with "mcpServers", a TOML block with [mcp_servers.*]), each `cloakpipe`
   or `cloakpipe-verify` invocation must name subcommands the binary has,
   and every --flag must appear in that subcommand's --help.
2. Walkthroughs run. A code block preceded by
       <!-- check-docs: run SESSION [cwd=DIR] -->
   is executed with bash, the `cloakpipe` binaries first on PATH, HOME and
   CLOAKPIPE_HOME pointing into a throwaway directory, from a scratch
   "repository root" that holds a fresh copy of DIR (cwd=DIR, a path from
   the repository root) so the block can `cd DIR` as a reader would. The run
   blocks of one session in one file share one
   shell (variables and functions carry over) and must each succeed. A code
   block preceded by
       <!-- check-docs: expect SESSION -->
   lists lines that must appear in the output (stdout and stderr) of that
   session's most recent run block, in any order; `…` matches anything.
   A session with `needs=network` on any of its run blocks (it downloads
   something) runs only with --network.
       <!-- check-docs: absent SESSION TEXT -->
   says TEXT must not appear in it. A code block preceded by
       <!-- check-docs: excerpt FILE -->
   must be an excerpt of FILE (a path from the repository root): each of
   its non-blank lines must be a line of FILE. A code block preceded by
       <!-- check-docs: file SESSION PATH -->
   is written to PATH (relative to the session's scratch root) before the
   session runs, so a document can show a file and then use it.
3. Local Markdown links resolve.
4. The README and the core docs say what the product is (see REQUIRED).
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Documents that must exist, with phrases each must contain.
REQUIRED = {
    "README.md": [
        "Model proposes. Code disposes.",
        "## Declare",
        "## Enforce",
        "## Prove",
        "claude mcp add",
        ".mcp.json",
        ".cursor/mcp.json",
        "~/.codex/config.toml",
        "## What it is not",
        "## Roadmap",
        "<!-- check-docs: run quickstart",
    ],
    "docs/MANIFEST.md": ["one_of_context", "idempotency_key", "approval", "undeclared_argument"],
    "docs/POLICY.md": ["principal", "context.counters", "@approval", "policy_denied", "fail_closed"],
    "docs/THREAT_MODEL.md": ["## In scope", "## Out of scope"],
    "docs/KEYS.md": ["gate.key", "--approver-key", "--tsa-root", "--rekor-key", "Rotation", "KMS"],
    "docs/legacy/README.md": ["legacy"],
    "docs/legacy/CERTIFICATION.md": ["Legacy"],
    "docs/legacy/AUDIT_PACK.md": ["Legacy"],
}
# Moved to docs/legacy/: must not come back at the top level.
GONE = ["docs/CERTIFICATION.md", "docs/AUDIT_PACK.md", "docs/AGENT_RELEASE.md"]
# The README is about the action boundary; these belong to the legacy docs.
README_FORBIDDEN = ["Evaluate → Certify", "Evaluate, Certify", "release certify", "eval import", "verify-cert"]

CHECKED_GLOBS = ["README.md", "docs/*.md", "examples/*/README.md"]

DIRECTIVE = re.compile(r"<!--\s*check-docs:\s*(run|expect|absent|excerpt|file)\s+(\S+)\s*(.*?)\s*-->")
FENCE = re.compile(r"^(\s*)(```+|~~~+)\s*([\w+-]*)")
SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh"}
CMD_SEPARATORS = {"|", "||", "&&", ";", "(", ")", "{", "--", "$(", "`", "exec", "sudo", "then", "do", "else"}
BINARIES = {"cloakpipe", "cloakpipe-verify"}


class Failure(Exception):
    pass


# ── Markdown parsing ────────────────────────────────────────────────────

def code_blocks(text):
    """Yield (start_line, lang, body, directives) for fenced code blocks.

    `directives` are the check-docs comments between the previous block (or
    the start of the file) and this one."""
    lines = text.split("\n")
    pending = []
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            pending.extend(DIRECTIVE.findall(lines[i]))
            i += 1
            continue
        indent, fence, lang = m.group(1), m.group(2), m.group(3).lower()
        start = i + 1
        body = []
        i += 1
        while i < len(lines) and not lines[i].strip().startswith(fence):
            line = lines[i]
            body.append(line[len(indent):] if line.startswith(indent) else line)
            i += 1
        yield start, lang, "\n".join(body), pending
        pending = []
        i += 1
    if pending:
        yield len(lines), None, "", pending


def prose(text):
    """The text outside fenced code blocks."""
    out, inside, fence = [], False, None
    for line in text.split("\n"):
        m = FENCE.match(line)
        if m and not inside:
            inside, fence = True, m.group(2)
            continue
        if inside and line.strip().startswith(fence):
            inside = False
            continue
        if not inside:
            out.append(line)
    return "\n".join(out)


def shell_lines(lang, body):
    """Logical command lines of a shell or console block."""
    raw = body.split("\n")
    if lang == "console":
        cmds, cur = [], None
        for line in raw:
            if line.startswith("$ "):
                cur = line[2:]
                cmds.append(cur)
            elif cmds and cmds[-1].endswith("\\"):
                cmds[-1] = cmds[-1][:-1] + " " + line.strip()
        raw = cmds
    joined, buf = [], ""
    for line in raw:
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        joined.append(buf + line)
        buf = ""
    if buf:
        joined.append(buf)
    return joined


def tokens(line):
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    lex.commenters = "#"
    try:
        return list(lex)
    except ValueError:
        # An unbalanced quote (a JSON payload split over lines): fall back.
        return line.split("#", 1)[0].split()


def invocations(toks):
    """Split a token list into the argument lists of each cloakpipe call."""
    out = []
    for i, t in enumerate(toks):
        name = t.rsplit("/", 1)[-1]
        if name not in BINARIES:
            continue
        prev = toks[i - 1] if i else None
        at_command = prev is None or prev in CMD_SEPARATORS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", prev or "")
        if not at_command:
            continue
        args = []
        for a in toks[i + 1:]:
            if a in {"|", "||", "&&", ";", ")", ">", ">>", "2>", "<"} or a.startswith(">") or a.startswith("2>"):
                break
            args.append(a)
        out.append((name, args))
    return out


# ── The CLI surface ─────────────────────────────────────────────────────

class Cli:
    def __init__(self, bindir):
        self.bindir = Path(bindir).resolve()
        self.cache = {}
        for b in BINARIES:
            if not (self.bindir / b).exists():
                raise SystemExit(f"check_docs: {self.bindir / b} not found (build it first)")

    def help(self, binary, path):
        key = (binary, tuple(path))
        if key not in self.cache:
            cmd = [str(self.bindir / binary), *path, "--help"]
            r = subprocess.run(cmd, capture_output=True, text=True, env=quiet_env())
            self.cache[key] = r.stdout + r.stderr if r.returncode == 0 else None
        return self.cache[key]

    @staticmethod
    def subcommands(help_text):
        names, inside = [], False
        for line in help_text.split("\n"):
            if line.strip() == "Commands:":
                inside = True
                continue
            if inside:
                if not line.startswith("  "):
                    break
                names.append(line.split()[0])
        return names

    def check(self, binary, args):
        """Raise Failure if `binary args` names a subcommand or flag the
        binary does not have."""
        args = [a.strip("[]") for a in args]
        args = [a for a in args if a]
        if binary == "cloakpipe-verify":
            text = self.help(binary, [])
            if args and not args[0].startswith("-") and not args[0].endswith(".tar") and "<" not in args[0]:
                if f"cloakpipe-verify {args[0]} " not in text:
                    raise Failure(f"`cloakpipe-verify {args[0]}`: no such subcommand")
            for a in args:
                flag = a.split("=", 1)[0]
                if flag.startswith("--") and not re.search(re.escape(flag) + r"\b", text):
                    raise Failure(f"`cloakpipe-verify`: no flag {flag}")
            return
        path = []
        rest = list(args)
        # Global options before the subcommand.
        while rest and rest[0] in ("-c", "--config"):
            rest = rest[2:]
        text = self.help(binary, [])
        while rest and not rest[0].startswith("-"):
            subs = self.subcommands(text)
            if not subs:
                break
            if rest[0] not in subs:
                raise Failure(f"`cloakpipe {' '.join(path + [rest[0]])}`: no such subcommand")
            path.append(rest.pop(0))
            text = self.help(binary, path)
            if text is None:
                raise Failure(f"`cloakpipe {' '.join(path)} --help` failed")
        for a in rest:
            flag = a.split("=", 1)[0]
            if flag.startswith("--") and len(flag) > 2:
                if not re.search(re.escape(flag) + r"(?![\w-])", text):
                    raise Failure(f"`cloakpipe {' '.join(path)}`: no flag {flag}")


def quiet_env(extra=None):
    env = dict(os.environ)
    env.pop("RUST_LOG", None)
    env.update(extra or {})
    return env


# ── Checks ──────────────────────────────────────────────────────────────

def checked_files():
    files = []
    for g in CHECKED_GLOBS:
        files.extend(sorted(ROOT.glob(g)))
    return files


def check_commands(cli, rel, text):
    errors = []
    for start, lang, body, _ in code_blocks(text):
        if lang is None:
            continue
        if lang in SHELL_LANGS:
            for line in shell_lines(lang, body):
                for binary, args in invocations(tokens(line)):
                    try:
                        cli.check(binary, args)
                    except Failure as e:
                        errors.append(f"{rel}:{start}: {e}")
        elif lang == "json" and '"mcpServers"' in body:
            try:
                servers = json.loads(body)["mcpServers"]
            except (ValueError, KeyError) as e:
                errors.append(f"{rel}:{start}: MCP config is not valid JSON: {e}")
                continue
            for name, s in servers.items():
                if Path(s.get("command", "")).name in BINARIES:
                    try:
                        cli.check(Path(s["command"]).name, s.get("args", []))
                    except Failure as e:
                        errors.append(f"{rel}:{start}: server {name}: {e}")
        elif lang == "toml" and "[mcp_servers." in body:
            cmd = re.search(r'^command\s*=\s*"([^"]+)"', body, re.M)
            argv = re.search(r"^args\s*=\s*(\[.*?\])", body, re.M | re.S)
            if not cmd or not argv:
                errors.append(f"{rel}:{start}: TOML MCP config needs command and args")
                continue
            try:
                args = json.loads(argv.group(1))
            except ValueError as e:
                errors.append(f"{rel}:{start}: TOML args are not a list of basic strings: {e}")
                continue
            if Path(cmd.group(1)).name in BINARIES:
                try:
                    cli.check(Path(cmd.group(1)).name, args)
                except Failure as e:
                    errors.append(f"{rel}:{start}: {e}")
    for m in re.finditer(r"`(cloakpipe(?:-verify)? [^`]+)`", prose(text)):
        line = m.group(1)
        if "…" in line or "..." in line:
            line = line.replace("…", "").replace("...", "")
        for binary, args in invocations(tokens(line)):
            try:
                cli.check(binary, args)
            except Failure as e:
                errors.append(f"{rel}: inline `{m.group(1)}`: {e}")
    return errors


def check_excerpts(rel, text):
    errors = []
    for start, lang, body, directives in code_blocks(text):
        for kind, name, _ in directives:
            if kind != "excerpt" or lang is None:
                continue
            src = ROOT / name
            if not src.exists():
                errors.append(f"{rel}:{start}: excerpt of {name}: no such file")
                continue
            have = {line.rstrip() for line in src.read_text().split("\n")}
            for line in body.split("\n"):
                if line.strip() and line.rstrip() not in have:
                    errors.append(f"{rel}:{start}: not a line of {name}:\n    {line}")
    return errors


def check_links(rel, text):
    errors = []
    base = (ROOT / rel).parent
    for m in re.finditer(r"\]\(([^)\s]+)\)", prose(text)):
        target = m.group(1)
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            continue
        path = target.split("#", 1)[0]
        if path and not (base / path).exists():
            errors.append(f"{rel}: broken link {target}")
    return errors


def check_required():
    errors = []
    for rel, phrases in REQUIRED.items():
        p = ROOT / rel
        if not p.exists():
            errors.append(f"{rel}: missing")
            continue
        text = p.read_text()
        for ph in phrases:
            if ph not in text:
                errors.append(f"{rel}: must mention {ph!r}")
    for rel in GONE:
        if (ROOT / rel).exists():
            errors.append(f"{rel}: moved to docs/legacy/; remove it")
    readme = (ROOT / "README.md").read_text()
    for ph in README_FORBIDDEN:
        if ph in readme:
            errors.append(f"README.md: legacy wording {ph!r} (it belongs in docs/legacy/)")
    for p in sorted((ROOT / "docs/legacy").glob("*.md")) if (ROOT / "docs/legacy").exists() else []:
        head = p.read_text()[:600]
        if "legacy" not in head.lower():
            errors.append(f"docs/legacy/{p.name}: must say it is legacy at the top")
    return errors


def expect_matches(expected, output):
    pattern = ".*".join(re.escape(part) for part in expected.split("…"))
    return re.search(pattern, output) is not None


def run_sessions(cli, rel, text, keep, network=False):
    """Run the file's check-docs sessions; return (errors, runs)."""
    sessions = {}  # name -> list of (start, body, cwd)
    files = {}  # name -> list of (path, body)
    needs_network = set()
    checks = []  # (session, index of the run block it follows, kind, arg, start)
    # A directive applies to the code block after it; `expect` and `absent`
    # check the output of the session's last run block before them.
    for start, lang, body, directives in code_blocks(text):
        for kind, name, rest in directives:
            if kind == "run" and lang is not None:
                m = re.search(r"cwd=(\S+)", rest)
                sessions.setdefault(name, []).append((start, body, m.group(1) if m else None))
                if "needs=network" in rest:
                    needs_network.add(name)
            elif kind == "expect" and lang is not None:
                checks.append((name, len(sessions.get(name, [])) - 1, "expect", body, start))
            elif kind == "absent":
                checks.append((name, len(sessions.get(name, [])) - 1, "absent", rest, start))
            elif kind == "file" and lang is not None:
                files.setdefault(name, []).append((rest, body + "\n"))
    errors, runs = [], 0
    for name, blocks in sessions.items():
        if name in needs_network and not network:
            print(f"check_docs: {rel}: session {name} needs the network; skipped (run with --network)")
            continue
        outputs = run_session(cli, rel, name, blocks, files.get(name, []), errors, keep)
        runs += len(blocks)
        for (s, idx, kind, arg, start) in checks:
            if s != name:
                continue
            if idx < 0 or idx >= len(outputs):
                errors.append(f"{rel}:{start}: check-docs {kind} {name}: no run block before it")
                continue
            out = outputs[idx]
            if kind == "expect":
                for line in arg.split("\n"):
                    line = line.strip()
                    if line and not expect_matches(line, out):
                        errors.append(f"{rel}:{start}: session {name}: expected output line not found:\n    {line}")
            elif arg and arg in out:
                errors.append(f"{rel}:{start}: session {name}: {arg!r} must not appear in the output")
    for s in list(files) + [c[0] for c in checks]:
        if s not in sessions:
            errors.append(f"{rel}: check-docs refers to session {s!r} with no run block")
    return errors, runs


def run_session(cli, rel, name, blocks, files, errors, keep):
    tmp = Path(tempfile.mkdtemp(prefix=f"check-docs-{name}-"))
    work = tmp / "work"
    work.mkdir()
    cwd = blocks[0][2]
    if cwd:
        shutil.copytree(ROOT / cwd, work / cwd)
    for path, body in files:
        target = work / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    home = tmp / "home"
    home.mkdir()
    script = ["set -u"]
    for i, (start, body, _) in enumerate(blocks):
        script.append(f"echo '@@check-docs {i} begin@@'; echo '@@check-docs {i} begin@@' >&2")
        script.append(body)
        script.append(f"__rc=$?; echo \"@@check-docs {i} end $__rc@@\"; echo '@@check-docs {i} end@@' >&2")
    env = quiet_env({
        "PATH": f"{cli.bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(home),
        "CLOAKPIPE_HOME": str(home / ".cloakpipe"),
        "REPO_ROOT": str(ROOT),
    })
    for var in ("CLOAKPIPE_LEDGER_DB", "CLOAKPIPE_SIGNING_KEY", "CLOAKPIPE_STATE_DB", "CLOAKPIPE_OPERATIONS_DB",
                "CLOAKPIPE_TASK_CONTEXT"):
        env.pop(var, None)
    r = subprocess.run(["bash", "-c", "\n".join(script)], cwd=work, env=env, capture_output=True, text=True,
                       timeout=300)
    outputs = []
    for i, (start, _, _) in enumerate(blocks):
        out = section(r.stdout, i)
        err = section(r.stderr, i)
        m = re.search(rf"@@check-docs {i} end (\d+)@@", r.stdout)
        if not m:
            errors.append(f"{rel}:{start}: session {name}: block did not finish (bash exit {r.returncode})\n"
                          f"{indent(r.stdout[-2000:])}\n{indent(r.stderr[-2000:])}")
        elif m.group(1) != "0":
            errors.append(f"{rel}:{start}: session {name}: block exited {m.group(1)}\n{indent(out)}\n{indent(err)}")
        outputs.append(out + "\n" + err)
    if keep:
        print(f"check_docs: kept {tmp}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return outputs


def section(text, i):
    m = re.search(rf"@@check-docs {i} begin@@\n(.*?)@@check-docs {i} end", text, re.S)
    return m.group(1) if m else ""


def indent(s):
    return "\n".join("    " + line for line in s.strip().split("\n"))


# ── Self-test of the parser and the command check ───────────────────────

def self_test():
    toks = tokens('emails 51 51 | cloakpipe mcp-proxy --upstream "python3 x.py" $gate 2>/dev/null')
    assert invocations(toks) == [("cloakpipe", ["mcp-proxy", "--upstream", "python3 x.py", "$gate"])], toks
    assert invocations(tokens("cd cloakpipe && ls")) == []
    assert invocations(tokens("claude mcp add crm -- cloakpipe mcp-proxy --manifest m.yaml")) == [
        ("cloakpipe", ["mcp-proxy", "--manifest", "m.yaml"])]
    assert invocations(tokens("CLOAKPIPE_HOME=x cloakpipe ledger entries > e.jsonl")) == [
        ("cloakpipe", ["ledger", "entries"])]
    assert shell_lines("console", "$ cloakpipe a \\\n  --b c\noutput\n$ cloakpipe d") == [
        "cloakpipe a  --b c", "cloakpipe d"]
    assert expect_matches("pack: 4 files, signed by ed25519:… (pinned), OK",
                          "x\npack: 4 files, signed by ed25519:abcd (pinned), OK\n")
    assert not expect_matches("result: OK", "result: FAIL")
    doc = "<!-- check-docs: run s cwd=x -->\n```bash\necho hi\n```\n<!-- check-docs: expect s -->\n```text\nhi\n```\n"
    blocks = list(code_blocks(doc))
    assert blocks[0][3] == [("run", "s", "cwd=x")] and blocks[1][3] == [("expect", "s", "")], blocks
    tail = list(code_blocks("```bash\nx\n```\n<!-- check-docs: absent s boom -->\n"))
    assert tail[-1][1] is None and tail[-1][3] == [("absent", "s", "boom")], tail

    class FakeCli(Cli):
        def __init__(self):
            self.bindir = Path(".")
            self.cache = {}

        def help(self, binary, path):
            return {
                (): "Commands:\n  ledger  x\n  mcp-proxy  y\n  help  z\n\nOptions:\n  -c",
                ("ledger",): "Commands:\n  export  x\n",
                ("ledger", "export"): "Options:\n      --out <FILE>\n      --since <WHEN>\n",
                ("mcp-proxy",): "Options:\n      --manifest <M>\n      --no-ledger\n",
            }.get(tuple(path))

    cli = FakeCli()
    cli.check("cloakpipe", ["ledger", "export", "--out", "x.tar", "[--since", "30d]"])
    for bad in (["ledger", "import"], ["ledger", "export", "--outfile", "x"], ["mcp-proxy", "--no-ledgers"],
                ["eval", "import"]):
        try:
            cli.check("cloakpipe", bad)
        except Failure:
            continue
        raise AssertionError(f"accepted {bad}")
    print("check_docs self-test: OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", help="directory with the cloakpipe and cloakpipe-verify binaries")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-run", action="store_true", help="check commands and links, do not run walkthroughs")
    ap.add_argument("--keep", action="store_true", help="keep the walkthroughs' scratch directories")
    ap.add_argument("--network", action="store_true", help="also run walkthroughs marked needs=network")
    a = ap.parse_args()
    self_test()
    if a.self_test:
        return 0
    if not a.bin:
        ap.error("--bin is required")
    cli = Cli(a.bin)
    errors = check_required()
    runs = 0
    files = checked_files()
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        text = p.read_text()
        errors += check_commands(cli, rel, text)
        errors += check_links(rel, text)
        errors += check_excerpts(rel, text)
        if not a.no_run:
            e, n = run_sessions(cli, rel, text, a.keep, a.network)
            errors += e
            runs += n
    for e in errors:
        print(f"FAIL {e}")
    print(f"check_docs: {len(files)} files, {runs} walkthrough blocks run, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
