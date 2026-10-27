# Example: read-only project files for a coding agent

Give Claude Code, Cursor or Codex the reference filesystem MCP server
([`@modelcontextprotocol/server-filesystem`](https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem))
for one project, but read-only, and never its secrets files.

| File | What it is |
|---|---|
| [`cloakpipe.manifest.yaml`](cloakpipe.manifest.yaml) | Declares only the reading tools (`read_text_file`, `list_directory`, `directory_tree`, `search_files`, `get_file_info`, `list_allowed_directories`) and their arguments. `write_file`, `edit_file`, `move_file` and `create_directory` are not declared, so they are refused as `undeclared_tool`. |
| [`policies/readonly.cedar`](policies/readonly.cedar) | Permits the reading tools, forbids reading `*.env`, `*.env.*`, `*.pem` and `*id_rsa*` files, and caps reads at 500 an hour. |

Check both files load:

<!-- check-docs: run fs-validate cwd=examples/filesystem -->
```bash
cd examples/filesystem
cloakpipe manifest validate cloakpipe.manifest.yaml
```

<!-- check-docs: expect fs-validate -->
```text
valid  sha256:…  coding-agent-fs@1  6 tools
policy sha256:…  ./policies/readonly.cedar  3 Cedar policies
```

## Wire it into your agent

See the [README](../../README.md#use-it-with-claude-code-cursor-and-codex)
for the Claude Code, Cursor and Codex snippets; they use this manifest.

## Try it by hand

This needs Node.js (`npx` downloads the server). A host sends `initialize`
first, then the calls; `sleep` keeps the pipe open until the server has
answered:

<!-- check-docs: run fs cwd=examples/filesystem needs=network -->
```bash
cd examples/filesystem
export CLOAKPIPE_HOME=$(mktemp -d)
project=$(mktemp -d)
echo 'hello from the project' > "$project/README.md"
echo 'API_TOKEN=do-not-leak' > "$project/.env"

{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/README.md"}}}\n' "$project"
  printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}\n' "$project"
  printf '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s/x","content":"x"}}}\n' "$project"
  sleep 5
} | cloakpipe mcp-proxy --manifest cloakpipe.manifest.yaml \
      --upstream "npx -y @modelcontextprotocol/server-filesystem $project"
```

<!-- check-docs: expect fs -->
```text
{"jsonrpc":"2.0","id":3,"error":{"code":-32001,"message":"tool call refused by CloakPipe: policy_denied","data":{"reason":"policy_denied","tool":"read_text_file","release":"sha256:…","policies":["no-secrets"]}}}
{"jsonrpc":"2.0","id":4,"error":{"code":-32001,"message":"tool call refused by CloakPipe: undeclared_tool","data":{"reason":"undeclared_tool","tool":"write_file","release":"sha256:…"}}}
{"result":{"content":[{"type":"text","text":"hello from the project…"id":2}
```
<!-- check-docs: absent fs do-not-leak -->

The README is read, the `.env` file is refused by the `no-secrets` policy
without its contents ever reaching the agent, and the write is refused
because the manifest does not declare `write_file`. No operations database
is needed, because no declared tool has side effects.
