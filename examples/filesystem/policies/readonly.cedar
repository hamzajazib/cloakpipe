// Read-only project access (see ../cloakpipe.manifest.yaml). The manifest
// already refuses every tool it does not declare; this policy adds what a
// per-argument contract cannot say well.
//
//   principal  Release::"coding-agent-fs"
//   action     Action::"<tool>"
//   resource   Call::"<fingerprint>", with the call's arguments as resource.args
//   context    { task, counters: { <tool>_1h, <tool>_24h }, time: { unix, hour_utc, weekday } }

@id("read-only-tools")
permit (
  principal == Release::"coding-agent-fs",
  action in [
    Action::"list_allowed_directories",
    Action::"list_directory",
    Action::"directory_tree",
    Action::"search_files",
    Action::"get_file_info",
    Action::"read_text_file"
  ],
  resource
);

// Never hand secrets files to the model, whatever the prompt says.
@id("no-secrets")
forbid (principal, action == Action::"read_text_file", resource)
when {
  resource.args.path like "*.env" ||
  resource.args.path like "*.env.*" ||
  resource.args.path like "*.pem" ||
  resource.args.path like "*id_rsa*"
};

// A runaway loop reading the whole tree stops at 500 files an hour.
@id("read-budget")
forbid (principal, action == Action::"read_text_file", resource)
when { context.counters.read_text_file_1h >= 500 };
