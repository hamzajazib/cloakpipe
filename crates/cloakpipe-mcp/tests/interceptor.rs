//! The transport-agnostic interceptor ([`Interceptor`]), driven without any
//! process or stream: each message in, the actions out. The stdio runner
//! (`run_proxy_io`) is a thin loop over exactly this.

use cloakpipe_ledger::decision::Decision;
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::{Action, DecisionLog, GateMode, Interceptor, ProxyContext, ToolGate, Upstream, UpstreamTransport, DEFAULT_SERVER};
use cloakpipe_release::AgentRelease;
use serde_json::{json, Value};

/// support-agent@184: declares `refund` and `lookup-customer`.
fn support_gate() -> ToolGate {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    let m: AgentRelease = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    ToolGate::new(GateMode::Enforce, &m).with_contracts(vec![], Some(json!({"taskId": "t-981"}))).unwrap()
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"amount": 5}}}).to_string()
}

fn ctx(gate: Option<ToolGate>, decisions: Option<DecisionLog>) -> ProxyContext {
    ProxyContext { pii: None, ledger_db: None, release: None, gate, decisions, events: Vec::new() }
}

fn agent_message(actions: &[Action]) -> Value {
    match actions {
        [Action::ToAgent(line)] => serde_json::from_str(line).unwrap(),
        other => panic!("expected one message for the agent: {other:?}"),
    }
}

#[test]
fn a_single_upstream_is_named_default() {
    let up = Upstream::stdio(DEFAULT_SERVER, vec!["mcp-server".into()]);
    assert_eq!(DEFAULT_SERVER, "default");
    assert_eq!(up.name, "default");
    assert_eq!(up.transport, UpstreamTransport::Stdio { command: vec!["mcp-server".into()] });
}

#[test]
fn decides_each_message_and_returns_what_to_send() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let decisions = DecisionLog::open(db.to_str().unwrap(), GateKey::from_seed([5; 32])).unwrap();
    let i = Interceptor::new(ctx(Some(support_gate()), Some(decisions))).unwrap();

    // Allowed: forwarded to the default upstream, re-serialized.
    let actions = i.on_agent_line(&call(1, "refund"));
    let [Action::ToUpstream { server, message }] = actions.as_slice() else { panic!("{actions:?}") };
    assert_eq!(server, DEFAULT_SERVER);
    let forwarded: Value = serde_json::from_str(message).unwrap();
    assert_eq!(forwarded["params"]["name"], "refund");

    // Refused: answered to the agent, never forwarded.
    let refusal = agent_message(&i.on_agent_line(&call(2, "export_customers")));
    assert_eq!(refusal["id"], 2);
    assert_eq!(refusal["error"]["data"]["reason"], "undeclared_tool");

    // Unreadable: refused with a parse error.
    let unreadable = agent_message(&i.on_agent_line("{not json"));
    assert_eq!(unreadable["error"]["code"], -32700);

    // The upstream's reply goes to the agent.
    let reply = agent_message(&i.on_upstream_line(DEFAULT_SERVER, r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#));
    assert_eq!(reply["id"], 1);
    assert!(i.finish().is_empty(), "nothing was left in flight");

    let entries = LedgerStore::open(db.to_str().unwrap()).unwrap().decisions().unwrap();
    let decided: Vec<_> = entries.iter().map(|e| (e.decision, e.reason.as_str())).collect();
    assert_eq!(decided, [(Decision::Allow, "ok"), (Decision::Deny, "undeclared_tool"), (Decision::Deny, "unreadable")]);
}

#[test]
fn without_a_gate_messages_pass_through_verbatim() {
    let i = Interceptor::new(ctx(None, None)).unwrap();
    assert_eq!(
        i.on_agent_line("not json at all"),
        [Action::ToUpstream { server: DEFAULT_SERVER.into(), message: "not json at all".into() }]
    );
    assert_eq!(i.on_upstream_line(DEFAULT_SERVER, "log line"), [Action::ToAgent("log line".into())]);
}
