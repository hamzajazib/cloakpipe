//! Which upstream serves which tool, and which tools drifted.
//!
//! Every tool definition a server lists is hashed ([`tool_hash`]) and held
//! against what it should be: its pin in the tools lock when there is one
//! (a tool with no pin counts as drifted), else the first definition seen
//! for it in this session. A tool that does not match is hidden from the
//! agent's `tools/list` and every call to it is refused as `tool_drift`
//! until the gate restarts, even if the server changes it back.
//!
//! Routing (several servers): each tool is served under its own name by the
//! one server that lists it. A name two servers list is a collision, refused
//! at start-up unless the manifest declares it per server as
//! `<server>__<tool>`; each copy is then served only under that name.

use crate::gate::Denial;
use crate::servers::ServerTools;
use crate::tools_lock::{tool_hash, ToolsLock};
use crate::DEFAULT_SERVER;
use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// A tool found drifted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Drift {
    pub server: String,
    /// The name the agent knows it by.
    pub tool: String,
}

pub(crate) struct Catalog {
    servers: Vec<String>,
    /// Tools are routed by name (several servers, or a lock): else the one
    /// upstream's messages pass through and only drift is watched.
    routed: bool,
    lock: Option<ToolsLock>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// (server, tool) -> the first hash seen (no lock).
    baseline: HashMap<(usize, String), String>,
    /// Drifted (server, tool): hidden and refused until restart.
    blocked: HashSet<(usize, String)>,
    /// Routed: the agent's name of a tool -> (server, its name there).
    exposed: HashMap<String, (usize, String)>,
    /// Routed: tool names served per server, as `<server>__<tool>`.
    namespaced: HashSet<String>,
}

impl Catalog {
    /// One upstream ([`DEFAULT_SERVER`]) whose messages pass through.
    pub(crate) fn passthrough() -> Self {
        Self { servers: vec![DEFAULT_SERVER.to_string()], routed: false, lock: None, state: Mutex::new(State::default()) }
    }

    /// The servers found at start-up, routed by tool. Refuses a tool name two
    /// servers list unless `declares` (the manifest) has it per server.
    /// Returns the drifts found now.
    pub(crate) fn routed(listing: &[ServerTools], lock: Option<ToolsLock>, declares: &dyn Fn(&str) -> bool) -> Result<(Self, Vec<Drift>)> {
        anyhow::ensure!(!listing.is_empty(), "no upstream MCP server");
        let mut names = HashSet::new();
        for s in listing {
            crate::servers::check_server_name(&s.name).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(names.insert(s.name.as_str()), "server {} is given twice", s.name);
        }
        let (namespaced, collisions) = crate::servers::collisions(listing, declares);
        if !collisions.is_empty() {
            bail!("tool name collision: {}", collisions.join("; "));
        }
        let state = State { namespaced, ..State::default() };
        if let Some(lock) = &lock {
            for s in listing.iter().filter(|s| !lock.has_server(&s.name)) {
                tracing::warn!("tools lock pins nothing for server {}: each of its tools is refused (tool_drift)", s.name);
            }
        }
        let catalog = Self { servers: listing.iter().map(|s| s.name.clone()).collect(), routed: true, lock, state: Mutex::new(state) };
        let mut drifts = Vec::new();
        for (i, s) in listing.iter().enumerate() {
            let (_, found, clashes) = catalog.observe_all(i, s.tools.clone());
            if let Some(name) = clashes.first() {
                bail!("tool name collision: {name:?} is served by two servers");
            }
            drifts.extend(found);
        }
        Ok((catalog, drifts))
    }

    pub(crate) fn servers(&self) -> &[String] {
        &self.servers
    }

    pub(crate) fn index(&self, server: &str) -> Option<usize> {
        self.servers.iter().position(|s| s == server)
    }

    /// The tools lock's digest, when the gate runs with one.
    pub(crate) fn lock_digest(&self) -> Option<String> {
        self.lock.as_ref().map(ToolsLock::digest)
    }

    /// A server's listing, as the agent may see it: drifted tools removed,
    /// routed names applied. Returns those tools and the drifts found now.
    pub(crate) fn observe(&self, server: usize, tools: Vec<Value>) -> (Vec<Value>, Vec<Drift>) {
        let (visible, drifts, clashes) = self.observe_all(server, tools);
        for name in clashes {
            tracing::warn!("server {} now lists {name:?}, which another server serves: hidden", self.servers[server]);
        }
        (visible, drifts)
    }

    fn observe_all(&self, server: usize, tools: Vec<Value>) -> (Vec<Value>, Vec<Drift>, Vec<String>) {
        let mut st = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (mut visible, mut drifts, mut clashes) = (Vec::new(), Vec::new(), Vec::new());
        for mut tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_string) else { continue };
            let agent_name = self.agent_name(&st, server, &name);
            if self.routed {
                match st.exposed.get(&agent_name) {
                    Some((owner, _)) if *owner != server => {
                        clashes.push(agent_name);
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        st.exposed.insert(agent_name.clone(), (server, name.clone()));
                    }
                }
            }
            let key = (server, name.clone());
            if st.blocked.contains(&key) {
                continue;
            }
            let hash = tool_hash(&tool);
            let drifted = match &self.lock {
                Some(lock) => lock.hash_of(&self.servers[server], &name) != Some(hash.as_str()),
                None => match st.baseline.get(&key) {
                    Some(first) => *first != hash,
                    None => {
                        st.baseline.insert(key.clone(), hash);
                        false
                    }
                },
            };
            if drifted {
                st.blocked.insert(key);
                drifts.push(Drift { server: self.servers[server].clone(), tool: agent_name });
                continue;
            }
            if agent_name != name {
                tool["name"] = Value::String(agent_name);
            }
            visible.push(tool);
        }
        (visible, drifts, clashes)
    }

    fn agent_name(&self, st: &State, server: usize, tool: &str) -> String {
        if self.routed && st.namespaced.contains(tool) {
            format!("{}__{tool}", self.servers[server])
        } else {
            tool.to_string()
        }
    }

    /// Where a call to the agent's `tool` goes: the server and the tool's
    /// name there. `None`: no server serves it.
    pub(crate) fn route(&self, tool: &str) -> Option<(usize, String)> {
        if !self.routed {
            return Some((0, tool.to_string()));
        }
        let st = self.state.lock().ok()?;
        st.exposed.get(tool).cloned()
    }

    /// Why a call to the agent's `tool` may not be sent: it drifted, or no
    /// server serves it.
    pub(crate) fn refuse(&self, tool: &str) -> Option<Denial> {
        let st = match self.state.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (server, name) = if self.routed {
            match st.exposed.get(tool) {
                Some(found) => found.clone(),
                None => return Some(Denial::ToolUnavailable),
            }
        } else {
            (0, tool.to_string())
        };
        st.blocked.contains(&(server, name)).then(|| Denial::ToolDrift { server: self.servers[server].clone() })
    }
}
