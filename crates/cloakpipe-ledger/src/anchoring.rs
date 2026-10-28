//! Scheduled anchoring of the decision ledger, off the request path.
//!
//! An [`AnchorScheduler`] seals new decision entries into the next epoch
//! ([`crate::epoch`]) every N entries and/or every T, then anchors each epoch
//! with every configured authority (an RFC 3161 TSA, Sigstore Rekor). The
//! clients verify each answer offline before it is kept, with the same code
//! auditors run. An epoch that is missing an anchor is retried after
//! [`AnchorPolicy::retry`], and in later runs too, since the state lives in
//! the ledger database. [`AnchorLoop`] runs a scheduler on its own thread
//! with its own database connection, so the gate never waits for an
//! anchor. Every failure is reported as an `anchor.failed` line.

use cloakpipe_anchor::anchor::rekor::RekorClient;
use cloakpipe_anchor::anchor::rfc3161::TsaClient;
use cloakpipe_anchor::receipt::ExternalReceipt;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::epoch::{receipt_kind, EpochHead, StoredEpoch};
use crate::gate_key::GateKey;
use crate::store::{LedgerStore, StoreError};

/// The authorities an epoch is anchored with.
pub struct Anchorer {
    tsa: Option<TsaClient>,
    rekor: Option<RekorClient>,
}

impl Anchorer {
    /// At least one of the two should be set; with neither, nothing is
    /// ever anchored.
    pub fn new(tsa: Option<TsaClient>, rekor: Option<RekorClient>) -> Self {
        Self { tsa, rekor }
    }

    /// The anchor kinds configured, sorted.
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut k = Vec::new();
        if self.rekor.is_some() {
            k.push("rekor");
        }
        if self.tsa.is_some() {
            k.push("rfc3161");
        }
        k
    }

    /// Anchor `head` with every configured authority it has no receipt
    /// from yet: the new receipts, and `(kind, error)` per failure.
    pub fn anchor(
        &self,
        head: &EpochHead,
        have: &[ExternalReceipt],
        signer: &SigningKey,
    ) -> (Vec<ExternalReceipt>, Vec<(&'static str, String)>) {
        let artifact = head.artifact();
        let has = |kind: &str| have.iter().any(|r| receipt_kind(r) == kind);
        let (mut got, mut failed) = (Vec::new(), Vec::new());
        if let Some(tsa) = self.tsa.as_ref().filter(|_| !has("rfc3161")) {
            match tsa.anchor_artifact(&head.id(), &artifact) {
                Ok(r) => got.push(r),
                Err(e) => failed.push(("rfc3161", e.to_string())),
            }
        }
        if let Some(rekor) = self.rekor.as_ref().filter(|_| !has("rekor")) {
            match rekor.anchor_artifact(&head.id(), &artifact, signer) {
                Ok(r) => got.push(r),
                Err(e) => failed.push(("rekor", e.to_string())),
            }
        }
        (got, failed)
    }
}

/// When to seal and how often to retry a missing anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorPolicy {
    /// Seal once this many entries are unsealed.
    pub every: Option<u64>,
    /// Seal whatever is unsealed once this long has passed since the last
    /// seal (or since start).
    pub interval: Option<Duration>,
    /// Wait this long before asking an authority again after it failed.
    pub retry: Duration,
}

/// What a scheduler did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorEvent {
    Sealed { epoch: u64, first_seq: u64, last_seq: u64 },
    Anchored { epoch: u64, first_seq: u64, last_seq: u64, kinds: Vec<&'static str> },
    Failed { epoch: u64, first_seq: u64, last_seq: u64, kind: &'static str, error: String },
}

impl fmt::Display for AnchorEvent {
    /// The stderr line the gate prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorEvent::Sealed { epoch, first_seq, last_seq } => {
                write!(f, "anchor.sealed epoch={epoch} seq={first_seq}..{last_seq}")
            }
            AnchorEvent::Anchored { epoch, first_seq, last_seq, kinds } => {
                write!(f, "anchor.ok epoch={epoch} seq={first_seq}..{last_seq} anchors={}", kinds.join(","))
            }
            AnchorEvent::Failed { epoch, first_seq, last_seq, kind, error } => {
                write!(f, "anchor.failed epoch={epoch} seq={first_seq}..{last_seq} anchor={kind} error={error}")
            }
        }
    }
}

/// Seals and anchors epochs of one ledger. Drive it with [`Self::tick`].
pub struct AnchorScheduler {
    store: LedgerStore,
    key: GateKey,
    anchorer: Anchorer,
    policy: AnchorPolicy,
    last_seal: Instant,
    /// Epoch -> when an anchor for it last failed.
    failed_at: HashMap<u64, Instant>,
}

impl AnchorScheduler {
    /// `started` is when the interval starts counting.
    pub fn new(store: LedgerStore, key: GateKey, anchorer: Anchorer, policy: AnchorPolicy, started: Instant) -> Self {
        Self { store, key, anchorer, policy, last_seal: started, failed_at: HashMap::new() }
    }

    /// Seal if due, then anchor every epoch missing an anchor whose retry
    /// time has come.
    pub fn tick(&mut self, now: Instant) -> Result<Vec<AnchorEvent>, StoreError> {
        let mut events = Vec::new();
        let unsealed = self.unsealed()?;
        let due = unsealed > 0
            && (self.policy.every.is_some_and(|n| unsealed >= n.max(1))
                || self.policy.interval.is_some_and(|i| now.saturating_duration_since(self.last_seal) >= i));
        if due {
            self.seal(now, &mut events)?;
        }
        self.anchor_pending(Some(now), &mut events)?;
        Ok(events)
    }

    /// Seal whatever is unsealed and try every missing anchor once, retry
    /// times ignored (at shutdown).
    pub fn flush(&mut self) -> Result<Vec<AnchorEvent>, StoreError> {
        let mut events = Vec::new();
        let now = Instant::now();
        if self.unsealed()? > 0 {
            self.seal(now, &mut events)?;
        }
        self.anchor_pending(None, &mut events)?;
        Ok(events)
    }

    fn unsealed(&self) -> Result<u64, StoreError> {
        let next = self.store.next_unsealed_seq()?;
        Ok(match self.store.decision_head_seq()? {
            Some(head) if head >= next => head - next + 1,
            _ => 0,
        })
    }

    fn seal(&mut self, now: Instant, events: &mut Vec<AnchorEvent>) -> Result<(), StoreError> {
        if let Some(h) = self.store.seal_epoch(&self.key, chrono::Utc::now())? {
            events.push(AnchorEvent::Sealed { epoch: h.epoch, first_seq: h.first_seq, last_seq: h.last_seq });
        }
        self.last_seal = now;
        Ok(())
    }

    /// `now: None` ignores retry times.
    fn anchor_pending(&mut self, now: Option<Instant>, events: &mut Vec<AnchorEvent>) -> Result<(), StoreError> {
        let wanted = self.anchorer.kinds();
        let pending: Vec<StoredEpoch> = self
            .store
            .epochs()?
            .into_iter()
            .filter(|e| {
                let have = e.kinds();
                wanted.iter().any(|k| !have.contains(k))
            })
            .collect();
        for e in pending {
            let h = &e.head;
            if let (Some(now), Some(at)) = (now, self.failed_at.get(&h.epoch)) {
                if now.saturating_duration_since(*at) < self.policy.retry {
                    continue;
                }
            }
            let (got, failed) = self.anchorer.anchor(h, &e.anchors, self.key.signing_key());
            let error = (!failed.is_empty())
                .then(|| failed.iter().map(|(k, e)| format!("{k}: {e}")).collect::<Vec<_>>().join("; "));
            self.store.add_epoch_anchors(h.epoch, got, error)?;
            if failed.is_empty() {
                self.failed_at.remove(&h.epoch);
                let kinds = self.store.epochs()?.into_iter().find(|s| s.head.epoch == h.epoch).map(|s| s.kinds());
                events.push(AnchorEvent::Anchored {
                    epoch: h.epoch,
                    first_seq: h.first_seq,
                    last_seq: h.last_seq,
                    kinds: kinds.unwrap_or_default(),
                });
            } else {
                self.failed_at.insert(h.epoch, now.unwrap_or_else(Instant::now));
                for (kind, error) in failed {
                    events.push(AnchorEvent::Failed {
                        epoch: h.epoch,
                        first_seq: h.first_seq,
                        last_seq: h.last_seq,
                        kind,
                        error,
                    });
                }
            }
        }
        Ok(())
    }
}

/// How often the background loop looks for work.
const POLL: Duration = Duration::from_millis(200);

/// A scheduler on its own thread. Lines go to stderr as
/// `cloakpipe: anchor.…`.
pub struct AnchorLoop {
    stop: mpsc::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

impl AnchorLoop {
    /// Open the ledger at `path` (a connection of its own) and start.
    pub fn spawn(path: &str, key: GateKey, anchorer: Anchorer, policy: AnchorPolicy) -> Result<Self, StoreError> {
        Self::spawn_with(path, key, anchorer, policy, |_| {})
    }

    /// [`Self::spawn`], also handing every [`AnchorEvent`] to `on_event`
    /// (on the loop's thread; e.g. to raise an `anchor.failed` gate event).
    pub fn spawn_with(
        path: &str,
        key: GateKey,
        anchorer: Anchorer,
        policy: AnchorPolicy,
        on_event: impl Fn(&AnchorEvent) + Send + 'static,
    ) -> Result<Self, StoreError> {
        let store = LedgerStore::open(path)?;
        let mut sched = AnchorScheduler::new(store, key, anchorer, policy, Instant::now());
        let (stop, stopped) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let report = |r: Result<Vec<AnchorEvent>, StoreError>| match r {
                Ok(events) => {
                    for e in events {
                        eprintln!("cloakpipe: {e}");
                        on_event(&e);
                    }
                }
                Err(e) => eprintln!("cloakpipe: anchor.failed error=ledger: {e}"),
            };
            // A stop message or a dropped sender ends the loop.
            while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(POLL) {
                report(sched.tick(Instant::now()));
            }
            report(sched.flush());
        });
        Ok(Self { stop, handle })
    }

    /// Stop: seal what is left, try to anchor it once, and wait for that.
    /// An epoch still unanchored is retried by the next run.
    pub fn finish(self) {
        let _ = self.stop.send(());
        let _ = self.handle.join();
    }
}
