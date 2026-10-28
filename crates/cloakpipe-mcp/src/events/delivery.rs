//! The delivery queue every sink shares: a bounded queue drained by one
//! background thread. Pushing never blocks: when the queue is full the item
//! is dropped, counted and reported on stderr. The decision path only ever
//! pushes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Items the queue holds before it drops.
pub const DEFAULT_CAPACITY: usize = 1024;

struct State<T> {
    items: VecDeque<T>,
    /// The worker holds a batch it has not finished.
    busy: bool,
    closed: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    /// Work arrived (or the queue closed).
    ready: Condvar,
    /// The worker went idle with nothing queued.
    idle: Condvar,
    capacity: usize,
    dropped: AtomicU64,
    name: String,
}

/// A bounded queue with its worker thread.
pub(crate) struct Queue<T> {
    shared: Arc<Shared<T>>,
}

impl<T: Send + 'static> Queue<T> {
    /// Start a worker that hands `handler` up to `max_batch` items at a time.
    pub(crate) fn spawn(name: &str, capacity: usize, max_batch: usize, mut handler: impl FnMut(Vec<T>) + Send + 'static) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State { items: VecDeque::new(), busy: false, closed: false }),
            ready: Condvar::new(),
            idle: Condvar::new(),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            name: name.to_string(),
        });
        let worker = shared.clone();
        let max_batch = max_batch.max(1);
        let spawned = std::thread::Builder::new().name(format!("cloakpipe-{name}")).spawn(move || loop {
            let batch: Vec<T> = {
                let mut s = lock(&worker.state);
                while s.items.is_empty() && !s.closed {
                    s = worker.ready.wait(s).unwrap_or_else(|p| p.into_inner());
                }
                if s.items.is_empty() {
                    return;
                }
                let n = s.items.len().min(max_batch);
                s.busy = true;
                s.items.drain(..n).collect()
            };
            // A panicking sink loses its batch, never the worker.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(batch))).is_err() {
                eprintln!("warning: cloakpipe {}: delivery panicked; batch dropped", worker.name);
            }
            let mut s = lock(&worker.state);
            s.busy = false;
            if s.items.is_empty() {
                worker.idle.notify_all();
            }
        });
        if let Err(e) = spawned {
            eprintln!("warning: cloakpipe {name}: cannot start the delivery thread ({e}); events are dropped");
            lock(&shared.state).closed = true;
        }
        Self { shared }
    }

    /// Queue `item`, or drop it when the queue is full (never blocks).
    pub(crate) fn push(&self, item: T) -> bool {
        let mut s = lock(&self.shared.state);
        if s.closed || s.items.len() >= self.shared.capacity {
            drop(s);
            let n = self.shared.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // The first drop, then every 100th: a dead endpoint must not
            // flood stderr either.
            if n == 1 || n.is_multiple_of(100) {
                eprintln!("warning: cloakpipe {}: delivery queue full; {n} event(s) dropped so far", self.shared.name);
            }
            return false;
        }
        s.items.push_back(item);
        self.shared.ready.notify_one();
        true
    }

    /// Wait until everything queued so far is handled, at most `timeout`.
    /// `true` when the queue drained in time.
    pub(crate) fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut s = lock(&self.shared.state);
        loop {
            if s.items.is_empty() && !s.busy {
                return true;
            }
            if s.closed && s.items.is_empty() {
                return !s.busy;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            s = self.shared.idle.wait_timeout(s, deadline - now).map(|(g, _)| g).unwrap_or_else(|p| p.into_inner().0);
        }
    }

    /// Items dropped because the queue was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

impl<T> Drop for Queue<T> {
    /// The worker finishes what is queued, then exits.
    fn drop(&mut self) {
        lock(&self.shared.state).closed = true;
        self.shared.ready.notify_all();
    }
}

fn lock<S>(m: &Mutex<S>) -> std::sync::MutexGuard<'_, S> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// What one HTTP delivery attempt sends.
pub(crate) struct Post<'a> {
    pub url: &'a str,
    pub body: &'a [u8],
    /// Headers for this attempt (a webhook signs each attempt anew).
    pub headers: &'a dyn Fn() -> Vec<(&'static str, String)>,
}

/// How deliveries retry: `tries` attempts in all, `backoff` doubling
/// between them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Retry {
    pub tries: u32,
    pub backoff: Duration,
}

/// POST `post` until it lands or the tries run out. A connection error, a
/// timeout, a 429 or a 5xx is retried; any other status is final.
/// `Ok(status)` on a 2xx.
pub(crate) fn post_with_retry(client: &reqwest::blocking::Client, post: &Post<'_>, retry: Retry) -> Result<u16, String> {
    let mut last = String::new();
    for attempt in 0..retry.tries.max(1) {
        if attempt > 0 {
            std::thread::sleep(retry.backoff * 2u32.saturating_pow(attempt - 1));
        }
        let mut req = client.post(post.url).header("Content-Type", "application/json").body(post.body.to_vec());
        for (k, v) in (post.headers)() {
            req = req.header(k, v);
        }
        match req.send() {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(status.as_u16());
                }
                last = format!("HTTP {}", status.as_u16());
                if !(status.is_server_error() || status.as_u16() == 429) {
                    return Err(last);
                }
            }
            // The error's kind only: it may name the URL, never a payload.
            Err(e) if e.is_timeout() => last = "timed out".to_string(),
            Err(e) if e.is_connect() => last = "connection failed".to_string(),
            Err(_) => last = "request failed".to_string(),
        }
    }
    Err(last)
}

/// A blocking HTTP client with `timeout` per request. Built on the worker
/// thread (never inside an async runtime).
pub(crate) fn client(timeout: Duration) -> Option<reqwest::blocking::Client> {
    match reqwest::blocking::Client::builder().timeout(timeout).user_agent(concat!("cloakpipe/", env!("CARGO_PKG_VERSION"))).build() {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("warning: cloakpipe: cannot build the HTTP client ({e}); events are not delivered");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_queue_drops_instead_of_blocking() {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.lock().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (g, s) = (gate.clone(), seen.clone());
        let q = Queue::spawn("test", 2, 10, move |batch: Vec<u32>| {
            let _wait = g.lock().unwrap();
            s.lock().unwrap().extend(batch);
        });
        q.push(0);
        // The worker takes item 0 and blocks; two more fit, the rest drop.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !lock(&q.shared.state).busy {
            assert!(Instant::now() < deadline, "the worker never took item 0");
            std::thread::sleep(Duration::from_millis(5));
        }
        let pushed: Vec<bool> = (1..6).map(|i| q.push(i)).collect();
        assert_eq!(pushed, [true, true, false, false, false]);
        assert_eq!(q.dropped(), 3);
        assert!(!q.flush(Duration::from_millis(50)), "still blocked");
        drop(held);
        assert!(q.flush(Duration::from_secs(5)));
        assert_eq!(*seen.lock().unwrap(), [0, 1, 2]);
    }
}
