//! A local HTTP receiver for the delivery tests (webhooks, OTLP): it
//! listens on 127.0.0.1:0, keeps every request and answers each with the
//! next scripted status (200 once the script runs out). No internet.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names lower-cased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub struct Receiver {
    /// `http://127.0.0.1:<port>`
    pub base: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Receiver {
    /// Answer the n-th request with `statuses[n]`, then 200.
    pub fn start(statuses: &[u16]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(statuses.to_vec()));
        {
            let requests = requests.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let (requests, script) = (requests.clone(), script.clone());
                    std::thread::spawn(move || serve(stream, &requests, &script));
                }
            });
        }
        Self { base, requests }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// Wait until at least `n` requests arrived.
    pub fn wait_for(&self, n: usize, timeout: Duration) -> Vec<Request> {
        let deadline = Instant::now() + timeout;
        loop {
            let got = self.requests();
            if got.len() >= n || Instant::now() > deadline {
                return got;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn serve(stream: TcpStream, requests: &Mutex<Vec<Request>>, script: &Mutex<Vec<u16>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    // Keep-alive: serve requests on this connection until it closes.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = vec![0; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        requests.lock().unwrap().push(Request { method, path, headers, body });
        let status = {
            let mut s = script.lock().unwrap();
            if s.is_empty() { 200 } else { s.remove(0) }
        };
        let reply = format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok");
        if stream.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

/// An endpoint that accepts connections and never answers.
pub fn black_hole() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    base
}

/// A local port nothing listens on.
pub fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    base
}
