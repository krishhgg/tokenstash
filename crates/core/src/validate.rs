//! Pattern + liveness validation at paste time, so a typo fails now, not 20 minutes later.

use crate::registry::Check;
use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

pub fn matches_pattern(pattern: &str, value: &SecretString) -> Result<bool> {
    let re = regex::Regex::new(pattern)?;
    Ok(re.is_match(value.expose_secret()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Liveness {
    Ok,
    Rejected(u16),
    Unknown(String),
}

impl Liveness {
    /// The provider said "slow down": the next probe must wait longer than after a mere outage.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Liveness::Unknown(s) if s == "HTTP 429")
    }
    /// The provider evaluated the key and found it live but not permitted on the probe
    /// endpoint (a restricted key). A verdict that will not change soon.
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Liveness::Unknown(s) if s == "HTTP 403")
    }
}

/// Timeout for a human-initiated probe (paste, `check`, import).
pub const TIMEOUT_HUMAN: Duration = Duration::from_secs(8);
/// Timeout for a probe on the agent's hot path (verify-on-use in `need`).
pub const TIMEOUT_AT_USE: Duration = Duration::from_secs(4);

/// One cheap authenticated request. Never logs the value. Network failure → Unknown (accept).
///
/// Verdicts: 401 (or a status the registry lists in `reject_status`) → Rejected. 403 is
/// "authenticated but not permitted". A restricted Stripe/SendGrid key answers 403 on an
/// endpoint outside its scope and is perfectly alive, so it is Unknown, never Rejected.
/// 429/5xx: the provider did not evaluate the key → Unknown. Redirects are never followed:
/// `ureq` would forward custom auth headers (xi-api-key, X-Subscription-Token) to whatever
/// origin the 3xx names, and strips Authorization so a redirected bearer probe would 401 on
/// a live key. A 3xx is therefore Unknown too.
pub fn liveness(check: &Check, value: &SecretString, timeout: Duration) -> Liveness {
    // `timeout` is a promise to the caller, and on the agent's hot path that caller is `need`.
    // ureq cannot keep it alone: its connect timeout defaults to 30 seconds and wins over the
    // request deadline, name resolution has no bound, and rustls finishes a handshake with
    // socket timeouts set once, so a peer that trickles bytes holds it open. The request runs
    // on a worker instead, and the caller stops waiting at the deadline whatever phase it is in.
    let (check, value) = (check.clone(), SecretString::from(value.expose_secret().to_string()));
    match within(&PROBES, timeout, move || probe_once(&check, &value, timeout)) {
        Ok(verdict) => verdict,
        Err(Waited::Busy) => Liveness::Unknown("too many provider checks already waiting".into()),
        Err(Waited::SpawnFailed) => Liveness::Unknown("could not start the provider check".into()),
        Err(Waited::TimedOut) => Liveness::Unknown("provider check timed out".into()),
        // The worker ended without an answer, which only a panic does: still no verdict, but
        // not a network one either.
        Err(Waited::Died) => Liveness::Unknown("provider check failed".into()),
    }
}

/// Workers for provider checks. A worker whose request is stuck keeps its slot, so a network
/// that never answers costs at most this many threads; past that a probe is Unknown at once,
/// and Unknown delivers the key unverified exactly as any other failed check does.
static PROBES: Limiter = Limiter::new(8);

/// Admission for workers: a count of the ones still running, given back when each worker
/// actually exits, not when its caller stops waiting.
pub(crate) struct Limiter {
    running: AtomicUsize,
    max: usize,
}

impl Limiter {
    pub(crate) const fn new(max: usize) -> Self {
        Limiter { running: AtomicUsize::new(0), max }
    }

    fn admit(&'static self) -> Option<Permit> {
        if self.running.fetch_add(1, Ordering::SeqCst) >= self.max {
            self.running.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Permit(self))
    }

    #[cfg(test)]
    pub(crate) fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }
}

struct Permit(&'static Limiter);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why `within` has no answer.
#[derive(Debug)]
pub(crate) enum Waited {
    /// Every slot is taken.
    Busy,
    /// The OS would not start a thread.
    SpawnFailed,
    /// The deadline passed. The worker keeps running, and keeps its slot, until it ends.
    TimedOut,
    /// The worker ended without an answer.
    Died,
}

/// Run `f` on a worker admitted by `limiter` and wait at most `timeout` for its answer. The
/// permit moves into the worker, so it is given back when the worker ends, or at once if the
/// thread never starts, because the closure that holds it is dropped with it.
pub(crate) fn within<T: Send + 'static>(
    limiter: &'static Limiter,
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Waited> {
    let permit = limiter.admit().ok_or(Waited::Busy)?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("tokenstash-probe".into())
        .spawn(move || {
            let _permit = permit;
            let _ = tx.send(f());
        })
        .map_err(|_| Waited::SpawnFailed)?;
    rx.recv_timeout(timeout).map_err(|e| match e {
        mpsc::RecvTimeoutError::Timeout => Waited::TimedOut,
        mpsc::RecvTimeoutError::Disconnected => Waited::Died,
    })
}

/// The one request, on the worker `liveness` waits for.
fn probe_once(check: &Check, value: &SecretString, timeout: Duration) -> Liveness {
    // The registry is compiled in and a test asserts every check URL is https, but this is
    // the line the secret actually crosses, so it asserts it too: a plain-http probe would
    // put the key on the wire in clear. Cheap, and it holds for whatever edits the file.
    if !url_is_safe_for_a_secret(&check.url) {
        return Liveness::Unknown("provider check URL is not https; refusing to send the key".into());
    }
    // `timeout_connect` too: otherwise ureq's 30-second connect default wins over the request
    // deadline, and a worker `liveness` has stopped waiting for would hold a socket, and its
    // slot, for half a minute.
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .timeout_connect(timeout)
        .redirects(0)
        .user_agent(concat!("tokenstash-liveness/", env!("CARGO_PKG_VERSION")))
        .build();
    let v = value.expose_secret();
    let mut url = check.url.clone();
    let mut req = match check.method.to_ascii_uppercase().as_str() {
        "POST" => agent.post(&url),
        _ => agent.get(&url),
    };
    match check.auth.as_str() {
        "bearer" => req = req.set("Authorization", &format!("Bearer {v}")),
        "basic-user" => {
            use base64::Engine;
            let b = base64::engine::general_purpose::STANDARD.encode(format!("{v}:"));
            req = req.set("Authorization", &format!("Basic {b}"));
        }
        a if a.starts_with("header:") => req = req.set(&a["header:".len()..], v),
        a if a.starts_with("prefix:") => req = req.set("Authorization", &format!("{} {v}", &a["prefix:".len()..])),
        a if a.starts_with("query:") => {
            let p = &a["query:".len()..];
            let sep = if url.contains('?') { '&' } else { '?' };
            url = format!("{url}{sep}{p}={}", percent_encode(v));
            req = match check.method.to_ascii_uppercase().as_str() {
                "POST" => agent.post(&url),
                _ => agent.get(&url),
            };
        }
        _ => {}
    }
    for (k, val) in &check.headers {
        req = req.set(k, val);
    }
    let resp = if check.method.eq_ignore_ascii_case("POST") { req.send_string("{}") } else { req.call() };
    match resp {
        // With redirects off, ureq hands a 3xx back as a plain response.
        Ok(r) if (300..400).contains(&r.status()) => Liveness::Unknown(format!("HTTP {}", r.status())),
        Ok(_) => Liveness::Ok,
        Err(ureq::Error::Status(code, _)) => {
            if code == 401 || check.reject_status.contains(&code) {
                Liveness::Rejected(code)
            } else if code == 403 || code == 429 || code >= 500 {
                // The provider did not evaluate the key (rate-limited, down, redirecting)
                // or evaluated it and found it live but under-scoped (403): no verdict.
                // Treating this as "accepted" would let an outage record a genuine dead-key
                // report as a false report and suppress it for the whole cooldown.
                Liveness::Unknown(format!("HTTP {code}"))
            } else {
                // 400/404 etc. usually mean the key was accepted but the probe was imperfect.
                Liveness::Ok
            }
        }
        // Transport Display strings include the request URL and may include peer-controlled
        // protocol details. A query-auth URL carries the percent-encoded credential, which
        // raw-value redaction cannot reliably recognize after URL normalization. ErrorKind
        // is a static category, so it stays actionable without reflecting either surface.
        Err(ureq::Error::Transport(e)) => Liveness::Unknown(format!("provider check failed: {}", e.kind())),
    }
}

/// https anywhere, or plain http to loopback (what the tests probe, and what a local
/// provider stub would be). Anything else would put the key on the wire in clear.
fn url_is_safe_for_a_secret(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    if l.starts_with("https://") {
        return true;
    }
    let Some(rest) = l.strip_prefix("http://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or("").to_string());
    matches!(host.trim_start_matches('[').trim_end_matches(']'), "127.0.0.1" | "::1" | "localhost")
}

/// Heuristic used to refuse a free-text human answer that is actually a credential. Matches
/// any registry key pattern, or a single long token with no whitespace (API keys, JWTs,
/// connection strings). Free-text answers are returned to the agent; secrets must go
/// through the secret flow where they are never emitted.
pub fn looks_like_secret(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    // Registry patterns are anchored (`^sk-`), so they are tried against each token as well
    // as the whole answer: "the key is sk-live-..." is the shape a human actually types.
    let tokens: Vec<&str> = t.split_whitespace().collect();
    for p in crate::registry::all() {
        if let Some(pat) = &p.pattern {
            if let Ok(re) = regex::Regex::new(pat) {
                if re.is_match(t) || tokens.iter().any(|tok| re.is_match(tok)) {
                    return true;
                }
            }
        }
    }
    let long = |s: &str| s.chars().count() >= 24;
    let mixed = |s: &str| s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c.is_ascii_alphabetic());
    // A long opaque token buried in a sentence: "the staging password is 8f3c...".
    if tokens.iter().any(|tok| long(tok) && mixed(tok)) {
        return true;
    }
    let url_with_creds = t.contains("://") && t.contains('@');
    if url_with_creds {
        return true;
    }
    // A single long token with no digits at all is still a credential shape, because a wordless
    // passphrase ("correcthorsebatterystaple") is exactly what a human types when asked for
    // one. Plain URLs and paths are the answers that legitimately look like this.
    let single_token = tokens.len() == 1;
    let is_url_or_path = ["http://", "https://", "/", "./", "../", "~/"].iter().any(|p| t.starts_with(p));
    single_token && long(t) && !is_url_or_path
}

/// RFC 3986 unreserved characters pass; everything else is `%XX`. Sent raw, a key with `&`
/// or `#` would reach the provider truncated and be reported "rejected" at paste time.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
