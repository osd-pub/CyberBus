//! Only public discovery GETs may use this loop. Grant POSTs and JWKS retain
//! their original code paths and ownership. No error/URL/body is formatted here.
use crate::{Error, Result};
use std::{io::Write, time::Duration};
use tokio::time::{Instant, sleep_until, timeout_at};
use zeroize::Zeroizing;

pub(super) const BUDGET: Duration = Duration::from_secs(30);
const ATTEMPTS: u8 = 3;

// Every caller passes a literal from the closed vocabulary below; remote strings
// never reach this formatter. status=0 means no response status was available.
pub(super) fn report(
    attempt: u8,
    class: &'static str,
    status: u16,
    began: Instant,
    deadline: Instant,
) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        line(attempt, class, status, began, deadline)
    );
}
fn line(
    attempt: u8,
    class: &'static str,
    status: u16,
    began: Instant,
    deadline: Instant,
) -> String {
    format!(
        "CYBERBUS_AUTH_GET stage=discovery attempt={attempt} class={class} status={status} elapsed_ms={} remaining_ms={}",
        began.elapsed().as_millis(),
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
}

struct Failure {
    class: &'static str,
    error: Error,
    retry: bool,
    retry_after: Duration,
}
impl Failure {
    fn transport(error: reqwest::Error, body: bool) -> Self {
        let (class, retry) = if error.is_timeout() {
            (
                if error.is_connect() {
                    "connect_timeout"
                } else {
                    "request_timeout"
                },
                true,
            )
        } else if error.is_builder() {
            ("configuration", false)
        } else if error.is_redirect() {
            ("redirect", false)
        } else if error.is_connect() {
            // Do not retry opaque connect errors such as permanent TLS/config
            // failures. Only typed transient IO causes qualify; never print them.
            use std::{error::Error as _, io::ErrorKind};
            let mut source = error.source();
            let mut transient = false;
            while let Some(cause) = source {
                if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                    transient |= matches!(
                        io.kind(),
                        ErrorKind::ConnectionRefused
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                            | ErrorKind::TimedOut
                            | ErrorKind::UnexpectedEof
                            | ErrorKind::BrokenPipe
                            | ErrorKind::Interrupted
                            | ErrorKind::WouldBlock
                    );
                }
                source = cause.source();
            }
            ("connect_transport", transient)
        } else if body {
            ("body_transport", true)
        } else {
            ("request_transport", error.is_request())
        };
        Self {
            class,
            error: if class == "configuration" {
                Error::Configuration
            } else {
                Error::Unavailable
            },
            retry,
            retry_after: Duration::ZERO,
        }
    }
}

async fn once(
    client: &reqwest::Client,
    url: &str,
    status: &mut u16,
) -> std::result::Result<Zeroizing<Vec<u8>>, Failure> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Failure::transport(e, false))?;
    *status = response.status().as_u16();
    if !response.status().is_success() {
        let mut retry = matches!(*status, 408 | 429 | 500 | 502 | 503 | 504);
        let mut retry_after = Duration::ZERO;
        if retry {
            if let Some(value) = response.headers().get(reqwest::header::RETRY_AFTER) {
                // Honor delta-seconds. Unsupported dates/malformed values stop
                // retries conservatively rather than ignoring server throttling.
                match value.to_str().ok().and_then(|s| s.parse::<u64>().ok()) {
                    Some(seconds) => retry_after = Duration::from_secs(seconds),
                    None => retry = false,
                }
            }
        }
        return Err(Failure {
            class: if response.status().is_redirection() {
                "redirect"
            } else {
                "http_status"
            },
            error: Error::Unavailable,
            retry,
            retry_after,
        });
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Failure::transport(e, true))?
    {
        if body.len() + chunk.len() > 262144 {
            return Err(Failure {
                class: "invalid_document",
                error: Error::InvalidClaims,
                retry: false,
                retry_after: Duration::ZERO,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(super) async fn get(
    client: &reqwest::Client,
    url: &str,
    began: Instant,
    deadline: Instant,
) -> Result<(Zeroizing<Vec<u8>>, u8, u16)> {
    run(client, url, began, deadline, report).await
}
async fn run(
    client: &reqwest::Client,
    url: &str,
    began: Instant,
    deadline: Instant,
    report: impl Fn(u8, &'static str, u16, Instant, Instant),
) -> Result<(Zeroizing<Vec<u8>>, u8, u16)> {
    // Count SDK-issued attempts. reqwest's existing safe protocol-NACK retries
    // remain default and share this same absolute deadline; no global POST policy.
    for attempt in 1..=ATTEMPTS {
        let mut status = 0;
        if Instant::now() >= deadline {
            report(attempt, "budget_exhausted", status, began, deadline);
            return Err(Error::Unavailable);
        }
        match timeout_at(deadline, once(client, url, &mut status)).await {
            Ok(Ok(body)) if Instant::now() < deadline => return Ok((body, attempt, status)),
            Ok(Ok(_)) => {
                report(attempt, "budget_exhausted", status, began, deadline);
                return Err(Error::Unavailable);
            }
            Err(_) => {
                report(attempt, "budget_exhausted", status, began, deadline);
                return Err(Error::Unavailable);
            }
            Ok(Err(failure)) => {
                report(attempt, failure.class, status, began, deadline);
                if !failure.retry || attempt == ATTEMPTS {
                    return Err(failure.error);
                }
                let mut random = [0; 2];
                if getrandom::fill(&mut random).is_err() {
                    report(attempt, "configuration", status, began, deadline);
                    return Err(Error::Configuration);
                }
                let jitter = Duration::from_millis(
                    100 * u64::from(attempt) + u64::from(u16::from_be_bytes(random) % 201),
                );
                let delay = jitter.max(failure.retry_after);
                let now = Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                // A large Retry-After cannot overflow Instant or extend budget.
                sleep_until(now + delay.min(remaining)).await;
                if Instant::now() >= deadline {
                    report(attempt, "budget_exhausted", status, began, deadline);
                    return Err(Error::Unavailable);
                }
            }
        }
    }
    unreachable!("every discovery attempt selects success, failure or retry")
}

#[cfg(test)]
mod tests;
