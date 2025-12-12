//! Human-friendly status output for CLI.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Status {
    inner: Arc<StatusInner>,
}

#[derive(Debug)]
struct StatusInner {
    start: Instant,
}

impl Status {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StatusInner {
                start: Instant::now(),
            }),
        }
    }

    pub fn phase(&self, name: &str) -> Phase {
        eprint!("{name}...");
        let _ = io::stderr().flush();
        Phase {
            start: Instant::now(),
        }
    }

    pub fn message(&self, msg: &str) {
        eprintln!("{msg}");
    }

    pub fn elapsed(&self) -> f64 {
        self.inner.start.elapsed().as_secs_f64()
    }
}

impl Default for Status {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Phase {
    start: Instant,
}

impl Phase {
    pub fn done(self) {
        let elapsed = self.start.elapsed();
        eprintln!(" done ({:.1}s)", elapsed.as_secs_f64());
    }

    pub fn done_with(self, detail: &str) {
        let elapsed = self.start.elapsed();
        eprintln!(" {detail} ({:.1}s)", elapsed.as_secs_f64());
    }
}
