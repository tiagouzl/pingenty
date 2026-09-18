use crate::cli::RecordTypeCli;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum DnsStatus {
    Success {
        records: Vec<String>,
        latency: Duration,
    },
    NotFound {
        latency: Duration,
    },
    Error {
        message: String,
        latency: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct DnsQueryResult {
    pub domain: String,
    pub record_type: RecordTypeCli,
    pub status: DnsStatus,
}

pub struct DnsEngine {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

impl DnsEngine {
    pub fn new(timeout_ms: u64) -> Result<Self, anyhow::Error> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(timeout_ms);
        opts.attempts = 2;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts);
        Ok(Self {
            resolver,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    pub async fn resolve(&self, domain: &str, record_type: RecordTypeCli) -> DnsQueryResult {
        let target_type = match record_type {
            RecordTypeCli::A => RecordType::A,
            RecordTypeCli::Aaaa => RecordType::AAAA,
            RecordTypeCli::Cname => RecordType::CNAME,
            RecordTypeCli::Mx => RecordType::MX,
            RecordTypeCli::Txt => RecordType::TXT,
        };
        let start = Instant::now();
        let status =
            match tokio::time::timeout(self.timeout, self.resolver.lookup(domain, target_type))
                .await
            {
                Ok(Ok(lookup)) => {
                    let records: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                    if records.is_empty() {
                        DnsStatus::NotFound {
                            latency: start.elapsed(),
                        }
                    } else {
                        DnsStatus::Success {
                            records,
                            latency: start.elapsed(),
                        }
                    }
                }
                Ok(Err(err)) => {
                    // Detecção tipada via ResolveErrorKind, sem depender do
                    // texto do Display do erro.
                    if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                        DnsStatus::NotFound {
                            latency: start.elapsed(),
                        }
                    } else {
                        DnsStatus::Error {
                            message: err.to_string(),
                            latency: start.elapsed(),
                        }
                    }
                }
                Err(_) => DnsStatus::Error {
                    message: "DNS Lookup Timeout".to_string(),
                    latency: start.elapsed(),
                },
            };
        DnsQueryResult {
            domain: domain.to_string(),
            record_type,
            status,
        }
    }

    pub async fn run_continuous(
        self: Arc<Self>,
        domains: Vec<String>,
        record_type: RecordTypeCli,
        interval: Duration,
        tx: tokio::sync::mpsc::UnboundedSender<DnsQueryResult>,
    ) {
        loop {
            for domain in &domains {
                let result = self.resolve(domain, record_type).await;
                if tx.send(result).is_err() {
                    return;
                }
            }
            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_domain_is_state_not_panic() {
        let engine = DnsEngine::new(2000).expect("resolver");
        let res = engine
            .resolve("inexistente-test-12345.invalid", RecordTypeCli::A)
            .await;
        // NXDOMAIN ou erro de rede: ambos são estados válidos, nunca panic.
        match res.status {
            DnsStatus::NotFound { .. } | DnsStatus::Error { .. } => {}
            DnsStatus::Success { .. } => panic!("domínio .invalid não deveria resolver"),
        }
    }
}
