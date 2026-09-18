use crate::cli::RecordTypeCli;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::proto::op::ResponseCode;
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

/// NXDOMAIN = o domínio não existe (NotFound). NODATA — resposta `NoError` sem
/// registros do tipo pedido — é outra coisa e não deve ser reportada como
/// domínio inexistente. Detecção tipada, sem depender do texto do Display.
fn is_nxdomain(err: &ResolveError) -> bool {
    matches!(
        err.kind(),
        ResolveErrorKind::NoRecordsFound {
            response_code: ResponseCode::NXDomain,
            ..
        }
    )
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
                    // NXDOMAIN vira NotFound; NODATA (domínio existe, sem esse
                    // registro) é falha de classificação diferente.
                    if is_nxdomain(&err) {
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

    #[test]
    fn nxdomain_e_nodata_nao_sao_a_mesma_coisa() {
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::Name;

        let erro = |code: ResponseCode| {
            ResolveError::from(ResolveErrorKind::NoRecordsFound {
                query: Box::new(Query::query(
                    Name::from_ascii("exemplo.test.").expect("nome válido"),
                    RecordType::A,
                )),
                soa: None,
                negative_ttl: None,
                response_code: code,
                trusted: true,
            })
        };

        // O domínio não existe.
        assert!(is_nxdomain(&erro(ResponseCode::NXDomain)));
        // O domínio existe, mas não há registro desse tipo (NODATA).
        assert!(!is_nxdomain(&erro(ResponseCode::NoError)));
        // Falha do servidor não é domínio inexistente.
        assert!(!is_nxdomain(&erro(ResponseCode::ServFail)));
    }
}
