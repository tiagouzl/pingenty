//! Export ao vivo do dashboard: CSV flat (ping) e NDJSON (ping + DNS).
//!
//! Os formatadores são puros (sem I/O) para teste byte-exato; o [`Exporter`]
//! só abre os arquivos em append e dá flush por amostra (volume baixo: ~1
//! linha/s por host, então corretude vence buffering).

use crate::dns::{DnsQueryResult, DnsStatus};
use crate::ping::PingSample;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cabeçalho do CSV de ping.
pub const CSV_HEADER: &str = "timestamp,host,rtt_ms,loss_pct,modo";

/// Segundos Unix atuais (relógio de parede; `0` se indisponível).
pub fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rtt_ms(rtt: Option<Duration>) -> String {
    rtt.map_or_else(String::new, |d| format!("{:.3}", d.as_secs_f64() * 1000.0))
}

/// Escapa o mínimo para embutir string em JSON (sem serde de propósito:
/// só host/domínio passam por aqui).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn modo(fallback: bool) -> &'static str {
    if fallback {
        "tcp"
    } else {
        "icmp"
    }
}

/// Uma linha do CSV de ping (`rtt` vazio em timeout).
pub fn csv_row(t: u64, sample: &PingSample, loss_pct: f64) -> String {
    format!(
        "{t},{},{},{loss_pct:.1},{}",
        sample.host,
        rtt_ms(sample.rtt),
        modo(sample.is_fallback)
    )
}

/// Um evento de ping em NDJSON (`rtt_ms: null` em timeout).
pub fn ndjson_ping(t: u64, sample: &PingSample, loss_pct: f64) -> String {
    let rtt = sample.rtt.map_or("null".into(), |d| {
        format!("{:.3}", d.as_secs_f64() * 1000.0)
    });
    format!(
        "{{\"t\":{t},\"kind\":\"ping\",\"host\":\"{}\",\"rtt_ms\":{rtt},\"loss_pct\":{loss_pct:.1},\"modo\":\"{}\"}}",
        esc(&sample.host),
        modo(sample.is_fallback)
    )
}

/// Um resultado DNS em NDJSON (`status`: `ok`/`nxdomain`/`erro`).
pub fn ndjson_dns(t: u64, res: &DnsQueryResult) -> String {
    let (status, latency) = match &res.status {
        DnsStatus::Success { latency, .. } => ("ok", latency),
        DnsStatus::NotFound { latency } => ("nxdomain", latency),
        DnsStatus::Error { latency, .. } => ("erro", latency),
    };
    format!(
        "{{\"t\":{t},\"kind\":\"dns\",\"domain\":\"{}\",\"status\":\"{status}\",\"latency_ms\":{:.3}}}",
        esc(&res.domain),
        latency.as_secs_f64() * 1000.0
    )
}

/// Anexa amostras do dashboard em CSV e/ou NDJSON (flush por amostra).
pub struct Exporter {
    csv: Option<BufWriter<std::fs::File>>,
    json: Option<BufWriter<std::fs::File>>,
}

impl Exporter {
    /// Abre em append; cabeçalho CSV só se o arquivo estiver vazio/novo.
    pub fn new(csv_path: Option<&str>, json_path: Option<&str>) -> std::io::Result<Self> {
        let csv = csv_path
            .map(|p| {
                let fresh = std::fs::metadata(p).map(|m| m.len() == 0).unwrap_or(true);
                let mut f = BufWriter::new(OpenOptions::new().create(true).append(true).open(p)?);
                if fresh {
                    writeln!(f, "{CSV_HEADER}")?;
                }
                std::io::Result::Ok(f)
            })
            .transpose()?;
        let json = json_path
            .map(|p| {
                Ok::<_, std::io::Error>(BufWriter::new(
                    OpenOptions::new().create(true).append(true).open(p)?,
                ))
            })
            .transpose()?;
        Ok(Self { csv, json })
    }

    /// Registra uma amostra de ping nos arquivos configurados (ignora os
    /// ausentes). Erros de I/O são descartados: export nunca quebra o dashboard.
    pub fn ping(&mut self, sample: &PingSample, loss_pct: f64) {
        let t = unix_secs_now();
        if let Some(f) = self.csv.as_mut() {
            let _ = writeln!(f, "{}", csv_row(t, sample, loss_pct));
            let _ = f.flush();
        }
        if let Some(f) = self.json.as_mut() {
            let _ = writeln!(f, "{}", ndjson_ping(t, sample, loss_pct));
            let _ = f.flush();
        }
    }

    /// Registra um resultado DNS no NDJSON (CSV é só ping).
    pub fn dns(&mut self, res: &DnsQueryResult) {
        if let Some(f) = self.json.as_mut() {
            let _ = writeln!(f, "{}", ndjson_dns(unix_secs_now(), res));
            let _ = f.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RecordTypeCli;

    fn ping(host: &str, rtt: Option<Duration>, fallback: bool) -> PingSample {
        PingSample {
            host: host.into(),
            rtt,
            is_fallback: fallback,
            error: None,
        }
    }

    #[test]
    fn csv_tem_cabecalho_e_linha_parseavel() {
        assert_eq!(CSV_HEADER, "timestamp,host,rtt_ms,loss_pct,modo");
        let row = csv_row(
            1700000000,
            &ping("h", Some(Duration::from_micros(42500)), false),
            12.345,
        );
        assert_eq!(row, "1700000000,h,42.500,12.3,icmp");
        let timeout = csv_row(7, &ping("h", None, true), 100.0);
        assert_eq!(timeout, "7,h,,100.0,tcp");
    }

    #[test]
    fn ndjson_ping_marca_null_e_escapa_host() {
        let line = ndjson_ping(9, &ping("h\"x\\y", None, true), 100.0);
        assert_eq!(
            line,
            r#"{"t":9,"kind":"ping","host":"h\"x\\y","rtt_ms":null,"loss_pct":100.0,"modo":"tcp"}"#
        );
    }

    #[test]
    fn ndjson_dns_cobre_ok_nxdomain_erro() {
        let ok = DnsQueryResult {
            domain: "a.com".into(),
            record_type: RecordTypeCli::A,
            status: DnsStatus::Success {
                records: vec!["1.1.1.1".into()],
                latency: Duration::from_millis(12),
            },
        };
        assert_eq!(
            ndjson_dns(1, &ok),
            r#"{"t":1,"kind":"dns","domain":"a.com","status":"ok","latency_ms":12.000}"#
        );
        let nx = DnsQueryResult {
            domain: "nx".into(),
            record_type: RecordTypeCli::A,
            status: DnsStatus::NotFound {
                latency: Duration::from_millis(3),
            },
        };
        assert!(ndjson_dns(1, &nx).contains("\"status\":\"nxdomain\""));
        let err = DnsQueryResult {
            domain: "e".into(),
            record_type: RecordTypeCli::A,
            status: DnsStatus::Error {
                message: "x".into(),
                latency: Duration::from_millis(500),
            },
        };
        assert!(ndjson_dns(1, &err).contains("\"status\":\"erro\""));
    }
}
