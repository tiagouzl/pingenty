//! Export ao vivo do dashboard: CSV flat (ping) e NDJSON (ping + DNS).
//!
//! Os formatadores são puros (sem I/O) para teste byte-exato; o [`Exporter`]
//! só abre os arquivos em append e dá flush por amostra (volume baixo: ~1
//! linha/s por host, então corretude vence buffering).

use crate::dns::{DnsQueryResult, DnsStatus};
use crate::ping::PingSample;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Teto do histórico antes de rotacionar (10 MB, 1 backup).
// ponytail: rotação ingênua (1 backup fixo); log-rotate de verdade se virar produto.
const HISTORY_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Cabeçalho do CSV de ping.
pub const CSV_HEADER: &str = "timestamp,host,rtt_ms,loss_pct,modo";

/// Segundos Unix atuais (relógio de parede; `0` se indisponível).
pub fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Caminho do histórico (`XDG_DATA_HOME` ou `~/.local/share`); `None` sem HOME.
pub fn history_path() -> Option<PathBuf> {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .ok()?;
    Some(base.join("pingenty").join("history.jsonl"))
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
    history: Option<BufWriter<std::fs::File>>,
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
        Ok(Self {
            csv,
            json,
            history: None,
        })
    }

    /// Liga o histórico persistente (cria dirs, rotaciona acima do teto).
    /// Silencioso se sem HOME ou com erro: histórico nunca quebra o dashboard.
    pub fn enable_history(&mut self) {
        let Some(path) = history_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::metadata(&path)
            .map(|m| m.len() > HISTORY_MAX_BYTES)
            .unwrap_or(false)
        {
            let backup = path.with_extension("jsonl.1");
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::rename(&path, &backup);
        }
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(&path) {
            self.history = Some(BufWriter::new(f));
        }
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
        if let Some(f) = self.history.as_mut() {
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
        if let Some(f) = self.history.as_mut() {
            let _ = writeln!(f, "{}", ndjson_dns(unix_secs_now(), res));
            let _ = f.flush();
        }
    }
}

/// Extrai o valor bruto após `"key":` (número, `null` ou string com escapes).
fn raw_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = line[start..].trim_start();
    if rest.starts_with('"') {
        let b = rest.as_bytes();
        let mut end = 1;
        while end < b.len() {
            match b[end] {
                b'\\' => end += 2,
                b'"' => return Some(&rest[1..end]),
                _ => end += 1,
            }
        }
        None
    } else {
        let end = rest.find([',', '}'])?;
        Some(rest[..end].trim())
    }
}

/// Inverso de [`esc`] (só o que o writer produz).
fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some(x) => {
                out.push('\\');
                out.push(x);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Converte texto do histórico: `json` filtra por idade e repassa as linhas;
/// `csv` reconstrói ping-only com cabeçalho. Retorna (saída, linhas ignoradas
/// por malformação). `now` é parâmetro para teste determinístico.
pub fn convert_history(
    text: &str,
    format: &str,
    now: u64,
    last_secs: Option<u64>,
) -> (String, u64) {
    let cutoff = last_secs.map(|s| now.saturating_sub(s));
    let mut out = String::new();
    let mut skipped = 0u64;
    if format == "csv" {
        out.push_str(CSV_HEADER);
        out.push('\n');
    }
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (Some(t), Some(kind)) = (raw_field(line, "t"), raw_field(line, "kind")) else {
            skipped += 1;
            continue;
        };
        let Ok(t) = t.parse::<u64>() else {
            skipped += 1;
            continue;
        };
        if cutoff.is_some_and(|c| t < c) {
            continue;
        }
        if format != "csv" {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if kind != "ping" {
            continue;
        }
        let (Some(host), Some(rtt), Some(loss), Some(modo)) = (
            raw_field(line, "host"),
            raw_field(line, "rtt_ms"),
            raw_field(line, "loss_pct"),
            raw_field(line, "modo"),
        ) else {
            skipped += 1;
            continue;
        };
        let rtt = if rtt == "null" {
            String::new()
        } else {
            rtt.into()
        };
        out.push_str(&format!("{t},{},{rtt},{loss},{modo}\n", unesc(host)));
    }
    (out, skipped)
}

/// Lê o arquivo do histórico e converte (ver [`convert_history`]).
pub fn export_history(
    path: &std::path::Path,
    format: &str,
    last_secs: Option<u64>,
) -> std::io::Result<(String, u64)> {
    let text = std::fs::read_to_string(path)?;
    Ok(convert_history(&text, format, unix_secs_now(), last_secs))
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

    #[test]
    fn roundtrip_ndjson_para_csv_e_fiel() {
        // O conversor lê exatamente o que o writer produz.
        let line = ndjson_ping(1000, &ping("h", Some(Duration::from_millis(7)), false), 0.0);
        let text = format!("{line}\n");
        let (out, skipped) = convert_history(&text, "csv", 2000, None);
        assert_eq!(skipped, 0);
        assert_eq!(out, format!("{CSV_HEADER}\n1000,h,7.000,0.0,icmp\n"));
        // Ida e volta do escape: host com aspa sobrevive.
        let line = ndjson_ping(1000, &ping("h\"x", None, true), 100.0);
        let (out, _) = convert_history(&format!("{line}\n"), "csv", 2000, None);
        assert!(out.contains("1000,h\"x,,100.0,tcp"));
    }

    #[test]
    fn filtro_por_idade_e_malformados() {
        let ok = ndjson_ping(900, &ping("a", None, true), 100.0);
        let dns = ndjson_dns(
            950,
            &DnsQueryResult {
                domain: "d".into(),
                record_type: RecordTypeCli::A,
                status: DnsStatus::NotFound {
                    latency: Duration::from_millis(1),
                },
            },
        );
        let text = format!("{ok}\n{dns}\nvelho demais\n{{\"t\":1}}\n");
        // now=1000, last=200 → corta t=1, mantém 900/950; 2 malformadas.
        let (out, skipped) = convert_history(&text, "json", 1000, Some(200));
        assert_eq!(skipped, 2);
        assert_eq!(out.lines().count(), 2);
        // CSV pula DNS e mantém só ping.
        let (csv, _) = convert_history(&text, "csv", 1000, Some(200));
        assert_eq!(csv.lines().count(), 2); // cabeçalho + 1 ping
        assert!(csv.contains("900,a,,100.0,tcp"));
    }
}
