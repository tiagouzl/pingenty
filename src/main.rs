use clap::Parser;
use pingenty::cli::{self, Cli, Commands};
use pingenty::dns::{self, DnsEngine};
use pingenty::ping::PingEngine;
use pingenty::tui;
use pingenty::watch::{self, PacketWatcher};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ping {
            hosts,
            interval,
            timeout,
            tcp_port,
        } => {
            println!(
                ">> Iniciando medição de latência em {} host(s)...",
                hosts.len()
            );
            let engine = Arc::new(PingEngine::new(interval, timeout, tcp_port));
            let mut join_set = JoinSet::new();

            for host in hosts {
                let eng = Arc::clone(&engine);
                join_set.spawn(async move {
                    eng.run_continuous(host, |sample, stats| {
                        let rtt_str = sample.rtt.map_or_else(
                            || sample.error.clone().unwrap_or_else(|| "TIMEOUT".into()),
                            |d| format!("{:.2?}", d),
                        );
                        let mode = if sample.is_fallback {
                            " [TCP-Fallback]"
                        } else {
                            " [ICMP]"
                        };
                        println!(
                            "Host: {:<15} | RTT: {:<10} | Perda: {:<5.1}% | Min: {:?} | Avg: {:?} | Max: {:?}{}",
                            sample.host,
                            rtt_str,
                            stats.loss_rate(),
                            stats.min_rtt.unwrap_or_default(),
                            stats.avg_rtt().unwrap_or_default(),
                            stats.max_rtt.unwrap_or_default(),
                            mode
                        );
                    })
                    .await;
                });
            }

            tokio::select! {
                _ = join_set.join_next() => {},
                _ = signal::ctrl_c() => println!("\n>> Finalizado pelo usuário."),
            }
        }

        Commands::Dns {
            domains,
            record_type,
            timeout,
        } => {
            let engine = Arc::new(DnsEngine::new(timeout)?);
            let (tx, mut rx) = mpsc::unbounded_channel();

            println!(
                ">> Resolvendo domínios com Hickory-DNS (Record: {:?})...",
                record_type
            );

            let eng = Arc::clone(&engine);
            tokio::spawn(async move {
                eng.run_continuous(domains, record_type, Duration::from_secs(2), tx)
                    .await;
            });

            loop {
                tokio::select! {
                    Some(res) = rx.recv() => {
                        match res.status {
                            dns::DnsStatus::Success { records, latency } => {
                                println!("[OK] Domínio: {} | Latência: {:.2?} | Registros: {:?}", res.domain, latency, records);
                            }
                            dns::DnsStatus::NotFound { latency } => {
                                println!("[NXDOMAIN] Domínio inexistente: {} | Latência: {:.2?}", res.domain, latency);
                            }
                            dns::DnsStatus::Error { message, latency } => {
                                println!("[FALHA] Domínio: {} | Latência: {:.2?} | Causa: {}", res.domain, latency, message);
                            }
                        }
                    }
                    _ = signal::ctrl_c() => {
                        println!("\n>> DNS Monitor encerrado.");
                        break;
                    }
                }
            }
        }

        Commands::Watch {
            interface,
            interval,
        } => {
            // Uma thread de captura por interface; erro numa não aborta as
            // outras (aviso no stderr, segue com as válidas).
            let specs = pingenty::watch::split_interface_spec(interface.as_deref());
            let attempts: Vec<Option<String>> = if specs.is_empty() {
                vec![None]
            } else {
                specs.into_iter().map(Some).collect()
            };
            let mut watchers = Vec::new();
            for attempt in attempts {
                let label = attempt.clone().unwrap_or_else(|| "<padrão>".into());
                match PacketWatcher::new(attempt) {
                    Ok((watcher, iface)) => {
                        match PacketWatcher::start_capture_thread(
                            iface,
                            Arc::clone(&watcher.metrics),
                        ) {
                            Ok(()) => {
                                println!(
                                    ">> Capturando tráfego na interface: [{}]",
                                    watcher.interface_name
                                );
                                watchers.push(watcher);
                            }
                            Err(e) => eprintln!(">> Ignorando '{label}': {e}"),
                        }
                    }
                    Err(e) => eprintln!(">> Ignorando '{label}': {e}"),
                }
            }
            if watchers.is_empty() {
                return Err(anyhow::anyhow!("nenhuma interface pôde ser capturada"));
            }
            println!(">> Dica: compare com: tcpdump -i <iface> -q -n");

            let all: Vec<Arc<watch::TrafficMetrics>> =
                watchers.iter().map(|w| Arc::clone(&w.metrics)).collect();
            let mut timer = tokio::time::interval(Duration::from_millis(interval));
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        let p = watch::TrafficMetrics::sum_snapshots(&all);
                        let flow_count = watch::TrafficMetrics::merge_flows(&all).len();
                        println!("--- [Métricas] Fluxos ativos: {flow_count} ---");
                        println!("TCP : {:<8} pacotes | {:<10} bytes", p.tcp_packets, p.tcp_bytes);
                        println!("UDP : {:<8} pacotes | {:<10} bytes", p.udp_packets, p.udp_bytes);
                        println!("ICMP: {:<8} pacotes | {:<10} bytes", p.icmp_packets, p.icmp_bytes);
                        println!("OUTR: {:<8} pacotes | {:<10} bytes\n", p.other_packets, p.other_bytes);
                    }
                    _ = signal::ctrl_c() => {
                        println!("\n>> Captura finalizada.");
                        break;
                    }
                }
            }
        }

        Commands::Dashboard {
            ping_hosts,
            dns_domains,
            interface,
            ping_interval,
            ping_timeout,
            dns_timeout,
            dns_interval,
            tcp_port,
            alert_loss,
            alert_rtt,
            export_csv,
            export_json,
            no_history,
        } => {
            let p_hosts: Vec<String> = ping_hosts
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let d_domains: Vec<String> = dns_domains
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            // Captura não é pré-requisito: sem permissão/interface, ping e DNS
            // seguem ao vivo e o painel de tráfego mostra o motivo.
            let (metrics, capture) = pingenty::watch::setup_capture(interface);
            eprintln!(">> Dashboard: ping + DNS ao vivo.");
            if let Some(w) = capture.warning.as_deref() {
                eprintln!(">> {w}");
            }

            // Canais unbounded: o callback síncrono do ping não pode aguardar
            // envio (não é async), então try_send em canal limitado descartaria
            // amostras sob carga — corrompendo a taxa de perda exibida. A TUI
            // drena os canais a cada tick (try_recv), então não há acumulação.
            let (ping_tx, ping_rx) = mpsc::unbounded_channel();
            let (dns_tx, dns_rx) = mpsc::unbounded_channel();

            // Export compartilha um writer via Mutex: o callback do ping é
            // síncrono e o DNS passa por task de repasse — lock curto, sem await.
            let exporter = std::sync::Arc::new(std::sync::Mutex::new(
                pingenty::export::Exporter::new(export_csv.as_deref(), export_json.as_deref())?,
            ));
            if !no_history {
                if let Ok(mut e) = exporter.lock() {
                    e.enable_history();
                }
            }
            let ping_engine = Arc::new(PingEngine::new(ping_interval, ping_timeout, tcp_port));
            for h in p_hosts.clone() {
                let eng = Arc::clone(&ping_engine);
                let tx = ping_tx.clone();
                let exp = std::sync::Arc::clone(&exporter);
                tokio::spawn(async move {
                    eng.run_continuous(h, move |sample, stats| {
                        if let Ok(mut e) = exp.lock() {
                            e.ping(&sample, stats.loss_rate());
                        }
                        let _ = tx.send(sample);
                    })
                    .await;
                });
            }

            let dns_engine = Arc::new(DnsEngine::new(dns_timeout)?);
            let (dns_in_tx, mut dns_in_rx) = mpsc::unbounded_channel();
            let exp = std::sync::Arc::clone(&exporter);
            tokio::spawn(async move {
                while let Some(res) = dns_in_rx.recv().await {
                    if let Ok(mut e) = exp.lock() {
                        e.dns(&res);
                    }
                    if dns_tx.send(res).is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                dns_engine
                    .run_continuous(
                        d_domains,
                        cli::RecordTypeCli::A,
                        Duration::from_millis(dns_interval),
                        dns_in_tx,
                    )
                    .await;
            });

            let mut state = tui::app::AppState::new(p_hosts, metrics, capture);
            state.set_alert_thresholds(alert_loss, alert_rtt);
            tui::TuiRunner::run(state, ping_rx, dns_rx).await?;
        }

        Commands::Export { format, last, path } => {
            let hist = pingenty::export::history_path().ok_or_else(|| {
                anyhow::anyhow!("sem diretório de histórico (HOME/XDG_DATA_HOME ausentes)")
            })?;
            let fmt = match format {
                cli::ExportFormatCli::Csv => "csv",
                cli::ExportFormatCli::Json => "json",
            };
            let (out, skipped) = pingenty::export::export_history(&hist, fmt, last)?;
            match path {
                Some(p) => std::fs::write(&p, &out)?,
                None => print!("{out}"),
            }
            if skipped > 0 {
                eprintln!(
                    ">> {skipped} linha(s) malformadas ignoradas em {}",
                    hist.display()
                );
            }
        }
    }

    Ok(())
}
