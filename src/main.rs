use clap::Parser;
use pingenty::cli::{self, Cli, Commands};
use pingenty::dns::{self, DnsEngine};
use pingenty::ping::PingEngine;
use pingenty::tui;
use pingenty::watch::PacketWatcher;
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
            let (watcher, iface) = PacketWatcher::new(interface)?;
            println!(
                ">> Capturando tráfego na interface: [{}]",
                watcher.interface_name
            );
            println!(
                ">> Dica: compare com: tcpdump -i {} -q -n",
                watcher.interface_name
            );

            PacketWatcher::start_capture_thread(iface, Arc::clone(&watcher.metrics))?;

            let mut timer = tokio::time::interval(Duration::from_millis(interval));
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        let p = watcher.metrics.global_protocols.snapshot();
                        let flow_count = watcher.metrics.flows.read().map(|f| f.len()).unwrap_or(0);
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

            let ping_engine = Arc::new(PingEngine::new(ping_interval, ping_timeout, tcp_port));
            for h in p_hosts.clone() {
                let eng = Arc::clone(&ping_engine);
                let tx = ping_tx.clone();
                tokio::spawn(async move {
                    eng.run_continuous(h, move |sample, _| {
                        let _ = tx.send(sample);
                    })
                    .await;
                });
            }

            let dns_engine = Arc::new(DnsEngine::new(dns_timeout)?);
            tokio::spawn(async move {
                dns_engine
                    .run_continuous(
                        d_domains,
                        cli::RecordTypeCli::A,
                        Duration::from_millis(dns_interval),
                        dns_tx,
                    )
                    .await;
            });

            let mut state = tui::app::AppState::new(p_hosts, metrics, capture);
            state.set_alert_thresholds(alert_loss, alert_rtt);
            tui::TuiRunner::run(state, ping_rx, dns_rx).await?;
        }
    }

    Ok(())
}
