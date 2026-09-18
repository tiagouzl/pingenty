use crate::dns::DnsStatus;
use crate::tui::app::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
    Frame,
};

/// Desenha header, painéis (ping/DNS/tráfego) e rodapé. Nunca dá panic em
/// terminal pequeno: hosts além do espaço são cortados (primeiros N).
pub fn render(frame: &mut Frame, state: &mut AppState) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.size());

    let header_text = match state.capture.interface.as_deref() {
        Some(iface) => {
            format!(" Pingenty :: Monitor de Rede Assíncrono | Interface: [{iface}] | Tick: 250ms ")
        }
        None => " Pingenty :: Monitor de Rede Assíncrono | Ping + DNS ao vivo ".to_string(),
    };
    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, main_chunks[0]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[1]);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body_chunks[0]);

    render_ping_panel(frame, state, left_chunks[0]);
    render_dns_panel(frame, state, left_chunks[1]);
    render_watch_panel(frame, state, body_chunks[1]);

    let alerts = state.alert_count();
    let footer_text = if alerts > 0 {
        format!(" Pressione 'q' ou 'Ctrl+C' para sair | Métricas coletadas em tempo real | Alertas: {alerts} ")
    } else {
        " Pressione 'q' ou 'Ctrl+C' para sair | Métricas coletadas em tempo real ".to_string()
    };
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, main_chunks[2]);
}

fn render_ping_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(" Latência ICMP/TCP (Sparkline ms) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    frame.render_widget(block, area);

    // Só cria constraints para os hosts que cabem de verdade (3 linhas cada +
    // 2 da borda do bloco). O restante é cortado pelo guard do loop — sempre os
    // primeiros N, em vez do subconjunto espalhado que o cassowary escolheria
    // se todas as constraints passassem do espaço disponível.
    let visible = ((area.height as usize).saturating_sub(2) / 3).min(state.ping_trackers.len());
    let inner_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(3); visible])
        .margin(1)
        .split(area);

    for (idx, tracker) in state.ping_trackers.iter().enumerate() {
        if idx >= inner_layout.len() {
            break;
        }
        let loss = tracker.loss_pct();
        let rtt_str = tracker
            .last_rtt
            .map_or("TIMEOUT".into(), |v| format!("{v} ms"));
        let mut label = format!(
            "{} => Atual: {} | Perda: {:.1}%",
            tracker.host, rtt_str, loss
        );
        let label_style = if tracker.alerting {
            label.push_str(" [ALERTA]");
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };
        let sub_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(inner_layout[idx]);
        frame.render_widget(Paragraph::new(label).style(label_style), sub_chunks[0]);
        let spark_data: Vec<u64> = tracker.history.iter().copied().collect();
        frame.render_widget(
            Sparkline::default()
                .data(&spark_data)
                .style(Style::default().fg(Color::Green))
                .bar_set(symbols::bar::NINE_LEVELS),
            sub_chunks[1],
        );
    }
}

fn render_dns_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .dns_results
        .iter()
        .rev()
        .take(10)
        .map(|res| {
            let (status_str, color) = match &res.status {
                DnsStatus::Success { latency, .. } => {
                    (format!("OK ({:.1?})", latency), Color::Green)
                }
                DnsStatus::NotFound { latency } => {
                    (format!("NXDOMAIN ({:.1?})", latency), Color::Yellow)
                }
                DnsStatus::Error { latency, .. } => (format!("ERRO ({:.1?})", latency), Color::Red),
            };
            Row::new(vec![
                Cell::from(res.domain.clone()),
                Cell::from(format!("{:?}", res.record_type)),
                Cell::from(status_str).style(Style::default().fg(color)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(50),
            Constraint::Percentage(20),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(vec!["Domínio", "Tipo", "Status / RTT"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" Monitor DNS ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    frame.render_widget(table, area);
}

fn render_watch_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(5)])
        .split(area);

    // try_read (não bloqueante): se a thread de captura estiver escrevendo,
    // pula um tick em vez de travar o executor async. Contadores atômicos
    // sempre lidos sem lock.
    let p = state.watcher_metrics.global_protocols.snapshot();
    let mut proto_summary = format!(
        "TCP: {} pkts ({} KB) | UDP: {} pkts ({} KB) | ICMP: {} pkts ({} KB) | OUTR: {} pkts ({} KB)",
        p.tcp_packets,
        p.tcp_bytes / 1024,
        p.udp_packets,
        p.udp_bytes / 1024,
        p.icmp_packets,
        p.icmp_bytes / 1024,
        p.other_packets,
        p.other_bytes / 1024
    );
    if let Some(warning) = state.capture.warning.as_deref() {
        proto_summary = format!("{proto_summary}\n[AVISO] {warning}");
    }
    frame.render_widget(
        Paragraph::new(proto_summary)
            .style(Style::default().fg(Color::Magenta))
            .block(
                Block::default()
                    .title(" Protocolos Agregados ")
                    .borders(Borders::ALL),
            ),
        chunks[0],
    );

    let rows: Vec<Row> = match state.watcher_metrics.flows.try_read() {
        Ok(flows) => {
            let mut top: Vec<_> = flows.iter().collect();
            top.sort_by_key(|a| std::cmp::Reverse(a.1.byte_count));
            top.into_iter()
                .take(15)
                .map(|(tuple, flow)| {
                    Row::new(vec![
                        Cell::from(tuple.protocol),
                        Cell::from(format!("{}:{}", tuple.src_ip, tuple.src_port)),
                        Cell::from(format!("{}:{}", tuple.dst_ip, tuple.dst_port)),
                        Cell::from(format!("{}", flow.packet_count)),
                        Cell::from(format!("{:.2} KB", flow.byte_count as f64 / 1024.0)),
                    ])
                })
                .collect()
        }
        Err(_) => vec![],
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Length(8),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Proto", "Origem", "Destino", "Pkts", "Volume"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" Fluxos Ativos (5-Tuple) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    frame.render_widget(table, chunks[1]);
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RecordTypeCli;
    use crate::dns::{DnsQueryResult, DnsStatus};
    use crate::ping::PingSample;
    use crate::watch::{CaptureStatus, FiveTuple, FlowStat, TrafficMetrics};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Renderiza num backend de teste e devolve o conteúdo linha a linha.
    /// `Buffer::content` é público e as chunks de `width` são exatamente as
    /// linhas da tela — evita depender de igualdade byte a byte do buffer.
    fn render_lines(state: &mut AppState, width: u16, height: u16) -> Vec<String> {
        let mut terminal =
            Terminal::new(TestBackend::new(width, height)).expect("terminal de teste");
        terminal.draw(|f| render(f, state)).expect("draw");
        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        buffer
            .content
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect())
            .collect()
    }

    fn screen_text(state: &mut AppState, width: u16, height: u16) -> String {
        render_lines(state, width, height).join("\n")
    }

    fn state_with_hosts(hosts: &[&str]) -> AppState {
        AppState::new(
            hosts.iter().map(|h| h.to_string()).collect(),
            Arc::new(TrafficMetrics::default()),
            CaptureStatus::active("eth-test".into()),
        )
    }

    fn sample(host: &str, rtt_ms: Option<u64>) -> PingSample {
        PingSample {
            host: host.to_string(),
            rtt: rtt_ms.map(Duration::from_millis),
            is_fallback: rtt_ms.is_none(),
            error: rtt_ms.is_none().then(|| "timeout".to_string()),
        }
    }

    fn dns_result(domain: &str, status: DnsStatus) -> DnsQueryResult {
        DnsQueryResult {
            domain: domain.to_string(),
            record_type: RecordTypeCli::A,
            status,
        }
    }

    #[test]
    fn header_e_footer_mostram_contexto() {
        let mut state = state_with_hosts(&["1.1.1.1"]);
        let text = screen_text(&mut state, 100, 30);
        assert!(text.contains("Pingenty"));
        assert!(text.contains("Interface: [eth-test]"));
        assert!(text.contains("Pressione 'q'"));
    }

    #[test]
    fn painel_ping_mostra_rtt_perda_e_timeout() {
        let mut state = state_with_hosts(&["host-a", "host-b"]);
        state.on_ping_sample(sample("host-a", Some(42)));
        state.on_ping_sample(sample("host-b", None));
        let text = screen_text(&mut state, 100, 30);
        assert!(text.contains("Latência ICMP/TCP"));
        assert!(text.contains("host-a => Atual: 42 ms | Perda: 0.0%"));
        assert!(text.contains("host-b => Atual: TIMEOUT | Perda: 100.0%"));
    }

    #[test]
    fn painel_ping_marca_host_em_alerta_e_conta_no_rodape() {
        let mut state = state_with_hosts(&["host-a", "host-b"]);
        state.set_alert_thresholds(10.0, 200);
        state.on_ping_sample(sample("host-a", None));
        state.on_ping_sample(sample("host-b", Some(42)));
        let text = screen_text(&mut state, 150, 30);
        assert!(text.contains("host-a => Atual: TIMEOUT | Perda: 100.0% [ALERTA]"));
        assert!(!text.contains("host-b => Atual: 42 ms | Perda: 0.0% [ALERTA]"));
        assert!(text.contains("Alertas: 1"));
    }

    #[test]
    fn painel_dns_mostra_ok_nxdomain_e_erro() {
        let mut state = state_with_hosts(&["1.1.1.1"]);
        state.on_dns_result(dns_result(
            "ok.example",
            DnsStatus::Success {
                records: vec!["1.2.3.4".into()],
                latency: Duration::from_millis(12),
            },
        ));
        state.on_dns_result(dns_result(
            "nx.example",
            DnsStatus::NotFound {
                latency: Duration::from_millis(3),
            },
        ));
        state.on_dns_result(dns_result(
            "err.example",
            DnsStatus::Error {
                message: "sem rota".into(),
                latency: Duration::from_millis(500),
            },
        ));
        let text = screen_text(&mut state, 120, 30);
        assert!(text.contains("Monitor DNS"));
        assert!(text.contains("ok.example"));
        assert!(text.contains("OK (12.0ms)"));
        assert!(text.contains("nx.example"));
        assert!(text.contains("NXDOMAIN (3.0ms)"));
        assert!(text.contains("err.example"));
        assert!(text.contains("ERRO (500.0ms)"));
    }

    #[test]
    fn painel_watch_mostra_protocolos_e_fluxos() {
        // Métricas montadas direto: o painel só lê contadores atômicos e o mapa
        // de 5-tuples, então não depende do caminho de captura.
        let metrics = Arc::new(TrafficMetrics::default());
        metrics
            .global_protocols
            .tcp_packets
            .store(1, Ordering::Relaxed);
        metrics
            .global_protocols
            .tcp_bytes
            .store(2048, Ordering::Relaxed);
        metrics.flows.write().expect("write").insert(
            FiveTuple {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 0,
                dst_port: 0,
                protocol: "TCP",
            },
            FlowStat {
                packet_count: 1,
                byte_count: 2048,
                last_seen: Some(Instant::now()),
            },
        );
        let mut state = AppState::new(
            vec!["1.1.1.1".into()],
            metrics,
            CaptureStatus::active("eth-test".into()),
        );
        let text = screen_text(&mut state, 200, 30);
        assert!(text.contains("Protocolos Agregados"));
        assert!(text.contains("TCP: 1 pkts (2 KB)"));
        assert!(text.contains("Fluxos Ativos (5-Tuple)"));
        assert!(text.contains("10.0.0.1:0"));
        assert!(text.contains("10.0.0.2:0"));
        assert!(text.contains("2.00 KB"));
    }

    #[test]
    fn mais_hosts_que_espaco_nao_causa_panic() {
        // 30 hosts: em terminal pequeno o guard de layout precisa cortar em vez
        // de estourar o índice das constraints.
        let hosts: Vec<String> = (0..30).map(|i| format!("h{i}")).collect();
        let mut state = AppState::new(
            hosts,
            Arc::new(TrafficMetrics::default()),
            CaptureStatus::active("eth-test".into()),
        );

        let apertado = render_lines(&mut state, 80, 12);
        assert_eq!(apertado.len(), 12, "buffer deve ter a altura da tela");
        assert!(apertado.join("\n").contains("Latência ICMP/TCP"));

        let folgado = render_lines(&mut state, 80, 24);
        let texto = folgado.join("\n");
        let desenhados = texto.matches("=> Atual:").count();
        // Espaço para 7 linhas úteis => cabem pelo menos 2 hosts inteiros.
        assert!(
            (2..30).contains(&desenhados),
            "mostra os primeiros que cabem e corta o resto (desenhados: {desenhados})"
        );
        assert!(texto.contains("h0 => Atual: TIMEOUT"));
        assert!(texto.contains("h1 => Atual: TIMEOUT"));
        assert!(!texto.contains("h29 => Atual"));
    }

    #[test]
    fn lock_de_fluxos_ocupado_nao_trava_renderizacao() {
        // A thread de captura escrevendo (write lock preso) não pode travar o
        // draw: a tabela é pulada e o resto do painel continua desenhado.
        let metrics = Arc::new(TrafficMetrics::default());
        let guard = metrics.flows.write().expect("write lock");
        let mut state = AppState::new(
            vec!["1.1.1.1".into()],
            Arc::clone(&metrics),
            CaptureStatus::active("eth-test".into()),
        );
        let text = screen_text(&mut state, 100, 30);
        assert!(text.contains("Fluxos Ativos (5-Tuple)"));
        assert!(text.contains("Pingenty"));
        drop(guard);
    }

    #[test]
    fn header_mostra_aviso_quando_captura_desligada() {
        let mut state = AppState::new(
            vec!["1.1.1.1".into()],
            Arc::new(TrafficMetrics::default()),
            CaptureStatus::disabled("sem captura: teste"),
        );
        let text = screen_text(&mut state, 120, 30);
        assert!(text.contains("Ping + DNS ao vivo"));
        assert!(!text.contains("Interface: ["));
        assert!(text.contains("[AVISO] sem captura: teste"));
    }
}
