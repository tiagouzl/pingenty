use crate::dns::DnsStatus;
use crate::tui::app::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
    Frame,
};

pub fn render(frame: &mut Frame, state: &mut AppState) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.size());

    let header_text = format!(
        " NETMON :: Monitor de Rede Assíncrono | Interface: [{}] | Tick: 250ms ",
        state.interface_name
    );
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

    let footer =
        Paragraph::new(" Pressione 'q' ou 'Ctrl+C' para sair | Métricas coletadas em tempo real ")
            .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, main_chunks[2]);
}

fn render_ping_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    let block = Block::default()
        .title(" Latência ICMP/TCP (Sparkline ms) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    frame.render_widget(block, area);

    let inner_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            state
                .ping_trackers
                .iter()
                .map(|_| Constraint::Length(3))
                .collect::<Vec<_>>(),
        )
        .margin(1)
        .split(area);

    for (idx, tracker) in state.ping_trackers.iter().enumerate() {
        if idx >= inner_layout.len() {
            break;
        }
        let loss = if tracker.transmitted == 0 {
            0.0
        } else {
            ((tracker.transmitted - tracker.received) as f64 / tracker.transmitted as f64) * 100.0
        };
        let label = format!(
            "{} => Atual: {} ms | Perda: {:.1}%",
            tracker.host,
            tracker.last_rtt.map_or("TIMEOUT".into(), |v| v.to_string()),
            loss
        );
        let sub_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(inner_layout[idx]);
        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(Color::Yellow)),
            sub_chunks[0],
        );
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
    let proto_summary = format!(
        "TCP: {} pkts ({} KB) | UDP: {} pkts ({} KB) | ICMP: {} pkts ({} KB)",
        p.tcp_packets,
        p.tcp_bytes / 1024,
        p.udp_packets,
        p.udp_bytes / 1024,
        p.icmp_packets,
        p.icmp_bytes / 1024
    );
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
