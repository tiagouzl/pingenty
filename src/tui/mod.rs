/// Estado mutável do dashboard (trackers, DNS, métricas, alertas).
pub mod app;
/// Renderização do dashboard (ratatui).
pub mod ui;

use app::AppState;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;

/// Runner da TUI: drena os canais, desenha a 250 ms e sai em `q`/Ctrl+C.
pub struct TuiRunner;

impl TuiRunner {
    /// Roda o dashboard até o usuário sair. Alertas de ping vão para stderr.
    pub async fn run(
        mut state: AppState,
        mut ping_rx: tokio::sync::mpsc::UnboundedReceiver<crate::ping::PingSample>,
        mut dns_rx: tokio::sync::mpsc::UnboundedReceiver<crate::dns::DnsQueryResult>,
    ) -> Result<(), anyhow::Error> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let tick_rate = Duration::from_millis(250);

        loop {
            while let Ok(sample) = ping_rx.try_recv() {
                if let Some(ev) = state.on_ping_sample(sample) {
                    eprintln!(
                        ">> ALERTA {}: {}",
                        if ev.entered { "início" } else { "fim" },
                        ev.host
                    );
                }
            }
            while let Ok(sample) = dns_rx.try_recv() {
                state.on_dns_result(sample);
            }

            terminal.draw(|f| ui::render(f, &mut state))?;

            if event::poll(tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q')
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL))
                    {
                        break;
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }
}
