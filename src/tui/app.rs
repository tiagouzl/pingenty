use crate::dns::DnsQueryResult;
use crate::ping::PingSample;
use crate::watch::{CaptureStatus, TrafficMetrics};
use std::collections::VecDeque;
use std::sync::Arc;

/// Série de um host no painel de ping: sparkline + contadores de perda.
pub struct PingHistory {
    /// Host monitorado.
    pub host: String,
    /// Últimas 40 amostras em ms (`0` = timeout; alimenta o sparkline).
    pub history: VecDeque<u64>,
    /// Último RTT (`None` = timeout).
    pub last_rtt: Option<u64>,
    /// Amostras enviadas.
    pub transmitted: u64,
    /// Respostas recebidas.
    pub received: u64,
    /// `true` enquanto os limiares de alerta estouram.
    pub alerting: bool,
}

impl PingHistory {
    /// Perda em % sobre as amostras deste host.
    pub fn loss_pct(&self) -> f64 {
        if self.transmitted == 0 {
            0.0
        } else {
            ((self.transmitted - self.received) as f64 / self.transmitted as f64) * 100.0
        }
    }

    /// Média só sobre amostras recebidas (0 = timeout, excluído).
    pub fn avg_rtt_ms(&self) -> Option<u64> {
        let (sum, n) = self
            .history
            .iter()
            .filter(|&&v| v > 0)
            .fold((0u64, 0u64), |(s, n), &v| (s + v, n + 1));
        (n > 0).then(|| sum / n)
    }
}

/// Transição de alerta de um host (só na entrada/saída, nunca por tick).
pub struct AlertEvent {
    /// Host que mudou de estado.
    pub host: String,
    /// `true` = entrou em alerta; `false` = voltou ao normal.
    pub entered: bool,
}

/// Estado mutável do dashboard: trackers de ping, últimos DNS, métricas da
/// captura e limiares de alerta.
pub struct AppState {
    /// Um tracker por host do dashboard.
    pub ping_trackers: Vec<PingHistory>,
    /// Últimos 20 resultados DNS.
    pub dns_results: VecDeque<DnsQueryResult>,
    /// Métricas da captura (escritas pela thread, lidas sem lock).
    pub watcher_metrics: Arc<TrafficMetrics>,
    /// Status da captura (ativa ou motivo do downgrade).
    pub capture: CaptureStatus,
    alert_loss_pct: f64,
    alert_rtt_ms: u64,
}

impl AppState {
    /// Trackers zerados para cada host (sparkline começa em 40 zeros).
    pub fn new(hosts: Vec<String>, metrics: Arc<TrafficMetrics>, capture: CaptureStatus) -> Self {
        let ping_trackers = hosts
            .into_iter()
            .map(|host| PingHistory {
                host,
                history: VecDeque::from(vec![0; 40]),
                last_rtt: None,
                transmitted: 0,
                received: 0,
                alerting: false,
            })
            .collect();
        Self {
            ping_trackers,
            dns_results: VecDeque::with_capacity(50),
            watcher_metrics: metrics,
            capture,
            alert_loss_pct: 0.0,
            alert_rtt_ms: 0,
        }
    }

    /// Limiares de alerta (`0` desliga cada um). Chamado uma vez pelo `main`.
    pub fn set_alert_thresholds(&mut self, loss_pct: f64, rtt_ms: u64) {
        self.alert_loss_pct = loss_pct;
        self.alert_rtt_ms = rtt_ms;
    }

    /// Hosts atualmente em alerta.
    pub fn alert_count(&self) -> usize {
        self.ping_trackers.iter().filter(|p| p.alerting).count()
    }

    /// Devolve evento só quando o host entra/sai de alerta.
    pub fn on_ping_sample(&mut self, sample: PingSample) -> Option<AlertEvent> {
        let target = self
            .ping_trackers
            .iter_mut()
            .find(|p| p.host == sample.host)?;
        target.transmitted += 1;
        let ms = sample.rtt.map_or(0, |d| d.as_millis() as u64);
        target.last_rtt = sample.rtt.map(|_| ms);
        if sample.rtt.is_some() {
            target.received += 1;
        }
        if target.history.len() >= 40 {
            target.history.pop_front();
        }
        target.history.push_back(ms);

        // Epsilon: perda exata no limiar (ex. 10,0% vs 10,0) não é excedente —
        // sem isso, 1/10 vira 10.000000000000002 e nunca sai do alerta.
        let alert = target.transmitted > 0
            && ((self.alert_loss_pct > 0.0 && target.loss_pct() - self.alert_loss_pct > 1e-9)
                || (self.alert_rtt_ms > 0
                    && target.avg_rtt_ms().is_some_and(|a| a > self.alert_rtt_ms)));
        if alert == target.alerting {
            return None;
        }
        target.alerting = alert;
        Some(AlertEvent {
            host: target.host.clone(),
            entered: alert,
        })
    }

    /// Guarda resultado DNS (máx. 20, descarta o mais antigo).
    pub fn on_dns_result(&mut self, result: DnsQueryResult) {
        if self.dns_results.len() >= 20 {
            self.dns_results.pop_front();
        }
        self.dns_results.push_back(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_history_tracks_loss() {
        let m = Arc::new(TrafficMetrics::default());
        let mut app = AppState::new(vec!["h".into()], m, CaptureStatus::active("eth0".into()));
        app.on_ping_sample(PingSample {
            host: "h".into(),
            rtt: None,
            is_fallback: true,
            error: Some("timeout".into()),
        });
        assert_eq!(app.ping_trackers[0].transmitted, 1);
        assert_eq!(app.ping_trackers[0].received, 0);
    }

    fn sample(host: &str, rtt_ms: Option<u64>) -> PingSample {
        PingSample {
            host: host.into(),
            rtt: rtt_ms.map(std::time::Duration::from_millis),
            is_fallback: rtt_ms.is_none(),
            error: rtt_ms.is_none().then(|| "timeout".into()),
        }
    }

    #[test]
    fn alerta_de_perda_dispara_na_transicao_e_silencia_fora_dela() {
        let m = Arc::new(TrafficMetrics::default());
        let mut app = AppState::new(vec!["h".into()], m, CaptureStatus::active("eth0".into()));
        app.set_alert_thresholds(10.0, 0);
        // 100% de perda > 10% → entra (1 evento).
        let ev = app.on_ping_sample(sample("h", None)).expect("entrada");
        assert!(ev.entered);
        assert_eq!(app.alert_count(), 1);
        // Segue em alerta: sem evento.
        assert!(app.on_ping_sample(sample("h", None)).is_none());
        // 2 perdas em 19 tx = 10,5% → ainda em alerta, sem evento.
        for _ in 0..17 {
            assert!(app.on_ping_sample(sample("h", Some(50))).is_none());
        }
        // 18º ok: 2 perdas em 20 tx = 10,0% (não excede) → sai (1 evento).
        let ev = app.on_ping_sample(sample("h", Some(50))).expect("saída");
        assert!(!ev.entered);
        assert_eq!(app.alert_count(), 0);
    }

    #[test]
    fn alerta_de_rtt_usa_media_dos_recebidos() {
        let m = Arc::new(TrafficMetrics::default());
        let mut app = AppState::new(vec!["h".into()], m, CaptureStatus::active("eth0".into()));
        app.set_alert_thresholds(100.0, 200);
        assert!(app.on_ping_sample(sample("h", Some(50))).is_none());
        let ev = app.on_ping_sample(sample("h", Some(400))).expect("entrada");
        assert!(ev.entered);
        // Timeout (0 ms) não entra na média: (50+400)/2 = 225 > 200, segue.
        assert!(app.on_ping_sample(sample("h", None)).is_none());
    }

    #[test]
    fn sem_limiares_nao_ha_alerta() {
        let m = Arc::new(TrafficMetrics::default());
        let mut app = AppState::new(vec!["h".into()], m, CaptureStatus::active("eth0".into()));
        for _ in 0..5 {
            assert!(app.on_ping_sample(sample("h", None)).is_none());
        }
        assert_eq!(app.alert_count(), 0);
    }
}
