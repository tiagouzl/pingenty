use crate::dns::DnsQueryResult;
use crate::ping::PingSample;
use crate::watch::TrafficMetrics;
use std::collections::VecDeque;
use std::sync::Arc;

pub struct PingHistory {
    pub host: String,
    pub history: VecDeque<u64>,
    pub last_rtt: Option<u64>,
    pub transmitted: u64,
    pub received: u64,
}

pub struct AppState {
    pub ping_trackers: Vec<PingHistory>,
    pub dns_results: VecDeque<DnsQueryResult>,
    pub watcher_metrics: Arc<TrafficMetrics>,
    pub interface_name: String,
}

impl AppState {
    pub fn new(hosts: Vec<String>, interface_name: String, metrics: Arc<TrafficMetrics>) -> Self {
        let ping_trackers = hosts
            .into_iter()
            .map(|host| PingHistory {
                host,
                history: VecDeque::from(vec![0; 40]),
                last_rtt: None,
                transmitted: 0,
                received: 0,
            })
            .collect();
        Self {
            ping_trackers,
            dns_results: VecDeque::with_capacity(50),
            watcher_metrics: metrics,
            interface_name,
        }
    }

    pub fn on_ping_sample(&mut self, sample: PingSample) {
        if let Some(target) = self
            .ping_trackers
            .iter_mut()
            .find(|p| p.host == sample.host)
        {
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
        }
    }

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
        let mut app = AppState::new(vec!["h".into()], "eth0".into(), m);
        app.on_ping_sample(PingSample {
            host: "h".into(),
            rtt: None,
            is_fallback: true,
            error: Some("timeout".into()),
        });
        assert_eq!(app.ping_trackers[0].transmitted, 1);
        assert_eq!(app.ping_trackers[0].received, 0);
    }
}
