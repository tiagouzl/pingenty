use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::sleep;

static SEQ: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Clone)]
pub struct PingSample {
    pub host: String,
    pub rtt: Option<Duration>,
    pub is_fallback: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PingStats {
    pub transmitted: u64,
    pub received: u64,
    pub min_rtt: Option<Duration>,
    pub max_rtt: Option<Duration>,
    pub sum_rtt: Duration,
}

impl PingStats {
    pub fn record(&mut self, rtt_opt: Option<Duration>) {
        self.transmitted += 1;
        if let Some(rtt) = rtt_opt {
            self.received += 1;
            self.sum_rtt += rtt;
            self.min_rtt = Some(self.min_rtt.map_or(rtt, |min| min.min(rtt)));
            self.max_rtt = Some(self.max_rtt.map_or(rtt, |max| max.max(rtt)));
        }
    }

    pub fn loss_rate(&self) -> f64 {
        if self.transmitted == 0 {
            return 0.0;
        }
        ((self.transmitted - self.received) as f64 / self.transmitted as f64) * 100.0
    }

    pub fn avg_rtt(&self) -> Option<Duration> {
        if self.received == 0 {
            None
        } else {
            Some(self.sum_rtt / (self.received as u32))
        }
    }
}

/// Checksum ICMP (RFC 1071). Quebra se o payload mudar e o checksum não —
/// por isso é calculado, nunca hardcoded.
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let (chunks, rem) = data.as_chunks::<2>();
    let mut sum: u32 = chunks.iter().map(|c| u16::from_be_bytes(*c) as u32).sum();
    if let [last] = rem {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo_request(ident: u16, seq: u16) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0x08; // Type 8 = Echo Request (ICMPv4)
    buf[1] = 0x00; // Code 0
                   // bytes 2..4 = checksum (preenchido abaixo)
    buf[4..6].copy_from_slice(&ident.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(b"NETM");
    let cksum = icmp_checksum(&buf);
    buf[2..4].copy_from_slice(&cksum.to_be_bytes());
    buf
}

/// Valida Echo Reply (type 0, code 0) com mesmo ident/seq.
/// Aceita tanto buffer com header IPv4 (raw socket) quanto só ICMP (dgram socket).
fn is_valid_echo_reply(buf: &[u8], n: usize, ident: u16, seq: u16) -> bool {
    let data = &buf[..n];
    // Candidatos: offset 0 (dgram) ou após header IPv4 (raw, IHL * 4).
    let mut offsets = vec![0usize];
    if data.len() > 20 && (data[0] >> 4) == 4 {
        let ihl = ((data[0] & 0x0F) as usize) * 4;
        if ihl >= 20 && data.len() >= ihl + 8 {
            offsets.push(ihl);
        }
    }
    for off in offsets {
        if data.len() < off + 8 {
            continue;
        }
        let icmp = &data[off..];
        if icmp[0] == 0x00
            && icmp[1] == 0x00
            && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
            && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
        {
            return true;
        }
    }
    false
}

pub struct PingEngine {
    interval: Duration,
    timeout: Duration,
    tcp_port: u16,
}

impl PingEngine {
    pub fn new(interval_ms: u64, timeout_ms: u64, tcp_port: u16) -> Self {
        Self {
            interval: Duration::from_millis(interval_ms),
            timeout: Duration::from_millis(timeout_ms),
            tcp_port,
        }
    }

    pub async fn ping_once(&self, target: &str) -> PingSample {
        let socket_addr = match format!("{}:{}", target, self.tcp_port).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    return PingSample {
                        host: target.to_string(),
                        rtt: None,
                        is_fallback: false,
                        error: Some("Falha ao resolver endereço IP".into()),
                    }
                }
            },
            Err(e) => {
                return PingSample {
                    host: target.to_string(),
                    rtt: None,
                    is_fallback: false,
                    error: Some(format!("Erro DNS: {e}")),
                }
            }
        };

        // v1 é IPv4-only por honestidade: ICMPv6 usa tipo 128 e pseudo-header
        // diferente — em vez de enviar pacote v4 malformado, pula direto pro TCP.
        let ipv4 = match socket_addr.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return self.tcp_fallback(target, socket_addr).await;
            }
        };

        match self.try_icmp_ping(ipv4).await {
            Ok(rtt) => PingSample {
                host: target.to_string(),
                rtt: Some(rtt),
                is_fallback: false,
                error: None,
            },
            Err(_) => self.tcp_fallback(target, socket_addr).await,
        }
    }

    async fn tcp_fallback(&self, target: &str, socket_addr: SocketAddr) -> PingSample {
        let tcp_start = Instant::now();
        match tokio::time::timeout(self.timeout, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => PingSample {
                host: target.to_string(),
                rtt: Some(tcp_start.elapsed()),
                is_fallback: true,
                error: None,
            },
            Ok(Err(e)) => PingSample {
                host: target.to_string(),
                rtt: None,
                is_fallback: true,
                error: Some(format!("TCP Erro: {e}")),
            },
            Err(_) => PingSample {
                host: target.to_string(),
                rtt: None,
                is_fallback: true,
                error: Some("Timeout excedido".into()),
            },
        }
    }

    async fn try_icmp_ping(&self, target_ip: Ipv4Addr) -> Result<Duration, anyhow::Error> {
        let timeout = self.timeout.min(Duration::from_millis(500));
        tokio::task::spawn_blocking(move || {
            use socket2::{Domain, Protocol, Socket, Type};
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))?;
            socket.set_read_timeout(Some(timeout))?;

            let ident = std::process::id() as u16;
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let echo_req = build_echo_request(ident, seq);

            let dest = SocketAddr::new(IpAddr::V4(target_ip), 0);
            let start = Instant::now();

            // Converte para std::net::UdpSocket: mesma syscall recvfrom(2) no
            // fd ICMP, mas com API segura (&mut [u8]) em vez de MaybeUninit +
            // unsafe. A conversão transfere a posse do fd (Socket → UdpSocket).
            let sock: std::net::UdpSocket = socket.into();
            sock.send_to(&echo_req, dest)?;

            // Deadline absoluto: não aceitar erro intermediário como pong.
            let deadline = start + timeout;
            let mut buf = [0u8; 512];
            loop {
                let (n, _) = sock.recv_from(&mut buf)?;
                if is_valid_echo_reply(&buf, n, ident, seq) {
                    return Ok(start.elapsed());
                }
                // Pacote estranho (ex: Destination Unreachable atrasado) — ignora
                // e continua esperando até o deadline.
                if Instant::now() >= deadline {
                    return Err(anyhow::anyhow!("sem Echo Reply válido antes do timeout"));
                }
            }
        })
        .await?
    }

    pub async fn run_continuous<F>(self: Arc<Self>, host: String, mut on_sample: F)
    where
        F: FnMut(PingSample, &PingStats) + Send + 'static,
    {
        let mut stats = PingStats::default();
        loop {
            let sample = self.ping_once(&host).await;
            stats.record(sample.rtt);
            on_sample(sample, &stats);
            sleep(self.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_stats_loss_rate_all_lost() {
        let mut stats = PingStats::default();
        stats.record(None);
        stats.record(None);
        assert_eq!(stats.loss_rate(), 100.0);
        assert_eq!(stats.avg_rtt(), None);
    }

    #[test]
    fn ping_stats_avg_rtt_ignores_losses() {
        let mut stats = PingStats::default();
        stats.record(Some(Duration::from_millis(10)));
        stats.record(None);
        stats.record(Some(Duration::from_millis(30)));
        assert_eq!(stats.avg_rtt(), Some(Duration::from_millis(20)));
        assert!((stats.loss_rate() - 33.333).abs() < 0.01);
    }

    #[test]
    fn checksum_roundtrip_valid() {
        let pkt = build_echo_request(0x1234, 0x0001);
        // Checksum de um pacote válido deve zerar a soma (resultado 0).
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn checksum_changes_with_payload() {
        let a = build_echo_request(1, 1);
        let b = build_echo_request(2, 1);
        assert_ne!(a, b);
        assert_eq!(icmp_checksum(&a), 0);
        assert_eq!(icmp_checksum(&b), 0);
    }

    #[test]
    fn rejects_wrong_type_and_id() {
        // Echo Reply válido
        let mut good = [0u8; 12];
        good[0] = 0x00;
        good[1] = 0x00;
        good[4..6].copy_from_slice(&7u16.to_be_bytes());
        good[6..8].copy_from_slice(&9u16.to_be_bytes());
        assert!(is_valid_echo_reply(&good, 12, 7, 9));
        // Destination Unreachable (type 3) com mesmo id/seq deve ser rejeitado
        let mut bad = good;
        bad[0] = 0x03;
        assert!(!is_valid_echo_reply(&bad, 12, 7, 9));
        // id diferente deve ser rejeitado
        assert!(!is_valid_echo_reply(&good, 12, 8, 9));
    }

    #[tokio::test]
    async fn ping_unreachable_host_returns_error_not_panic() {
        let engine = PingEngine::new(500, 300, 80);
        let sample = engine.ping_once("host.invalido.test").await;
        assert!(sample.rtt.is_none());
        assert!(sample.error.is_some());
    }
}
