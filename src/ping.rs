use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::sleep;

/// Sequência de Echo Request, compartilhada entre os hosts monitorados.
static SEQ: AtomicU16 = AtomicU16::new(1);

/// Identificador ICMP único por processo (pid XOR bits do relógio no primeiro
/// uso). Com o pid puro, duas instâncias do netmon na mesma máquina usariam o
/// mesmo ident e uma aceitaria o Echo Reply da outra.
fn icmp_ident() -> u16 {
    static IDENT: OnceLock<u16> = OnceLock::new();
    *IDENT.get_or_init(|| {
        let pid = std::process::id() as u16;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos() as u16);
        pid ^ nanos
    })
}

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

fn build_echo_request_v4(ident: u16, seq: u16) -> [u8; 12] {
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

/// ICMPv6 Echo Request (RFC 4443 §4.1). O checksum fica zerado de propósito:
/// em Linux o kernel sempre calcula o checksum sobre o pseudo-header IPv6 para
/// sockets ICMPv6 (RFC 3542 §11.1) e sobrescreve o campo. Calcular aqui exigiria
/// o endereço de origem, que só é escolhido pela stack na hora do envio.
fn build_echo_request_v6(ident: u16, seq: u16) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0x80; // Type 128 = Echo Request (ICMPv6)
    buf[1] = 0x00; // Code 0
                   // bytes 2..4 = checksum (kernel preenche em ICMPv6)
    buf[4..6].copy_from_slice(&ident.to_be_bytes());
    buf[6..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(b"NETM");
    buf
}

/// Valida Echo Reply IPv4 (type 0, code 0) com mesmo ident/seq.
/// Aceita tanto buffer com header IPv4 (raw socket) quanto só ICMP (dgram socket).
fn is_valid_echo_reply_v4(buf: &[u8], n: usize, ident: u16, seq: u16) -> bool {
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

/// Valida Echo Reply ICMPv6 (type 129, code 0) com mesmo ident/seq.
/// Header IPv6 tem 40 bytes fixos (não há IHL como no v4).
fn is_valid_echo_reply_v6(buf: &[u8], n: usize, ident: u16, seq: u16) -> bool {
    let data = &buf[..n];
    let mut offsets = vec![0usize];
    if data.len() > 40 && (data[0] >> 4) == 6 {
        offsets.push(40);
    }
    for off in offsets {
        if data.len() < off + 8 {
            continue;
        }
        let icmp = &data[off..];
        if icmp[0] == 0x81
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
        // `fe80::1%wlan0` precisa ser separado antes da resolução: o `%` não é
        // parte do endereço e o resolver não entende zona.
        let (host, zone) = split_zone(target);
        let socket_addr = match format!("{}:{}", host, self.tcp_port).to_socket_addrs() {
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

        // Link-local IPv6 precisa de scope_id (zona) antes de qualquer envio —
        // isso vale para o ICMP e para o fallback TCP conectando no mesmo addr.
        let socket_addr = with_link_local_scope(socket_addr, zone);

        // ICMPv4 (Echo Request tipo 8) e ICMPv6 (tipo 128) com fallback TCP
        // transparente quando o socket exige privilégio ou o reply não chega.
        // Porta 0: ICMP não usa portas, o endereço já está resolvido.
        let icmp_dest = SocketAddr::new(socket_addr.ip(), 0);
        match self.try_icmp_ping(icmp_dest).await {
            Ok(rtt) => PingSample {
                host: target.to_string(),
                rtt: Some(rtt),
                is_fallback: false,
                error: None,
            },
            Err(_) => self.tcp_fallback(target, socket_addr).await,
        }
    }
}

/// fe80::/10: primeiros 10 bits = 1111 1110 10xx xxxx.
/// (Funções livres de propósito: pura manipulação de endereço, testável sem rede;
/// `PingEngine` só as chama em `ping_once`.)
fn is_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Separa "host" de "%zona" (sintaxe `fe80::1%wlan0`). Hostnames não contêm
/// `%`, então só literais IPv6 são afetados.
fn split_zone(target: &str) -> (&str, Option<&str>) {
    match target.rsplit_once('%') {
        Some((host, zone)) if !zone.is_empty() => (host, Some(zone)),
        _ => (target, None),
    }
}

/// Primeira interface não-loopback com algum endereço link-local. Chute honesto
/// para quando o literal não traz zona — no pior caso, o ICMP dá timeout e
/// segue o caminho normal (fallback TCP).
fn first_link_local_iface() -> Option<u32> {
    pnet::datalink::interfaces().into_iter().find_map(|iface| {
        let has_ll = iface
            .ips
            .iter()
            .any(|net| matches!(net.ip(), IpAddr::V6(ip) if is_link_local(&ip)));
        (!iface.is_loopback() && has_ll).then_some(iface.index)
    })
}

/// Anexa scope_id a link-local (`fe80::/10`) que veio sem. Sem isso o kernel
/// rejeita o envio (EINVAL) e o host cairia direto no fallback — que também
/// falha sem zona. Zona explícita (`%wlan0`) vence quando a interface
/// existe; zona inexistente e sem-candidata voltam intocados.
fn with_link_local_scope(addr: SocketAddr, zone: Option<&str>) -> SocketAddr {
    let SocketAddr::V6(v6) = addr else {
        return addr;
    };
    if v6.scope_id() != 0 || !is_link_local(v6.ip()) {
        return addr;
    }
    let index = match zone {
        // Explícita mas inexistente: passa intocado em vez de chutar outra
        // interface em silêncio (o envio falha claro, o TCP também).
        Some(name) => pnet::datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .map(|iface| iface.index),
        // Sem zona: palpite honesto; sem candidata, volta intocado.
        None => first_link_local_iface(),
    };
    match index {
        Some(idx) => {
            let scoped = SocketAddrV6::new(*v6.ip(), v6.port(), v6.flowinfo(), idx);
            SocketAddr::V6(scoped)
        }
        None => addr,
    }
}

impl PingEngine {
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

    /// Tenta ICMP na família do endereço de destino (v4 ou v6).
    /// `target` deve ter porta 0 — ICMP não usa portas.
    async fn try_icmp_ping(&self, target: SocketAddr) -> Result<Duration, anyhow::Error> {
        let timeout = self.timeout.min(Duration::from_millis(500));
        tokio::task::spawn_blocking(move || {
            use socket2::{Domain, Protocol, Socket, Type};
            let is_v6 = target.is_ipv6();
            let (domain, protocol) = if is_v6 {
                (Domain::IPV6, Protocol::ICMPV6)
            } else {
                (Domain::IPV4, Protocol::ICMPV4)
            };
            // DGRAM primeiro (sem privilégio); RAW como segunda tentativa.
            let socket = Socket::new(domain, Type::DGRAM, Some(protocol))
                .or_else(|_| Socket::new(domain, Type::RAW, Some(protocol)))
                .map_err(|e| anyhow::anyhow!("socket ICMP indisponível: {e}"))?;
            socket.set_read_timeout(Some(timeout))?;

            let ident = icmp_ident();
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let echo_req = if is_v6 {
                build_echo_request_v6(ident, seq)
            } else {
                build_echo_request_v4(ident, seq)
            };

            // Converte para std::net::UdpSocket: mesma syscall recvfrom(2) no
            // fd ICMP, mas com API segura (&mut [u8]) em vez de MaybeUninit +
            // unsafe. A conversão transfere a posse do fd (Socket → UdpSocket).
            let sock: std::net::UdpSocket = socket.into();
            let start = Instant::now();
            sock.send_to(&echo_req, target)?;

            // Deadline absoluto: não aceitar erro intermediário como pong.
            let deadline = start + timeout;
            let mut buf = [0u8; 512];
            loop {
                let (n, _) = sock.recv_from(&mut buf)?;
                let valid = if is_v6 {
                    is_valid_echo_reply_v6(&buf, n, ident, seq)
                } else {
                    is_valid_echo_reply_v4(&buf, n, ident, seq)
                };
                if valid {
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
        let pkt = build_echo_request_v4(0x1234, 0x0001);
        // Checksum de um pacote válido deve zerar a soma (resultado 0).
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn checksum_changes_with_payload() {
        let a = build_echo_request_v4(1, 1);
        let b = build_echo_request_v4(2, 1);
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
        assert!(is_valid_echo_reply_v4(&good, 12, 7, 9));
        // Destination Unreachable (type 3) com mesmo id/seq deve ser rejeitado
        let mut bad = good;
        bad[0] = 0x03;
        assert!(!is_valid_echo_reply_v4(&bad, 12, 7, 9));
        // id diferente deve ser rejeitado
        assert!(!is_valid_echo_reply_v4(&good, 12, 8, 9));
    }

    #[test]
    fn v6_echo_request_uses_type_128_and_unique_ident() {
        let a = build_echo_request_v6(0x1234, 0x0001);
        assert_eq!(a[0], 0x80, "ICMPv6 Echo Request é tipo 128");
        assert_eq!(a[1], 0x00);
        assert_eq!(u16::from_be_bytes([a[4], a[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 0x0001);
        // Checksum fica zerado: o kernel preenche em ICMPv6 (RFC 3542 §11.1).
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), 0);
        // ident diferente => pacote diferente (não aceita reply de outra instância)
        assert_ne!(a, build_echo_request_v6(0x1235, 0x0001));
    }

    #[test]
    fn v6_accepts_echo_reply_and_rejects_request_type() {
        let mut good = [0u8; 12];
        good[0] = 0x81; // Echo Reply ICMPv6
        good[1] = 0x00;
        good[4..6].copy_from_slice(&7u16.to_be_bytes());
        good[6..8].copy_from_slice(&9u16.to_be_bytes());
        assert!(is_valid_echo_reply_v6(&good, 12, 7, 9));
        // Echo Request (128) refletido não é resposta válida
        let mut reflected = good;
        reflected[0] = 0x80;
        assert!(!is_valid_echo_reply_v6(&reflected, 12, 7, 9));
        assert!(!is_valid_echo_reply_v6(&good, 12, 7, 10));
    }

    #[test]
    fn v6_accepts_reply_behind_ipv6_header() {
        // Socket RAW entrega o pacote com header IPv6 de 40 bytes fixos.
        let mut raw = [0u8; 40 + 12];
        raw[0] = 0x60; // version 6
        raw[40] = 0x81; // Echo Reply
        raw[41] = 0x00;
        raw[44..46].copy_from_slice(&5u16.to_be_bytes());
        raw[46..48].copy_from_slice(&6u16.to_be_bytes());
        assert!(is_valid_echo_reply_v6(&raw, 52, 5, 6));
    }

    #[test]
    fn icmp_ident_is_stable_and_not_plain_pid() {
        // Estável dentro do processo (OnceLock), para o reply casar com o request.
        assert_eq!(icmp_ident(), icmp_ident());
    }

    #[test]
    fn zona_e_separada_antes_da_resolucao() {
        assert_eq!(split_zone("fe80::1%wlan0"), ("fe80::1", Some("wlan0")));
        assert_eq!(split_zone("fe80::1"), ("fe80::1", None));
        assert_eq!(split_zone("1.1.1.1"), ("1.1.1.1", None));
        assert_eq!(split_zone("host.example"), ("host.example", None));
        // Zona vazia não é zona.
        assert_eq!(split_zone("fe80::1%"), ("fe80::1%", None));
    }

    #[test]
    fn prefixo_link_local_reconhecido() {
        use std::str::FromStr;
        let ll = Ipv6Addr::from_str("fe80::1").unwrap();
        assert!(is_link_local(&ll));
        // fe90:: também é link-local (fe80::/10 cobre fe80..febb).
        assert!(is_link_local(&Ipv6Addr::from_str("feb0::5").unwrap()));
        assert!(!is_link_local(&Ipv6Addr::from_str("2001:db8::1").unwrap()));
        assert!(!is_link_local(&Ipv6Addr::from_str("::1").unwrap()));
    }

    #[test]
    fn scope_nao_mexem_em_nao_link_local() {
        // Global unicast passa intocado, mesmo com zona explícita.
        let global: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        assert_eq!(with_link_local_scope(global, None), global);
        let v4: SocketAddr = "1.1.1.1:80".parse().unwrap();
        assert_eq!(with_link_local_scope(v4, None), v4);
        // Zona explícita inexistente: intocado, nunca chute silencioso.
        let ll: SocketAddr = "[fe80::1]:80".parse().unwrap();
        assert_eq!(
            with_link_local_scope(ll, Some("iface-que-nao-existe-xyz")),
            ll
        );
    }

    #[test]
    fn validator_uses_received_length_not_full_buffer() {
        // Integração do caminho recv_from → validação com socket real: o kernel
        // entrega apenas n bytes, e o validador não pode olhar além disso.
        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind servidor");
        let addr = server.local_addr().expect("local_addr");
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind cliente");

        let mut reply = [0u8; 12];
        reply[0] = 0x81; // Echo Reply ICMPv6
        reply[4..6].copy_from_slice(&42u16.to_be_bytes());
        reply[6..8].copy_from_slice(&7u16.to_be_bytes());
        client.send_to(&reply, addr).expect("send");

        let mut buf = [0xFFu8; 512]; // lixo depois do payload, de propósito
        let (n, _) = server.recv_from(&mut buf).expect("recv");
        assert_eq!(n, 12);
        assert!(is_valid_echo_reply_v6(&buf, n, 42, 7));
        assert!(!is_valid_echo_reply_v6(&buf, n, 43, 7));
    }

    #[tokio::test]
    async fn ping_unreachable_host_returns_error_not_panic() {
        let engine = PingEngine::new(500, 300, 80);
        let sample = engine.ping_once("host.invalido.test").await;
        assert!(sample.rtt.is_none());
        assert!(sample.error.is_some());
    }
}
