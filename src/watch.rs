use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct FlowStat {
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_seen: Option<Instant>,
}

// Contadores globais em atômicos: todo pacote incrementa sem adquirir lock.
// Só o HashMap de flows usa RwLock. Limitação conhecida da v1: o lock do mapa
// ainda é global (ver README) — sharding/DashMap fica para quando houver
// benchmark real mostrando contenção.
#[derive(Debug, Default)]
pub struct ProtocolCounters {
    pub tcp_bytes: AtomicU64,
    pub tcp_packets: AtomicU64,
    pub udp_bytes: AtomicU64,
    pub udp_packets: AtomicU64,
    pub icmp_bytes: AtomicU64,
    pub icmp_packets: AtomicU64,
    pub other_bytes: AtomicU64,
    pub other_packets: AtomicU64,
}

impl ProtocolCounters {
    pub fn snapshot(&self) -> ProtocolSnapshot {
        ProtocolSnapshot {
            tcp_bytes: self.tcp_bytes.load(Ordering::Relaxed),
            tcp_packets: self.tcp_packets.load(Ordering::Relaxed),
            udp_bytes: self.udp_bytes.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
            icmp_bytes: self.icmp_bytes.load(Ordering::Relaxed),
            icmp_packets: self.icmp_packets.load(Ordering::Relaxed),
            other_bytes: self.other_bytes.load(Ordering::Relaxed),
            other_packets: self.other_packets.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolSnapshot {
    pub tcp_bytes: u64,
    pub tcp_packets: u64,
    pub udp_bytes: u64,
    pub udp_packets: u64,
    pub icmp_bytes: u64,
    pub icmp_packets: u64,
    pub other_bytes: u64,
    pub other_packets: u64,
}

/// Teto de fluxos mantidos em memória: acima disso, varredura imediata.
const FLOW_MAX_ENTRIES: usize = 10_000;
/// Fluxo sem tráfego por mais que isso é considerado morto.
const FLOW_IDLE_SECS: u64 = 300;
/// Intervalo mínimo entre varreduras periódicas de fluxos mortos.
const FLOW_SWEEP_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Default)]
pub struct TrafficMetrics {
    pub global_protocols: ProtocolCounters,
    pub flows: RwLock<HashMap<FiveTuple, FlowStat>>,
    /// Instante da última varredura, em segundos desde `epoch`.
    last_sweep_secs: AtomicU64,
    /// Referência monotônica para converter `Instant` em segundos. Definida no
    /// primeiro pacote e nunca alterada depois.
    epoch: OnceLock<Instant>,
}

impl TrafficMetrics {
    /// Varredura de flows inativos agendada por tempo (no máximo uma a cada
    /// `FLOW_SWEEP_INTERVAL_SECS`). Mantém a memória previsível mesmo abaixo do
    /// teto de entradas, onde o backstop por tamanho nunca dispara.
    fn due_for_sweep(&self, now: Instant) -> bool {
        let epoch = *self.epoch.get_or_init(|| now);
        let secs = now.duration_since(epoch).as_secs();
        let last = self.last_sweep_secs.load(Ordering::Relaxed);
        secs >= last.saturating_add(FLOW_SWEEP_INTERVAL_SECS)
            && self
                .last_sweep_secs
                .compare_exchange(last, secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }
}

/// Fluxo sem tráfego por mais de `FLOW_IDLE_SECS` — candidato a remoção.
fn is_stale(stat: &FlowStat, now: Instant) -> bool {
    stat.last_seen
        .is_some_and(|seen| now.duration_since(seen).as_secs() >= FLOW_IDLE_SECS)
}

pub struct PacketWatcher {
    pub interface_name: String,
    pub metrics: Arc<TrafficMetrics>,
}

impl PacketWatcher {
    pub fn new(
        interface_name_opt: Option<String>,
    ) -> Result<(Self, NetworkInterface), anyhow::Error> {
        let interfaces = datalink::interfaces();
        let iface = match interface_name_opt {
            Some(name) => interfaces
                .into_iter()
                .find(|i| i.name == name)
                .ok_or_else(|| anyhow::anyhow!("Interface '{name}' não encontrada no host."))?,
            None => interfaces
                .into_iter()
                .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("Nenhuma interface de rede ativa e utilizável detectada.")
                })?,
        };
        Ok((
            Self {
                interface_name: iface.name.clone(),
                metrics: Arc::new(TrafficMetrics::default()),
            },
            iface,
        ))
    }

    pub fn start_capture_thread(
        iface: NetworkInterface,
        metrics: Arc<TrafficMetrics>,
    ) -> Result<(), anyhow::Error> {
        let cfg = datalink::Config {
            read_timeout: Some(std::time::Duration::from_millis(200)),
            ..Default::default()
        };

        let (_, mut rx) = match datalink::channel(&iface, cfg) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(anyhow::anyhow!(
                    "Canal de dados não suportado (não-Ethernet)."
                ))
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                "Permissão negada ao abrir interface '{}'. Requer root ou CAP_NET_RAW. Erro: {}",
                iface.name,
                e
            ))
            }
        };

        std::thread::Builder::new()
            .name("netmon-pcap".to_string())
            .spawn(move || loop {
                match rx.next() {
                    Ok(frame) => {
                        let len = frame.len() as u64;
                        if let Some(eth) = EthernetPacket::new(frame) {
                            match eth.get_ethertype() {
                                EtherTypes::Ipv4 => {
                                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                        Self::process_l4(
                                            IpAddr::V4(ip.get_source()),
                                            IpAddr::V4(ip.get_destination()),
                                            ip.get_next_level_protocol(),
                                            ip.payload(),
                                            len,
                                            &metrics,
                                        );
                                    }
                                }
                                EtherTypes::Ipv6 => {
                                    if let Some(ip) = Ipv6Packet::new(eth.payload()) {
                                        Self::process_l4(
                                            IpAddr::V6(ip.get_source()),
                                            IpAddr::V6(ip.get_destination()),
                                            ip.get_next_header(),
                                            ip.payload(),
                                            len,
                                            &metrics,
                                        );
                                    }
                                }
                                _ => {
                                    metrics
                                        .global_protocols
                                        .other_bytes
                                        .fetch_add(len, Ordering::Relaxed);
                                    metrics
                                        .global_protocols
                                        .other_packets
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(e) => {
                        eprintln!("Captura interrompida: {e}");
                        break;
                    }
                }
            })?;

        Ok(())
    }

    fn process_l4(
        src: IpAddr,
        dst: IpAddr,
        proto: pnet::packet::ip::IpNextHeaderProtocol,
        payload: &[u8],
        raw_len: u64,
        metrics: &Arc<TrafficMetrics>,
    ) {
        let (proto_str, src_p, dst_p) = match proto {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(payload);
                (
                    "TCP",
                    tcp.as_ref().map_or(0, |p| p.get_source()),
                    tcp.as_ref().map_or(0, |p| p.get_destination()),
                )
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(payload);
                (
                    "UDP",
                    udp.as_ref().map_or(0, |p| p.get_source()),
                    udp.as_ref().map_or(0, |p| p.get_destination()),
                )
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => ("ICMP", 0, 0),
            _ => ("OUTRO", 0, 0),
        };

        let g = &metrics.global_protocols;
        match proto_str {
            "TCP" => {
                g.tcp_bytes.fetch_add(raw_len, Ordering::Relaxed);
                g.tcp_packets.fetch_add(1, Ordering::Relaxed);
            }
            "UDP" => {
                g.udp_bytes.fetch_add(raw_len, Ordering::Relaxed);
                g.udp_packets.fetch_add(1, Ordering::Relaxed);
            }
            "ICMP" => {
                g.icmp_bytes.fetch_add(raw_len, Ordering::Relaxed);
                g.icmp_packets.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                g.other_bytes.fetch_add(raw_len, Ordering::Relaxed);
                g.other_packets.fetch_add(1, Ordering::Relaxed);
            }
        }

        let tuple = FiveTuple {
            src_ip: src,
            dst_ip: dst,
            src_port: src_p,
            dst_port: dst_p,
            protocol: proto_str,
        };

        let now = Instant::now();
        let sweep_due = metrics.due_for_sweep(now);

        if let Ok(mut flows) = metrics.flows.write() {
            let flow = flows.entry(tuple).or_default();
            flow.byte_count += raw_len;
            flow.packet_count += 1;
            flow.last_seen = Some(now);

            // Varredura por tempo (máx. 1x por minuto) ou backstop por tamanho.
            if sweep_due || flows.len() > FLOW_MAX_ENTRIES {
                flows.retain(|_, v| !is_stale(v, now));
            }
        }
        // Se o lock falhar (poisoned), o pacote é descartado: captura nunca trava.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn counters_increment_without_lock_contention_path() {
        let m = Arc::new(TrafficMetrics::default());
        PacketWatcher::process_l4(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpNextHeaderProtocols::Tcp,
            &[],
            100,
            &m,
        );
        let snap = m.global_protocols.snapshot();
        assert_eq!(snap.tcp_packets, 1);
        assert_eq!(snap.tcp_bytes, 100);
        assert_eq!(m.flows.read().unwrap().len(), 1);
    }

    #[test]
    fn stale_predicate_uses_idle_window() {
        let now = Instant::now();
        let fresh = FlowStat {
            last_seen: Some(now - Duration::from_secs(10)),
            ..Default::default()
        };
        let dead = FlowStat {
            last_seen: Some(now - Duration::from_secs(FLOW_IDLE_SECS + 1)),
            ..Default::default()
        };
        // sem last_seen (nunca visto) não é considerado morto por aqui
        let unseen = FlowStat::default();
        assert!(!is_stale(&fresh, now));
        assert!(is_stale(&dead, now));
        assert!(!is_stale(&unseen, now));
    }

    #[test]
    fn sweep_schedule_respects_interval() {
        let m = TrafficMetrics::default();
        let t0 = Instant::now();
        // Primeira chamada define a epoch: nada a varrer ainda.
        assert!(!m.due_for_sweep(t0));
        assert!(!m.due_for_sweep(t0 + Duration::from_secs(30)));
        assert!(m.due_for_sweep(t0 + Duration::from_secs(FLOW_SWEEP_INTERVAL_SECS + 1)));
        // Logo depois de varrer, não varre de novo.
        assert!(!m.due_for_sweep(t0 + Duration::from_secs(FLOW_SWEEP_INTERVAL_SECS + 2)));
    }

    #[test]
    fn sweep_uses_size_backstop_even_without_schedule() {
        // Um fluxo morto é removido quando o mapa passa do teto, sem esperar
        // pelo agendamento temporal.
        let m = Arc::new(TrafficMetrics::default());
        {
            let mut flows = m.flows.write().unwrap();
            for i in 0..(FLOW_MAX_ENTRIES + 1) {
                flows.insert(
                    FiveTuple {
                        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8)),
                        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
                        src_port: i as u16,
                        dst_port: 80,
                        protocol: "TCP",
                    },
                    FlowStat {
                        packet_count: 1,
                        byte_count: 1,
                        last_seen: Some(Instant::now() - Duration::from_secs(FLOW_IDLE_SECS + 60)),
                    },
                );
            }
        }
        PacketWatcher::process_l4(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpNextHeaderProtocols::Tcp,
            &[],
            100,
            &m,
        );
        // Todos os mortos saíram; sobrou só o fluxo do pacote novo.
        assert_eq!(m.flows.read().unwrap().len(), 1);
    }
}
