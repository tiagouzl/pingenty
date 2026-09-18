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
use std::sync::{Arc, RwLock};
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

#[derive(Debug, Default)]
pub struct TrafficMetrics {
    pub global_protocols: ProtocolCounters,
    pub flows: RwLock<HashMap<FiveTuple, FlowStat>>,
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

        if let Ok(mut flows) = metrics.flows.write() {
            let flow = flows.entry(tuple).or_default();
            flow.byte_count += raw_len;
            flow.packet_count += 1;
            flow.last_seen = Some(Instant::now());

            if flows.len() > 10_000 {
                flows.retain(|_, v| {
                    v.last_seen
                        .is_some_and(|seen| seen.elapsed().as_secs() < 300)
                });
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
}
