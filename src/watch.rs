use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
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

/// Chave de agregação de um fluxo: 5-tuple clássico (origem, destino, proto).
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FiveTuple {
    /// IP de origem.
    pub src_ip: IpAddr,
    /// IP de destino.
    pub dst_ip: IpAddr,
    /// Porta de origem (`0` quando o protocolo não tem portas).
    pub src_port: u16,
    /// Porta de destino (`0` quando o protocolo não tem portas).
    pub dst_port: u16,
    /// `"TCP"`, `"UDP"`, `"ICMP"` ou outro (cai em `OUTR`).
    pub protocol: &'static str,
}

/// Contadores acumulados de um fluxo.
#[derive(Debug, Clone, Default)]
pub struct FlowStat {
    /// Pacotes vistos no fluxo.
    pub packet_count: u64,
    /// Bytes vistos no fluxo.
    pub byte_count: u64,
    /// Último pacote (para varredura de fluxos mortos).
    pub last_seen: Option<Instant>,
}

// Contadores globais em atômicos: todo pacote incrementa sem adquirir lock.
// Só o HashMap de flows usa RwLock. Limitação conhecida da v1: o lock do mapa
// ainda é global (ver README) — sharding/DashMap fica para quando houver
// benchmark real mostrando contenção.
#[derive(Debug, Default)]
/// Contadores por protocolo em atômicos (leitura nunca bloqueia a captura).
pub struct ProtocolCounters {
    /// Bytes TCP acumulados.
    pub tcp_bytes: AtomicU64,
    /// Pacotes TCP acumulados.
    pub tcp_packets: AtomicU64,
    /// Bytes UDP acumulados.
    pub udp_bytes: AtomicU64,
    /// Pacotes UDP acumulados.
    pub udp_packets: AtomicU64,
    /// Bytes ICMP acumulados.
    pub icmp_bytes: AtomicU64,
    /// Pacotes ICMP acumulados.
    pub icmp_packets: AtomicU64,
    /// Bytes de outros protocolos acumulados.
    pub other_bytes: AtomicU64,
    /// Pacotes de outros protocolos acumulados.
    pub other_packets: AtomicU64,
}

impl ProtocolCounters {
    /// Leitura consistente (Relaxed: basta para exibição).
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

/// Foto imutável dos contadores para exibição (ver [`ProtocolCounters`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolSnapshot {
    /// Bytes TCP.
    pub tcp_bytes: u64,
    /// Pacotes TCP.
    pub tcp_packets: u64,
    /// Bytes UDP.
    pub udp_bytes: u64,
    /// Pacotes UDP.
    pub udp_packets: u64,
    /// Bytes ICMP.
    pub icmp_bytes: u64,
    /// Pacotes ICMP.
    pub icmp_packets: u64,
    /// Bytes de outros protocolos.
    pub other_bytes: u64,
    /// Pacotes de outros protocolos.
    pub other_packets: u64,
}

/// Teto de fluxos mantidos em memória: acima disso, varredura imediata.
const FLOW_MAX_ENTRIES: usize = 10_000;
/// Fluxo sem tráfego por mais que isso é considerado morto.
const FLOW_IDLE_SECS: u64 = 300;
/// Intervalo mínimo entre varreduras periódicas de fluxos mortos.
const FLOW_SWEEP_INTERVAL_SECS: u64 = 60;

/// Métricas compartilhadas entre a thread de captura e a TUI: contadores
/// atômicos por protocolo + mapa de fluxos com varredura de mortos por tempo
/// (1x/min, 300 s inativo) e por tamanho (10 mil entradas).
#[derive(Debug, Default)]
pub struct TrafficMetrics {
    /// Contadores por protocolo (sem lock).
    pub global_protocols: ProtocolCounters,
    /// Fluxos por 5-tuple (lei com `try_read` na TUI para nunca travar).
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

    /// Soma os snapshots de N interfaces (resumo do `watch` multi-interface).
    pub fn sum_snapshots(all: &[Arc<TrafficMetrics>]) -> ProtocolSnapshot {
        let mut acc = ProtocolSnapshot::default();
        for m in all {
            let p = m.global_protocols.snapshot();
            acc.tcp_bytes += p.tcp_bytes;
            acc.tcp_packets += p.tcp_packets;
            acc.udp_bytes += p.udp_bytes;
            acc.udp_packets += p.udp_packets;
            acc.icmp_bytes += p.icmp_bytes;
            acc.icmp_packets += p.icmp_packets;
            acc.other_bytes += p.other_bytes;
            acc.other_packets += p.other_packets;
        }
        acc
    }

    /// Junta fluxos de N interfaces por 5-tuple (mesmo tuple soma pacotes e
    /// bytes, `last_seen` = maior), ordenado por bytes desc. Nota honesta:
    /// interfaces que veem o mesmo tráfego (ex. `lo,lo`) somam dobrado — a
    /// agregação soma, não deduplica.
    pub fn merge_flows(all: &[Arc<TrafficMetrics>]) -> Vec<(FiveTuple, FlowStat)> {
        let mut merged: HashMap<FiveTuple, FlowStat> = HashMap::new();
        for m in all {
            let Ok(flows) = m.flows.read() else {
                continue;
            };
            for (tuple, flow) in flows.iter() {
                merged
                    .entry(tuple.clone())
                    .and_modify(|e| {
                        e.packet_count += flow.packet_count;
                        e.byte_count += flow.byte_count;
                        e.last_seen = e.last_seen.max(flow.last_seen);
                    })
                    .or_insert_with(|| flow.clone());
            }
        }
        let mut top: Vec<_> = merged.into_iter().collect();
        top.sort_by_key(|a| std::cmp::Reverse(a.1.byte_count));
        top
    }

    /// Contabiliza um pacote já classificado: contadores atômicos por protocolo
    /// (sem lock) + agregação por 5-tuple (com lock do mapa).
    ///
    /// Público de propósito: é o ponto que o benchmark de contenção mede, e
    /// permite alimentar as métricas a partir de outra fonte de captura.
    pub fn record(&self, tuple: FiveTuple, raw_len: u64) {
        let g = &self.global_protocols;
        match tuple.protocol {
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

        let now = Instant::now();
        let sweep_due = self.due_for_sweep(now);

        if let Ok(mut flows) = self.flows.write() {
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

/// Fluxo sem tráfego por mais de `FLOW_IDLE_SECS` — candidato a remoção.
fn is_stale(stat: &FlowStat, now: Instant) -> bool {
    stat.last_seen
        .is_some_and(|seen| now.duration_since(seen).as_secs() >= FLOW_IDLE_SECS)
}

/// Remove tags VLAN 802.1Q (0x8100) / QinQ (0x88A8), até 2 níveis, e devolve
/// o ethertype real + payload. Sem isso, tráfego em porta trunk cai em OUTRO
/// e nenhum fluxo é indexado.
fn strip_vlan_tags(ethertype: EtherType, mut payload: &[u8]) -> (EtherType, &[u8]) {
    let mut ethertype = ethertype;
    for _ in 0..2 {
        if ethertype != EtherTypes::Vlan && ethertype.0 != 0x88A8 {
            break;
        }
        if payload.len() < 4 {
            break;
        }
        ethertype = EtherType(u16::from_be_bytes([payload[2], payload[3]]));
        payload = &payload[4..];
    }
    (ethertype, payload)
}

/// Resultado da tentativa de captura: ativa ou desligada com motivo.
#[derive(Debug, Clone, Default)]
pub struct CaptureStatus {
    /// Nome da interface em captura, ou `None` quando a captura foi desligada.
    pub interface: Option<String>,
    /// Motivo exibido na TUI quando a captura está desligada.
    pub warning: Option<String>,
}

impl CaptureStatus {
    /// Captura ligada nesta interface.
    pub fn active(interface_name: String) -> Self {
        Self {
            interface: Some(interface_name),
            warning: None,
        }
    }

    /// Captura desligada com motivo exibível na TUI (downgrade gracioso).
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            interface: None,
            warning: Some(reason.into()),
        }
    }
}

/// Tenta ligar a captura passiva. Nunca falha o programa: sem permissão
/// (`CAP_NET_RAW`) ou sem interface, volta com métricas vazias e um aviso para
/// a TUI exibir — ping e DNS continuam ao vivo.
pub fn setup_capture(interface: Option<String>) -> (Arc<TrafficMetrics>, CaptureStatus) {
    let metrics = Arc::new(TrafficMetrics::default());
    match PacketWatcher::new(interface) {
        Err(e) => (
            metrics,
            CaptureStatus::disabled(format!("sem interface utilizável ({e})")),
        ),
        Ok((watcher, iface)) => {
            match PacketWatcher::start_capture_thread(iface, Arc::clone(&watcher.metrics)) {
                Ok(()) => (
                    watcher.metrics,
                    CaptureStatus::active(watcher.interface_name),
                ),
                Err(e) => (
                    metrics,
                    CaptureStatus::disabled(format!(
                        "sem captura: rode com CAP_NET_RAW (setcap) p/ tráfego ({e})"
                    )),
                ),
            }
        }
    }
}

/// Captura passiva numa interface: resolve o nome (ou escolhe a padrão) e
/// mantém as métricas compartilhadas com a TUI.
pub struct PacketWatcher {
    /// Nome da interface em captura.
    pub interface_name: String,
    /// Métricas compartilhadas (thread de captura escreve, TUI lê).
    pub metrics: Arc<TrafficMetrics>,
}

/// Divide `--interface` em nomes (`"eth0, wlan0"` → 2). `None`/vazio = `[]`
/// (o chamador usa a interface padrão).
pub fn split_interface_spec(spec: Option<&str>) -> Vec<String> {
    spec.map_or_else(Vec::new, |s| {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    })
}

impl PacketWatcher {
    /// Localiza a interface (`None` = primeira ativa não-loopback com IPs).
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

    /// Sobe a thread de captura (bloqueante em `datalink::channel`). Uma por
    /// interface; exige `CAP_NET_RAW`.
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
            .name("pingenty-pcap".to_string())
            .spawn(move || loop {
                match rx.next() {
                    Ok(frame) => Self::process_frame(frame, &metrics),
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(e) => {
                        eprintln!("Captura interrompida: {e}");
                        break;
                    }
                }
            })?;

        Ok(())
    }

    /// Processa um frame Ethernet lido do canal: remove tags VLAN, despacha pelo
    /// ethertype e alimenta as métricas. Extraído do loop de captura para ser
    /// testável sem abrir interface (e sem privilégio de rede).
    fn process_frame(frame: &[u8], metrics: &Arc<TrafficMetrics>) {
        let len = frame.len() as u64;
        let Some(eth) = EthernetPacket::new(frame) else {
            return;
        };
        let (ethertype, payload) = strip_vlan_tags(eth.get_ethertype(), eth.payload());
        match ethertype {
            EtherTypes::Ipv4 => {
                if let Some(ip) = Ipv4Packet::new(payload) {
                    Self::process_l4(
                        IpAddr::V4(ip.get_source()),
                        IpAddr::V4(ip.get_destination()),
                        ip.get_next_level_protocol(),
                        ip.payload(),
                        len,
                        metrics,
                    );
                }
            }
            EtherTypes::Ipv6 => {
                // `payload` (já sem VLAN), não `eth.payload()`: com tag, o header
                // IPv6 não começa no offset 14 e o parse falha em silêncio.
                if let Some(ip) = Ipv6Packet::new(payload) {
                    Self::process_l4(
                        IpAddr::V6(ip.get_source()),
                        IpAddr::V6(ip.get_destination()),
                        ip.get_next_header(),
                        ip.payload(),
                        len,
                        metrics,
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

        metrics.record(
            FiveTuple {
                src_ip: src,
                dst_ip: dst,
                src_port: src_p,
                dst_port: dst_p,
                protocol: proto_str,
            },
            raw_len,
        );
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

    #[test]
    fn split_interface_spec_aceita_lista_e_vazio() {
        assert!(split_interface_spec(None).is_empty());
        assert!(split_interface_spec(Some("  ")).is_empty());
        assert_eq!(
            split_interface_spec(Some("eth0, wlan0,,lo")),
            vec!["eth0", "wlan0", "lo"]
        );
    }

    fn tuple(proto: &'static str, dst: u8) -> FiveTuple {
        FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, dst)),
            src_port: 1234,
            dst_port: 80,
            protocol: proto,
        }
    }

    #[test]
    fn soma_e_merge_agregam_sem_concatenar() {
        let a = Arc::new(TrafficMetrics::default());
        let b = Arc::new(TrafficMetrics::default());
        a.record(tuple("TCP", 2), 100);
        a.record(tuple("TCP", 2), 100);
        b.record(tuple("TCP", 2), 50);
        b.record(tuple("UDP", 3), 60);
        let all = vec![Arc::clone(&a), Arc::clone(&b)];

        let sum = TrafficMetrics::sum_snapshots(&all);
        assert_eq!(sum.tcp_packets, 3);
        assert_eq!(sum.tcp_bytes, 250);
        assert_eq!(sum.udp_packets, 1);

        // Mesmo 5-tuple soma (não duplica a entrada); distintos coexistem;
        // ordem por bytes desc.
        let merged = TrafficMetrics::merge_flows(&all);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].1.packet_count, 3);
        assert_eq!(merged[0].1.byte_count, 250);
        assert_eq!(merged[1].1.byte_count, 60);
    }

    // ---- Frames Ethernet montados byte a byte (sem privilégio de rede) ----
    fn udp_bytes(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&8u16.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp
    }

    /// [MAC dst][MAC src][cadeia de tags VLAN…][ethertype interno][l3]
    fn eth_frame(inner_ethertype: u16, vlan_ethertypes: &[u16], l3: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
        let mut header = inner_ethertype.to_be_bytes().to_vec();
        for et in vlan_ethertypes.iter().rev() {
            let mut next = et.to_be_bytes().to_vec();
            next.extend_from_slice(&[0x00, 0x64]); // TCI: VLAN 100
            next.extend_from_slice(&header);
            header = next;
        }
        frame.extend_from_slice(&header);
        frame.extend_from_slice(l3);
        frame
    }

    fn udp_ipv4(src_port: u16, dst_port: u16) -> Vec<u8> {
        let udp = udp_bytes(src_port, dst_port);
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&udp);
        ip
    }

    fn udp_ipv6(src_port: u16, dst_port: u16) -> Vec<u8> {
        let udp = udp_bytes(src_port, dst_port);
        let mut ip = vec![0x60, 0x00, 0x00, 0x00];
        ip.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        ip.push(17); // next header = UDP
        ip.push(64); // hop limit
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[15] = 0x01;
        let mut dst = [0u8; 16];
        dst[0] = 0x20;
        dst[1] = 0x01;
        dst[15] = 0x02;
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);
        ip
    }

    #[test]
    fn sem_vlan_passa_direto() {
        let payload = [0x45u8, 0x00, 0x00, 0x14];
        let (ethertype, rest) = strip_vlan_tags(EtherTypes::Ipv4, &payload);
        assert_eq!(ethertype, EtherTypes::Ipv4);
        assert_eq!(rest, &payload);
    }

    #[test]
    fn tag_8021q_e_qinq_sao_removidas() {
        // Uma tag 802.1Q: [TCI][ethertype interno][l3…]
        let uma = [0x00u8, 0x64, 0x08, 0x00, 0xAA];
        let (ethertype, rest) = strip_vlan_tags(EtherTypes::Vlan, &uma);
        assert_eq!(ethertype, EtherTypes::Ipv4);
        assert_eq!(rest, &[0xAA]);

        // QinQ: 0x88A8 externo envolvendo 0x8100, interno IPv6.
        let duas = [0x00u8, 0x64, 0x81, 0x00, 0x00, 0x64, 0x86, 0xDD, 0xBB];
        let (ethertype, rest) = strip_vlan_tags(EtherType(0x88A8), &duas);
        assert_eq!(ethertype, EtherType(0x86DD));
        assert_eq!(rest, &[0xBB]);
    }

    #[test]
    fn mais_de_duas_tags_para_no_limite() {
        // 3 tags: o loop cobre 2 níveis, a terceira permanece — mas sem travar.
        let tres = [
            0x00u8, 0x64, 0x81, 0x00, 0x00, 0x64, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0xCC,
        ];
        let (ethertype, rest) = strip_vlan_tags(EtherTypes::Vlan, &tres);
        assert_eq!(ethertype, EtherTypes::Vlan);
        assert_eq!(rest, &[0x00, 0x64, 0x08, 0x00, 0xCC]);
    }

    #[test]
    fn frame_vlan_truncado_nao_causa_panic() {
        // Só o TCI, sem ethertype interno: precisa parar em vez de indexar.
        let curto = [0x00u8, 0x64];
        let (ethertype, rest) = strip_vlan_tags(EtherTypes::Vlan, &curto);
        assert_eq!(ethertype, EtherTypes::Vlan);
        assert_eq!(rest, &curto);
    }

    #[test]
    fn frame_ipv4_sem_vlan_indexa_fluxo() {
        let m = Arc::new(TrafficMetrics::default());
        let frame = eth_frame(0x0800, &[], &udp_ipv4(5000, 53));
        PacketWatcher::process_frame(&frame, &m);
        let snap = m.global_protocols.snapshot();
        assert_eq!(snap.udp_packets, 1);
        assert_eq!(snap.udp_bytes, frame.len() as u64);
        let flows = m.flows.read().expect("read");
        let (tuple, flow) = flows.iter().next().expect("fluxo indexado");
        assert_eq!(tuple.protocol, "UDP");
        assert_eq!(tuple.src_port, 5000);
        assert_eq!(tuple.dst_port, 53);
        assert_eq!(flow.packet_count, 1);
    }

    #[test]
    fn frame_ipv4_com_tag_8021q_indexa_fluxo() {
        // Sem remover a tag, o header IPv4 não está no offset esperado.
        let m = Arc::new(TrafficMetrics::default());
        let frame = eth_frame(0x0800, &[0x8100], &udp_ipv4(5000, 53));
        PacketWatcher::process_frame(&frame, &m);
        assert_eq!(m.global_protocols.snapshot().udp_packets, 1);
        assert_eq!(m.flows.read().expect("read").len(), 1);
    }

    #[test]
    fn frame_ipv6_com_qinq_indexa_fluxo() {
        // Regressão de bug real: o branch IPv6 usava `eth.payload()` e descartava
        // frames com VLAN em silêncio (nenhum fluxo, nenhum contador).
        let m = Arc::new(TrafficMetrics::default());
        let frame = eth_frame(0x86DD, &[0x88A8, 0x8100], &udp_ipv6(4000, 443));
        PacketWatcher::process_frame(&frame, &m);
        let snap = m.global_protocols.snapshot();
        assert_eq!(snap.udp_packets, 1, "IPv6 com VLAN precisa ser indexado");
        let flows = m.flows.read().expect("read");
        let (tuple, flow) = flows.iter().next().expect("fluxo indexado");
        assert_eq!(tuple.src_port, 4000);
        assert_eq!(tuple.dst_port, 443);
        assert_eq!(flow.byte_count, frame.len() as u64);
    }

    #[test]
    fn frame_nao_ip_conta_como_outro() {
        let m = Arc::new(TrafficMetrics::default());
        let frame = eth_frame(0x0806, &[], &[0u8; 28]); // ARP
        PacketWatcher::process_frame(&frame, &m);
        let snap = m.global_protocols.snapshot();
        assert_eq!(snap.other_packets, 1);
        assert_eq!(snap.udp_packets, 0);
        assert!(m.flows.read().expect("read").is_empty());
    }

    #[test]
    fn frame_truncado_nao_causa_panic() {
        let m = Arc::new(TrafficMetrics::default());
        PacketWatcher::process_frame(&[], &m);
        PacketWatcher::process_frame(&[0x02, 0x00], &m);
        let snap = m.global_protocols.snapshot();
        let total = snap.udp_packets + snap.tcp_packets + snap.icmp_packets + snap.other_packets;
        assert_eq!(total, 0, "frame curto demais não pode ser contado");
    }

    #[test]
    fn setup_capture_nunca_aborta_o_dashboard() {
        // Interface inexistente: sempre cai no downgrade, e o motivo nunca é vazio.
        let (metrics, capture) = setup_capture(Some("iface-que-nao-existe-xyz".into()));
        assert!(capture.interface.is_none());
        assert!(!capture
            .warning
            .expect("sem captura sempre explica")
            .is_empty());
        assert_eq!(metrics.global_protocols.snapshot().tcp_packets, 0);
    }
}
