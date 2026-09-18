//! Benchmark de contenção do mapa de fluxos.
//!
//! Pergunta que este benchmark responde: vale trocar o `RwLock` global do mapa
//! de 5-tuples por sharding/`DashMap`? (limitação documentada no README)
//!
//! O caminho de produção é medido por `TrafficMetrics::record` — contadores
//! atômicos (sem lock) + agregação por 5-tuple (com lock). A alternativa
//! *sharded* é implementada **aqui**, no benchmark, para comparação: o código de
//! produção não muda sem evidência.
//!
//! Rodar: `cargo bench`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use netmon::ping::icmp_checksum;
use netmon::watch::{FiveTuple, FlowStat, TrafficMetrics};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Shards da alternativa avaliada.
const SHARDS: usize = 16;
/// Fluxos distintos no conjunto de trabalho (tráfego realista, não 1 chave só).
const FLOW_POOL: usize = 1024;
/// Pacotes processados por thread em cada iteração dos testes concorrentes.
const PER_THREAD: usize = 5_000;

fn tuple_pool(n: usize) -> Vec<FiveTuple> {
    (0..n)
        .map(|i| FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)),
            src_port: (49152 + (i % 16384)) as u16,
            dst_port: 443,
            protocol: if i % 4 == 0 { "UDP" } else { "TCP" },
        })
        .collect()
}

/// Alternativa hipotética ao lock global: 16 shards independentes, cada um com
/// seu próprio `RwLock` (o mesmo esquema que um `DashMap` usaria por baixo).
#[derive(Default)]
struct ShardedFlows {
    shards: Vec<RwLock<HashMap<FiveTuple, FlowStat>>>,
}

impl ShardedFlows {
    fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| RwLock::new(HashMap::new())).collect(),
        }
    }

    fn record(&self, tuple: FiveTuple, raw_len: u64) {
        let mut hasher = DefaultHasher::new();
        tuple.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % SHARDS;
        if let Ok(mut shard) = self.shards[idx].write() {
            let flow = shard.entry(tuple).or_default();
            flow.byte_count += raw_len;
            flow.packet_count += 1;
            flow.last_seen = Some(Instant::now());
        }
    }
}

/// Baseline micro: custo do checksum ICMPv4 calculado (RFC 1071).
fn bench_checksum(c: &mut Criterion) {
    let echo = [
        0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, b'N', b'E', b'T', b'M',
    ];
    c.bench_function("checksum_icmp_12b", |b| {
        b.iter(|| icmp_checksum(black_box(&echo)))
    });
}

/// Custo por pacote, uma thread: o caminho exato do `netmon watch`.
fn bench_pacote_individual(c: &mut Criterion) {
    let pool = tuple_pool(FLOW_POOL);
    let mut group = c.benchmark_group("pacote_individual");
    group.throughput(Throughput::Elements(1));

    group.bench_function("global_rwlock", |b| {
        let metrics = TrafficMetrics::default();
        let mut i = 0usize;
        b.iter(|| {
            let tuple = pool[i % FLOW_POOL].clone();
            i += 1;
            metrics.record(black_box(tuple), black_box(1500));
        });
    });

    group.bench_function("sharded16", |b| {
        let flows = ShardedFlows::new();
        let mut i = 0usize;
        b.iter(|| {
            let tuple = pool[i % FLOW_POOL].clone();
            i += 1;
            flows.record(black_box(tuple), black_box(1500));
        });
    });

    group.finish();
}

/// Escala com N threads disputando o mesmo mapa (cenário hipotético: o design
/// atual tem uma thread de captura por interface).
fn bench_concorrencia(c: &mut Criterion) {
    let pool = Arc::new(tuple_pool(FLOW_POOL));
    let mut group = c.benchmark_group("concorrencia");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(2));

    for threads in [1usize, 2, 4, 8] {
        group.throughput(Throughput::Elements((threads * PER_THREAD) as u64));

        group.bench_with_input(
            BenchmarkId::new("global_rwlock", threads),
            &threads,
            |b, &threads| {
                let metrics = Arc::new(TrafficMetrics::default());
                b.iter(|| {
                    std::thread::scope(|scope| {
                        for t in 0..threads {
                            let metrics = Arc::clone(&metrics);
                            let pool = Arc::clone(&pool);
                            scope.spawn(move || {
                                for i in 0..PER_THREAD {
                                    metrics.record(pool[(i + t * 31) % FLOW_POOL].clone(), 1500);
                                }
                            });
                        }
                    });
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sharded16", threads),
            &threads,
            |b, &threads| {
                let flows = Arc::new(ShardedFlows::new());
                b.iter(|| {
                    std::thread::scope(|scope| {
                        for t in 0..threads {
                            let flows = Arc::clone(&flows);
                            let pool = Arc::clone(&pool);
                            scope.spawn(move || {
                                for i in 0..PER_THREAD {
                                    flows.record(pool[(i + t * 31) % FLOW_POOL].clone(), 1500);
                                }
                            });
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_checksum,
    bench_pacote_individual,
    bench_concorrencia
);
criterion_main!(benches);
