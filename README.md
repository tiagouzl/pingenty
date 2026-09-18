# Netmon — Network Monitor Assíncrono em Rust

Monitor de latência (ICMP com fallback TCP), resolução DNS com medição de RTT
e captura passiva de tráfego com agregação por protocolo e por conexão (5-tuple),
com dashboard TUI ao vivo.

## Limitações honestas da v1

- **IPv4-only no ping.** ICMPv6 usa tipo 128 e checksum sobre pseudo-header —
  ainda não implementado. Hosts AAAA caem direto no fallback TCP (documentado
  em `ping.rs`, não é falha silenciosa).
- **Lock global no mapa de flows** (`watch.rs`). Contadores por protocolo são
  atômicos (sem lock), mas o `HashMap` de 5-tuples ainda usa um `RwLock`
  global. Troca por sharding/`DashMap` fica para quando houver benchmark real.
- **TUI usa `std::sync::RwLock::try_read`** (não-bloqueante): se a thread de
  captura estiver escrevendo, o tick pula a tabela em vez de travar o executor.
- **Sem números de benchmark inventados.** Para medir de verdade:
  `iperf3` + `netmon watch` lado a lado com `tcpdump -i <iface> -q -n`,
  comparando pps, RSS (`/usr/bin/time -v`) e CPU. Até lá, sem tabela de performance.

## Privilégios (decisão de design, não bug)

- **Ping ICMP:** tenta socket DGRAM/RAW ICMP. Sem permissão → fallback TCP connect.
- **Captura datalink (`pnet`):** exige `CAP_NET_RAW`. Em produção, nunca `sudo`:

```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/netmon
./target/release/netmon dashboard
```

## Uso

```bash
netmon dashboard --ping-hosts "1.1.1.1,8.8.8.8" --dns-domains "github.com,cloudflare.com"
netmon ping 1.1.1.1 8.8.8.8 --interval 1000
netmon dns cloudflare.com archlinux.org --record-type a
netmon watch --interface eth0 --interval 1000
# validar lado a lado: sudo tcpdump -i eth0 -q -n
```

## Testes (Fase 6)

```bash
cargo test
```

Cobre: perda total/parcial (`PingStats`), checksum ICMP calculado,
rejeição de ICMP type/id errado, host inalcançável sem panic,
domínio inexistente como estado, contadores do watcher, histórico da TUI.
