# Roadmap v0.2.0 — "daily driver"

Objetivo: transformar o Pingenty em ferramenta de uso diário, não só demo.
Ordem de execução: 1 → 2 → 3 → 4 → 5 (2 alimenta o 5; 3 independe e pode ir em paralelo).

## 1. Alertas de latência/perda (P0)

**Comportamento.** No `dashboard`, cada host é avaliado a cada tick contra dois
limiares. Entrada e saída de alerta geram uma linha no stderr (edge-triggered —
uma linha por transição, nunca spam por tick). No painel, host em alerta rende
a linha em vermelho + contador `Alertas: N` no rodapé.

**CLI** (subcomando `dashboard`):
- `--alert-loss 10.0` — % de perda que dispara alerta (`0` desliga)
- `--alert-rtt 200` — RTT médio em ms que dispara alerta (`0` desliga)

**Arquivos.**
- `src/cli.rs` — flags + teste de parse (inclui `0` = desligado)
- `src/tui/app.rs` — estado por host (`Normal`/`Alertando`), função pura
  `avaliar(host, loss, avg_rtt, limiares) -> bool` + detecção de transição
- `src/tui/ui.rs` — render da linha em alerta e do contador no rodapé
- `src/main.rs` — `eprintln!` nas transições (entra/sai)

**Testes.** Unidade em `app.rs`: normal→alerta→normal com 3 ticks; parse em
`cli.rs`.

**Aceite.** Host com perda acima do limiar fica vermelho em ≤2 ticks; cada
transição gera exatamente 1 linha no stderr.

## 2. Export ao vivo CSV/JSON (P0)

**Comportamento.** Flags do `dashboard` que anexam amostras em tempo real:
- `--export-csv ping.csv` — só amostras de ping, flat:
  `timestamp,host,rtt_ms,loss_pct,modo` (cabeçalho escrito uma vez)
- `--export-json eventos.ndjson` — NDJSON com campo `kind`:
  `{"t":"...","kind":"ping","host":"...","rtt_ms":..,"loss_pct":..,"modo":"icmp|tcp"}`
  e `{"t":"...","kind":"dns","domain":"...","status":"ok|nxdomain|erro","latency_ms":..}`

**Arquivos.**
- `src/export.rs` (novo) — writers + formatação de linha (puro, sem I/O nos
  formatadores para ser testável)
- `src/cli.rs` — flags; `src/main.rs` — abre arquivos, passa handles
- `src/lib.rs` — `pub mod export`

**Testes.** Unidade em `export.rs`: linha CSV e objeto NDJSON byte-exatos.

**Aceite.** Dashboard 5 s com as flags → arquivos existem, CSV parseável com
cabeçalho, NDJSON com ≥1 linha de cada `kind`.

## 3. Docs 20% → 70%+ (P0)

**Comportamento.** Doc-comments em todos os itens públicos de `ping.rs`,
`dns.rs`, `watch.rs`, `cli.rs` e `export.rs`.

**Arquivos.**
- `src/lib.rs` — `#![warn(missing_docs)]` (o CI já roda clippy com
  `-D warnings`, então a cobertura passa a ser fiscalizada automaticamente)
- doc-comments nos 5 módulos

**Aceite.** `cargo doc --no-deps` sem warnings; docs.rs da próxima versão >70%.

## 4. `watch` multi-interface (P1)

**Comportamento.** `--interface eth0,wlan0` (vírgula). Uma thread de captura
por interface — o design atual já é assim, então não há contenção nova e o
gatilho do sharding/DashMap documentado no README continua não disparando.
O resumo soma os snapshots; a tabela de fluxos agrega por 5-tuple com coluna
de origem implícita (sem coluna nova: fluxos de interfaces distintas com
mesmo 5-tuple somam — documentar).

**Arquivos.**
- `src/watch.rs` — construtor por lista (`Vec`), agregação de snapshots
- `src/cli.rs` — ajuda atualizada; `src/main.rs` — loop sobre interfaces
- `src/tui/app.rs` — dashboard aceita `metrics` já agregado (sem mudança)

**Testes.** Unidade da agregação (2 snapshots → 1 soma); parse em `cli.rs`.

**Aceite.** `watch --interface lo,lo` não duplica contadores na soma
(agregação soma, não concatena); erro ao abrir uma interface não aborta as
outras (aviso no stderr, segue com as válidas).

## 5. Histórico persistente + `export` (P1)

**Comportamento.** O dashboard sempre anexa ao histórico
(`$XDG_DATA_HOME/pingenty/history.jsonl`, fallback `~/.local/share/...` —
`std::env`, sem dependência nova). Rotação: acima de 10 MB renomeia para
`history.jsonl.1` (1 backup só).
`--no-history` desliga. Novo subcomando lê o histórico e converte:

```
pingenty export --format csv|json --last 86400 [caminho]
```

`--last` em segundos (sem parsing de data — `chrono` foi removido de
propósito). Sem `--last`, exporta tudo. Saída em stdout se caminho omitido.

**Arquivos.**
- `src/export.rs` — leitor do JSONL + filtro por idade + conversores
  (reuso dos formatadores do item 2)
- `src/cli.rs` — subcomando `Export`, flag `--no-history` no dashboard
- `src/main.rs` — wiring

**Testes.** Unidade: filtro `--last`, conversão JSONL→CSV; integração leve:
roda dashboard 5 s, confere que o histórico cresceu e que `export` o lê.

**Aceite.** Após 5 s de dashboard, `export --last 3600 --format csv`
imprime CSV válido com as amostras do período.

## Fora do escopo (de propósito)

- Sharding/DashMap nos flows — sem N capturas concorrentes, o lock global
  vence (benchmark no README). Reavaliar só se o item 4 mudar o design.
- Windows/macOS — pnet/AF_PACKET é Linux-only; portar é outro projeto.
- AUR/Homebrew — distribuição, não produto; v0.2.1 se houver demanda.
- Arquivo de config — flags bastam até ~20; hoje são 9 no dashboard.
