//! Pingenty — monitor de rede assíncrono.
//!
//! Os módulos são expostos como biblioteca para que testes de integração e
//! benchmarks possam usar o mesmo código que o binário executa (o binário em
//! `main.rs` é só a camada de CLI/wiring).

#![warn(missing_docs)]

/// CLI (clap): subcomandos e flags.
pub mod cli;
/// Resolução DNS com RTT (Hickory).
pub mod dns;
/// Export ao vivo CSV/NDJSON do dashboard.
pub mod export;
/// Ping ICMP/ICMPv6 com fallback TCP.
pub mod ping;
/// Dashboard TUI (estado + render).
pub mod tui;
/// Captura passiva e agregação por protocolo/5-tuple.
pub mod watch;
