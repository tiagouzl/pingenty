//! Pingenty — monitor de rede assíncrono.
//!
//! Os módulos são expostos como biblioteca para que testes de integração e
//! benchmarks possam usar o mesmo código que o binário executa (o binário em
//! `main.rs` é só a camada de CLI/wiring).

pub mod cli;
pub mod dns;
pub mod export;
pub mod ping;
pub mod tui;
pub mod watch;
