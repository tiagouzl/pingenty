use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "netmon",
    version = "0.1.0",
    about = "Network Monitor assíncrono em tempo real com TUI"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Medição de latência ICMP/ICMPv6 com fallback transparente para TCP
    Ping {
        /// Hostnames ou endereços IP para monitorar
        #[arg(required = true)]
        hosts: Vec<String>,

        /// Intervalo entre pings em milissegundos (mínimo 50)
        #[arg(short, long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(50..))]
        interval: u64,

        /// Timeout de cada pacote em milissegundos
        #[arg(short, long, default_value_t = 1500)]
        timeout: u64,

        /// Porta para uso no fallback TCP connect caso ICMP necessite de privilégios elevados
        #[arg(long, default_value_t = 80)]
        tcp_port: u16,
    },

    /// Resolução e benchmark de latência DNS
    Dns {
        /// Domínios a serem resolvidos
        #[arg(required = true)]
        domains: Vec<String>,

        /// Tipo de registro a consultar
        #[arg(short, long, value_enum, default_value = "a")]
        record_type: RecordTypeCli,

        /// Timeout por consulta em milissegundos
        #[arg(short, long, default_value_t = 2000, value_parser = clap::value_parser!(u64).range(100..))]
        timeout: u64,
    },

    /// Captura passiva e agregador de pacotes por protocolo e 5-tuple
    Watch {
        /// Interface de rede (ex: eth0, wlan0, en0). Se omitida, usa a interface padrão
        #[arg(short, long)]
        interface: Option<String>,

        /// Intervalo de impressão estatística em milissegundos
        #[arg(long, default_value_t = 1000)]
        interval: u64,
    },

    /// Dashboard visual unificado em TUI
    Dashboard {
        /// Hosts de ping separados por vírgula
        #[arg(long, default_value = "1.1.1.1,8.8.8.8")]
        ping_hosts: String,

        /// Domínios DNS separados por vírgula
        #[arg(long, default_value = "cloudflare.com,google.com")]
        dns_domains: String,

        /// Interface de captura passiva
        #[arg(short, long)]
        interface: Option<String>,

        /// Intervalo entre pings em milissegundos (mínimo 50)
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(50..))]
        ping_interval: u64,

        /// Timeout de cada ping em milissegundos
        #[arg(long, default_value_t = 1500)]
        ping_timeout: u64,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RecordTypeCli {
    #[value(name = "a")]
    A,
    #[value(name = "aaaa")]
    Aaaa,
    #[value(name = "cname")]
    Cname,
    #[value(name = "mx")]
    Mx,
    #[value(name = "txt")]
    Txt,
}
