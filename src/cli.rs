use clap::{Parser, Subcommand, ValueEnum};

/// Interface de linha de comando do Pingenty.
#[derive(Parser, Debug)]
#[command(
    name = "pingenty",
    version,
    about = "Monitor de rede assíncrono em tempo real com TUI"
)]
pub struct Cli {
    /// Subcomando a executar.
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcomandos do Pingenty (cada um também existe dentro do dashboard).
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

        /// Intervalo de impressão estatística em milissegundos (mínimo 50)
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(50..))]
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

        /// Timeout por consulta DNS em milissegundos
        #[arg(long, default_value_t = 2000)]
        dns_timeout: u64,

        /// Intervalo entre rodadas DNS em milissegundos (mínimo 500)
        #[arg(long, default_value_t = 3000, value_parser = clap::value_parser!(u64).range(500..))]
        dns_interval: u64,

        /// Porta TCP para o fallback do ping quando o ICMP é inviável
        #[arg(long, default_value_t = 80)]
        tcp_port: u16,

        /// % de perda que dispara alerta no dashboard (0 desliga)
        #[arg(long, default_value_t = 10.0)]
        alert_loss: f64,

        /// RTT médio em ms que dispara alerta no dashboard (0 desliga)
        #[arg(long, default_value_t = 200)]
        alert_rtt: u64,

        /// Anexa amostras de ping em CSV (cria com cabeçalho se novo/vazio)
        #[arg(long)]
        export_csv: Option<String>,

        /// Anexa eventos ping+DNS em NDJSON
        #[arg(long)]
        export_json: Option<String>,
    },
}

/// Tipo de registro DNS pedido no `dns` (só leitura pontual; o dashboard usa A).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum RecordTypeCli {
    /// Registro A (IPv4).
    #[value(name = "a")]
    A,
    /// Registro AAAA (IPv6).
    #[value(name = "aaaa")]
    Aaaa,
    /// Registro CNAME (apelido).
    #[value(name = "cname")]
    Cname,
    /// Registro MX (troca de e-mail).
    #[value(name = "mx")]
    Mx,
    /// Registro TXT (texto livre).
    #[value(name = "txt")]
    Txt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_aceita_knobs_de_ping_e_dns() {
        let cli = Cli::try_parse_from([
            "pingenty",
            "dashboard",
            "--ping-hosts",
            "a",
            "--dns-domains",
            "b",
            "--ping-interval",
            "500",
            "--ping-timeout",
            "800",
            "--dns-timeout",
            "900",
            "--dns-interval",
            "1200",
            "--tcp-port",
            "443",
        ])
        .expect("parse do dashboard");
        match cli.command {
            Commands::Dashboard {
                ping_interval,
                ping_timeout,
                dns_timeout,
                dns_interval,
                tcp_port,
                ..
            } => {
                assert_eq!(ping_interval, 500);
                assert_eq!(ping_timeout, 800);
                assert_eq!(dns_timeout, 900);
                assert_eq!(dns_interval, 1200);
                assert_eq!(tcp_port, 443);
            }
            _ => panic!("deveria ser dashboard"),
        }
    }

    #[test]
    fn dashboard_aceita_limiares_de_alerta_e_zero_desliga() {
        let cli = Cli::try_parse_from([
            "pingenty",
            "dashboard",
            "--alert-loss",
            "5.5",
            "--alert-rtt",
            "300",
        ])
        .expect("parse dos limiares");
        match cli.command {
            Commands::Dashboard {
                alert_loss,
                alert_rtt,
                ..
            } => {
                assert_eq!(alert_loss, 5.5);
                assert_eq!(alert_rtt, 300);
            }
            _ => panic!("deveria ser dashboard"),
        }
        // Defaults: alerta ligado (10% / 200 ms).
        let cli = Cli::try_parse_from(["pingenty", "dashboard"]).expect("defaults");
        match cli.command {
            Commands::Dashboard {
                alert_loss,
                alert_rtt,
                ..
            } => {
                assert_eq!(alert_loss, 10.0);
                assert_eq!(alert_rtt, 200);
            }
            _ => panic!("deveria ser dashboard"),
        }
    }

    #[test]
    fn intervalos_minimos_sao_rejeitados() {
        assert!(Cli::try_parse_from(["pingenty", "ping", "--interval", "49", "h"]).is_err());
        assert!(Cli::try_parse_from(["pingenty", "dashboard", "--dns-interval", "499"]).is_err());
        assert!(Cli::try_parse_from(["pingenty", "ping", "--interval", "50", "h"]).is_ok());
    }
}
