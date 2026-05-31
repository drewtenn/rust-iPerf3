//! CLI parsing for `rPerf3`.
//!
//! Accepts either `-s` (server mode) or `-c <host>` (client mode) as
//! mutually-exclusive top-level flags — one must be given. Parsed
//! [`Cli`] values convert into a [`Mode`] that the binary dispatches
//! on, keeping the rest of the code free of clap-specific types.

use clap::{ArgGroup, Parser};

use crate::common::test::Config;
use crate::common::wire::DEFAULT_TCP_LEN;
use crate::common::{bandwidth, Direction, TransportKind};

/// Default iPerf3 control port.
pub const DEFAULT_PORT: u16 = 5201;
/// Default test duration in seconds, matching iPerf3.
pub const DEFAULT_TIME_SECS: u32 = 10;
/// Default parallel stream count.
pub const DEFAULT_PARALLEL: u32 = 1;
/// Default listen address when running as a server.
pub const DEFAULT_BIND: &str = "0.0.0.0";
/// Default omit-window length in seconds. Matches iPerf3's behavior of
/// not omitting anything unless explicitly requested.
pub const DEFAULT_OMIT_SECS: u32 = 0;
/// iPerf3's default UDP payload size. Small enough to fit in a standard
/// Ethernet MTU without IP fragmentation (1500 − 20 IP − 8 UDP = 1472;
/// iPerf3 uses 1460 to leave headroom for encapsulation).
pub const DEFAULT_UDP_LEN: u32 = 1460;
/// Default bandwidth for UDP streams (1 Mbps), matching iperf3's UDP default.
pub const DEFAULT_UDP_BANDWIDTH_BPS: u64 = 1_000_000;

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(name = "rperf3", version, about = "rPerf3 — a Rust iPerf3-compatible client/server")]
#[command(disable_version_flag = true)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["server", "host"]),
))]
pub struct Cli {
    /// Run as a server (listen for incoming connections).
    #[arg(short = 's', long = "server")]
    pub server: bool,

    /// Run as a client and connect to this server host.
    #[arg(short = 'c', long = "client", value_name = "HOST")]
    pub host: Option<String>,

    /// Server port.
    #[arg(short = 'p', long = "port", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// Test duration in seconds (client-side).
    #[arg(short = 't', long = "time", default_value_t = DEFAULT_TIME_SECS)]
    pub time: u32,

    /// Number of parallel streams (client-side).
    #[arg(short = 'P', long = "parallel", default_value_t = DEFAULT_PARALLEL)]
    pub parallel: u32,

    /// Bytes per write. Default depends on transport: TCP uses iPerf3's
    /// 128 KiB, UDP uses 1460 bytes (sub-MTU). When set explicitly,
    /// the value is honored as-is.
    #[arg(short = 'l', long = "len")]
    pub len: Option<u32>,

    /// Seconds to omit at the start of the test (excludes TCP slow
    /// start from the reported measurement window). iPerf3-compatible.
    #[arg(short = 'O', long = "omit", default_value_t = DEFAULT_OMIT_SECS)]
    pub omit: u32,

    /// Use UDP rather than TCP for the data streams.
    #[arg(short = 'u', long = "udp")]
    pub udp: bool,

    /// Target bandwidth for UDP (and TCP when set). Accepts integer bps,
    /// or K/M/G suffixes. `0` = unlimited. Default: `1M` when `-u`, else `0`.
    #[arg(short = 'b', long = "bandwidth")]
    pub bandwidth: Option<String>,

    /// Exit after one test (default is to loop forever, matching iperf3).
    #[arg(short = '1', long = "one-off")]
    pub one_off: bool,

    /// Maximum concurrent sessions. Default 1 (matches iperf3). rperf3
    /// extension: N > 1 allows N simultaneous tests via cookie demux.
    #[arg(long = "max-concurrent", default_value_t = 1)]
    pub max_concurrent: u32,

    /// Reverse the direction of the test. Server sends, client receives.
    #[arg(short = 'R', long = "reverse", conflicts_with = "bidir")]
    pub reverse: bool,

    /// Run in bidirectional mode. Both sides send and receive simultaneously.
    #[arg(long = "bidir")]
    pub bidir: bool,

    /// Emit end-of-test JSON output (iperf3-compatible shape).
    #[arg(short = 'J', long = "json")]
    pub json: bool,

    /// Force a specific format unit for text output (k, K, m, M, g, G).
    #[arg(short = 'f', long = "format")]
    pub format: Option<char>,

    /// Redirect all output to this file.
    #[arg(long = "logfile")]
    pub logfile: Option<std::path::PathBuf>,

    /// Verbose output (currently a no-op stub — accepted for iperf3 CLI compat).
    #[arg(short = 'V', long = "verbose")]
    pub verbose: bool,

    /// Prefix each output line with a timestamp (currently a no-op stub).
    #[arg(long = "timestamps")]
    pub timestamps: bool,

    /// Socket send/receive buffer size (SO_SNDBUF / SO_RCVBUF). Accepts K/M/G suffix.
    /// Parsed; socket-option application is a Linux follow-up.
    #[arg(short = 'w', long = "window")]
    pub window: Option<String>,

    /// TCP maximum segment size in bytes (TCP_MAXSEG). Linux-only; silently ignored elsewhere.
    /// Parsed stub — setsockopt application is a Linux follow-up.
    #[arg(short = 'M', long = "set-mss")]
    pub mss: Option<u32>,

    /// TCP congestion control algorithm name (e.g. cubic, bbr). Linux-only.
    /// Parsed stub — application is a Linux follow-up.
    #[arg(short = 'C', long = "congestion")]
    pub congestion: Option<String>,

    /// IP type-of-service byte (IP_TOS). Accepts decimal, 0x-hex, or 0-octal.
    /// Parsed stub — setsockopt application is a Linux follow-up.
    #[arg(short = 'S', long = "tos")]
    pub tos: Option<String>,

    /// Use zero-copy (sendfile). Parsed stub — not yet implemented.
    #[arg(short = 'Z', long = "zerocopy")]
    pub zerocopy: bool,

    /// Terminate after sending/receiving this many bytes. Accepts K/M/G suffix.
    /// Parsed stub — termination logic is a follow-up.
    #[arg(short = 'n', long = "bytes")]
    pub bytes: Option<String>,

    /// Terminate after this many blocks (writes). Parsed stub — follow-up.
    #[arg(short = 'k', long = "blockcount")]
    pub blockcount: Option<u64>,

    /// Prefix every output line with this title string (e.g. "run-1").
    #[arg(short = 'T', long = "title")]
    pub title: Option<String>,

    /// CPU affinity specification (e.g. "0,1" or "0-3"). Linux-only.
    /// Parsed stub — application is a Linux follow-up.
    #[arg(short = 'A', long = "affinity")]
    pub affinity: Option<String>,

    /// Username for RSA authentication (client-side).
    #[arg(long = "username")]
    pub username: Option<String>,

    /// Password for RSA authentication (client-side). If omitted and
    /// --rsa-public-key is set, the password is prompted interactively.
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Path to the server's RSA public key PEM file (client-side).
    #[arg(long = "rsa-public-key")]
    pub rsa_public_key: Option<std::path::PathBuf>,

    /// Path to the server's RSA private key PEM file (server-side).
    #[arg(long = "rsa-private-key")]
    pub rsa_private_key: Option<std::path::PathBuf>,

    /// Path to the authorized users CSV file (server-side).
    /// Format: one `username,sha256hex_of_password` per line.
    #[arg(long = "authorized-users")]
    pub authorized_users: Option<std::path::PathBuf>,
}

/// Result of a successful parse: either client or server mode, each
/// carrying a fully-populated `Config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Client(Config),
    Server(Config),
}

impl Cli {
    pub fn into_mode(self) -> Mode {
        self.try_into_mode().unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(2);
        })
    }

    pub fn try_into_mode(self) -> Result<Mode, String> {
        let transport = if self.udp { TransportKind::Udp } else { TransportKind::Tcp };
        let bandwidth = match self.bandwidth.as_deref() {
            Some(s) => bandwidth::parse(s)?,
            None if self.udp => DEFAULT_UDP_BANDWIDTH_BPS,
            None => 0,
        };
        let len = self.len.unwrap_or(if self.udp { DEFAULT_UDP_LEN } else { DEFAULT_TCP_LEN as u32 });

        let direction = if self.bidir {
            Direction::Bidirectional
        } else if self.reverse {
            Direction::Reverse
        } else {
            Direction::Forward
        };

        // Parse window size (-w): binary K/M/G multipliers, stored as u32 bytes.
        let window_size = match self.window.as_deref() {
            Some(s) => {
                let v = bandwidth::parse_size(s)?;
                if v > u32::MAX as u64 {
                    return Err(format!("window size '{}' exceeds u32::MAX", s));
                }
                Some(v as u32)
            }
            None => None,
        };

        // Parse TOS (-S): decimal, 0x-hex, or 0-octal.
        let tos = match self.tos.as_deref() {
            Some(s) => Some(bandwidth::parse_tos(s)?),
            None => None,
        };

        // Parse byte count (-n): binary K/M/G multipliers.
        let total_bytes = match self.bytes.as_deref() {
            Some(s) => Some(bandwidth::parse_size(s)?),
            None => None,
        };

        let base = Config {
            host: self.host.clone().unwrap_or_else(|| DEFAULT_BIND.to_string()),
            port: self.port,
            time: self.time,
            parallel: self.parallel,
            len,
            omit: self.omit,
            transport,
            bandwidth,
            one_off: self.one_off,
            max_concurrent: self.max_concurrent.max(1),
            direction,
            json: self.json,
            format_unit: self.format,
            logfile: self.logfile,
            window_size,
            mss: self.mss,
            congestion: self.congestion,
            tos,
            zero_copy: self.zerocopy,
            total_bytes,
            total_blocks: self.blockcount,
            title: self.title.clone(),
            affinity: self.affinity,
            username: self.username,
            password: self.password,
            rsa_public_key: self.rsa_public_key,
            rsa_private_key: self.rsa_private_key,
            authorized_users: self.authorized_users,
        };
        Ok(if self.server { Mode::Server(base) } else { Mode::Client(base) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_full_client_flag_set() {
        let cli = Cli::try_parse_from([
            "rperf3", "-c", "127.0.0.1", "-p", "5202", "-t", "3", "-P", "2", "-l", "65536",
        ])
        .expect("parse");

        assert!(!cli.server);
        assert_eq!(cli.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(cli.port, 5202);
        assert_eq!(cli.time, 3);
        assert_eq!(cli.parallel, 2);
        assert_eq!(cli.len, Some(65_536));
    }

    #[test]
    fn applies_defaults_when_only_host_given() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "example.com"]).expect("parse");
        assert_eq!(cli.port, DEFAULT_PORT);
        assert_eq!(cli.time, DEFAULT_TIME_SECS);
        assert_eq!(cli.parallel, DEFAULT_PARALLEL);
        assert_eq!(cli.len, None);
    }

    #[test]
    fn udp_default_len_is_sub_mtu() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-u"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.len, DEFAULT_UDP_LEN),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn tcp_default_len_is_iperf3_tcp_default() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.len, DEFAULT_TCP_LEN as u32),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn parses_server_only_mode() {
        let cli = Cli::try_parse_from(["rperf3", "-s"]).expect("parse");
        assert!(cli.server);
        assert_eq!(cli.host, None);
        assert_eq!(cli.port, DEFAULT_PORT);
    }

    #[test]
    fn parses_server_with_port() {
        let cli = Cli::try_parse_from(["rperf3", "-s", "-p", "5202"]).expect("parse");
        assert!(cli.server);
        assert_eq!(cli.port, 5202);
    }

    #[test]
    fn server_and_client_conflict() {
        let err = Cli::try_parse_from(["rperf3", "-s", "-c", "1.2.3.4"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn missing_both_server_and_client_is_error() {
        assert!(Cli::try_parse_from(["rperf3"]).is_err());
    }

    #[test]
    fn client_mode_uses_host() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "10.0.0.1", "-p", "5202"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => {
                assert_eq!(cfg.host, "10.0.0.1");
                assert_eq!(cfg.port, 5202);
                assert_eq!(cfg.host_port(), "10.0.0.1:5202");
            }
            Mode::Server(_) => panic!("expected client mode"),
        }
    }

    #[test]
    fn server_mode_uses_default_bind() {
        let cli = Cli::try_parse_from(["rperf3", "-s", "-p", "5202"]).unwrap();
        match cli.into_mode() {
            Mode::Server(cfg) => {
                assert_eq!(cfg.host, DEFAULT_BIND);
                assert_eq!(cfg.port, 5202);
            }
            Mode::Client(_) => panic!("expected server mode"),
        }
    }

    #[test]
    fn parses_udp_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-u"]).unwrap();
        assert!(cli.udp);
        match cli.into_mode() {
            Mode::Client(cfg) => {
                assert_eq!(cfg.transport, crate::common::TransportKind::Udp);
                assert_eq!(cfg.bandwidth, 1_000_000);
            }
            Mode::Server(_) => panic!("expected client"),
        }
    }

    #[test]
    fn parses_bandwidth_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-u", "-b", "100M"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.bandwidth, 100_000_000),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn bandwidth_zero_is_unlimited() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-u", "-b", "0"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.bandwidth, 0),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn tcp_default_bandwidth_is_zero() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => {
                assert_eq!(cfg.transport, crate::common::TransportKind::Tcp);
                assert_eq!(cfg.bandwidth, 0);
            }
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn invalid_bandwidth_errors_on_try_into_mode() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-b", "garbage"]).unwrap();
        assert!(cli.try_into_mode().is_err());
    }

    #[test]
    fn parses_reverse_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-R"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.direction, crate::common::Direction::Reverse),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn parses_bidir_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "--bidir"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.direction, crate::common::Direction::Bidirectional),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn reverse_and_bidir_conflict() {
        let err = Cli::try_parse_from(["rperf3", "-c", "h", "-R", "--bidir"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn default_direction_is_forward() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h"]).unwrap();
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.direction, crate::common::Direction::Forward),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn one_off_defaults_false() {
        let cli = Cli::try_parse_from(["rperf3", "-s"]).unwrap();
        assert!(!cli.one_off);
        match cli.into_mode() {
            Mode::Server(cfg) => assert!(!cfg.one_off),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_one_off_short() {
        let cli = Cli::try_parse_from(["rperf3", "-s", "-1"]).unwrap();
        assert!(cli.one_off);
    }

    #[test]
    fn parses_max_concurrent() {
        let cli = Cli::try_parse_from(["rperf3", "-s", "--max-concurrent", "4"]).unwrap();
        assert_eq!(cli.max_concurrent, 4);
        match cli.into_mode() {
            Mode::Server(cfg) => assert_eq!(cfg.max_concurrent, 4),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_json_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-J"]).unwrap();
        assert!(cli.json);
        match cli.into_mode() {
            Mode::Client(cfg) => assert!(cfg.json),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_format_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-f", "M"]).unwrap();
        assert_eq!(cli.format, Some('M'));
        match cli.into_mode() {
            Mode::Client(cfg) => assert_eq!(cfg.format_unit, Some('M')),
            _ => panic!(),
        }
    }

    #[test]
    fn parses_logfile_flag() {
        let cli = Cli::try_parse_from(["rperf3", "-s", "--logfile", "/tmp/out.log"]).unwrap();
        assert!(cli.logfile.is_some());
    }

    #[test]
    fn parses_verbose_and_timestamps_stubs() {
        let cli = Cli::try_parse_from(["rperf3", "-c", "h", "-V", "--timestamps"]).unwrap();
        assert!(cli.verbose);
        assert!(cli.timestamps);
    }
}
