//! Cross-iperf3 UDP interop. Skips when the `iperf3` binary is not on
//! PATH; otherwise runs rPerf3↔iperf3 in both directions.

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn iperf3_available() -> bool {
    Command::new("iperf3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn rperf3_client_talks_to_iperf3_server_udp() {
    if !iperf3_available() {
        println!("skipping cross-interop: iperf3 not on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let iperf3_server = Command::new("iperf3")
        .args(["-s", "-p", &port.to_string(), "-1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn iperf3 server");

    thread::sleep(Duration::from_millis(200));

    let client_cfg = rperf3::Config {
        host: "127.0.0.1".into(),
        port,
        time: 1,
        parallel: 1,
        len: 1400,
        omit: 0,
        transport: rperf3::TransportKind::Udp,
        bandwidth: 10_000_000,
        one_off: false,
        max_concurrent: 1,
        direction: rperf3::Direction::Forward,
        json: false,
        format_unit: None,
        logfile: None,
        window_size: None,
        mss: None,
        congestion: None,
        tos: None,
        zero_copy: false,
        total_bytes: None,
        total_blocks: None,
        title: None,
        affinity: None,
        username: None,
        password: None,
        rsa_public_key: None,
        rsa_private_key: None,
        authorized_users: None,
    };
    rperf3::run_client(client_cfg);

    let output = iperf3_server.wait_with_output().expect("wait iperf3");
    assert!(output.status.success(), "iperf3 server failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Mbits/sec") || stdout.contains("bits/sec"),
        "iperf3 output missing throughput line: {}",
        stdout
    );
}

#[test]
fn iperf3_client_talks_to_rperf3_server_udp() {
    if !iperf3_available() {
        println!("skipping cross-interop: iperf3 not on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let server = thread::spawn(move || rperf3::run_server_on(listener));
    thread::sleep(Duration::from_millis(200));

    let iperf3_client = Command::new("iperf3")
        .args([
            "-c",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-u",
            "-b",
            "10M",
            "-t",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn iperf3 client");

    let output = iperf3_client.wait_with_output().expect("wait iperf3");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "iperf3 client failed. stdout: {}\nstderr: {}",
        stdout,
        stderr
    );

    let total_bytes = server.join().expect("server panic").expect("server err");
    assert!(total_bytes > 100_000, "server saw only {} bytes", total_bytes);
}
