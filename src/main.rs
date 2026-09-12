//
// Copyright (c) 2022 Pouriya Jamshidi (pouriya at thegraynode dot io)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/pouriyajamshidi/oxipot
//

use chrono::{DateTime, Utc};
use log::{error, info, warn};
use rusqlite::Connection;
use serde::Deserialize;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::exit;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread::{self, sleep};
use std::time::Duration;

const CONNECTION_LIMIT: u32 = 10;
const CONNECTION_FLUSH_TIME_PERIOD: Duration = Duration::from_secs(60);
const CONNECTION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(20);
const LOGIN_DELAY: Duration = Duration::from_secs(2);

const DB_URL: &str = "db/oxipot.db";
const DEFAULT_PORT: u16 = 2223;

const IP_INFO_PROVIDER: &str = "https://api.iplocation.net/?ip=";
const IP_INFO_TIMEOUT: Duration = Duration::from_secs(3);

const TELNET_ECHO: &[u8] = &[0xff, 0xfb, 0x01];
const TELNET_SUPPRESS_GO_AHEAD: &[u8] = &[0xff, 0xfb, 0x03];
const TELNET_TERMINAL_TYPE: &[u8] = &[0xff, 0xfd, 0x18];
const TELNET_TERMINAL_SPEED: &[u8] = &[0xff, 0xfd, 0x1f];
const TELNET_CARRIAGE_RETURN: &[u8] = &[0x0d];
const TELNET_TOGGLE_FLOW_CONTROL: &[u8] = &[0xff, 0xfe, 0x20];
const TELNET_LINE_MODE: &[u8] = &[0xff, 0xfe, 0x21];
const TELNET_CARRIAGE_RETURN_LINE_FEED: &[u8] = &[0xff, 0xfe, 0x22];
const TELNET_OUTPUT_MARKING: &[u8] = &[0xff, 0xfe, 0x27];
const TELNET_NEGOTIATE_SUPPRESS_GO_AHEAD: &[u8] = &[0xff, 0xfc, 0x05];
const TELNET_CRLF: &[u8] = &[0x0d, 0x0a];

const BANNER: &str = "

#############################################################################
# UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED You must have explicit,  #
# authorized permission to access or configure this device.                 #
# Unauthorized attempts and actions to access or use this system may result #
# in civil and/or criminal penalties.                                       #
# All activities performed on this device are logged and monitored.         #
#############################################################################

";

static HTTP: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(IP_INFO_TIMEOUT))
        .build()
        .into()
});

type IPInfoCache = HashMap<IpAddr, IPInfo>;

struct Intruder {
    username: String,
    password: String,
    ip_info: IPInfo,
    ip: IpAddr,
    source_port: u16,
    time: DateTime<Utc>,
}

impl Intruder {
    fn time_to_text(&self) -> String {
        self.time.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
struct IPInfo {
    country_name: String,
    #[serde(rename = "country_code2")]
    country_code: String,
    isp: String,
}

struct TelnetStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TelnetStream<'a> {
    fn new(stream: &'a TcpStream) -> Self {
        Self { stream }
    }

    fn write_all(&mut self, buf: &[u8]) {
        if let Err(e) = self.stream.write_all(buf) {
            warn!("Could not write to the telnet stream: {e}");
            self.close();
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                warn!("Could not read from the telnet stream: {e}");
                self.close();
                Err(e)
            }
        }
    }

    fn close(&mut self) {
        if let Err(e) = self.stream.shutdown(Shutdown::Both) {
            error!("Encountered {e:?} while shutting down the TCP stream");
        }
    }
}

fn create_intruders_table() -> rusqlite::Result<()> {
    if let Some(dir) = Path::new(DB_URL).parent() {
        fs::create_dir_all(dir).expect("Could not create the database directory");
    }

    info!("Opening database: {DB_URL}");
    let conn = Connection::open(DB_URL)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS intruders (
            id INTEGER PRIMARY KEY NOT NULL,
            username VARCHAR(250),
            password VARCHAR(250),
            ip VARCHAR(250),
            source_port VARCHAR(250),
            country_name VARCHAR(250),
            country_code VARCHAR(250),
            isp VARCHAR(250),
            time TIMESTAMP
        )",
        (),
    )?;

    info!("The intruders table is ready");

    Ok(())
}

fn log_to_db(intruder: &Intruder) -> rusqlite::Result<()> {
    let conn = Connection::open(DB_URL)?;

    conn.execute(
        "INSERT INTO intruders (
        username,
        password,
        ip,
        source_port,
        country_name,
        country_code,
        isp,
        time) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        (
            &intruder.username,
            &intruder.password,
            intruder.ip.to_string(),
            intruder.source_port,
            &intruder.ip_info.country_name,
            &intruder.ip_info.country_code,
            &intruder.ip_info.isp,
            intruder.time_to_text(),
        ),
    )?;

    info!("Inserted intruder {} into the database", intruder.ip);

    Ok(())
}

fn ip_info_from_db(ip: IpAddr) -> Option<IPInfo> {
    let conn = Connection::open(DB_URL).ok()?;

    conn.query_row(
        "SELECT country_name, country_code, isp FROM intruders
         WHERE ip = ? AND country_name != '' ORDER BY id DESC LIMIT 1",
        [ip.to_string()],
        |row| {
            Ok(IPInfo {
                country_name: row.get(0)?,
                country_code: row.get(1)?,
                isp: row.get(2)?,
            })
        },
    )
    .ok()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn whois(ip: IpAddr) -> Result<IPInfo, ureq::Error> {
    info!("Looking up {ip}");

    HTTP.get(format!("{IP_INFO_PROVIDER}{ip}"))
        .call()?
        .body_mut()
        .read_json()
}

fn lookup_ip_info(cache: &Mutex<IPInfoCache>, intruder: &mut Intruder) {
    if let Some(ip_info) = lock(cache).get(&intruder.ip).cloned() {
        info!("Found {} in the in-memory cache", intruder.ip);
        intruder.ip_info = ip_info;
        return;
    }

    if let Some(ip_info) = ip_info_from_db(intruder.ip) {
        info!("Found {} in the database", intruder.ip);
        lock(cache).insert(intruder.ip, ip_info.clone());
        intruder.ip_info = ip_info;
        return;
    }

    if is_private_ip(intruder.ip) {
        return;
    }

    match whois(intruder.ip) {
        Ok(ip_info) => {
            lock(cache).insert(intruder.ip, ip_info.clone());
            intruder.ip_info = ip_info;
        }
        Err(e) => warn!("Could not look up {}: {e}", intruder.ip),
    }
}

fn read_until_cr(telnet: &mut TelnetStream) -> String {
    let mut buffer = Vec::new();

    'outer: loop {
        let mut buf = [0; 1024];

        let n = match telnet.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        let text = match std::str::from_utf8(&buf[..n]) {
            Ok(text) => text,
            Err(e) => {
                warn!("Problem reading telnet stream data: {e}");
                continue;
            }
        };

        for c in text.chars() {
            if c == '\r' || c == '\n' {
                break 'outer;
            }

            if c.is_ascii() {
                buffer.push(c as u8);
            }
        }
    }

    String::from_utf8_lossy(&buffer).trim().to_string()
}

fn get_telnet_username(stream: &TcpStream) -> String {
    let mut telnet = TelnetStream::new(stream);

    telnet.write_all(BANNER.as_bytes());
    telnet.write_all(b"login: ");

    read_until_cr(&mut telnet)
}

fn get_telnet_password(stream: &TcpStream) -> String {
    let mut telnet = TelnetStream::new(stream);

    telnet.write_all(TELNET_ECHO);
    telnet.write_all(TELNET_SUPPRESS_GO_AHEAD);
    telnet.write_all(TELNET_TERMINAL_TYPE);
    telnet.write_all(TELNET_TERMINAL_SPEED);
    telnet.write_all(TELNET_CARRIAGE_RETURN);
    telnet.write_all(b"Password: ");
    telnet.write_all(TELNET_TOGGLE_FLOW_CONTROL);
    telnet.write_all(TELNET_LINE_MODE);
    telnet.write_all(TELNET_CARRIAGE_RETURN_LINE_FEED);
    telnet.write_all(TELNET_OUTPUT_MARKING);
    telnet.write_all(TELNET_NEGOTIATE_SUPPRESS_GO_AHEAD);

    let password = read_until_cr(&mut telnet);
    telnet.write_all(TELNET_CRLF);

    password
}

fn display_intruder_info(intruder: &Intruder) {
    info!("Username: {}", intruder.username);
    info!("Password: {}", intruder.password);
    info!("IP address: {}", intruder.ip);
    info!("Source port: {}", intruder.source_port);
    info!("Time: {}", intruder.time_to_text());
    info!("Country name: {}", intruder.ip_info.country_name);
    info!("Country code: {}", intruder.ip_info.country_code);
    info!("ISP: {}", intruder.ip_info.isp);
}

fn handle_connection(stream: TcpStream, cache: &Mutex<IPInfoCache>) {
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(e) => {
            warn!("Could not determine the peer address: {e}");
            return;
        }
    };

    info!(
        "[+] connection from {} with source port {}",
        peer.ip(),
        peer.port()
    );

    let timeout = Some(CONNECTION_INACTIVITY_TIMEOUT);
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let mut intruder = Intruder {
        username: get_telnet_username(&stream),
        password: get_telnet_password(&stream),
        ip_info: IPInfo::default(),
        ip: peer.ip(),
        source_port: peer.port(),
        time: Utc::now(),
    };

    sleep(LOGIN_DELAY);

    lookup_ip_info(cache, &mut intruder);

    if let Err(e) = log_to_db(&intruder) {
        error!("Could not store intruder {}: {e}", intruder.ip);
    }

    display_intruder_info(&intruder);
}

fn listen(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    info!("Listening on port {port}");

    let cache = Arc::new(Mutex::new(IPInfoCache::new()));

    let rate_limiter = Arc::new(Mutex::new(HashMap::<IpAddr, u32>::new()));
    let rate_limiter_cleaner = Arc::clone(&rate_limiter);

    thread::spawn(move || {
        loop {
            thread::sleep(CONNECTION_FLUSH_TIME_PERIOD);
            lock(&rate_limiter_cleaner).clear();
        }
    });

    loop {
        let (stream, addr) = match listener.accept() {
            Ok(connection) => connection,
            Err(e) => {
                warn!("Could not accept a connection: {e}");
                continue;
            }
        };

        let connections = {
            let mut rate_limiter = lock(&rate_limiter);
            let connections = rate_limiter.entry(addr.ip()).or_insert(0);
            *connections += 1;
            *connections
        };

        if connections > CONNECTION_LIMIT {
            warn!("Rate limiting {}", addr.ip());
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }

        let cache = Arc::clone(&cache);
        thread::spawn(move || handle_connection(stream, &cache));
    }
}

// Required rather than relying on the default disposition: oxipot runs as PID 1
// in its container, where unhandled SIGTERM and SIGINT are ignored.
fn handle_signal() {
    let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();

    for signal in signals.forever() {
        match signal {
            SIGINT => info!("Received SIGINT, cleaning up and shutting down."),
            SIGTERM => info!("Received SIGTERM, cleaning up and shutting down."),
            _ => continue,
        }
        exit(0);
    }
}

fn main() {
    env_logger::init();

    if let Err(e) = create_intruders_table() {
        error!("Could not prepare the database: {e}");
        exit(1);
    }

    thread::spawn(handle_signal);

    if let Err(e) = listen(DEFAULT_PORT) {
        error!("Could not listen on port {DEFAULT_PORT}: {e}");
        exit(1);
    }
}
