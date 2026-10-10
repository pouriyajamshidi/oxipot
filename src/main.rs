//
// Copyright (c) 2022 Pouriya Jamshidi (pouriya at thegraynode dot io)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/pouriyajamshidi/oxipot
//

use chrono::{DateTime, SecondsFormat, Utc};
use log::{error, info, warn};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::json;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::exit;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
use std::thread::{self, sleep};
use std::time::Duration;

const CONNECTION_LIMIT: u32 = 10;
const CONNECTION_FLUSH_TIME_PERIOD: Duration = Duration::from_secs(60);
const CONNECTION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(20);
const LOGIN_DELAY: Duration = Duration::from_secs(2);
// Same as BusyBox login, which most IoT devices use.
const LOGIN_ATTEMPTS: u32 = 3;

const DB_URL: &str = "db/oxipot.db";
// Only written when OXIPOT_JSON_LOG=true.
const JSON_LOG_PATH: &str = "db/oxipot.json";
const DEFAULT_PORT: u16 = 2223;

// Free offline database from https://ip66.dev, updated daily. Optional.
const MMDB_PATH: &str = "db/ip66.mmdb";

const IP_INFO_PROVIDER: &str = "https://api.iplocation.net/?ip=";
const IP_INFO_TIMEOUT: Duration = Duration::from_secs(3);

// Every telnet command starts with this byte.
const TELNET_IAC: u8 = 0xff;
const TELNET_SUBNEGOTIATION_START: u8 = 0xfa;
const TELNET_SUBNEGOTIATION_END: u8 = 0xf0;

const TELNET_WILL_ECHO: &[u8] = &[0xff, 0xfb, 0x01];
const TELNET_WILL_SUPPRESS_GO_AHEAD: &[u8] = &[0xff, 0xfb, 0x03];
const TELNET_DO_TERMINAL_TYPE: &[u8] = &[0xff, 0xfd, 0x18];
const TELNET_DO_WINDOW_SIZE: &[u8] = &[0xff, 0xfd, 0x1f];
const TELNET_CARRIAGE_RETURN: &[u8] = &[0x0d];
const TELNET_DONT_TERMINAL_SPEED: &[u8] = &[0xff, 0xfe, 0x20];
const TELNET_DONT_FLOW_CONTROL: &[u8] = &[0xff, 0xfe, 0x21];
const TELNET_DONT_LINE_MODE: &[u8] = &[0xff, 0xfe, 0x22];
const TELNET_DONT_NEW_ENVIRON: &[u8] = &[0xff, 0xfe, 0x27];
const TELNET_WONT_STATUS: &[u8] = &[0xff, 0xfc, 0x05];
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

static JSON_LOG: OnceLock<Mutex<File>> = OnceLock::new();

type IPInfoCache = HashMap<IpAddr, IPInfo>;

/// Everything needed to find the details of an intruder's IP address.
struct IpInfoLookup {
    cache: Mutex<IPInfoCache>,
    // Asked in order until one of them knows the IP address.
    providers: Vec<Box<dyn IpInfoProvider>>,
}

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

/// A source of country and ISP details for an IP address.
trait IpInfoProvider: Send + Sync {
    fn name(&self) -> &str;
    fn lookup(&self, ip: IpAddr) -> Option<IPInfo>;
}

/// A local MaxMind-format (.mmdb) database file, such as the one from ip66.dev.
struct MmdbFile {
    reader: maxminddb::Reader<Vec<u8>>,
}

// The parts of an .mmdb record that we use.
#[derive(Deserialize)]
struct MmdbRecord {
    #[serde(default)]
    country: MmdbCountry,
    #[serde(default)]
    autonomous_system_organization: String,
}

#[derive(Default, Deserialize)]
struct MmdbCountry {
    #[serde(default)]
    iso_code: String,
    #[serde(default)]
    names: MmdbNames,
}

#[derive(Default, Deserialize)]
struct MmdbNames {
    #[serde(default)]
    en: String,
}

impl MmdbFile {
    fn open(path: &str) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        Ok(Self { reader })
    }
}

impl IpInfoProvider for MmdbFile {
    fn name(&self) -> &str {
        MMDB_PATH
    }

    fn lookup(&self, ip: IpAddr) -> Option<IPInfo> {
        let record = self
            .reader
            .lookup(ip)
            .and_then(|result| result.decode::<MmdbRecord>());

        match record {
            // A record without a country is not useful, so let the next provider try.
            Ok(Some(record)) if record.country.iso_code.is_empty() => None,
            Ok(Some(record)) => Some(IPInfo {
                country_name: record.country.names.en,
                country_code: record.country.iso_code,
                isp: record.autonomous_system_organization,
            }),
            Ok(None) => None,
            Err(e) => {
                warn!("Could not look up {ip} in {}: {e}", self.name());
                None
            }
        }
    }
}

/// The free iplocation.net web API.
struct IpLocationApi;

impl IpInfoProvider for IpLocationApi {
    fn name(&self) -> &str {
        "iplocation.net"
    }

    fn lookup(&self, ip: IpAddr) -> Option<IPInfo> {
        let response = HTTP.get(format!("{IP_INFO_PROVIDER}{ip}")).call();

        match response.and_then(|mut response| response.body_mut().read_json()) {
            Ok(ip_info) => Some(ip_info),
            Err(e) => {
                warn!("Could not look up {ip} on {}: {e}", self.name());
                None
            }
        }
    }
}

struct TelnetStream<'a> {
    stream: &'a TcpStream,
    // Keeps the bytes that arrive after the end of a line, so the next
    // read gets them instead of losing them.
    reader: BufReader<&'a TcpStream>,
    closed: bool,
}

impl<'a> TelnetStream<'a> {
    fn new(stream: &'a TcpStream) -> Self {
        Self {
            stream,
            reader: BufReader::new(stream),
            closed: false,
        }
    }

    fn write_all(&mut self, buf: &[u8]) {
        if self.closed {
            return;
        }

        if let Err(e) = self.stream.write_all(buf) {
            warn!("Could not write to the telnet stream: {e}");
            self.close();
        }
    }

    // Returns None when the client leaves before ending the line.
    fn read_line(&mut self) -> Option<String> {
        let mut line = Vec::new();

        loop {
            match self.read_byte()? {
                // What is left of the previous line's "\r\n" or "\r\0".
                b'\n' | 0 if line.is_empty() => continue,
                b'\r' | b'\n' => break,
                TELNET_IAC => self.skip_command(),
                byte if byte.is_ascii() => line.push(byte),
                _ => {}
            }
        }

        Some(String::from_utf8_lossy(&line).trim().to_string())
    }

    // Clients answer our telnet options, often in the same packet as their
    // username or password, so the command bytes must be skipped one by one.
    fn skip_command(&mut self) {
        match self.read_byte() {
            // WILL, WONT, DO and DONT are followed by one option byte.
            Some(0xfb..=0xfe) => {
                self.read_byte();
            }
            Some(TELNET_SUBNEGOTIATION_START) => {
                while let Some(byte) = self.read_byte() {
                    if byte == TELNET_IAC && self.read_byte() == Some(TELNET_SUBNEGOTIATION_END) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    fn read_byte(&mut self) -> Option<u8> {
        let mut byte = [0];

        match self.reader.read(&mut byte) {
            Ok(0) => None,
            Ok(_) => Some(byte[0]),
            Err(e) => {
                warn!("Could not read from the telnet stream: {e}");
                self.close();
                None
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;

        // NotConnected only means the client has already left.
        if let Err(e) = self.stream.shutdown(Shutdown::Both)
            && e.kind() != io::ErrorKind::NotConnected
        {
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

// One JSON object per line, which tools like Filebeat and Splunk read as is.
fn open_json_log() -> io::Result<()> {
    if env::var("OXIPOT_JSON_LOG").as_deref() != Ok("true") {
        return Ok(());
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(JSON_LOG_PATH)?;
    info!("Writing JSON logs to {JSON_LOG_PATH}");

    let _ = JSON_LOG.set(Mutex::new(file));

    Ok(())
}

fn log_to_json(intruder: &Intruder) -> io::Result<()> {
    let Some(file) = JSON_LOG.get() else {
        return Ok(());
    };

    let line = json!({
        "username": intruder.username,
        "password": intruder.password,
        "ip": intruder.ip,
        "source_port": intruder.source_port,
        "country_name": intruder.ip_info.country_name,
        "country_code": intruder.ip_info.country_code,
        "isp": intruder.ip_info.isp,
        "time": intruder.time.to_rfc3339_opts(SecondsFormat::Secs, true),
    });

    writeln!(lock(file), "{line}")
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

fn lookup_ip_info(lookup: &IpInfoLookup, intruder: &mut Intruder) {
    let cache = &lookup.cache;

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

    for provider in &lookup.providers {
        info!("Looking up {} on {}", intruder.ip, provider.name());

        if let Some(ip_info) = provider.lookup(intruder.ip) {
            lock(cache).insert(intruder.ip, ip_info.clone());
            intruder.ip_info = ip_info;
            return;
        }
    }
}

fn get_telnet_username(telnet: &mut TelnetStream) -> Option<String> {
    telnet.write_all(b"login: ");

    telnet.read_line()
}

fn get_telnet_password(telnet: &mut TelnetStream) -> Option<String> {
    telnet.write_all(TELNET_WILL_ECHO);
    telnet.write_all(TELNET_WILL_SUPPRESS_GO_AHEAD);
    telnet.write_all(TELNET_DO_TERMINAL_TYPE);
    telnet.write_all(TELNET_DO_WINDOW_SIZE);
    telnet.write_all(TELNET_CARRIAGE_RETURN);
    telnet.write_all(b"Password: ");
    telnet.write_all(TELNET_DONT_TERMINAL_SPEED);
    telnet.write_all(TELNET_DONT_FLOW_CONTROL);
    telnet.write_all(TELNET_DONT_LINE_MODE);
    telnet.write_all(TELNET_DONT_NEW_ENVIRON);
    telnet.write_all(TELNET_WONT_STATUS);

    let password = telnet.read_line();
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

fn handle_connection(stream: TcpStream, lookup: &IpInfoLookup) {
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

    let mut telnet = TelnetStream::new(&stream);
    telnet.write_all(BANNER.as_bytes());

    for _ in 0..LOGIN_ATTEMPTS {
        // Port scanners connect and leave, so there is nothing worth saving.
        let username = match get_telnet_username(&mut telnet) {
            Some(username) if !username.is_empty() => username,
            _ => {
                info!("No username from {}, closing the connection", peer.ip());
                return;
            }
        };

        let mut intruder = Intruder {
            username,
            password: get_telnet_password(&mut telnet).unwrap_or_default(),
            ip_info: IPInfo::default(),
            ip: peer.ip(),
            source_port: peer.port(),
            time: Utc::now(),
        };

        sleep(LOGIN_DELAY);
        telnet.write_all(b"Login incorrect\r\n");

        lookup_ip_info(lookup, &mut intruder);

        if let Err(e) = log_to_db(&intruder) {
            error!("Could not store intruder {}: {e}", intruder.ip);
        }

        if let Err(e) = log_to_json(&intruder) {
            error!("Could not log intruder {} as JSON: {e}", intruder.ip);
        }

        display_intruder_info(&intruder);
    }
}

fn listen(port: u16, lookup: IpInfoLookup) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    info!("Listening on port {port}");

    let lookup = Arc::new(lookup);

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

        let lookup = Arc::clone(&lookup);
        thread::spawn(move || handle_connection(stream, &lookup));
    }
}

fn ip_info_providers() -> Vec<Box<dyn IpInfoProvider>> {
    let mut providers: Vec<Box<dyn IpInfoProvider>> = Vec::new();

    match MmdbFile::open(MMDB_PATH) {
        Ok(mmdb) => {
            info!("Using {MMDB_PATH} for IP lookups");
            providers.push(Box::new(mmdb));
        }
        Err(e) => info!("Not using {MMDB_PATH}: {e}"),
    }

    providers.push(Box::new(IpLocationApi));
    providers
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

    if let Err(e) = open_json_log() {
        error!("Could not open {JSON_LOG_PATH}: {e}");
        exit(1);
    }

    thread::spawn(handle_signal);

    let lookup = IpInfoLookup {
        cache: Mutex::new(IPInfoCache::new()),
        providers: ip_info_providers(),
    };

    if let Err(e) = listen(DEFAULT_PORT, lookup) {
        error!("Could not listen on port {DEFAULT_PORT}: {e}");
        exit(1);
    }
}
