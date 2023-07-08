use chrono::{DateTime, Utc};
use env_logger;
use log::{error, info, warn};
use reqwest::blocking::Client;
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread::{self, sleep};
use std::time::Duration;

const CONNECTION_LIMIT: u32 = 10;
const CONNECTION_FLUSH_TIME_PERIOD: Duration = Duration::from_secs(60);
const CONNECTION_INACTIVITY_TIMEOUT: u64 = 20;

const DB_URL: &str = "db/oxipot.db";
const DEFAULT_PORT: u16 = 2223;

const IP_INFO_PROVIDER: &str = "https://api.iplocation.net/?ip=";

// type ConnectionCounter = Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>;

struct Intruder {
    username: String,
    password: String,
    ip_info: IPInfo,
    ip_v4_address: Option<Ipv4Addr>,
    ip_v6_address: Option<Ipv6Addr>,
    ip: String,
    source_port: u16,
    time: DateTime<Utc>,
}

impl Intruder {
    fn new() -> Self {
        Self {
            username: "".to_string(),
            password: "".to_string(),
            ip_info: IPInfo::new(),
            ip_v4_address: None,
            ip_v6_address: None,
            ip: "".to_string(),
            source_port: 0,
            time: Utc::now(),
        }
    }

    fn set_ip(&mut self) {
        if let Some(ip) = self.ip_v4_address {
            self.ip = ip.to_string();
        } else if let Some(ip) = self.ip_v6_address {
            self.ip = ip.to_string();
        } else {
            self.ip = "".to_string();
        }
    }

    fn time_to_text(&self) -> String {
        self.time.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

#[derive(Debug, Deserialize, Clone)]
struct IPInfo {
    ip: String,
    country_name: String,
    #[serde(rename = "country_code2")]
    country_code: String,
    isp: String,
}

impl IPInfo {
    fn new() -> Self {
        Self {
            ip: "".to_string(),
            country_name: "".to_string(),
            country_code: "".to_string(),
            isp: "".to_string(),
        }
    }
}

#[derive(Clone)]
struct IPInfoCache {
    cache: Vec<IPInfo>,
}

impl IPInfoCache {
    fn new() -> Self {
        IPInfoCache { cache: vec![] }
    }

    fn retrieve(&self, intruder: &Intruder) -> Option<IPInfo> {
        let ip_info = self.retrieve_from_memory(intruder);

        if let Some(_) = ip_info {
            info!("Found intruder info in memory");
            return ip_info.clone();
        }

        // Intruder was not in memory, check the DB

        let ip_info = self.retrieve_from_database(intruder);

        if let Some(_) = ip_info {
            info!("Found intruder info in Database");
            return ip_info.clone();
        }

        return None;
    }

    fn retrieve_from_memory(&self, intruder: &Intruder) -> Option<IPInfo> {
        info!("Checking memory for intruder info");

        for existing_info in &self.cache {
            if existing_info.ip == intruder.ip {
                // If the existing IPInfo's country name is not empty, return it.
                if !existing_info.country_name.is_empty() {
                    return Some(existing_info.clone());
                }
                break;
            }
        }
        return None;
    }

    fn retrieve_from_database(&self, intruder: &Intruder) -> Option<IPInfo> {
        info!("Checking database for intruder info");

        let conn = Connection::open(DB_URL).unwrap();
        let result = conn.query_row(
            "SELECT country_name, country_code, isp from intruders WHERE ip=? ORDER BY id DESC LIMIT 1",
            &[&intruder.ip],
            |row| {
                let country_name: String = row.get(0)?;
                let country_code: String = row.get(1)?;
                let isp: String = row.get(2)?;
                Ok(IPInfo {
                    ip: intruder.ip.clone(),
                    country_name,
                    country_code,
                    isp,
                })
            },
        ).optional();

        result.unwrap_or(None)
    }

    fn add(&mut self, intruder: &Intruder) {
        let mut idx_to_remove = None;
        let mut got_a_match = false;

        for (i, existing_info) in self.cache.iter().enumerate() {
            if existing_info.ip == intruder.ip {
                got_a_match = true;
                info!("got a match for {} in cache", intruder.ip);

                // If the existing IPInfo's country name is empty, mark it for removal.
                if existing_info.country_name.is_empty() {
                    info!(
                        "removing {} from cache due to lack of country info",
                        existing_info.ip
                    );
                    idx_to_remove = Some(i);
                } else {
                    return;
                }
            }
        }
        // If we marked an existing IPInfo for removal, remove it now.
        if let Some(idx) = idx_to_remove {
            self.cache.remove(idx);
        }

        if !got_a_match {
            info!("got no match for {} in cache", intruder.ip);
        }

        info!("adding {} to cache", intruder.ip);
        self.cache.push(intruder.ip_info.clone());
    }
}

struct TelnetStream<'a> {
    stream: &'a TcpStream,
}

impl<'a> TelnetStream<'a> {
    fn new(stream: &'a TcpStream) -> TelnetStream<'a> {
        TelnetStream { stream }
    }

    fn write_all(&mut self, buf: &[u8]) {
        match self.stream.write_all(buf) {
            Ok(_) => (),
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe => {
                    self.close();
                }
                _ => self.close(),
            },
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.stream.read(buf) {
            Ok(n) => Ok(n),
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe => {
                    warn!("Connection closed by peer");
                    self.close();
                    Err(e)
                }
                _ => {
                    self.close();
                    Err(e)
                }
            },
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.stream.flush() {
            Ok(_) => Ok(()),
            Err(e) => match e.kind() {
                std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe => {
                    warn!("Connection closed by peer");
                    self.close();
                    Err(e)
                }
                _ => {
                    self.close();
                    Err(e)
                }
            },
        }
    }

    fn close(&mut self) {
        match self.stream.shutdown(Shutdown::Both) {
            Ok(_) => {
                info!("Connection closed successfully");
            }
            Err(e) => {
                error!("Encountered {:?} while shutting down the TCP stream", e);
            }
        }
    }
}

enum TelnetCommand {
    Echo,
    SuppressGoAhead,
    TerminalType,
    TerminalSpeed,
    CarriageReturn,
    ToggleFlowControl,
    LineMode,
    CarriageReturnLineFeed,
    OutputMarking,
    NegotiateSuppressGoAhead,
    CarriageReturnLineFeedCRLF,
}

impl TelnetCommand {
    fn as_bytes(&self) -> &[u8] {
        match self {
            TelnetCommand::Echo => &[0xff, 0xfb, 0x01],
            TelnetCommand::SuppressGoAhead => &[0xff, 0xfb, 0x03],
            TelnetCommand::TerminalType => &[0xff, 0xfd, 0x18],
            TelnetCommand::TerminalSpeed => &[0xff, 0xfd, 0x1f],
            TelnetCommand::CarriageReturn => &[0x0d],
            TelnetCommand::ToggleFlowControl => &[0xff, 0xfe, 0x20],
            TelnetCommand::LineMode => &[0xff, 0xfe, 0x21],
            TelnetCommand::CarriageReturnLineFeed => &[0xff, 0xfe, 0x22],
            TelnetCommand::OutputMarking => &[0xff, 0xfe, 0x27],
            TelnetCommand::NegotiateSuppressGoAhead => &[0xff, 0xfc, 0x05],
            TelnetCommand::CarriageReturnLineFeedCRLF => &[0x0d, 0x0a],
        }
    }
}

fn create_intruders_table() -> rusqlite::Result<()> {
    info!("Creating Database: {} ", DB_URL);
    let mut conn = Connection::open(DB_URL).unwrap();
    let tx = conn.transaction().unwrap();

    match tx.execute(
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
    ) {
        Ok(it) => {
            info!("Successfully created intruders table");
            it
        }
        Err(err) => {
            error!("Error creating intruders table: {}", err);
            return Err(err);
        }
    };

    tx.commit().unwrap();
    conn.close().unwrap();

    Ok(())
}

fn log_to_db(intruder: &Intruder) -> rusqlite::Result<()> {
    info!("Inserting intruder's info into Database: {} ", DB_URL);
    let mut conn = Connection::open(DB_URL).unwrap();
    let tx = conn.transaction().unwrap();

    tx.execute(
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
            intruder.username.clone(),
            intruder.password.clone(),
            intruder.ip.clone(),
            intruder.source_port.clone(),
            intruder.ip_info.country_name.clone(),
            intruder.ip_info.country_code.clone(),
            intruder.ip_info.isp.clone(),
            intruder.time_to_text(),
        ),
    )?;

    info!(
        "inserted intruder {} information into database",
        intruder.ip
    );

    tx.commit().unwrap();
    conn.close().unwrap();

    Ok(())
}

fn is_private_ip(ip: &String) -> bool {
    let ip_addr = match ip.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => return false,
    };

    match ip_addr {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback(),
        IpAddr::V6(_) => false,
    }
}

fn whois(intruder: &mut Intruder) -> Result<(), Box<dyn std::error::Error>> {
    info!("Looking up {:?}", intruder.ip);
    let query_url = format!("{}{}", IP_INFO_PROVIDER, intruder.ip);

    // let client = reqwest::Client::builder()
    //     .timeout(Duration::from_secs(3))
    //     .build()?;

    let client = Client::new();

    let resp: IPInfo = client.get(query_url).send()?.json()?;
    intruder.ip_info = resp;

    Ok(())
}

fn default_banner() -> String {
    return "

#############################################################################
# UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED You must have explicit,  #
# authorized permission to access or configure this device.                 #
# Unauthorized attempts and actions to access or use this system may result #
# in civil and/or criminal penalties.                                       #
# All activities performed on this device are logged and monitored.         #
#############################################################################

"
    .to_string();
}

fn print_banner(stream: &TcpStream, banner: Option<String>) -> io::Result<()> {
    let mut stream = stream;

    match banner {
        Some(banner) => {
            stream.write_all(banner.as_bytes())?;
        }
        None => {
            stream.write_all(default_banner().as_bytes())?;
        }
    }

    Ok(())
}

fn get_telnet_username(stream: &TcpStream, intruder: &mut Intruder) {
    let mut telnet_stream = TelnetStream::new(stream);

    telnet_stream.write_all(b"login: ");

    let username = read_until_cr(&telnet_stream.stream);
    intruder.username = username.trim().to_string().clone();
}

fn read_until_cr(stream: &TcpStream) -> String {
    let mut telnet_stream = TelnetStream::new(stream);
    let mut buffer = Vec::new();

    'outer: loop {
        telnet_stream.flush().unwrap();

        let mut buf = [0; 1024];
        let n = telnet_stream.read(&mut buf).unwrap(); // TODO: this errors out: panicked at 'called `Result::unwrap()` on an `Err` value: Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }'

        if n == 0 {
            return String::from_utf8(buffer).unwrap();
        }

        let s = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(e) => {
                warn!("Problem reading telnet stream data: {}", e);
                continue;
            }
        };

        for c in s.chars() {
            if c == '\r' || c == '\n' {
                break 'outer;
            }

            if c.is_ascii() {
                buffer.push(c as u8);
            }
        }
    }

    String::from_utf8(buffer).unwrap()
}

fn get_telnet_password(stream: &TcpStream, intruder: &mut Intruder) {
    let mut telnet_stream = TelnetStream::new(stream);

    telnet_stream.write_all(TelnetCommand::Echo.as_bytes());
    telnet_stream.write_all(TelnetCommand::SuppressGoAhead.as_bytes());
    telnet_stream.write_all(TelnetCommand::TerminalType.as_bytes());
    telnet_stream.write_all(TelnetCommand::TerminalSpeed.as_bytes());
    telnet_stream.write_all(TelnetCommand::CarriageReturn.as_bytes());
    telnet_stream.write_all(b"Password: ");
    telnet_stream.write_all(TelnetCommand::ToggleFlowControl.as_bytes());
    telnet_stream.write_all(TelnetCommand::LineMode.as_bytes());
    telnet_stream.write_all(TelnetCommand::CarriageReturnLineFeed.as_bytes());
    telnet_stream.write_all(TelnetCommand::OutputMarking.as_bytes());
    telnet_stream.write_all(TelnetCommand::NegotiateSuppressGoAhead.as_bytes());

    let mut password = read_until_cr(&telnet_stream.stream);
    telnet_stream.write_all(TelnetCommand::CarriageReturnLineFeedCRLF.as_bytes());

    password = password.trim().to_string();

    intruder.password = password.clone();
}

fn display_intruder_info(intruder: &Intruder) {
    info!("Username: {}", intruder.username);
    info!("Password: {}", intruder.password);
    info!("IP address: {}", intruder.ip);
    info!("Source port: {}", intruder.source_port);
    info!("Time: {}", intruder.time_to_text());

    info!("ip: {}", intruder.ip_info.ip);
    info!("country_name: {}", intruder.ip_info.country_name);
    info!("country_code: {}", intruder.ip_info.country_code);
    info!("ISP: {}", intruder.ip_info.isp);
}

fn handle_telnet_client(stream: TcpStream, mut intruder: &mut Intruder) -> io::Result<()> {
    let _ = print_banner(&stream, None);

    let _ = get_telnet_username(&stream, &mut intruder);
    let _ = get_telnet_password(&stream, &mut intruder);

    sleep(Duration::new(2, 0));

    Ok(())
}

fn log_incoming_connection(ip_address: IpAddr, source_port: u16, intruder: &mut Intruder) {
    intruder.time = Utc::now();

    if let IpAddr::V4(ipv4) = ip_address {
        intruder.ip_v4_address = Some(ipv4);
    } else if let IpAddr::V6(ipv6) = ip_address {
        intruder.ip_v6_address = Some(ipv6);
    }

    intruder.set_ip();
    intruder.source_port = source_port;
}

fn handle_connection(stream: TcpStream, ip_info_cache: &Arc<Mutex<IPInfoCache>>) -> io::Result<()> {
    let ip_address = stream.peer_addr().unwrap().ip();
    let source_port = stream.peer_addr().unwrap().port();

    info!(
        "[+] connection from {} with source port {}",
        ip_address, source_port
    );

    stream
        .set_read_timeout(Some(Duration::from_secs(CONNECTION_INACTIVITY_TIMEOUT)))
        .unwrap();

    stream
        .set_write_timeout(Some(Duration::from_secs(CONNECTION_INACTIVITY_TIMEOUT)))
        .unwrap();

    let mut intruder = Intruder::new();

    log_incoming_connection(ip_address, source_port, &mut intruder);

    let _ = handle_telnet_client(stream, &mut intruder);

    let cache_guard = ip_info_cache.lock().map_err(|_| io::ErrorKind::Other)?;
    let mut ip_info_cache = cache_guard;

    if let Some(ip_info) = ip_info_cache.retrieve(&intruder) {
        info!("The intruder {} exists in cache", intruder.ip);
        intruder.ip_info = ip_info;
    } else {
        info!("The intruder {} does not exist in cache", intruder.ip);
        if !(is_private_ip(&intruder.ip)) {
            let _ = whois(&mut intruder);
            ip_info_cache.add(&intruder)
        }
    }

    let _ = log_to_db(&intruder);

    display_intruder_info(&intruder);

    Ok(())
}

fn listen(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();

    let ip_info_cache = Arc::new(Mutex::new(IPInfoCache::new()));

    let rate_limiter = Arc::new(Mutex::new(HashMap::<IpAddr, u32>::new()));
    let rate_limiter_cloned = Arc::clone(&rate_limiter);

    // Set up a cleaner task
    thread::spawn(move || loop {
        thread::sleep(CONNECTION_FLUSH_TIME_PERIOD);

        let mut rate_limiter = rate_limiter_cloned.lock().unwrap();
        rate_limiter.clear();
    });

    while let Ok((stream, addr)) = listener.accept() {
        let mut rate_limiter = rate_limiter.lock().unwrap();

        if let Some(count) = rate_limiter.get_mut(&addr.ip()) {
            if *count >= CONNECTION_LIMIT {
                warn!("Rate limiting {}", addr.ip());
                continue;
            }
            *count += 1;
        } else {
            rate_limiter.insert(addr.ip(), 1);
        }

        let ip_info_cache = ip_info_cache.clone();

        thread::spawn(move || {
            let _ = handle_connection(stream, &ip_info_cache);
        });
    }

    Ok(())
}

fn handle_signal() {
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).unwrap();

    for signal in signals.forever() {
        match signal {
            SIGINT => {
                info!("\nReceived SIGINT, cleaning up and shutting down.");
                exit(0);
            }
            SIGTERM => {
                info!("\nReceived SIGTERM, cleaning up and shutting down.");
                exit(0);
            }
            _ => return,
        }
    }
}

fn main() {
    env_logger::init();

    let db_result = create_intruders_table();
    match db_result {
        Ok(()) => (),
        Err(_) => exit(1),
    }

    thread::spawn(move || handle_signal());

    listen(DEFAULT_PORT).unwrap();
}
