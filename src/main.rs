use chrono::{DateTime, Utc};
use env_logger;
use log::{error, info, warn};
use serde::Deserialize;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;
use sqlx::SqlitePool;
use sqlx::{migrate::MigrateDatabase, Sqlite};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::exit;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

// Set the limit to 10 connections per minute
const CONNECTION_LIMIT: u32 = 10;
const CONNECTION_FLUSH_TIME_PERIOD: Duration = Duration::from_secs(60);
const CONNECTION_INACTIVITY_TIMEOUT: u64 = 20;

// const DB_URL: &str = "sqlite://oxipot.db";
const DB_URL: &str = "/var/log/oxipot/oxipot.db";

// Use an Arc<Mutex<T>> to allow multiple tasks to access the connection_counter concurrently.
// This allows multiple tasks to modify the connection_counter hashmap simultaneously without
// causing a race condition.
type ConnectionCounter = Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>;

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
            ip_info: IPInfo::default(),
            ip_v4_address: None,
            ip_v6_address: None,
            ip: "".to_string(),
            source_port: 0,
            time: Utc::now(),
        }
    }

    // fn set_ip(&mut self) {
    //     self.ip = self
    //         .ip_v4_address
    //         .map(|ip| ip.to_string())
    //         .or_else(|| self.ip_v6_address.map(|ip| ip.to_string()))
    //         .unwrap_or_else(|| "".to_string());
    // }

    fn set_ip(&mut self) {
        match (self.ip_v4_address, self.ip_v6_address) {
            (Some(ip), _) => self.ip = ip.to_string(),
            (_, Some(ip)) => self.ip = ip.to_string(),
            (None, None) => self.ip = "".to_string(),
        }
    }

    fn time_str(&self) -> String {
        self.time.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn ipv4_str(&self) -> String {
        self.ip_v4_address
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
            .to_string()
    }

    fn ipv6_str(&self) -> String {
        self.ip_v6_address
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
            .to_string()
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
    fn default() -> Self {
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
        for existing_info in &self.cache {
            if existing_info.ip == intruder.ip {
                // If the existing IPInfo's country name is not empty, return it.
                if !existing_info.country_name.is_empty() {
                    return Some(existing_info.clone());
                }
                break;
            }
        }

        None
    }

    fn add(&mut self, intruder: &Intruder) {
        let mut idx_to_remove = None;

        for (i, existing_info) in self.cache.iter().enumerate() {
            if existing_info.ip == intruder.ip {
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
            info!("got no match for {} in cache", intruder.ip);
        }

        info!("adding {} to cache", intruder.ip);
        self.cache.push(intruder.ip_info.clone());

        // If we marked an existing IPInfo for removal, remove it now.
        if let Some(idx) = idx_to_remove {
            self.cache.remove(idx);
        }
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
                    // warn!("connection closed by peer");
                    self.close();
                }
                _ => {
                    self.close();
                }
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
                    warn!("connection closed by peer");
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
                    warn!("connection closed by peer");
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
                warn!("connection closed successfully");
            }
            Err(e) => {
                error!("Error Occured {:?} while shutting down the stream", e);
            }
        }
    }
}

// fn create_database() -> Result<(), sqlx::Error> {
//     match !Sqlite::database_exists(DB_URL) {
//         true => {
//             info!("Creating database {}", DB_URL);
//             match Sqlite::create_database(DB_URL) {
//                 Ok(_) => info!("DB created successfully"),
//                 Err(error) => panic!("error: {}", error),
//             }
//         }
//         false => {
//             info!("Database already exists");
//         }
//     }
//     Ok(())
// }

async fn log_to_db(intruder: &Intruder) -> Result<(), sqlx::Error> {
    if !Sqlite::database_exists(DB_URL).await.unwrap_or(false) {
        info!("Creating database {}", DB_URL);
        match Sqlite::create_database(DB_URL).await {
            Ok(_) => info!("DB created successfully"),
            Err(error) => panic!("error: {}", error),
        }
    } else {
        info!("Database already exists");
    }

    let db = SqlitePool::connect(DB_URL).await.unwrap();
    let mut tx = db.begin().await?;
    tx.lock_handle().await?;

    let result = sqlx::query(
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
        );",
    )
    .execute(&mut tx)
    .await
    .unwrap();

    info!("Create intruders table result: {:?}", result);

    let insert_result = sqlx::query(
        "INSERT INTO intruders (
        username, 
        password,
        ip,
        source_port,
        country_name,
        country_code,
        isp,
        time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(intruder.username.clone())
    .bind(intruder.password.clone())
    .bind(intruder.ip.clone())
    .bind(intruder.source_port.clone())
    .bind(intruder.ip_info.country_name.clone())
    .bind(intruder.ip_info.country_code.clone())
    .bind(intruder.ip_info.isp.clone())
    .bind(intruder.time_to_text())
    .execute(&mut tx)
    .await
    .unwrap();

    info!("Insert into intruders result: {:?}", insert_result);
    tx.commit().await.unwrap();
    info!("commit successfull");

    db.close().await;

    Ok(())
}

fn check_rfc_1918(ip: &String) -> bool {
    let ip_addr = match ip.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => return false,
    };

    match ip_addr {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(_) => false,
    }
}

async fn whois(intruder: &mut Intruder) -> Result<(), Box<dyn std::error::Error>> {
    info!("Looking up {:?}", intruder.ip);
    let query_url = format!("https://api.iplocation.net/?ip={}", intruder.ip);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    // let resp: IPInfo = reqwest::get(query_url).await?.json().await?;
    let resp: IPInfo = client.get(query_url).send().await?.json().await?;
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

fn log_incoming_connection(stream: &TcpStream, intruder: &mut Intruder) {
    let ip_address = stream.peer_addr().unwrap().ip();
    let source_port = stream.peer_addr().unwrap().port();

    info!(
        "[+] connection from {} with source port {}",
        ip_address, source_port
    );

    intruder.time = Utc::now();

    if let IpAddr::V4(ipv4) = ip_address {
        intruder.ip_v4_address = Some(ipv4);
    } else if let IpAddr::V6(ipv6) = ip_address {
        intruder.ip_v6_address = Some(ipv6);
    }

    intruder.set_ip();
    intruder.source_port = source_port;
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

    let mut username = read_until_cr(&telnet_stream.stream);
    // telnet_stream.write_all(TelnetCommand::CarriageReturnLineFeedCRLF.as_bytes());

    username = username.trim().to_string();

    intruder.username = username.clone();
}

// fn get_telnet_username(stream: &TcpStream, intruder: &mut Intruder) {
//     let mut telnet_stream = TelnetStream::new(stream);

//     match telnet_stream.stream.peer_addr() {
//         Ok(_) => {
//             telnet_stream.write_all(b"Username: ");

//             let mut username = read_until_cr(&telnet_stream.stream);
//             telnet_stream.write_all(b"\x0d\x0a");

//             username = username.trim().to_string();

//             intruder.username = username.clone();
//         }
//         Err(_) => {
//             return;
//         }
//     }
// }

fn read_until_cr(stream: &TcpStream) -> String {
    let mut telnet_stream = TelnetStream::new(stream);
    let mut buffer = Vec::new();

    'outer: loop {
        telnet_stream.flush().unwrap();

        let mut buf = [0; 1024];
        let n = telnet_stream.read(&mut buf).unwrap();

        if n == 0 {
            return String::from_utf8(buffer).unwrap();
        }

        let s = match std::str::from_utf8(&buf[..n]) {
            Ok(s) => s,
            Err(e) => {
                error!("Error parsing UTF-8 data: {}", e);
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

// fn get_telnet_password(stream: &TcpStream, intruder: &mut Intruder) {
//     let mut telnet_stream = TelnetStream::new(stream);

//     match telnet_stream.stream.peer_addr() {
//         Ok(_) => {
//             telnet_stream.write_all(b"\xff\xfb\x01"); // Echo
//             telnet_stream.write_all(b"\xff\xfb\x03"); // Suppress go ahead
//             telnet_stream.write_all(b"\xff\xfd\x18"); // Terminal type
//             telnet_stream.write_all(b"\xff\xfd\x1f"); // Terminal speed
//             telnet_stream.write_all(b"\x0d"); // \r
//             telnet_stream.write_all(b"Password: ");
//             telnet_stream.write_all(b"\xff\xfe\x20"); // Toggle flow control
//             telnet_stream.write_all(b"\xff\xfe\x21"); // Line mode
//             telnet_stream.write_all(b"\xff\xfe\x22"); // Carriage return/line feed (CR/LF) transmission
//             telnet_stream.write_all(b"\xff\xfe\x27"); // Output marking
//             telnet_stream.write_all(b"\xff\xfc\x05"); // negotiate the suppress go ahead option

//             let mut password = read_until_cr(&telnet_stream.stream);
//             telnet_stream.write_all(b"\x0d\x0a"); // \r\n

//             password = password.trim().to_string();

//             intruder.password = password.clone();
//         }
//         Err(_) => {
//             return;
//         }
//     }
// }

fn display_intruder_info(intruder: Intruder) {
    info!("Username: {}", intruder.username);
    info!("Password: {}", intruder.password);
    info!("IP address: {}", intruder.ip);
    info!("Source port: {}", intruder.source_port);
    info!("Time: {}", intruder.time_str());

    info!("ip: {}", intruder.ip_info.ip);
    info!("country_name: {}", intruder.ip_info.country_name);
    info!("country_code: {}", intruder.ip_info.country_code);
    info!("ISP: {}", intruder.ip_info.isp);
}

async fn handle_telnet_client(
    stream: TcpStream,
    ip_info_cache: &Arc<Mutex<IPInfoCache>>,
) -> io::Result<()> {
    let mut intruder = Intruder::new();

    log_incoming_connection(&stream, &mut intruder);
    let _ = print_banner(&stream, None);

    let _ = get_telnet_username(&stream, &mut intruder);
    let _ = get_telnet_password(&stream, &mut intruder);

    let mut cache_guard = ip_info_cache.lock().await;
    let ip_info_cache = &mut *cache_guard;

    if let Some(ip_info) = ip_info_cache.retrieve(&intruder) {
        info!("The intruder {} exists in cache", intruder.ip);
        intruder.ip_info = ip_info;
    } else {
        info!("The intruder {} does not exist in cache", intruder.ip);
        if !(check_rfc_1918(&intruder.ip)) {
            let _ = whois(&mut intruder).await;
            ip_info_cache.add(&intruder)
        }
    }

    let _ = log_to_db(&intruder).await;

    display_intruder_info(intruder);

    // sleep(Duration::new(2, 0));

    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    connection_counter: ConnectionCounter,
    ip_info_cache: &Arc<Mutex<IPInfoCache>>,
) -> io::Result<()> {
    let ip_address = stream.peer_addr()?.ip();
    let source_port = stream.peer_addr().unwrap().port();

    info!("IP address: {}", ip_address);
    info!("Source port: {}", source_port);

    // let mut connection_counter = connection_counter.lock().await;

    // let entry = connection_counter
    //     .entry(ip_address)
    //     .or_insert((0, Instant::now()));

    // if entry.1.elapsed() > CONNECTION_FLUSH_TIME_PERIOD {
    //     entry.0 = 0;
    //     entry.1 = Instant::now();
    // }

    // if entry.0 >= CONNECTION_LIMIT {
    //     warn!("Connection limit exceeded for {}", ip_address);
    //     let _ = stream.shutdown(Shutdown::Both);
    //     return Ok(());
    // }

    // entry.0 += 1;

    stream
        .set_read_timeout(Some(Duration::from_secs(CONNECTION_INACTIVITY_TIMEOUT)))
        .unwrap();

    stream
        .set_write_timeout(Some(Duration::from_secs(CONNECTION_INACTIVITY_TIMEOUT)))
        .unwrap();

    let _ = handle_telnet_client(stream, ip_info_cache).await;

    Ok(())
}

async fn listen(port: u16) -> std::io::Result<()> {
    let connection_counter = Arc::new(Mutex::new(HashMap::new()));
    let ip_info_cache = Arc::new(Mutex::new(IPInfoCache::new()));

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;

    while let Ok((stream, _)) = listener.accept() {
        let connection_counter = connection_counter.clone();
        let mut ip_info_cache = ip_info_cache.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, connection_counter, &mut ip_info_cache).await;
        });
    }
    Ok(())
}

async fn handle_signal() {
    let mut signals = Signals::new(&[SIGINT, SIGTERM]).unwrap();

    for signal in signals.forever() {
        match signal {
            SIGINT => {
                println!("Received SIGINT, cleaning up and shutting down.");
                exit(0);
            }
            SIGTERM => {
                println!("Received SIGTERM, cleaning up and shutting down.");
                exit(0);
            }
            // _ => unreachable!(),
            _ => return,
        }
    }
}

#[tokio::main]
async fn main() {
    // tokio::spawn(handle_signal());
    env_logger::init();
    info!("meow!!!");
    listen(2223).await.unwrap();
}
