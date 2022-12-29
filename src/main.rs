use chrono::{DateTime, Utc};
use env_logger;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, TcpListener, TcpStream};
// use std::sync::Mutex;
// use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

// Set the limit to 10 connections per minute
const CONNECTION_LIMIT: u32 = 10;
const CONNECTION_FLUSH_TIME_PERIOD: Duration = Duration::from_secs(60);

const MY_IP: &str = "81.164.189.195";

// Use an Arc<Mutex<T>> to allow multiple tasks to access the connection_counter concurrently.
// This allows multiple tasks to modify the connection_counter hashmap simultaneously without
// causing a race condition.
// type ConnectionCounter = Arc<Mutex<HashMap<String, (u32, Instant)>>>;
type ConnectionCounter = Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>;

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
}

#[derive(Debug, Deserialize)]
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
    info!("Looking up {}", intruder.ip);

    let url = format!("https://api.iplocation.net/?ip={}", intruder.ip);

    let resp: IPInfo = reqwest::get(url).await?.json().await?;
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
        "[+] connection from {} on port {}\n",
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

// fn print_banner(stream: &TcpStream, banner: Option<String>) {
fn print_banner(stream: &TcpStream, banner: Option<String>) -> io::Result<()> {
    let mut stream = stream;

    match banner {
        Some(banner) => {
            // stream.write_all(banner.as_bytes()).unwrap();
            stream.write_all(banner.as_bytes())?;
        }
        None => {
            // stream.write_all(default_banner().as_bytes()).unwrap();
            stream.write_all(default_banner().as_bytes())?;
        }
    }

    Ok(())
}

fn get_telnet_username(stream: &TcpStream, intruder: &mut Intruder) -> io::Result<String> {
    let mut reader = BufReader::new(stream);
    let mut writer = stream;

    let mut username = String::new();

    writer.write_all(b"Username: ").unwrap();
    writer.flush().unwrap();
    reader.read_line(&mut username)?;

    username = username.trim().to_string();

    intruder.username = username.clone();

    Ok(username)
}

fn read_until_cr(stream: &TcpStream) -> String {
    let mut writer = stream;
    let mut buffer = Vec::new();

    'outer: loop {
        writer.flush().unwrap();

        let mut buf = [0; 1024];
        let n = writer.read(&mut buf).unwrap();

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

fn get_telnet_password(stream: &TcpStream, intruder: &mut Intruder) -> io::Result<String> {
    let mut stream = stream;

    stream.write_all(b"\xff\xfb\x01")?; // Echo
    stream.write_all(b"\xff\xfb\x03")?; // Suppress go ahead
    stream.write_all(b"\xff\xfd\x18")?; // Terminal type
    stream.write_all(b"\xff\xfd\x1f")?; // Terminal speed

    stream.write_all(b"\x0d")?; // \r
    stream.write_all(b"Password: ")?;

    stream.write_all(b"\xff\xfe\x20")?; // Toggle flow control

    stream.write_all(b"\xff\xfe\x21")?; // Line mode
    stream.write_all(b"\xff\xfe\x22")?; // Carriage return/line feed (CR/LF) transmission
    stream.write_all(b"\xff\xfe\x27")?; // Output marking

    stream.write_all(b"\xff\xfc\x05")?; // negotiate the suppress go ahead option

    let mut password = read_until_cr(stream);
    stream.write_all(b"\x0d\x0a")?; // \r\n

    password = password.trim().to_string();

    intruder.password = password.clone();

    Ok(password)
}

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

async fn handle_telnet_client(stream: TcpStream) -> io::Result<()> {
    let mut intruder = Intruder::new();

    log_incoming_connection(&stream, &mut intruder);
    print_banner(&stream, None);

    let _ = get_telnet_username(&stream, &mut intruder).unwrap();
    let _ = get_telnet_password(&stream, &mut intruder).unwrap();

    intruder.ip = MY_IP.to_string();

    if !check_rfc_1918(&intruder.ip) {
        let _ = whois(&mut intruder).await;
    }

    display_intruder_info(intruder);

    Ok(())
}

// Check the number of connections from each IP address every time a new connection is made
async fn handle_connection(
    stream: TcpStream,
    connection_counter: ConnectionCounter,
) -> io::Result<()> {
    let ip_address = stream.peer_addr()?.ip();
    let source_port = stream.peer_addr().unwrap().port();

    info!("IP address: {}", ip_address);
    info!("Source port: {}", source_port);

    let mut connection_counter = connection_counter.lock().await;

    let entry = connection_counter
        .entry(ip_address)
        .or_insert((0, Instant::now()));

    // info!("Entry: {}", entry.0);

    if entry.1.elapsed() > CONNECTION_FLUSH_TIME_PERIOD {
        entry.0 = 0;
        entry.1 = Instant::now();
    }

    if entry.0 >= CONNECTION_LIMIT {
        warn!("Connection limit exceeded");
        return Ok(());
    }

    entry.0 += 1;

    // let _ = handle_telnet_client(stream).await;

    Ok(())
}

async fn listen(port: u16) -> std::io::Result<()> {
    // Create a hash map to store the number of connections from each IP address
    let connection_counter = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind(format!("127.0.0.23:{}", port))?;

    while let Ok((stream, _)) = listener.accept() {
        let connection_counter = connection_counter.clone();
        tokio::spawn(async move {
            // let _ = handle_telnet_client(stream).await;
            let _ = handle_connection(stream, connection_counter).await;
        });
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::init();
    listen(2223).await.unwrap();
}
