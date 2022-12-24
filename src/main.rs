/*
[x] I need to press enter to see the banner because of:
    while match stream.read(&mut data) {

[ ] For password, this could become handy:
    https://docs.rs/dialoguer/latest/dialoguer/struct.Password.html

[ ] For TTY stuff check this crate:
        https://docs.rs/termios/0.3.3/termios/

[ ] This one is doing a similar thing:
    https://stackoverflow.com/questions/52214856/turn-off-echoing-in-terminal-golang

[ ] GNU docs on this:
    https://www.gnu.org/software/libc/manual/html_node/Mode-Functions.html

[ ] How Go does it:
    https://pkg.go.dev/golang.org/x/term#Terminal.ReadPassword

[ ] TTY and libc in Rust:
    https://docs.rs/libc/latest/libc/

[] PTY man page:
    https://man7.org/linux/man-pages/man7/pty.7.html

[] Fake PTY:
    https://github.com/dtolnay/faketty
    https://github.com/stemjail/tty-rs

[] Good post regarding PTY:
    https://fasterthanli.me/articles/a-terminal-case-of-linux

*/

use env_logger;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

struct IntruderInfo {
    username: String,
    password: String,
    ip_address: IpAddr,
    source_port: u16,
    // ip_v4_address: Ipv4Addr,
    // ip_v6_address: Ipv6Addr,
    // time: Time
}

#[derive(Debug, Deserialize)]
struct IntruderWhois {
    ip: String,
    country_name: String,
    #[serde(rename = "country_code2")]
    country_code: String,
    isp: String,
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

fn get_credentials(stream: &mut TcpStream, intruder_info: &mut IntruderInfo) {
    get_username(stream, intruder_info);
    get_password(stream, intruder_info);

    // if let Ok(Some(user)) = user {
    //     stream.write_all(b"\n").unwrap();
    //     credentials.username = user.to_string();
    // } else {
    //     stream.write_all(b"Error\n").unwrap();
    // }

    println!(
        "username: {}\npassword: {}\nip: {}\nport: {}",
        intruder_info.username,
        intruder_info.password,
        intruder_info.ip_address,
        intruder_info.source_port
    );
}

fn get_username(stream: &mut TcpStream, intruder_info: &mut IntruderInfo) {
    stream.write_all(b"username: ").unwrap();
    stream.flush().unwrap();

    let mut reader = io::BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();
    reader.consume(received.len());

    let mut username = String::from_utf8(received).unwrap();
    username.pop();

    intruder_info.username = username;
    // intruder_info.username = String::from_utf8(received).unwrap();
}

fn get_password(stream: &mut TcpStream, intruder_info: &mut IntruderInfo) {
    stream.write_all(b"password: ").unwrap();
    stream.flush().unwrap();

    let mut reader = io::BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();
    reader.consume(received.len());

    let mut password = String::from_utf8(received).unwrap();
    password.pop();

    intruder_info.password = password;
    // intruder_info.password = String::from_utf8(received).unwrap();
}

fn handle_connection(mut stream: TcpStream) {
    let mut intruder_info = IntruderInfo {
        username: String::new(),
        password: String::new(),
        source_port: 0,
        ip_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        // ip_v4_address: Ipv4Addr::new(0, 0, 0, 0),
        // ip_v6_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
    };

    let ip_address = stream.peer_addr().unwrap().ip();
    let port = stream.peer_addr().unwrap().port();

    intruder_info.ip_address = ip_address;
    intruder_info.source_port = port;

    info!("[+] connection from {} on port {}\n", ip_address, port);

    stream.set_read_timeout(Some(Duration::new(15, 0))).unwrap();
    stream.set_write_timeout(Some(Duration::new(3, 0))).unwrap();

    stream.write_all(default_banner().as_bytes()).unwrap();

    get_credentials(&mut stream, &mut intruder_info);
}

// fn send_initial_telnet_client_command(stream: TcpStream) {
//     let mut writer = &stream;

//     writer.write_all(b"\xff\xfd\x03")?; // Terminal type
//     writer.write_all(b"\xff\xfb\x18")?; // End of record
//     writer.write_all(b"\xff\xfb\x1f")?; // Terminal speed
//     writer.write_all(b"\xff\xfb\x20")?; // Toggle flow control
//     writer.write_all(b"\xff\xfb\x21")?; // Line mode
//     writer.write_all(b"\xff\xfb\x22")?; // Carriage return/line feed (CR/LF) transmission
//     writer.write_all(b"\xff\xfb\x27")?; // Output marking
//     writer.write_all(b"\xff\xfd\x05")?; // Supress go ahead
// }

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
                dbg!("Got EOF");
                break 'outer;
            }

            if c.is_ascii() {
                buffer.push(c as u8);
            }
        }
    }

    String::from_utf8(buffer).unwrap()
}

fn get_telnet_password(stream: &TcpStream) -> io::Result<String> {
    // let mut writer = &mut stream;
    let mut writer = stream;

    writer.write_all(b"\xff\xfb\x01")?; // Echo
    writer.write_all(b"\xff\xfb\x03")?; // Suppress go ahead
    writer.write_all(b"\xff\xfd\x18")?; // Terminal type
    writer.write_all(b"\xff\xfd\x1f")?; // Terminal speed

    // writer.write_all(b"\x0d\x0a")?; // \r\n
    writer.write_all(b"\x0d")?; // \r
    writer.write_all(b"Password: ")?;
    // writer.write_all(b"\x0d\x0a")?; // \r\n

    // writer.write_all(b"\xff\xfa\x18")?; // End of record
    // writer.write_all(b"\x01\xff\xf0")?; // Output line width
    writer.write_all(b"\xff\xfe\x20")?; // Toggle flow control

    writer.write_all(b"\xff\xfe\x21")?; // Line mode
    writer.write_all(b"\xff\xfe\x22")?; // Carriage return/line feed (CR/LF) transmission
    writer.write_all(b"\xff\xfe\x27")?; // Output marking

    writer.write_all(b"\xff\xfc\x05")?; // negotiate the suppress go ahead option

    // let mut password = String::new();
    let mut password = read_until_cr(writer);
    password = password.trim().to_string();

    // writer.write_all(b"\x0d\x0a")?; // \r\n
    // writer.write_all(b"Password: ")?;

    Ok(password)
}

fn handle_telnet_client(stream: TcpStream) -> io::Result<()> {
    let ip_address = stream.peer_addr().unwrap().ip();
    let port = stream.peer_addr().unwrap().port();
    info!("[+] connection from {} on port {}\n", ip_address, port);

    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;

    writer.write_all(default_banner().as_bytes()).unwrap();

    // Read the client's username
    let mut username = String::new();
    writer.write_all(b"Username: ").unwrap();
    writer.flush().unwrap();
    reader.read_line(&mut username)?;
    username = username.trim().to_string();

    let password = get_telnet_password(writer).unwrap();

    info!("Username: {}", username);
    info!("Password: {}", password);

    Ok(())
}

fn listen() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.23:2223")?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        let _ = handle_telnet_client(stream?);
        // let _ = get_telnet_password(&mut stream?);
    }
    Ok(())
}

fn whois(ip: String) -> Result<(), Box<dyn std::error::Error>> {
    info!("Looking up {}", ip);

    let url = format!("https://api.iplocation.net/?ip={}", ip);

    let resp: IntruderWhois = reqwest::blocking::get(url).unwrap().json().unwrap();

    println!("{:#?}", resp);

    Ok(())
}

fn main() {
    env_logger::init();
    // let _ = whois("81.164.189.195".to_string());
    listen().unwrap();
}
