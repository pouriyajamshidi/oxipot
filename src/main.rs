extern crate termion;

use std::io::{stdin, stdout, Write};
use termion::input::TermRead;

struct Credentials {
    username: String,
    password: String,
}

fn get_credentials() -> Credentials {
    let mut credentials = Credentials {
        username: String::new(),
        password: String::new(),
    };

    let stdin = stdin();
    let stdout = stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    stdout.write_all(b"username: ").unwrap();
    stdout.flush().unwrap();

    let user = stdin.read_line();

    stdout.write_all(b"password: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout);

    if let Ok(Some(user)) = user {
        stdout.write_all(b"\n").unwrap();
        credentials.username = user.to_string();
    } else {
        stdout.write_all(b"Error\n").unwrap();
    }

    if let Ok(Some(pass)) = pass {
        stdout.write_all(b"\n").unwrap();
        credentials.password = pass.to_string();
    } else {
        stdout.write_all(b"Error\n").unwrap();
    }

    return credentials;
}

fn main() {
    let credentials = get_credentials();
    println!(
        "username: {}\npassword: {}",
        credentials.username, credentials.password
    );
}
