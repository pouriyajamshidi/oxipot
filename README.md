# Oxipot

![oxipot_logo](artwork/oxipot_logo_final.png)

A network telnet `HoneyPot` written in Rust.

## Features

- Detect **IT**, **OT** and **IoT** bots 🤖
- Capture IP and location information of bots, attackers and intruders trying to gain access to your network
- In-memory (`volatile`) and database (`non-volatile`) IP and location information caching
- Handles a lot of concurrent network connections
- Rate-limits persistent intruders
- Build a big username and password database for IT, OT and IoT (thanks to malicious actors)
- Extremely resource friendly and efficient to run
- Containerized for portability and better security
- SSH support (TBD)

## Run

### Using Docker Compose

This is the recommended way since it will always makes sure the container is up.

```bash
docker compose up
```

> Please note this example is using the `compose` plugin and not `docker-compose`.

### Using Docker

Map port 23 to oxipot's default port, 2223 and specify the directory you want the database to be stored in.

```bash
docker run --name oxipot --rm -t -p 23:2223 -v $(pwd):/oxipot/db:rw oxipot:latest
```

### Using The Executable

Directly using the executable is not recommended. This method should be used only if you know your craft.

1. Download [the executable](https://github.com/pouriyajamshidi/oxipot/releases/latest/download/oxipot.tar.gz).

2. Extract the file:

   ```bash
   tar -zxvf oxipot.tar.gz
   ```

3. Make it executable:

   ```bash
   chmod +x oxipot
   ```

4. Run it:

   ```bash
   ./oxipot
   ```

## Disclaimer

This is a hobby project and work in progress prone to many changes. Run at your own risk.

## Why Not Tokio?

[Tokio](https://tokio.rs) (as of the commit time) struggled on **single core** machines with **128 MB or less** of RAM leading it not to handle multiple incoming connections concurrently. However if you are interested to see how it looked when I first tried to make it work, check the `async` branch of this repo.

⚠️ Use of `tokio` was at a very early stage of my development and the code might be too ugly to look at. Nonetheless, it is kept as a reference and might be deleted soon.
