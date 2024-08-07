# Oxipot

![oxipot_logo](artwork/oxipot_logo.jpeg)

![Downloads](https://img.shields.io/github/downloads/pouriyajamshidi/oxipot/total.svg?label=DOWNLOADS&logo=github)
![Docker Pulls](https://img.shields.io/docker/pulls/pouriyajamshidi/oxipot)

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

This is the recommended way since it will always makes sure the container remains up.

1. Make the database directory:

   ```bash
   mkdir /var/log/oxipot
   ```

2. Start the container:

   ```bash
   docker compose up
   ```

> Please note this example is using the new `compose` plugin and not `docker-compose`. Nonetheless, there should be no difference.

### Using Docker

1. Make the database directory:

   ```bash
   mkdir /var/log/oxipot
   ```

2. Map port 23 to oxipot's default port, 2223 and specify the directory you want the database to be stored in.

   ```bash
   docker run --name oxipot --rm -t -p 23:2223 -v /var/log/oxipot:/oxipot/db:rw oxipot:latest
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

4. Make the database directory:

   ```bash
   mkdir db
   ```

5. Run it:

   ```bash
   ./oxipot
   ```

> A folder named `db` will be created in the same directory that will host `oxipot.db` containing the intruder reports.

## View The Report

After a connection is made to the machine running `oxipot`, a **sqlite3** database is created that you can refer to in order to see who has connected to the machine and what credentials they have used.

Depending on how you run `oxipot`, the location of the database will differ.

- Using [docker compose](#using-docker-compose), the database will be located at `/var/log/oxipot/oxipot.db`.
- Using [docker run](#using-docker), the database will be located at the directory the image was started at `/var/log/oxipot/oxipot.db` or a custom directory you have specified.
- Using [the executable](#using-the-executable), the database will be located at the same directory as `oxipot`.

Utilizing sqlite3, you can view the reports.

1. Open the database:

   ```bash
   sqlite3 /var/log/oxipot/oxipot.db
   ```

2. Run your query:

   ```sql
   SELECT * FROM intruders;
   ```

The result will be similar to:

![oxipot_report](artwork/oxipot_example_report.png)

## Disclaimer

This is a hobby project and work in progress prone to many changes. Run at your own risk.
