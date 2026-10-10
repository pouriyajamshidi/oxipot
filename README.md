# Oxipot

![oxipot_logo](artwork/oxipot_logo.jpeg)

![Downloads](https://img.shields.io/github/downloads/pouriyajamshidi/oxipot/total.svg?label=DOWNLOADS&logo=github)
![Docker Pulls](https://img.shields.io/docker/pulls/pouriyajamshidi/oxipot)

A network telnet `HoneyPot` written in Rust.

## Features

- Detect **IT**, **OT** and **IoT** bots 🤖
- Capture IP and location information of bots, attackers and intruders trying to gain access to your network
- Offline IP lookups with the free [ip66.dev](https://ip66.dev) database, with an online fallback
- In-memory (`volatile`) and database (`non-volatile`) IP and location information caching
- Handles a lot of concurrent network connections
- Rate-limits persistent intruders
- Optional JSON logs for the Elastic Stack, Splunk and similar tools
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

1. Download the executable for your architecture:
   [x86_64](https://github.com/pouriyajamshidi/oxipot/releases/latest/download/oxipot-linux-x86_64.tar.gz)
   or
   [aarch64](https://github.com/pouriyajamshidi/oxipot/releases/latest/download/oxipot-linux-aarch64.tar.gz).

2. Extract the file:

   ```bash
   tar -zxvf oxipot-linux-x86_64.tar.gz
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

## IP Lookups

To find the country and ISP of an intruder, `oxipot` checks these in order and stops at the first one that knows the IP address:

1. The in-memory cache and the `oxipot.db` database.
2. The `ip66.mmdb` file in the database directory, if it exists. It is free and updated daily by [ip66.dev](https://ip66.dev) (CC BY 4.0).
3. The [iplocation.net](https://www.iplocation.net) web API.

To use the offline file, download it into the database directory and restart `oxipot`:

```bash
curl -o /var/log/oxipot/ip66.mmdb https://downloads.ip66.dev/db/ip66.mmdb
```

> Use `db/ip66.mmdb` instead if you run [the executable](#using-the-executable).

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
   .mode box
   SELECT time, ip, country_name, username, password FROM intruders ORDER BY time DESC LIMIT 5;
   ```

The result will be similar to:

```text
┌─────────────────────┬─────────────────┬──────────────┬──────────┬──────────────────────────────────────┐
│        time         │       ip        │ country_name │ username │               password               │
├─────────────────────┼─────────────────┼──────────────┼──────────┼──────────────────────────────────────┤
│ 2025-09-12 18:45:30 │ 185.44.81.104   │ France       │ telnet   │ telnet                               │
│ 2025-09-12 18:44:02 │ 111.92.20.228   │ India        │ guest    │ 123456                               │
│ 2025-09-12 18:43:55 │ 124.234.245.229 │ China        │ enable   │ cat /proc/mounts; /bin/busybox SCWCD │
│ 2025-09-12 18:42:19 │ 95.214.27.248   │ Netherlands  │ admin    │ 1234                                 │
│ 2025-09-12 18:41:07 │ 103.79.142.242  │ Viet Nam     │ root     │ admin                                │
└─────────────────────┴─────────────────┴──────────────┴──────────┴──────────────────────────────────────┘
```

> The `intruders` table also holds `source_port`, `country_code` and `isp`. Use `SELECT * FROM intruders;` to see everything.

## JSON Logs

To send the reports to tools like the Elastic Stack or Splunk, set `OXIPOT_JSON_LOG=true`. `oxipot` then also writes every login try to `oxipot.json`, next to `oxipot.db`, one JSON object per line:

```json
{"country_code":"FR","country_name":"France","ip":"185.44.81.104","isp":"Example ISP","password":"telnet","source_port":51432,"time":"2025-09-12T18:45:30Z","username":"telnet"}
```

- Using [docker compose](#using-docker-compose), add it under `services.oxipot`:

  ```yaml
  environment:
    - OXIPOT_JSON_LOG=true
  ```

- Using [docker run](#using-docker), add `-e OXIPOT_JSON_LOG=true`.
- Using [the executable](#using-the-executable), run `OXIPOT_JSON_LOG=true ./oxipot`.

## Disclaimer

This is a hobby project and work in progress prone to many changes. Run at your own risk.
