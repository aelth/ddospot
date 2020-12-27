![Logo](https://i.imgur.com/hyOLWXr.png)

[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/aelth/ddospot/blob/main/LICENSE) [![Python 3.x](https://img.shields.io/badge/python-3.x-blue)](https://www.python.org/)

# About

*DDoSPot* is a honeypot "platform" for tracking and monitoring UDP-based *Distributed Denial of Service* (DDoS) attacks.
The platform currently supports following honeypot services/servers in form of relatively simple plugins called *pots*:
- DNS server
- NTP server
- SSDP server
- CHARGEN server
- Random/mock UDP server

![DDoSPot](https://i.imgur.com/OFDMN3u.png)

# Plugins

All plugins share the same generic structure (in `pots/` directory), can be configured through dedicated configuration file and store info about the queries (i.e. *attacks* or *scans*) in the corresponding database and log file.
Every plugin uses separate database (in `db/` directory) and dedicated log file (in `logs/` directory) and has the ability to generate daily collection of IP addresses that can be considered *attackers/scanners* - these *blacklists* are stored in the `bl/` directory.
Additionally, every plugin can send e-mail notifications when attack on certain country is started.

Short info about currently available plugins is mentioned in the sections below.

## DNS
DNS plugin is based on [UDPot](https://github.com/jekil/UDPot) and uses [Twisted framework/engine](https://twistedmatrix.com/trac/).
It tries to emulate real DNS service as close as posible, by forwarding all requests to a valid recursive resolver and returns arbitrary response to CHAOS query.
*Amplification factor* thus depends on the returned response.

## NTP
Responds to 3 NTP packet modes:
- Client (mode 3)
- Control (mode 6)
- `monlist` (mode 7)

These modes were chosen because they are the ones most utilized in amplification-based DDoS attacks on NTP (mode 6 and 7), and client mode was implemented in order to make the service look more realistic.
All NTP client variables for those modes are fully configurable (for example, leap, delay, precision, ...).
List of `monlist` peers and information about those peers can be generated randomly or using the provided fixed list. *Amplification factor* can be tweaked, because it directly depends on the number of defined peers.

## SSDP
Responds to valid multicast (`M-SEARCH`) requests and provides (extremely constrained and light) emulation of [MiniUPnP](https://github.com/miniupnp/miniupnp).
Like NTP, it is fully configurable - *amplification factor* depends on the number of defined UPnP devices and their data, specified in the configuration.

## CHARGEN
Emulates [xinetd](https://github.com/xinetd-org/xinetd) chargen (which is not fully RFC 864 compliant). Response size of the service (and *amplification factor* as a result) is fully configurable (1 KB by default).

## Generic
This plugin can be used to emulate a response of arbitrary service, without following specific protocol specification or algorithm.
Plugin can either return fixed response for every query, or can generate a random response with a size depending on the input size (in order to achieve multiplication, desired by the attacker).

# Installation

*DDoSPot* requires *Python 3* and several additional packages:
- colorama
- hpfeeds
- python-geoip
- python-geoip-geolite2
- schedule
- SQLAlchemy
- tabulate
- Twisted

One way to install it is to use *virtualenv*:
```
git clone https://github.com/aelth/ddospot
cd ddospot/ddospot
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

The other way to install it is to create *Docker* image using provided [Dockerfile](https://github.com/aelth/ddospot/blob/main/ddospot/Dockerfile) or (better) using [Docker Compose](https://github.com/aelth/ddospot/blob/main/docker-compose.yml):
```
git clone https://github.com/aelth/ddospot
cd ddospot
docker-compose build
```

# Configuration

Global configuration file `global.conf` only lists all available plugins and whether they are enabled or not (initially, all plugins are enabled, but not started).

Every plugin provided with the tool and created from scratch, must have a valid configuration file that is stored along with the plugin/pot code in `pots/<plugin>` directory. Usually, you don't need to do any changes in the configuration file, especially if you're using *Docker* version.

Configuration file is well commented and has several sections.
- **general** - section that specifies the listening interface and port of the plugin:
```
[general]
listen_ip = 0.0.0.0
listen_port = 19
```
- **logging** - logging related section, specifies path to *SQLiteDB*, log file and specifies log rotation and flush intervals
```
[logging]
# Name of the SQLite database
# SQLite DB stores requests for easier lookup and/or dump
sqlitedb = db/chargenpot.sqlite3

# Name of the log file where relevant output will be stored
log = logs/chargenpot.log

# Size in MB after which log file is rotated
rotate_size = 10

# Number of old log files to keep
keep_backup_log_count = 5

# Separate thread periodically dumps local cache to database
# Value is in minutes (default: 5)
packet_flush_interval = 5

# Log *request* packet data in Base64 format
# Default is true 
log_req_packets = true
```
- **blacklist** - specifies blacklist creation rules. Important parameter is `blacklist_packet_threshold` - the only way to discriminate between attackers/scanners and victims in reflected DDoS attacks (i.e. all UDP-based attacks) is to use heuristic approach. If the number of requests reaching the plugin is low (below this threshold), then it is very likely that the source IP represents an attacker or a scanning entity. If the number is high, then it is very likely a victim
```
[blacklist]
# Blacklist section contains settings for periodic dumps of blacklist information
enabled = true

# Base name of the blacklist - 'daily', 'weekly', 'full' will be appended
blacklist_file = bl/blacklist-chargen

# Time to create daily blacklist in HH:MM format
daily_at = 16:00

# Blacklist packet threshold - all IPs which sent less packets than the threshold are considered scanner/attacker IPs.
# IPs with lots of packets are typically targets
blacklist_packet_threshold = 3
```
- **attack** - attack thresholds. **VERY IMPORTANT**: `packet_threshold` parameter is the **crucial** parameter that defines how many identical requests are allowed from the same IP address. If the number of requests surpasses the threshold, no more responses will be generated. Keep this parameter low, otherwise the server will be an active DDoS participant.
```
[attack]
# Threshold after which the responses will not be sent
# This parameter is crucial for stopping real DDoS attacks so it should be fairly low
packet_threshold = 10

# Time interval during which no packets/queries from a specific
# IP address have been observed.
# This time interval (in minutes) is used for detecting multiple attacks
# on the same IP address using same amplification method:
# If no packets have been seen from the IP address A and mode B for
# N minutes, this is qualified as a new attack.
# Default: 5 minutes
new_attack_detection_interval = 5
```
- **alerting** - mail notification parameters. Notifications will only be generated if the victim of an attack (IP address) is located in the specified country.
```
[alerting]
enabled = false

# SMTP host details
mail_host = mail.server.com
mail_port = 25
mail_username = username
mail_password = password

# Mail transport security.
# Available values:
#   None
#   SSL
#   STARTTLS
mail_sec = None

# Mail sender
mail_from = name@mail.com

# Comma-separated list of mail alert recepients
mail_to = name@mail.com

# Subject of the alert
mail_subject = New chargenpot alert

# Comma-separated list of country codes for which mail notifications/alerts should be sent.
# Please refer to https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2 for available codes.
# Length of the list directly affects honeypot performance because of additional lookup in case of the attack!
trigger_countries = GB

# Number of notifications that should be sent per 1 minute (60 seconds) in order to slow down multiple notifications.
# Notifications are put in a bounded queue with a fixed capacity.
# If the queue capacity is exceeded and message rate is also exceeded, oldest notifications are removed from the queue and lost.
# Default: 5  notifications per minute
notification_rate = 5
```
- **specific part** - every plugin has its specific configuration part that depends on the emulated service.
```
[chargen]
# Size of the generated response in bytes.
# Per RFC 864, response length is 0-512 bytes (random).
# However, xinetd implementation of chargen uses fixed-size circular response of 1024 bytes.
# The honeypot mimics xinetd behavior by returning 1024 bytes of circular data by default.
# This parameter directly affects amplification factor!
# Default: 1024
response_size = 1024

# Number of characters printed in one line of output.
# RFC 864 and xinetd chargen implementation specify 72 chars as line length.
# It is recommended to leave this parameter at the default value.
# Default: 72
line_len = 72
```

# Usage

To use *DDoSPot* with an interactive console, execute it without parameters:
```
./ddospot.py
```

Start desired plugin using `start <plugin>` command:

![start](https://i.imgur.com/jFgpDu5.png)

Status of the plugin, including detailed *statistics* can be obtained using `status <plugin>`:

![status](https://i.imgur.com/64k3kwA.png)


In non-interactive mode, all *enabled* (see `global.conf` configuration file) plugins will automatically be started using corresponding configuration files:
```
./ddospot.py -n
```

To run inside *Docker*, after building the image, execute:
```
docker-compose up
```

# Practical observations

Data collected in 2016, almost certainly outdated:)

## MTBS

**Mean-time-before-S(can)/(hadowserver)/S(hodan)** - how long does it take before freshly deployed honeypot gets detected?
- First scan can happen minutes after deployment
- DNS/NTP usually under an hour
- Almost all in 24 hours

![MTBS](https://i.imgur.com/llZjWIk.png)

## Attack distribution

NTP and DNS are prevalent protocols.

![Attacks](https://i.imgur.com/HMXGTOr.png)

## DNS domains used for amplification

Attackers use domains that give the highest ammount of amplification - domains that have DNSSEC implemented. Use minimal responses and minimal ANY.

![DNS](https://i.imgur.com/dfLaHWA.png)

# License

*DDoSPot* is provided under a MIT License. See the accompanying [LICENSE](https://github.com/aelth/ddospot/blob/master/LICENSE) file for more information.

# Presentations

- HNP Workshop 2016, San Antonio, TX, 2016

# Credits

Icons made by [Freepik](http://www.freepik.com/") from [Flaticon](https://www.flaticon.com/)

