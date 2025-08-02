# SIP and H.323 VCS Validation Tool

## Overview

The SIP and H.323 VCS Validation Tool is a diagnostic utility designed for monitoring SIP gateways and H.323 video conferencing systems. Originally created by Daniel Thompson and modified by Vlad Markov, Version 3.2 of this tool supports SIP OPTIONS and INFO methods for granular troubleshooting, as well as H.225 Keep-alives for H.323 VCS validation.

## Features

- Supports SIP protocols (OPTIONS and INFO methods) for granular diagnostics.
- Implements H.225 Keep-alives for H.323 VCS validation.
- Provides real-time latency and response monitoring.
- Offers detailed logging capabilities with CSV output.
- Supports multiple transport protocols: UDP, TCP, TLS, and H.225.

## Installation

1. Ensure you have Python 3 installed on your system.
2. Download the `sipping.py` script to your local machine.

## Usage

Run the `sipping.py` script with the necessary command-line arguments. For a list of available options, use the `-h` flag:

```bash
python sipping.py -h
```

### Example Command

```bash
python sipping.py target_host \
    -I 1000 \
    -u sipping \
    -i * \
    -d example.com \
    -p 5060 \
    --proto udp \
    --method OPTIONS \
    --accept application/xml
```

### Command-Line Arguments

- `host`: Target device to ping (SIP gateway or H.323 VCS).
- `-I`: Interval in milliseconds between pings (default 1000).
- `-u`: User part of the From header (default sipping).
- `-i`: IP to send in the Via header (default is to get local IP).
- `-d`: Domain part of the From header (default is "gekk.info").
- `-p`: Destination port (default 5060 for SIP, 1720 for H.323).
- `--ttl`: Max-Forwards field value (default 70).
- `-w`: File to write results to (default is "sipping-logs/[ip]").
- `-t`: Time in ms to wait for response (default 1000).
- `-c`: Number of pings to send (default infinite).
- `-x`: Print raw transmitted packets.
- `-X`: Print raw received responses.
- `-q`: Do not print status messages.
- `-S`: Do not print loss statistics.
- `-B`: Outbound port to bind for sending packets (default is any available port).
- `--proto`: Protocol to use for sending packets (default is udp). Options: udp, tcp, tls, h225.
- `--ssl-debug`: Enable SSL debug output.
- `--cafile`: Path to CA certificate file for server verification.
- `--cert`: Path to client certificate file.
- `--key`: Path to client private key file.
- `--method`: SIP method to use (default is OPTIONS).
- `--dest-userid`: User part of the request URI and To field (optional).
- `--user-agent`: User-Agent header value (optional).
- `--use-ip`: Use destination IP and port instead of domain.
- `--contact`: Contact header value (optional, defaults to From field).
- `--accept`: Accept header value (optional).
