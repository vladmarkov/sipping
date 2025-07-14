# SIP Ping Utility

## Overview

SIP Ping is a diagnostic utility for critical VoIP troubleshooting. It was originally created by Daniel Thompson and has been modified by Vlad Markov in Version 2.0. This tool is designed for troubleshooting a SIP peering (such as PBX, SBC, or phone) for deep-dive diagnostics. U

## Features

- Sends SIP OPTIONS messages to a target SIP device to measure response time.
- Continuously logs results to CSV files for further analysis.
- Supports both UDP and TLS protocols for sending packets.
- Allows configuration of various parameters, including intervals, user IDs, domains, and more.

## Installation

1. Ensure you have Python 3 installed on your system.
2. Download the `sipping.py` script to your local machine.

## Usage

Run the `sipping.py` script with the necessary command-line arguments. For a list of available options, use the `-h` flag:

```bash
python sipping.py -h
