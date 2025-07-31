#!/usr/bin/python3
"""
SIP and H.323 VCS Validation Tool - A diagnostic utility for VoIP and video conferencing systems
Created by Daniel Thompson
Modified by Vlad Markov
Version 3.0
==========================================================================

Software License:
MIT

Original Not-license:
I'd like to hear back from you if you do something interesting with this.
See http://gekk.info/sipping for more information and suggested usage.

==========================================================================

This tool is designed for monitoring SIP gateways and H.323 video conferencing systems for deep
dive diagnostics. It supports SIP OPTIONS and INFO methods for granular troubleshooting, as well
as H.225 Keep-alives for H.323 VCS validation.

Commandline flags and defaults are available by running "python sipping.py -h"

"""

from hashlib import md5
import random
import re
import cgi
import cgitb
import sys
import os
import socket
import ssl
import json
import struct
import urllib.request, urllib.parse, urllib.error
import signal
import argparse
import logging
from datetime import datetime
import time

# Configure logging for SSL debug output
logging.basicConfig(level=logging.CRITICAL)  # Default to suppressing debug output

# Handler for ctrl+c / SIGINT
def signal_handler(signal, frame):
    print('\nCtrl+C - exiting.')
    if v_logpath != "*":
        with open(v_logpath, "a") as f_log:
            f_log.write('\n')
    printstats()
    sys.exit(0)

def printstats():
    # Loss stats
    print(("\t[Recd: {recd} | Lost: {lost}]".format(recd=v_recd, lost=v_lost)), end=' ')
    if v_longest_run > 0:
        print(("\t[loss stats:"), end=' ')
        print(("longest run: " + str(v_longest_run)), end=' ')
    if v_last_run_loss > 0:
        print((" length of last run: " + str(v_last_run_loss)), end=' ')
    if v_current_run_loss > 0:
        print((" length of current run: " + str(v_current_run_loss)), end=' ')
    print("]")

    # Min, max, avg
    v_total = sum(l_history)
    v_avg = v_total / len(l_history) if v_total > 0 else 0
    print(("\t[min/max/avg {min}/{max}/{avg}]".format(min=v_min, max=v_max, avg=v_avg)))

# Create and execute command line parser
parser = argparse.ArgumentParser(description="Send SIP and H.225 messages to a host and measure response time. Results are logged continuously to CSV.")
parser.add_argument("host", help="Target device to ping (SIP gateway or H.323 VCS)")
parser.add_argument("-I", metavar="interval", default=1000, help="Interval in milliseconds between pings (default 1000)")
parser.add_argument("-u", metavar="userid", default="sipping", help="User part of the From header (default sipping)")
parser.add_argument("-i", metavar="ip", default="*", help="IP to send in the Via header (will TRY to get local IP by default)")
parser.add_argument("-d", metavar="domain", default="gekk.info", help="Domain part of the From header (needed if your device filters based on domain)")
parser.add_argument("-p", metavar="port", default=5060, help="Destination port (default 5060 for SIP, 1720 for H.323)")
parser.add_argument("--ttl", metavar="ttl", default=70, help="Value to use for the Max-Forwards field (default 70)")
parser.add_argument("-w", metavar="file", default="[[default]]", help="File to write results to. (default sipping-logs/[ip] - * to disable.")
parser.add_argument("-t", metavar="timeout", default="1000", help="Time (ms) to wait for response (default 1000)")
parser.add_argument("-c", metavar="count", default="0", help="Number of pings to send (default infinite)")
parser.add_argument("-x", nargs="?", default=False, help="Print raw transmitted packets")
parser.add_argument("-X", nargs="?", default=False, help="Print raw received responses")
parser.add_argument("-q", nargs="?", default=True, help="Do not print status messages (-x and -X ignore this)")
parser.add_argument("-S", nargs="?", default=True, help="Do not print loss statistics")
parser.add_argument("-B", metavar="bind_port", default=0, help="Outbound port to bind for sending packets (default is any available port)")
parser.add_argument("--proto", metavar="protocol", choices=["udp", "tcp", "tls", "h225"], default="udp", help="Protocol to use for sending packets (default is udp)")
parser.add_argument("--ssl-debug", action="store_true", help="Enable SSL debug output")
parser.add_argument("--cafile", metavar="cafile", help="Path to CA certificate file for server verification")
parser.add_argument("--cert", metavar="cert_file", help="Path to client certificate file")
parser.add_argument("--key", metavar="key_file", help="Path to client private key file")
parser.add_argument("--method", metavar="method", choices=["OPTIONS", "INFO"], default="OPTIONS", help="SIP method to use (default is OPTIONS)")
parser.add_argument("--dest-userid", metavar="dest_userid", default=None, help="User part of the request URI and To field (optional)")
parser.add_argument("--user-agent", metavar="user_agent", default=None, help="User-Agent header value (optional)")
parser.add_argument("--use-ip", action="store_true", help="Use destination IP and port instead of domain")
parser.add_argument("--contact", metavar="contact", nargs="?", const="", help="Contact header value (optional, defaults to From field)")
parser.add_argument("--accept", metavar="accept", default=None, help="Accept header value (optional)")
args = vars(parser.parse_args())

# Enable SSL debug output if requested
if args["ssl_debug"]:
    logging.getLogger("ssl").setLevel(logging.DEBUG)

# Populate data from command line
v_interval = int(args["I"])
v_fromip = args["i"]
v_sbc = args["host"]
v_bind_port = int(args["B"])
v_protocol = args["proto"]
cafile = args["cafile"]
cert_file = args["cert"]
key_file = args["key"]
sip_method = args["method"]
dest_userid = args["dest_userid"] if args["dest_userid"] else args["u"]
user_agent = args["user_agent"]
use_ip = args["use_ip"]
contact = args["contact"]
accept_header = "Accept: {}\n".format(args["accept"]) if args["accept"] else ""
# Did the user enter an IP?
if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v_sbc) is None:
    # The user entered a hostname; resolve it
    try:
        v_sbc = socket.getaddrinfo(v_sbc, 5060 if v_protocol in ["udp", "tcp", "tls"] else 1720, proto=socket.SOL_TCP if v_protocol in ["tcp", "tls", "h225"] else socket.SOL_UDP)[0][4][0]
    except Exception as error:
        # DNS resolution failure
        print("DNS resolution error:", error)
        sys.exit(1)

v_userid = args["u"]
v_port = int(args["p"])
v_domain = args["d"]
v_ttl = args["ttl"]
v_timeout = int(args["t"])
v_rawsend = args["x"] == None
v_rawrecv = args["X"] == None
v_quiet = not args["q"]
v_nostats = not args["S"]
v_count = int(args["c"])
if v_count == 0: v_count = sys.maxsize

if args["w"] == "[[default]]":
    if not os.path.exists("sipping-logs"): os.mkdir("sipping-logs")
    v_logpath = "sipping-logs/{ip}.csv".format(ip=v_sbc)
else:
    v_logpath = args["w"]

# If log output is enabled, ensure CSV has header
if v_logpath != "*":
    if not os.path.isfile(v_logpath):
        with open(v_logpath, "w") as f_log:
            f_log.write("time,timestamp,host,latency,callid,response")

def generate_nonce(length=8):
    """Generate pseudorandom number for call IDs."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

# Writes onscreen timestamps in a consistent format
def timef(timev=None):
    if timev is None:
        return datetime.now().strftime("%d/%m/%y %I:%M:%S:%f")
    else:
        return datetime.fromtimestamp(timev)

# Register signal handler for ctrl+c since we're ready to start
signal.signal(signal.SIGINT, signal_handler)
if not v_quiet: print("Press Ctrl+C to abort")

# Zero out statistics variables
v_recd = 0
v_lost = 0
v_longest_run = 0
v_last_run_loss = 0
v_current_run_loss = 0
last_lost = "never"
l_history = []
v_min = float("inf")
v_max = float("-inf")
v_iter = 0

# Empty list of last 5 pings
l_current_results = []

def send_sip_message(skt_sbc, v_register_one, v_protocol, v_sbc, v_port):
    """Send SIP message and handle exceptions."""
    try:
        if v_protocol == "udp":
            skt_sbc.sendto(v_register_one.encode('utf-8'), (v_sbc, v_port))
        else:  # For both TCP and TLS
            skt_sbc.send(v_register_one.encode('utf-8'))
    except Exception as e:
        print(f"Error sending data to {v_sbc}:{v_port}: {e}")
        return False
    return True

def send_h225_keep_alive(skt_sbc, v_sbc, v_port):
    """Send H.225 Keep-alive for H.323 VCS validation."""
    # Example H.225 Keep-alive packet (binary format)
    h225_keep_alive = struct.pack('!HH', 1, 1)
    try:
        skt_sbc.send(h225_keep_alive)
        if v_rawsend:
            print(f"Sending H.225 Keep-alive to {v_sbc}:{v_port}: {h225_keep_alive.hex()}")
    except Exception as e:
        print(f"Error sending H.225 Keep-alive to {v_sbc}:{v_port}: {e}")
        return False
    return True

# Start the ping loop
while v_count > 0:
    v_count -= 1
    # Create a socket
    try:
        if v_protocol == "udp":
            skt_sbc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            skt_sbc.bind(("0.0.0.0", v_bind_port))  # Bind to specified outbound port
            skt_sbc.settimeout(v_timeout / 1000.0)
        elif v_protocol == "tcp":
            skt_sbc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            skt_sbc.settimeout(v_timeout / 1000.0)
            skt_sbc.bind(("0.0.0.0", v_bind_port))
            skt_sbc.connect((v_sbc, v_port))
        elif v_protocol == "tls":
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if cafile:
                context.load_verify_locations(cafile=cafile)
            if cert_file and key_file:
                context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            skt_sbc = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=v_sbc)
            skt_sbc.settimeout(v_timeout / 1000.0)
            skt_sbc.connect((v_sbc, v_port))
        elif v_protocol == "h225":
            skt_sbc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            skt_sbc.settimeout(v_timeout / 1000.0)
            skt_sbc.connect((v_sbc, v_port))
    except socket.timeout:
        print(f"Connection to {v_sbc}:{v_port} timed out.")
        v_lost += 1
        continue
    except OSError as e:
        if e.errno == 98:
            print(f"Address {v_bind_port} already in use.")
        else:
            print(f"OS error: {e}")
        v_lost += 1
        continue
    except Exception as e:
        print(f"Error connecting to {v_sbc}:{v_port}: {e}")
        v_lost += 1
        continue

    # Use the bind port directly for the Via header
    v_localport = skt_sbc.getsockname()[1]
    # Find out what IP we're sourcing from to populate the Via and From
    if v_fromip != "*":
        v_lanip = v_fromip
    else:
        v_lanip = socket.gethostbyname(socket.gethostname())

    # Latency is calculated from this timestamp
    start = time.time()

    # Create a random callid so we can identify the message in a packet capture
    v_callid = generate_nonce(length=10)

    v_branch = generate_nonce(length=10)
    v_tag = "z9hG4" + generate_nonce(length=10)

    # Determine Request URI with port if missing
    domain_or_ip = v_sbc if use_ip else v_domain
    request_uri = "{dest_userid}@{domain_or_ip}:{port}".format(dest_userid=dest_userid, domain_or_ip=domain_or_ip, port=v_port)

    # Construct the From field
    from_field = "From: \"SIP Ping\"<sip:{userid}@{lanip}:{localport}>;tag={tag}".format(userid=v_userid, lanip=v_lanip, localport=v_localport, tag=v_tag)

    # Determine Contact field
    contact_value = contact if contact else "<sip:{userid}@{lanip}:{localport}>".format(userid=v_userid, lanip=v_lanip, localport=v_localport)
    contact_header = "Contact: {}\n".format(contact_value)

    # Write the SIP packet with specified method
    content_type = "Content-Type: text/plain\n" if sip_method == "INFO" else ""
    user_agent_header = "User-Agent: {}\n".format(user_agent) if user_agent else ""
    v_register_one = """{method} sip:{request_uri} SIP/2.0
Via: SIP/2.0/{proto} {lanip}:{localport};branch=z9hG4bK{branch}
To: "SIP Ping"<sip:{dest_userid}@{domain_or_ip}:{port}>
{from_field}
Call-ID: {callid}
CSeq: 1 {method}
Max-forwards: {ttl}
{user_agent_header}{contact_header}{accept_header}{content_type}Content-Length: 0

""".format(method=sip_method, request_uri=request_uri, dest_userid=dest_userid, domain_or_ip=domain_or_ip, port=v_port, lanip=v_lanip, localport=v_localport, branch=v_branch, userid=v_userid, callid=v_callid, ttl=v_ttl, proto=v_protocol.upper(), content_type=content_type, user_agent_header=user_agent_header, contact_header=contact_header, from_field=from_field, accept_header=accept_header)

    # Print transmit announcement
    if not v_quiet:
        if v_protocol in ["udp", "tcp", "tls"]:
            print(("> ({time}) Sending {method} to {host}:{port} [id: {id}]".format(method=sip_method, host=v_sbc, port=v_port, time=timef(), id=v_callid)))
        elif v_protocol == "h225":
            print(("> ({time}) Sending H.225 Keep-alive to {host}:{port}".format(host=v_sbc, port=v_port, time=timef())))

    # If -x was passed, print the transmitted packet
    if v_rawsend:
        if v_protocol in ["udp", "tcp", "tls"]:
            print(v_register_one)
        elif v_protocol == "h225":
            print(f"H.225 Keep-alive packet: {h225_keep_alive.hex()}")

    # Send the packet based on protocol
    if v_protocol in ["udp", "tcp", "tls"]:
        success = send_sip_message(skt_sbc, v_register_one, v_protocol, v_sbc, v_port)
    elif v_protocol == "h225":
        success = send_h225_keep_alive(skt_sbc, v_sbc, v_port)
    else:
        success = False

    if not success:
        v_lost += 1
        continue

    start = time.time()
    # Wait for response
    try:
        # Start a synchronous receive
        if v_protocol == "udp":
            data, addr = skt_sbc.recvfrom(1024)  # Buffer size is 1024 bytes
        else:
            data = skt_sbc.recv(1024)

        # Latency is calculated against this time
        end = time.time()
        diff = float("%.2f" % ((end - start) * 1000.0))

        # Pick out the first line in order to get the SIP response code
        v_response = data.split("\n".encode('utf-8'))[0]

        # Print success message and response code
        if not v_quiet:
            if v_protocol in ["udp", "tcp", "tls"]:
                print(("< ({time}) Reply from {host} ({diff}ms): {response}".format(host=addr[0] if v_protocol == "udp" else v_sbc, diff=diff, time=timef(), response=v_response)))
            elif v_protocol == "h225":
                print(("< ({time}) Reply from {host} ({diff}ms): {response}".format(host=v_sbc, diff=diff, time=timef(), response=data.hex())))

        # If -X was passed, print the received packet
        if v_rawrecv:
            if v_protocol in ["udp", "tcp", "tls"]:
                print(data)
            elif v_protocol == "h225":
                print(f"H.225 Keep-alive response: {data.hex()}")

        # Log success
        l_current_results.append("{time},{timestamp},{host},{diff},{id},{response}".format(host=addr[0] if v_protocol == "udp" else v_sbc, diff=diff, time=timef(), timestamp=time.time(), id=v_callid, response=v_response))

        # Update statistics
        l_history.append(diff)
        if len(l_history) > 200:
            l_history = l_history[1:]
        if diff < v_min:
            v_min = diff
        if diff > v_max:
            v_max = diff
        v_recd += 1
        if v_current_run_loss > 0:
            v_last_run_loss = v_current_run_loss
            if v_last_run_loss > v_longest_run:
                v_longest_run = v_last_run_loss
            v_current_run_loss = 0
    except socket.timeout:
        # Timed out; print a drop
        if not v_quiet: print(("X ({time}) Timed out waiting for response from {host}".format(host=v_sbc, time=timef())))
        # Log a drop
        l_current_results.append("{time},{timestamp},{host},drop,{id},drop".format(host=v_sbc, time=timef(), timestamp=time.time(), id=v_callid))

        # Increment statistics
        v_lost += 1
        v_current_run_loss += 1

    v_iter += 1
    # If it's been five packets, print stats and write logfile
    if v_iter > 4:
        # Print stats to screen
        if not v_nostats:
            printstats()

        # If logging is enabled, append stats to logfile
        if v_logpath != "*":
            with open(v_logpath, "a") as f_log:
                f_log.write("\n" + ("\n".join(l_current_results)))
        l_current_results = []

        v_iter = 0

    # Pause for user-requested interval before sending next packet
    if v_count > 0: time.sleep(v_interval / 1000.0)

if v_lost > 0:
    sys.exit(1)
