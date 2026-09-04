# DPI-Python

A Python-based Deep Packet Inspection (DPI) engine for analyzing network traffic from PCAP files.

The project parses network packets, tracks flows, classifies application traffic, extracts protocol information such as TLS SNI, HTTP Host and DNS queries, applies traffic rules, and generates an output PCAP.

## 🚀 Features

- PCAP file reading and writing
- Ethernet and IPv4 packet parsing
- TCP and UDP packet parsing
- IPv4/TCP options handling
- Five-tuple based flow tracking
- Deterministic flow load balancing
- Multithreaded DPI processing
- TLS SNI extraction
- HTTP Host extraction
- DNS query extraction
- Basic QUIC detection
- Application classification
- Source IP blocking
- Application blocking
- Domain-based blocking
- Forward / Drop decisions
- Output PCAP generation
- Automated unit and integration tests
- Command-line interface

## 🏗️ Architecture

```text
                    Input PCAP
                        │
                        ▼
                 ┌─────────────┐
                 │ PCAP Reader │
                 └──────┬──────┘
                        │
                        ▼
                ┌──────────────┐
                │Packet Parser │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │Load Balancer │
                └──────┬───────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
           FastPath FastPath FastPath
              │        │        │
              └────────┼────────┘
                       │
                       ▼
                 Flow Tracking
                       │
                       ▼
                Classification
                       │
                       ▼
                  Rule Check
                       │
                 ┌─────┴─────┐
                 ▼           ▼
              Forward       Drop
                 │
                 ▼
              Output PCAP
🔍 DPI Processing Pipeline
PCAP
 ↓
Raw Packet
 ↓
Ethernet Parsing
 ↓
IPv4 Parsing
 ↓
TCP / UDP Parsing
 ↓
Five-Tuple Flow Identification
 ↓
Load Balancing
 ↓
Flow Tracking
 ↓
Protocol / Application Classification
 ↓
Rule Evaluation
 ↓
Forward or Drop
 ↓
Output PCAP
🧠 Application Classification

The engine classifies traffic using protocol information and payload inspection.

Classification priority:

TLS SNI inspection for HTTPS traffic
HTTP Host inspection
DNS traffic detection
HTTPS fallback
HTTP fallback

Supported application classifications include examples such as:

AMAZON
APPLE
CLOUDFLARE
DISCORD
DNS
FACEBOOK
GITHUB
GOOGLE
HTTP
HTTPS
INSTAGRAM
SPOTIFY
TELEGRAM
TIKTOK
TWITTER
YOUTUBE
ZOOM
UNKNOWN
🛡️ Traffic Rules

The DPI engine supports three active rule types.

Source IP Blocking

Blocks packets originating from configured source IPv4 addresses.

Application Blocking

Blocks traffic based on the detected application.

Domain Blocking

Blocks traffic when the extracted domain matches a configured domain substring.

Rules are evaluated during packet processing.

📁 Project Structure
DPI-Python/
│
├── python_dpi/
│   ├── __init__.py
│   ├── __main__.py
│   ├── models.py
│   ├── pcap_reader.py
│   ├── packet_parser.py
│   ├── extractors.py
│   ├── classifier.py
│   ├── rules.py
│   ├── flow_tracker.py
│   ├── fast_path.py
│   ├── load_balancer.py
│   ├── dpi_engine.py
│   │
│   └── tests/
│       ├── test_models.py
│       ├── test_pcap_reader.py
│       ├── test_packet_parser.py
│       ├── test_extractors.py
│       ├── test_classifier.py
│       ├── test_rules.py
│       ├── test_flow_tracker.py
│       ├── test_fast_path.py
│       ├── test_load_balancer.py
│       ├── test_dpi_engine.py
│       └── test_cli.py
│
├── test_dpi.pcap
├── README.md
└── .gitignore
🐍 Requirements
Python 3.10+
No external Python packages are required.
The project uses the Python standard library.
▶️ Run the DPI Engine

Open a terminal in the project root:

python -m python_dpi INPUT.pcap OUTPUT.pcap

For example:

python -m python_dpi test_dpi.pcap output.pcap

The command reads the input PCAP, processes the packets through the DPI pipeline, and generates the resulting output PCAP.

Example
Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738

Example application classification:

AMAZON: 1
APPLE: 1
CLOUDFLARE: 1
DISCORD: 1
DNS: 4
FACEBOOK: 1
GITHUB: 1
GOOGLE: 1
HTTP: 2
HTTPS: 39
INSTAGRAM: 1
SPOTIFY: 1
TELEGRAM: 1
TIKTOK: 1
TWITTER: 3
UNKNOWN: 16
YOUTUBE: 1
ZOOM: 1
🧪 Testing

The project contains unit tests and integration tests covering:

Data models
IPv4 address conversion
PCAP parsing
Native and swapped-endian PCAP files
Ethernet parsing
IPv4 parsing
IPv4 options
TCP parsing
TCP options
UDP parsing
TLS SNI extraction
HTTP Host extraction
DNS extraction
QUIC detection
Application classification
Traffic rules
Flow tracking
FastPath processing
Load balancing
Complete DPI engine
CLI execution

Run all tests:

python -m unittest discover -s python_dpi/tests -v

Current validation:

88 tests passed
📊 Validation

The Python DPI engine was validated using a test PCAP containing 77 packets.

Validation result:

Input packets       : 77
Processed packets   : 77
Forwarded packets   : 77
Dropped packets     : 0
Total bytes         : 5738
TCP packets         : 73
UDP packets         : 4

The implementation was also tested against malformed packets, non-IPv4 traffic, non-TCP/UDP IPv4 traffic, HTTP traffic, TLS/SNI traffic, DNS traffic, and traffic blocking rules.

📦 PCAP Input / Output

Input:

test_dpi.pcap

Output:

output.pcap

The output PCAP contains the packets that were forwarded by the DPI engine.

You can open the generated PCAP in Wireshark for packet-level inspection.

⚙️ Implementation

The project is implemented using Python's standard library.

Major components:

Component	Responsibility
pcap_reader.py	Reads PCAP files
packet_parser.py	Parses Ethernet, IPv4, TCP and UDP
extractors.py	Extracts SNI, HTTP Host, DNS and QUIC information
classifier.py	Identifies applications
rules.py	Applies traffic blocking rules
flow_tracker.py	Tracks packet flows
fast_path.py	Processes packets and applies DPI logic
load_balancer.py	Distributes flows between workers
dpi_engine.py	Coordinates the complete DPI pipeline
__main__.py	Command-line interface
⚠️ Limitations
Current packet inspection focuses on IPv4 traffic.
TCP and UDP traffic are supported.
Flow tracking uses directional five-tuples.
Multithreaded processing means output packet order may differ from input order.
The project currently processes PCAP files rather than capturing packets directly from a live network interface.
The DPI signatures are intentionally limited to the applications implemented by the classifier.
🎯 Purpose

This project demonstrates the implementation of a Deep Packet Inspection pipeline in Python, including low-level packet parsing, protocol inspection, flow tracking, application classification, rule evaluation, multithreading, and PCAP generation.

The project is designed as a practical networking and backend-oriented systems project.
```
