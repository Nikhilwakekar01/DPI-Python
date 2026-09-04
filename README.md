# DPI-Python

A Python implementation of a Deep Packet Inspection (DPI) engine, ported from an existing C++ DPI implementation.

The project analyzes network packets from PCAP files, tracks flows, classifies application traffic, extracts domains/SNI information, applies traffic rules, and generates a forwarded output PCAP.

---

## 🚀 Features

- Deep Packet Inspection of PCAP traffic
- IPv4 packet parsing
- TCP and UDP packet processing
- Five-tuple based flow tracking
- Deterministic flow-to-worker load balancing
- TLS SNI extraction
- HTTP Host extraction
- DNS query extraction
- Basic QUIC detection
- Application classification
- Source IP blocking
- Application blocking
- Domain-based blocking
- Forward / Drop packet decisions
- Output PCAP generation
- Multithreaded DPI pipeline
- C++ and Python implementations
- Automated test suite

---

## 🏗️ Architecture

```text
                 PCAP Input
                     │
                     ▼
              ┌──────────────┐
              │ PCAP Reader  │
              └──────┬───────┘
                     │
                     ▼
             ┌───────────────┐
             │ Packet Parser │
             └───────┬───────┘
                     │
                     ▼
             ┌────────────────┐
             │ Load Balancer  │
             └───────┬────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       FastPath   FastPath   FastPath ...
          │          │          │
          └──────────┼──────────┘
                     │
                     ▼
              Flow Tracking
                     │
                     ▼
             Classification
                     │
                     ▼
               Rule Engine
                     │
                ┌────┴────┐
                ▼         ▼
             Forward    Drop
                │
                ▼
             Output PCAP
🔍 DPI Processing

The engine processes packets through the following pipeline:

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
Rule Checking
  ↓
Forward or Drop
  ↓
Output PCAP
🧠 Application Classification

The DPI engine uses protocol information and payload inspection for classification.

Classification order:

TLS SNI inspection for HTTPS traffic
HTTP Host inspection
DNS traffic detection
HTTPS fallback
HTTP fallback

The classifier can identify applications/domains using configured signatures and extracted information.

🛡️ Traffic Rules

The active DPI implementation supports:

Source IP Blocking

Packets can be blocked based on their source IPv4 address.

Application Blocking

Traffic can be blocked based on the detected application.

Domain Blocking

Traffic can be blocked when the extracted domain contains a configured substring.

Rules are evaluated for every processed packet.

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
├── Packet_analyzer/
│   ├── include/
│   ├── src/
│   ├── test_dpi.pcap
│   └── README.md
│
├── README.md
└── .gitignore
🐍 Python Version

The Python implementation is located in:

python_dpi/

It is implemented using the Python standard library and does not require external Python packages.

Run the Python DPI Engine

From the project root:

python -m python_dpi INPUT.pcap OUTPUT.pcap

Example:

python -m python_dpi Packet_analyzer/test_dpi.pcap output.pcap

The engine reads the input PCAP, processes the packets, applies DPI logic and rules, and writes the resulting packets to the output PCAP.

🧪 Testing

The Python implementation includes an automated test suite covering:

Data models
PCAP reading
Endianness handling
Packet parsing
IPv4 options
TCP options
UDP packets
TLS SNI extraction
HTTP Host extraction
DNS extraction
QUIC detection
Application classification
Traffic rules
Flow tracking
Load balancing
FastPath processing
Complete DPI engine integration
CLI execution

Current test result:

88 tests passed

Run the complete test suite with:

python -m unittest discover -s python_dpi/tests -v
⚙️ C++ Implementation

The original DPI implementation is written in C++ and is located under:

Packet_analyzer/

The active C++ implementation is:

Packet_analyzer/src/dpi_mt.cpp

It uses the following supporting components:

src/dpi_mt.cpp
src/pcap_reader.cpp
src/packet_parser.cpp
src/sni_extractor.cpp
src/types.cpp

The Python implementation was developed to reproduce the behavior of the active C++ implementation.

🔨 Building the C++ Version

Using a C++17-compatible compiler:

g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
src/dpi_mt.cpp \
src/pcap_reader.cpp \
src/packet_parser.cpp \
src/sni_extractor.cpp \
src/types.cpp
📊 Validation

The Python implementation was validated against the active C++ implementation using PCAP traffic.

Validation included:

Normal packets
Malformed packets
Non-IPv4 packets
Non-TCP/UDP IPv4 packets
HTTP traffic
TLS/SNI traffic
DNS traffic
Source-IP rules
Application rules
Domain rules
PCAP endianness handling
End-to-end packet processing

Example integration validation:

Input packets       : 77
Processed packets   : 77
Forwarded packets   : 77
Dropped packets     : 0
Total bytes         : 5738
TCP packets         : 73
UDP packets         : 4
📦 PCAP Support

The engine works with packet capture (.pcap) files.

Input:

input.pcap

Output:

output.pcap

The output PCAP preserves the packet data and timestamps for forwarded packets.

⚠️ Notes
The current implementation focuses on IPv4 TCP/UDP traffic.
Flow tracking follows directional five-tuples.
Packet output order may differ because of multithreaded processing.
The implementation is designed to reproduce the behavior of the active C++ DPI implementation rather than introduce unrelated features.
🛠️ Technologies
Python
Python 3
Standard Library
unittest
Multithreading
PCAP binary parsing
Raw packet parsing
C++
C++17
GCC
POSIX-style threading
PCAP processing
🎯 Purpose

This project demonstrates how a packet inspection pipeline can be implemented from low-level packet parsing through flow tracking, application classification, rule evaluation, and PCAP output.

It also demonstrates the process of porting an existing multithreaded C++ networking implementation to Python while preserving its observable behavior.
```
