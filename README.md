# DPI-Python

A Python-based **Deep Packet Inspection (DPI)** engine for analyzing and filtering network traffic from PCAP files, with an experimental Windows live-traffic mode using WinDivert.

The project implements a complete DPI pipeline including:

- Low-level packet parsing
- IPv4 packet inspection
- TCP/UDP parsing
- Flow tracking
- Deterministic flow load balancing
- Multithreaded packet processing
- TLS SNI extraction
- HTTP Host extraction
- DNS query extraction
- Basic QUIC packet detection
- Application classification
- Source IP blocking
- Application blocking
- Domain-based blocking
- Packet forwarding/dropping
- Output PCAP generation
- Windows live traffic interception
- Unit and integration testing

> **The PCAP/offline DPI engine is the primary validated implementation.**
> The live DPI implementation is currently an experimental Windows prototype.

---

## 🚀 Features

### PCAP DPI Engine

- PCAP file reading and writing
- Native-endian PCAP support
- Swapped-endian PCAP support
- Ethernet frame parsing
- IPv4 packet parsing
- IPv4 options handling
- TCP parsing
- TCP options handling
- UDP parsing
- Five-tuple based flow tracking
- Directional flow tracking
- Deterministic flow load balancing
- Multithreaded DPI processing
- TLS SNI extraction
- HTTP Host extraction
- DNS query extraction
- Basic QUIC packet detection
- Application classification
- Source IP blocking
- Application blocking
- Domain-based blocking
- Forward / Drop decisions
- Output PCAP generation
- Command-line interface
- Unit tests
- Integration tests

### Experimental Live DPI

The repository also contains an experimental Windows live-traffic implementation using WinDivert.

It can:

- Intercept IPv4 TCP/UDP traffic
- Parse intercepted packets
- Inspect visible TLS SNI information
- Classify traffic
- Apply DPI rules
- Forward allowed packets
- Drop blocked packets

> **Important:** Live DPI is currently Windows-specific and experimental.
> The PCAP-based DPI engine is the primary validated implementation.

---

## 🏗️ Architecture

```text
                         Input PCAP
                             │
                             ▼
                     ┌──────────────┐
                     │  PCAP Reader │
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Packet Parser│
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Load Balancer│
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          FastPath       FastPath      FastPath
              │             │             │
              └─────────────┼─────────────┘
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
                     ┌──────┴──────┐
                     ▼             ▼
                  Forward        Drop
                     │
                     ▼
                  Output PCAP
```

### 🔍 DPI Processing Pipeline

```text
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
```

### 🧠 Application Classification

The classifier uses packet metadata and payload inspection.

**Classification Priority**

The current classification order is:

1. TLS SNI
2. HTTP Host
3. DNS
4. HTTPS fallback
5. HTTP fallback

More specifically:

```text
1. Destination port 443 + sufficient payload
      ↓
   Try TLS SNI extraction

2. Destination port 80 + sufficient payload
      ↓
   Try HTTP Host extraction

3. Source OR destination port 53
      ↓
   DNS classification

4. Destination port 443
      ↓
   HTTPS fallback

5. Destination port 80
      ↓
   HTTP fallback
```

**Supported Application Types**

The current classifier contains application categories including:

```
AMAZON       APPLE        CLOUDFLARE   DISCORD
DNS          FACEBOOK     GITHUB       GOOGLE
HTTP         HTTPS        INSTAGRAM    SPOTIFY
TELEGRAM     TIKTOK       TWITTER      YOUTUBE
ZOOM         UNKNOWN
```

The exact classification depends on the information visible inside the packet.

Encrypted traffic or traffic without an inspectable hostname may be classified as `HTTPS` or `UNKNOWN`.

---

### 🛡️ Traffic Rules

The DPI engine currently supports three active rule types.

**1. Source IP Blocking**

Blocks packets originating from a configured IPv4 address.

```python
engine.block_ip("192.168.1.10")
```

**2. Application Blocking**

Blocks traffic based on the detected application.

```python
engine.block_app("YouTube")
```

**3. Domain Blocking**

Blocks traffic when the extracted domain/SNI contains the configured domain substring.

```python
engine.block_domain("youtube")
```

> Domain matching follows the current implementation's substring and case-sensitive behavior.

---

## 📁 Project Structure

```
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
├── live_dpi.py
├── windivert/
│   └── WinDivert64.sys
│
├── README.md
└── .gitignore
```

> Depending on the environment, WinDivert-related files such as `WinDivert.dll` and `WinDivert.lib` may be present locally but ignored by Git.

---

## 🐍 Requirements

### Offline / PCAP Mode

The offline DPI engine uses Python's standard library.

- **Recommended:** Python 3.10+
- No external Python package is required for the offline PCAP engine.

### Live DPI Mode

Live DPI requires:

- Windows
- 64-bit Python
- Python 3.10+
- WinDivert
- PyDivert
- Administrator privileges

Install PyDivert with:

```bash
python -m pip install pydivert
```

Verify installation:

```bash
python -c "import pydivert; print('PyDivert installed successfully')"
```

Expected:

```
PyDivert installed successfully
```

> The live implementation is Windows-specific because it relies on WinDivert.

---

## ⬇️ Installation

### Step 1 — Clone the Repository

Open PowerShell or Command Prompt.

```bash
git clone https://github.com/Nikhilwakekar01/DPI-Python.git
```

Then enter the project directory:

```bash
cd DPI-Python
```

### Step 2 — Verify Project Files

```bash
dir
```

You should see files/folders similar to:

```
python_dpi
test_dpi.pcap
live_dpi.py
windivert
README.md
.gitignore
```

### Step 3 — Check Python

```bash
python --version
```

Example:

```
Python 3.14.2
```

Python 3.10 or newer is recommended.

### Step 4 — Optional Virtual Environment

A virtual environment is recommended if you want an isolated Python environment.

Create it:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

For Command Prompt:

```cmd
.venv\Scripts\activate
```

If activation succeeds, your terminal may show `(.venv)` at the beginning of the command line.

### Step 5 — Verify Python Module

From the project root, run:

```bash
python -c "import python_dpi; print('DPI-Python imported successfully')"
```

Expected:

```
DPI-Python imported successfully
```

At this point the offline DPI engine is ready.

---

## 🖥️ Offline DPI Mode

The offline mode reads packets from a PCAP file, processes them through the DPI pipeline, and writes forwarded packets to another PCAP file.

```text
Input PCAP
    ↓
PCAP Reader
    ↓
Packet Parser
    ↓
Flow Tracking
    ↓
Classification
    ↓
Rule Check
    ↓
Forward / Drop
    ↓
Output PCAP
```

### ▶️ Run the Offline DPI Engine

Make sure you are inside the `DPI-Python` directory, then run:

```bash
python -m python_dpi test_dpi.pcap output.pcap
```

**Expected Output:**

```
Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738
```

You should now have `output.pcap` inside the project directory.

### 🔎 Check That output.pcap Was Created

```powershell
dir output.pcap
```

Check its size:

```powershell
(Get-Item output.pcap).Length
```

The size may vary depending on the input/output data.

---

## 🧪 Run All Tests

The project contains unit tests and integration tests.

From the project root:

```bash
python -m unittest discover -s python_dpi/tests -v
```

**What Is Tested?**

| Area | Coverage |
|------|----------|
| Data models | IPv4 address conversion, Five-tuple hashing |
| PCAP parsing | Native-endian, Swapped-endian, Malformed PCAP |
| Packet parsing | Ethernet, IPv4, IPv4 options, TCP, TCP options, UDP |
| Extractors | TLS SNI, HTTP Host, DNS, QUIC detection |
| Engine | Application classification, Traffic rules, Flow tracking, FastPath, Load balancing, Complete DPI, CLI |
| Integration | Real PCAP integration |

**Expected Test Result:**

```
Ran 88 tests
OK
```

---

## 🔐 Test Offline Blocking

The DPI engine can block traffic while processing a PCAP. The included `test_dpi.pcap` contains a packet that can be classified as YouTube traffic.

Run:

```bash
python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"
```

**Expected Result:**

```
Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738
```

**What happened:**

```text
77 packets entered DPI
        │
        ▼
   DPI processing
        │
   ┌────┴────┐
   ▼         ▼
 DROP      FORWARD
  1           76
```

### 🔎 Verify Blocked Output PCAP

```bash
python -c "from python_dpi.pcap_reader import PcapReader; r=PcapReader(); print('Opened:', r.open('blocked_output.pcap')); n=0; p=r.read_next_packet(); exec('while p is not None:\n n += 1\n p = r.read_next_packet()'); print('Output packets:', n); r.close()"
```

**Expected:**

```
Opened: True
Output packets: 76
```

This confirms:
- **Input:** 77 packets
- **Output:** 76 packets
- **Dropped:** 1 packet

---

## 📊 Offline Validation

The Python DPI engine has been validated using the included test PCAP.

**Validation Result:**

```
Input packets       : 77
Processed packets   : 77
Forwarded packets   : 77
Dropped packets     : 0
Total bytes         : 5738
TCP packets         : 73
UDP packets         : 4
```

**Application Classification:**

```
AMAZON      : 1       APPLE       : 1
CLOUDFLARE  : 1       DISCORD     : 1
DNS         : 4       FACEBOOK    : 1
GITHUB      : 1       GOOGLE      : 1
HTTP        : 2       HTTPS       : 39
INSTAGRAM   : 1       SPOTIFY     : 1
TELEGRAM    : 1       TIKTOK      : 1
TWITTER     : 3       UNKNOWN     : 16
YOUTUBE     : 1       ZOOM        : 1
```

Additional tests cover: malformed packets, non-IPv4 traffic, non-TCP/UDP IPv4 traffic, HTTP traffic, TLS/SNI traffic, DNS traffic, flow handling, and blocking rules.

---

## 📦 PCAP Input / Output

| File | Description |
|------|-------------|
| `test_dpi.pcap` | Input |
| `output.pcap` | Normal output |
| `blocked_output.pcap` | Blocking test output |

The output PCAP contains packets that were forwarded by the DPI engine. Generated PCAP files can be opened using Wireshark.

---

## 🦈 Wireshark Verification

After running:

```bash
python -m python_dpi test_dpi.pcap output.pcap
```

Open `output.pcap` in Wireshark. You can inspect: Packet number, Source/Destination IP, Protocol, Ports, Packet length, TCP/UDP/TLS/DNS/HTTP information.

**Verify Blocking With Wireshark**

After running the blocking test, open `blocked_output.pcap` in Wireshark. The blocked packet should not be present in the output.

---

## ⚙️ Implementation

| Component | Responsibility |
|-----------|---------------|
| `pcap_reader.py` | Reads classic PCAP files |
| `packet_parser.py` | Parses Ethernet, IPv4, TCP and UDP |
| `extractors.py` | Extracts TLS SNI, HTTP Host, DNS and basic QUIC information |
| `classifier.py` | Identifies applications |
| `rules.py` | Applies traffic blocking rules |
| `flow_tracker.py` | Tracks directional flows |
| `fast_path.py` | Processes packets and applies DPI logic |
| `load_balancer.py` | Distributes flows between FastPath workers |
| `dpi_engine.py` | Coordinates the complete multithreaded DPI pipeline |
| `__main__.py` | Provides the command-line interface |

---

## 🧵 Multithreaded Processing

The default DPI engine configuration is:

```
Load Balancers : 2
FastPaths/LB   : 2
Total FastPaths: 4
Queue size     : 10000
```

**Architecture:**

```text
             DPI Engine
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   Load Balancer 1     Load Balancer 2
        │                   │
     ┌──┴──┐             ┌──┴──┐
     ▼     ▼             ▼     ▼
    FP1   FP2            FP3   FP4
```

Packets are processed concurrently. Therefore, output packet order is not guaranteed to match input packet order. Correctness is based on packet contents, timestamps, packet lengths, and forward/drop decisions — not strictly on output order.

---

## 🌐 Live DPI — Windows / WinDivert

The repository also contains `live_dpi.py` — the live traffic entry point.

**Architecture:**

```text
Windows Network Traffic
          │
          ▼
       WinDivert
          │
          ▼
     Packet Parser
          │
          ▼
       FastPath
          │
          ▼
   SNI / Classification
          │
          ▼
       Rule Check
       /         \
      /           \
   DROP          FORWARD
    │               │
    X               ▼
                 WinDivert
```

> ⚠️ **IMPORTANT BEFORE LIVE DPI:** Live DPI modifies the handling of real network packets.
>
> - `FORWARD` → packet continues
> - `DROP` → packet is discarded
>
> Use live mode carefully.

### 🐍 Live DPI Installation

**Step 1 — Install PyDivert**

```bash
python -m pip install pydivert
```

**Step 2 — Verify PyDivert**

```bash
python -c "import pydivert; print('PyDivert installed successfully')"
```

Expected:

```
PyDivert installed successfully
```

**Step 3 — Check Python Architecture**

Live WinDivert usage should use 64-bit Python.

```bash
python -c "import platform; print(platform.architecture()[0])"
```

Expected:

```
64bit
```

### 🔑 Run Live DPI as Administrator

Close the current terminal. Open PowerShell → Right Click → **Run as administrator**.

Then navigate to the project:

```powershell
cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"
```

Verify:

```powershell
dir
```

You should see: `live_dpi.py`, `python_dpi`, `windivert`.

### ▶️ Start Live DPI

```bash
python live_dpi.py
```

The program starts WinDivert and begins intercepting IPv4 TCP and UDP traffic.

### 🧪 Live DPI Basic Test

Once `python live_dpi.py` is running, open another browser window and generate some network traffic:

```
https://example.com
https://github.com
https://google.com
```

The DPI engine may print detected TLS SNI information. Example:

```
Detected SNI:
example.com -> HTTPS
```

### 🛑 Stop Live DPI

```
Ctrl + C
```

The program should stop its packet interception loop and print its final statistics.

---

### 🛡️ Live Domain Blocking Test

The current `live_dpi.py` contains a domain blocking rule:

```python
rules.block_domain("youtube.com")
```

**✏️ Change the Live Blocking Domain**

Open `live_dpi.py`, find `rules.block_domain("youtube.com")`, and change it to another test domain:

```python
rules.block_domain("example.com")
```

Save the file, then run `python live_dpi.py` as Administrator.

**🧪 Live Blocking Test Procedure**

1. Open Administrator PowerShell
2. Go to the project: `cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"`
3. Start live DPI: `python live_dpi.py`
4. Generate traffic to the test domain (e.g., `https://example.com`)
5. Watch the terminal — if a TLS ClientHello with a visible SNI reaches the DPI engine, it can detect the domain and produce a `DROP` instead of `FORWARD`

---

### 🔄 Live Packet Flow

**Allowed packet:**

```text
Network → WinDivert → DPI Parser → Classification → Rule Check → FORWARD → WinDivert → Network
```

**Blocked packet:**

```text
Network → WinDivert → DPI Parser → Classification → Rule Check → DROP → Packet not reinjected
```

### 🔎 Live SNI Detection

TLS SNI is useful because the TLS ClientHello may contain the hostname the client is trying to connect to:

```text
Client
   ↓
TLS ClientHello
   ↓
SNI = example.com
   ↓
DPI
   ↓
Domain Rule
```

> The hostname is not guaranteed to be visible in every connection.

---

## ⚠️ Important Limitations

### Live DPI Limitations

Modern web traffic can make hostname inspection difficult. Possible reasons include:

- Encrypted traffic / QUIC / HTTP/3 / ECH
- Connection reuse
- Already-established TLS connections
- IPv6 traffic
- Missing ClientHello
- Traffic that does not expose hostname information

> A domain rule does not guarantee that every packet belonging to that website will be identified and blocked.

### 🌐 IPv4 Scope

The current implementation focuses on **IPv4**. The core parser does not currently provide IPv6 DPI processing. Traffic using IPv6 is outside the current supported DPI scope.

### ⚡ QUIC / HTTP3 Limitation

The project contains basic QUIC packet detection. However, the active FastPath classification path does not provide complete modern QUIC application identification. QUIC traffic may not always be classified with the same accuracy as TCP/TLS traffic.

### 🔐 TLS / HTTPS Limitation

The DPI engine **does not decrypt HTTPS traffic**. It attempts to inspect information that is visible without decryption (TLS ClientHello / SNI). If SNI is unavailable, traffic may be classified as `HTTPS` or `UNKNOWN`. The project does not perform TLS man-in-the-middle interception.

### 🔄 Connection Reuse Limitation

If a browser already has an established connection to a server, a new TLS ClientHello may not appear when a new rule is added. The rule may not immediately affect the already-established connection.

> For testing, start DPI first, then start a new browser session, then open the test website.

---

## 🧹 Generated Files

Running the offline project may generate:

```
output.pcap
blocked_output.pcap
__pycache__/
*.pyc
```

These are development/test artifacts and should normally not be committed to Git. The `.gitignore` file contains rules for common Python cache files, virtual environments, generated PCAP files, IDE files, and build artifacts.

---

## 📋 Quick Start

### Offline Mode

```bash
# 1. Clone
git clone https://github.com/Nikhilwakekar01/DPI-Python.git

# 2. Enter project
cd DPI-Python

# 3. Check Python
python --version

# 4. Run all tests
python -m unittest discover -s python_dpi/tests -v

# 5. Process sample PCAP
python -m python_dpi test_dpi.pcap output.pcap
```

**Expected:**

```
Ran 88 tests
OK
```

```
Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738
```

Then open `output.pcap` in Wireshark.

### Offline Blocking

```bash
python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"
```

**Expected:**

```
Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738
```

### Live Mode (Windows Only)

```bash
# Install
python -m pip install pydivert

# Verify
python -c "import pydivert; print('PyDivert installed successfully')"
```

Open PowerShell as Administrator, go to the project, then:

```bash
python live_dpi.py
```

Generate browser traffic, watch for detected SNI, stop with `Ctrl + C`.

---

## 🧪 Complete Test Procedures

### Complete Offline Test — From Zero

```bash
# 1. Clone
git clone https://github.com/Nikhilwakekar01/DPI-Python.git

# 2. Enter directory
cd DPI-Python

# 3. Check Python
python --version

# 4. Verify files
dir

# 5. Run all tests
python -m unittest discover -s python_dpi/tests -v
# Expected: Ran 88 tests / OK

# 6. Run DPI
python -m python_dpi test_dpi.pcap output.pcap
# Expected: Processed: 77 / Forwarded: 77 / Dropped: 0 / Total bytes: 5738

# 7. Verify output file
dir output.pcap

# 8. Open output.pcap in Wireshark
```

### Complete Offline Blocking Test

```bash
python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"
```

Expected:

```
Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738
```

Then:

```bash
dir blocked_output.pcap

python -c "from python_dpi.pcap_reader import PcapReader; r=PcapReader(); print('Opened:', r.open('blocked_output.pcap')); n=0; p=r.read_next_packet(); exec('while p is not None:\n n += 1\n p = r.read_next_packet()'); print('Output packets:', n); r.close()"
```

Expected:

```
Opened: True
Output packets: 76
```

### Complete Live Test — From Zero

```bash
# 1. Install PyDivert
python -m pip install pydivert

# 2. Verify PyDivert
python -c "import pydivert; print('PyDivert installed successfully')"

# 3. Verify 64-bit Python
python -c "import platform; print(platform.architecture()[0])"
```

4. Open Administrator PowerShell
5. Enter project: `cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"`
6. Start live DPI: `python live_dpi.py`
7. Generate traffic by visiting `https://example.com`, `https://github.com`, `https://google.com`
8. Watch for detected SNI output (e.g., `example.com -> HTTPS`)
9. Test controlled blocking: edit `live_dpi.py`, set `rules.block_domain("example.com")`, restart, then visit `https://example.com`
10. Stop with `Ctrl + C`

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `python is not recognized` | Try `py --version`. If it works, use `py` instead of `python` in all commands. |
| PyDivert import error | Run `python -m pip install pydivert`, then verify with `python -c "import pydivert; print('PyDivert OK')"` |
| Live DPI permission error | Close terminal, open PowerShell as Administrator, navigate to project, run `python live_dpi.py` |
| No SNI detected | Traffic may be encrypted, using QUIC/HTTP3, IPv6, or connection was already established. This does not mean the engine is broken. |
| Website not blocked | Traffic may have used IPv6, QUIC/HTTP3, or the TLS ClientHello was not visible. Treat as experimental prototype. |
| Browser stops working during live test | Press `Ctrl + C` to stop DPI, wait a few seconds, then retry the connection. |
| Output packet order looks different | This is expected. The multithreaded engine does not guarantee input-to-output order. Check correctness via packet contents, lengths, timestamps, and forward/drop decisions. |

---

## 📌 Design Details

### Directional Five-Tuple

Flow identification uses:

```
Source IP + Destination IP + Source Port + Destination Port + Protocol
```

Example:
```
192.168.1.5:50000  →  142.250.x.x:443   (forward flow)
142.250.x.x:443    →  192.168.1.5:50000 (treated as separate directional flow)
```

Bidirectional flow merging is not currently implemented.

### ⚖️ Deterministic Load Balancing

Flows are distributed using deterministic five-tuple hashing to consistently assign packets from the same directional flow to the same processing path:

```text
Five-Tuple → Hash → Load Balancer → FastPath Worker
```

### 🔢 IPv4 Representation

The implementation follows the reference behavior for IPv4 integer representation:

```
octet0 | octet1 << 8 | octet2 << 16 | octet3 << 24
```

This behavior is relevant to compatibility with the reference implementation and deterministic hashing.

---

## 📈 Performance / Concurrency

The current default configuration:

```
Load Balancers : 2
FastPaths/LB   : 2
Total FastPaths: 4
Queue Size     : 10000
```

The system is designed around a multithreaded packet-processing pipeline. It is intended for:

- Learning
- Research
- Networking experiments
- DPI prototyping
- Systems programming practice
- Backend/networking projects

> It should not currently be considered a production-grade firewall or high-performance commercial DPI engine.

---

## ⚠️ Limitations Summary

### Protocol Limitations

- Packet inspection currently focuses on IPv4; IPv6 is not currently supported
- TCP and UDP are supported
- TLS inspection relies on visible ClientHello/SNI information
- QUIC detection is basic/heuristic; full QUIC application identification is not implemented
- Encrypted traffic whose hostname is not visible cannot always be classified by domain

### Flow Limitations

- Flow tracking uses directional five-tuples
- Reverse-direction packets are treated as separate flows
- Bidirectional flow merging is not currently implemented
- No advanced flow expiration/cleanup mechanism in the active implementation

### Rule Limitations

Current rules support: Source IPv4 address, Application, Domain substring.

The current implementation does not provide: Port-based blocking, CIDR/range rules, Advanced protocol rules, Persistent rule configuration, Rule files, Database-backed rules, or full firewall functionality.

### Live DPI Limitations

- Currently targets Windows; WinDivert is required; Administrator privileges may be required
- IPv6 is outside the current implementation scope
- Not every website can be reliably blocked by hostname
- Modern HTTPS/QUIC/ECH behavior can limit hostname visibility
- Connection reuse can prevent a newly added rule from affecting an existing connection
- Live mode should be treated as an experimental implementation rather than a production firewall

---

## 🔒 Safety Note

Live DPI interacts with real network traffic.

Use it only on systems and networks where you are **authorized to inspect and filter traffic**.

For development/testing, prefer:

- Your own Windows machine
- Your own test network
- Controlled test domains
- PCAP files

Do not use packet interception to inspect traffic you are not authorized to monitor.

---

## 🎯 Purpose

This project demonstrates the implementation of a practical **Deep Packet Inspection Pipeline** in Python, focusing on:

- Low-level network packet parsing
- Protocol inspection (TLS SNI, HTTP Host, DNS)
- Basic QUIC detection
- Flow tracking
- Deterministic load balancing
- Multithreaded packet processing
- Application classification
- Traffic rule evaluation
- Packet forwarding/dropping
- PCAP generation
- Automated testing
- Windows live traffic interception

The project demonstrates how a DPI pipeline can be implemented using Python without depending on a large networking framework.

---

## 🧾 Validation Summary

The current implementation has been validated with:

- **88 automated tests**
- A real PCAP containing **77 packets / 5738 bytes / 73 TCP / 4 UDP**

```
Normal processing:
Processed : 77
Forwarded : 77
Dropped   : 0
```

Application classification and blocking behavior have also been tested.

> The live Windows implementation has been tested separately with real WinDivert traffic, but remains experimental and has limitations around IPv6, QUIC, HTTP/3, ECH, TLS visibility, connection reuse, and modern browser traffic.