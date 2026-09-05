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

The **PCAP/offline DPI engine is the primary validated implementation**.

The live DPI implementation is currently an experimental Windows prototype.

---

# 🚀 Features

## PCAP DPI Engine

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

---

## Experimental Live DPI

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

# 🏗️ Architecture

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

The classifier uses packet metadata and payload inspection.

Classification Priority

The current classification order is:

1. TLS SNI
2. HTTP Host
3. DNS
4. HTTPS fallback
5. HTTP fallback

More specifically:

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
Supported Application Types

The current classifier contains application categories including:

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

The exact classification depends on the information visible inside the packet.

Encrypted traffic or traffic without an inspectable hostname may be classified as:

HTTPS

or:

UNKNOWN
🛡️ Traffic Rules

The DPI engine currently supports three active rule types.

1. Source IP Blocking

Blocks packets originating from a configured IPv4 address.

Example:

engine.block_ip("192.168.1.10")
2. Application Blocking

Blocks traffic based on the detected application.

Example:

engine.block_app("YouTube")
3. Domain Blocking

Blocks traffic when the extracted domain/SNI contains the configured domain substring.

Example:

engine.block_domain("youtube")

Domain matching follows the current implementation's substring and case-sensitive behavior.

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
├── live_dpi.py
├── windivert/
│   └── WinDivert64.sys
│
├── README.md
└── .gitignore
Generated / ignored WinDivert files

Depending on the environment, WinDivert-related files such as:

WinDivert.dll
WinDivert.lib

may be present locally but ignored by Git.

🐍 Requirements
Offline / PCAP Mode

The offline DPI engine uses Python's standard library.

Recommended:

Python 3.10+

No external Python package is required for the offline PCAP engine.

Live DPI Mode

Live DPI requires:

Windows
64-bit Python
Python 3.10+
WinDivert
PyDivert
Administrator privileges

Install PyDivert with:

python -m pip install pydivert

Verify installation:

python -c "import pydivert; print('PyDivert installed successfully')"

Expected:

PyDivert installed successfully

The live implementation is Windows-specific because it relies on WinDivert.

⬇️ Installation
Step 1 — Clone the Repository

Open PowerShell or Command Prompt.

Run:

git clone https://github.com/Nikhilwakekar01/DPI-Python.git

This downloads the project from GitHub.

Then enter the project directory:

cd DPI-Python

Your terminal should now be inside:

DPI-Python
Step 2 — Verify Project Files

Run:

dir

You should see files/folders similar to:

python_dpi
test_dpi.pcap
live_dpi.py
windivert
README.md
.gitignore
Step 3 — Check Python

Run:

python --version

Example:

Python 3.14.2

Python 3.10 or newer is recommended.

Step 4 — Optional Virtual Environment

A virtual environment is recommended if you want an isolated Python environment.

Create it:

python -m venv .venv

Activate it on Windows PowerShell:

.\.venv\Scripts\Activate.ps1

If activation succeeds, your terminal may show:

(.venv)

at the beginning of the command line.

For Command Prompt:

.venv\Scripts\activate
Step 5 — Verify Python Module

From the project root, run:

python -c "import python_dpi; print('DPI-Python imported successfully')"

Expected:

DPI-Python imported successfully

At this point the offline DPI engine is ready.

🖥️ OFFLINE DPI MODE

The offline mode reads packets from a PCAP file, processes them through the DPI pipeline, and writes forwarded packets to another PCAP file.

The basic flow is:

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
▶️ Run the Offline DPI Engine

Make sure you are inside:

DPI-Python

Run:

python -m python_dpi test_dpi.pcap output.pcap

The command means:

python
    ↓
-m python_dpi
    ↓
read test_dpi.pcap
    ↓
process packets
    ↓
write forwarded packets to output.pcap
Expected Output

A successful run should produce output similar to:

Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738

You should now have:

output.pcap

inside the project directory.

🔎 Check That output.pcap Was Created

Run:

dir output.pcap

You should see the file information.

You can also check its size:

(Get-Item output.pcap).Length

The size may vary depending on the input/output data.

🧪 RUN ALL TESTS

The project contains unit tests and integration tests.

From the project root:

python -m unittest discover -s python_dpi/tests -v

This runs all tests under:

python_dpi/tests/
What Is Tested?

The test suite covers:

Data models
IPv4 address conversion
Five-tuple hashing
PCAP parsing
Native-endian PCAP
Swapped-endian PCAP
Malformed PCAP
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
Real PCAP integration
Expected Test Result

The validated test suite result is:

Ran 88 tests
OK

If you see:

OK

the complete automated test suite has passed.

🔐 TEST OFFLINE BLOCKING

The DPI engine can also block traffic while processing a PCAP.

The included:

test_dpi.pcap

contains a packet that can be classified as YouTube traffic.

We can test application blocking without changing the source code.

Run:

python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"
What Does This Command Do?

The command:

from python_dpi.dpi_engine import DPIEngine

imports the DPI engine.

Then:

e = DPIEngine()

creates a DPI engine.

Then:

e.block_app("YouTube")

adds a YouTube blocking rule.

Then:

e.process(
    "test_dpi.pcap",
    "blocked_output.pcap"
)

processes the input PCAP and writes only forwarded packets to:

blocked_output.pcap
Expected Result

Expected validation result:

Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738

The important part is:

Processed: 77
Forwarded: 76
Dropped: 1

This means:

77 packets entered DPI
        │
        ▼
   DPI processing
        │
   ┌────┴────┐
   ▼         ▼
 DROP      FORWARD
  1           76
🔎 VERIFY BLOCKED OUTPUT PCAP

The generated file is:

blocked_output.pcap

Check that it exists:

dir blocked_output.pcap
Count Packets in Output

Run:

python -c "from python_dpi.pcap_reader import PcapReader; r=PcapReader(); print('Opened:', r.open('blocked_output.pcap')); n=0; p=r.read_next_packet(); exec('while p is not None:\n n += 1\n p = r.read_next_packet()'); print('Output packets:', n); r.close()"

Expected:

Opened: True
Output packets: 76

This confirms that:

Input:
77 packets

Output:
76 packets

Therefore:

1 packet was dropped
📊 OFFLINE VALIDATION

The Python DPI engine has been validated using the included test PCAP.

Validation result:

Input packets       : 77
Processed packets   : 77
Forwarded packets   : 77
Dropped packets     : 0
Total bytes         : 5738
TCP packets         : 73
UDP packets         : 4

Application classification includes:

AMAZON      : 1
APPLE       : 1
CLOUDFLARE  : 1
DISCORD     : 1
DNS         : 4
FACEBOOK    : 1
GITHUB      : 1
GOOGLE      : 1
HTTP        : 2
HTTPS       : 39
INSTAGRAM   : 1
SPOTIFY     : 1
TELEGRAM    : 1
TIKTOK      : 1
TWITTER     : 3
UNKNOWN     : 16
YOUTUBE     : 1
ZOOM        : 1

Additional tests cover:

Malformed packets
Non-IPv4 traffic
Non-TCP/UDP IPv4 traffic
HTTP traffic
TLS/SNI traffic
DNS traffic
Flow handling
Blocking rules
📦 PCAP INPUT / OUTPUT
Input
test_dpi.pcap
Normal Output
output.pcap
Blocking Test Output
blocked_output.pcap

The output PCAP contains packets that were forwarded by the DPI engine.

Generated PCAP files can be opened using Wireshark.

🦈 WIRESHARK VERIFICATION

Wireshark can be used to inspect the generated PCAP files.

After running:

python -m python_dpi test_dpi.pcap output.pcap

open:

output.pcap

in Wireshark.

You can inspect:

Packet number
Source IP
Destination IP
Protocol
Source port
Destination port
Packet length
TCP information
UDP information
TLS information
DNS information
HTTP information
Verify Blocking With Wireshark

After running:

python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"

open:

blocked_output.pcap

in Wireshark.

The blocked packet should not be present in the output.

⚙️ IMPLEMENTATION

The offline DPI engine uses Python's standard library.

Component	Responsibility
pcap_reader.py	Reads classic PCAP files
packet_parser.py	Parses Ethernet, IPv4, TCP and UDP
extractors.py	Extracts TLS SNI, HTTP Host, DNS and basic QUIC information
classifier.py	Identifies applications
rules.py	Applies traffic blocking rules
flow_tracker.py	Tracks directional flows
fast_path.py	Processes packets and applies DPI logic
load_balancer.py	Distributes flows between FastPath workers
dpi_engine.py	Coordinates the complete multithreaded DPI pipeline
__main__.py	Provides the command-line interface
🧵 MULTITHREADED PROCESSING

The default DPI engine configuration is:

Load Balancers : 2
FastPaths/LB   : 2
Total FastPaths: 4
Queue size     : 10000

The architecture is:

             DPI Engine
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   Load Balancer 1     Load Balancer 2
        │                   │
     ┌──┴──┐             ┌──┴──┐
     ▼     ▼             ▼     ▼
    FP1   FP2            FP3   FP4

Packets are processed concurrently.

Therefore:

Output packet order is not guaranteed to match input packet order.

Correctness is based on:

Packet contents
Timestamps
Packet lengths
Forward/drop decisions
Flow processing

and not strictly on output order.

🌐 LIVE DPI — WINDOWS / WINDIVERT

The repository also contains:

live_dpi.py

This is the live traffic entry point.

The architecture is:

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
⚠️ IMPORTANT BEFORE LIVE DPI

Live DPI modifies the handling of real network packets.

When a packet is intercepted:

Packet received by WinDivert
          │
          ▼
       DPI checks
       /       \
      /         \
   DROP        FORWARD
                 │
                 ▼
             w.send()

If the packet is allowed, it must be reinjected into the network stack.

If the packet is blocked, it is not reinjected.

Therefore:

FORWARD → packet continues
DROP    → packet is discarded

Use live mode carefully.

🐍 LIVE DPI INSTALLATION
Step 1 — Install PyDivert

Open PowerShell.

Run:

python -m pip install pydivert

Wait until installation completes.

Step 2 — Verify PyDivert

Run:

python -c "import pydivert; print('PyDivert installed successfully')"

Expected:

PyDivert installed successfully
Step 3 — Check Python Architecture

Live WinDivert usage should use 64-bit Python.

Run:

python -c "import platform; print(platform.architecture()[0])"

Expected:

64bit
🔑 RUN LIVE DPI AS ADMINISTRATOR

This is important.

Close the current terminal.

Open:

Start Menu
    ↓
PowerShell
    ↓
Right Click
    ↓
Run as administrator

Then navigate to the project.

For example:

cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"

Check:

dir

You should see:

live_dpi.py
python_dpi
windivert
▶️ START LIVE DPI

Run:

python live_dpi.py

The program starts WinDivert and begins intercepting:

IPv4 TCP traffic
IPv4 UDP traffic
🧪 LIVE DPI BASIC TEST

Once:

python live_dpi.py

is running, open another browser window.

Generate some network traffic by visiting websites.

For example:

https://example.com
https://github.com
https://google.com

The DPI engine may print detected TLS SNI information.

Example:

Detected SNI:
example.com -> HTTPS

At the end, or when stopped, a summary can include:

Packets seen
Packets processed
Packets forwarded
Packets dropped
Parse errors
Detected SNI
🛑 STOP LIVE DPI

To stop the live DPI program:

Ctrl + C

Press:

CTRL
+
C

The program should stop its packet interception loop and print its final statistics.

🛡️ LIVE DOMAIN BLOCKING TEST

The current live_dpi.py contains a domain blocking rule.

For example:

rules.block_domain("youtube.com")

This means the live DPI attempts to block packets when the extracted hostname/SNI contains:

youtube.com
✏️ CHANGE THE LIVE BLOCKING DOMAIN

Open:

live_dpi.py

Find:

rules.block_domain("youtube.com")

You can change it to another test domain.

For example:

rules.block_domain("example.com")

Save the file.

Then run:

python live_dpi.py

as Administrator.

🧪 LIVE BLOCKING TEST PROCEDURE

Use the following procedure.

Step 1

Open Administrator PowerShell.

Step 2

Go to the project:

cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"
Step 3

Start live DPI:

python live_dpi.py
Step 4

Generate traffic to the test domain.

For example:

https://example.com
Step 5

Watch the terminal.

If a TLS ClientHello with a visible SNI reaches the DPI engine, it can detect:

example.com

The rule can then produce:

DROP

instead of:

FORWARD
🔄 LIVE PACKET FLOW

For an allowed packet:

Network
   ↓
WinDivert
   ↓
DPI Parser
   ↓
Classification
   ↓
Rule Check
   ↓
FORWARD
   ↓
WinDivert
   ↓
Network

For a blocked packet:

Network
   ↓
WinDivert
   ↓
DPI Parser
   ↓
Classification
   ↓
Rule Check
   ↓
DROP
   ↓
Packet not reinjected
🔎 LIVE SNI DETECTION

TLS SNI is useful because the TLS ClientHello may contain the hostname the client is trying to connect to.

For example:

Client
   ↓
TLS ClientHello
   ↓
SNI = example.com
   ↓
DPI
   ↓
Domain Rule

The DPI engine can use this hostname for classification/rule evaluation.

However, the hostname is not guaranteed to be visible.

⚠️ IMPORTANT LIVE DPI LIMITATIONS

Modern web traffic can make hostname inspection difficult.

Possible reasons include:

Encrypted traffic
QUIC
HTTP/3
ECH
Connection reuse
Already-established TLS connections
IPv6 traffic
Missing ClientHello
Traffic that does not expose hostname information

Therefore:

A domain rule does not guarantee that every packet belonging to that website will be identified and blocked.

🌐 IPv4 SCOPE

The current implementation focuses on:

IPv4

The core parser does not currently provide IPv6 DPI processing.

Therefore, traffic using:

IPv6

is outside the current supported DPI scope.

For example, if a browser chooses IPv6 for a website, the current IPv4-only live filter may not inspect that traffic.

This is an intentional limitation of the current implementation.

⚡ QUIC / HTTP3 LIMITATION

Modern browsers frequently use:

QUIC
HTTP/3
UDP/443

The project contains basic QUIC packet detection.

However:

The active FastPath classification path does not provide complete modern QUIC application identification.

Therefore, QUIC traffic may not always be classified with the same accuracy as TCP/TLS traffic.

🔐 TLS / HTTPS LIMITATION

The DPI engine does not decrypt HTTPS traffic.

It attempts to inspect information that is visible without decryption, such as:

TLS ClientHello
SNI

If SNI is unavailable, the traffic may simply be classified as:

HTTPS

or:

UNKNOWN

The project does not perform TLS man-in-the-middle interception.

🔄 CONNECTION REUSE LIMITATION

Suppose a browser already has an established connection to a server.

Then you start DPI and add:

rules.block_domain("example.com")

The browser may reuse the existing connection.

In that situation, a new TLS ClientHello may not appear.

Therefore the rule may not immediately affect the already-established connection.

For testing, it is better to:

1. Start DPI
2. Start a new browser session
3. Open the test website
🧹 GENERATED FILES

Running the offline project may generate:

output.pcap
blocked_output.pcap
__pycache__/
*.pyc

These are development/test artifacts.

They should normally not be committed to Git.

The .gitignore file contains rules for common:

Python cache files
Virtual environments
Generated PCAP files
IDE files
Build artifacts
🧪 COMPLETE OFFLINE TEST — FROM ZERO

A new user can perform the complete offline validation using the following commands.

1. Clone
git clone https://github.com/Nikhilwakekar01/DPI-Python.git
2. Enter directory
cd DPI-Python
3. Check Python
python --version
4. Verify files
dir
5. Run all tests
python -m unittest discover -s python_dpi/tests -v

Expected:

Ran 88 tests
OK
6. Run DPI
python -m python_dpi test_dpi.pcap output.pcap

Expected:

Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738
7. Verify output file
dir output.pcap
8. Open output.pcap in Wireshark

Inspect:

IPv4
TCP
UDP
DNS
TLS
HTTP
Application traffic
🧪 COMPLETE OFFLINE BLOCKING TEST

Run:

python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"

Expected:

Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738

Then:

dir blocked_output.pcap

And optionally:

python -c "from python_dpi.pcap_reader import PcapReader; r=PcapReader(); print('Opened:', r.open('blocked_output.pcap')); n=0; p=r.read_next_packet(); exec('while p is not None:\n n += 1\n p = r.read_next_packet()'); print('Output packets:', n); r.close()"

Expected:

Opened: True
Output packets: 76
🧪 COMPLETE LIVE TEST — FROM ZERO
1. Install PyDivert
python -m pip install pydivert
2. Verify PyDivert
python -c "import pydivert; print('PyDivert installed successfully')"

Expected:

PyDivert installed successfully
3. Verify 64-bit Python
python -c "import platform; print(platform.architecture()[0])"

Expected:

64bit
4. Open Administrator PowerShell

Run PowerShell as:

Administrator
5. Enter project
cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"
6. Start live DPI
python live_dpi.py
7. Generate traffic

Open a browser and visit websites.

Example:

https://example.com
https://github.com
https://google.com
8. Watch detected traffic

The program may display detected SNI information such as:

example.com -> HTTPS
9. Test a controlled blocking rule

Edit:

live_dpi.py

and configure:

rules.block_domain("example.com")

Save the file.

Restart:

python live_dpi.py

Then visit:

https://example.com

If the hostname is visible in a TLS ClientHello and the rule matches, the packet can be dropped.

10. Stop

Press:

Ctrl + C
🛠️ TROUBLESHOOTING
Problem 1 — python is not recognized

If you see:

'python' is not recognized...

Python may not be installed or may not be in PATH.

Check:

py --version

If that works, you can use:

py -m python_dpi test_dpi.pcap output.pcap

and:

py -m unittest discover -s python_dpi/tests -v
Problem 2 — PyDivert import error

If:

python -c "import pydivert"

fails, install:

python -m pip install pydivert

Then test again:

python -c "import pydivert; print('PyDivert OK')"
Problem 3 — Live DPI Permission Error

If WinDivert cannot start or access is denied:

Close the terminal.
Open PowerShell as Administrator.
Go to the project directory.
Run:
python live_dpi.py
Problem 4 — No SNI Is Detected

This does not necessarily mean the DPI engine is broken.

Possible reasons:

Traffic is encrypted
Packet is not a TLS ClientHello
Browser is using QUIC
Browser is using HTTP/3
IPv6 is being used
Connection was already established
SNI is not visible

The current project cannot guarantee hostname detection for every modern connection.

Problem 5 — Website Is Not Blocked

A domain rule may fail to block a website because:

The traffic used IPv6
The traffic used QUIC/HTTP3
The TLS ClientHello was not visible
The connection was already established
The hostname was not exposed
The packet was classified only as HTTPS/UNKNOWN

The current implementation should therefore be treated as an experimental DPI prototype rather than a complete production firewall.

Problem 6 — Browser Stops Working During Live Testing

Stop the DPI process:

Ctrl + C

Then wait a few seconds and retry the connection.

Live packet interception can affect active network connections.

Problem 7 — Output Packet Order Looks Different

This is expected.

The DPI engine uses multiple worker threads.

Therefore:

Input order

does not necessarily equal:

Output order

Correctness should be checked using:

Packet contents
Packet lengths
Timestamps
Forward/drop decisions
Flow information

rather than packet ordering alone.

📌 DESIGN DETAILS
Directional Five-Tuple

Flow identification uses:

Source IP
Destination IP
Source Port
Destination Port
Protocol

Example:

192.168.1.5:50000
        ↓
142.250.x.x:443

and the reverse direction:

142.250.x.x:443
        ↓
192.168.1.5:50000

are currently treated as separate directional flows.

Bidirectional flow merging is not currently implemented.

⚖️ DETERMINISTIC LOAD BALANCING

Flows are distributed using deterministic five-tuple hashing.

The purpose is to consistently assign packets belonging to the same directional flow to the same processing path.

Conceptually:

Five-Tuple
    ↓
Hash
    ↓
Load Balancer
    ↓
FastPath Worker

This allows flow-specific state to remain associated with the selected processing worker.

🔢 IPV4 REPRESENTATION

The implementation follows the reference behavior for IPv4 integer representation.

The byte representation is effectively:

octet0
|
octet1 << 8
|
octet2 << 16
|
octet3 << 24

This behavior is relevant to compatibility with the reference implementation and deterministic hashing.

📈 PERFORMANCE / CONCURRENCY

The current default configuration is:

Load Balancers : 2
FastPaths/LB   : 2
Total FastPaths: 4
Queue Size     : 10000

The system is designed around a multithreaded packet-processing pipeline.

It is intended for:

Learning
Research
Networking experiments
DPI prototyping
Systems programming practice
Backend/networking projects

It should not currently be considered a production-grade firewall or high-performance commercial DPI engine.

⚠️ LIMITATIONS
Protocol Limitations
Packet inspection currently focuses on IPv4.
IPv6 is not currently supported by the core parser.
TCP and UDP are supported.
TLS inspection relies on visible ClientHello/SNI information.
QUIC detection is basic/heuristic.
Full QUIC application identification is not implemented.
Encrypted traffic whose hostname is not visible cannot always be classified by domain.
Flow Limitations
Flow tracking uses directional five-tuples.
Reverse-direction packets are treated as separate flows.
Bidirectional flow merging is not currently implemented.
There is no advanced flow expiration/cleanup mechanism in the active implementation.
Rule Limitations

Current rules support:

Source IPv4 address
Application
Domain substring

The current implementation does not provide:

Port-based blocking
CIDR/range rules
Advanced protocol rules
Persistent rule configuration
Rule files
Database-backed rules
Full firewall functionality
Live DPI Limitations
Live DPI currently targets Windows.
WinDivert is required.
Administrator privileges may be required.
IPv6 is outside the current implementation scope.
Not every website can be reliably blocked by hostname.
Modern HTTPS/QUIC/ECH behavior can limit hostname visibility.
Connection reuse can prevent a newly added rule from affecting an existing connection.
Live mode should currently be treated as an experimental implementation rather than a production firewall.
🔒 SAFETY NOTE

Live DPI interacts with real network traffic.

Use it only on systems and networks where you are authorized to inspect and filter traffic.

For development/testing, prefer:

Your own Windows machine
Your own test network
Controlled test domains
PCAP files

Do not use packet interception to inspect traffic you are not authorized to monitor.

🎯 PURPOSE

This project demonstrates the implementation of a practical:

Deep Packet Inspection Pipeline

in Python.

The project focuses on:

Low-level network packet parsing
Protocol inspection
TLS SNI extraction
HTTP Host extraction
DNS inspection
Basic QUIC detection
Flow tracking
Deterministic load balancing
Multithreaded packet processing
Application classification
Traffic rule evaluation
Packet forwarding
Packet dropping
PCAP generation
Automated testing
Windows live traffic interception

The project demonstrates how a DPI pipeline can be implemented using Python without depending on a large networking framework.

📋 QUICK START

For someone downloading this repository for the first time:

Offline Mode
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

Expected:

Ran 88 tests
OK

and:

Processed packets: 77
Forwarded: 77
Dropped: 0
Total bytes: 5738

Then open:

output.pcap

in Wireshark.

📋 QUICK START — OFFLINE BLOCKING
python -c "from python_dpi.dpi_engine import DPIEngine; e=DPIEngine(); e.block_app('YouTube'); ok=e.process('test_dpi.pcap','blocked_output.pcap'); print('Process successful:', ok); print('Processed:', e.stats.total_packets); print('Forwarded:', e.stats.forwarded); print('Dropped:', e.stats.dropped); print('Bytes:', e.stats.total_bytes)"

Expected:

Process successful: True
Processed: 77
Forwarded: 76
Dropped: 1
Bytes: 5738
📋 QUICK START — LIVE MODE

Windows only.

Install:

python -m pip install pydivert

Verify:

python -c "import pydivert; print('PyDivert installed successfully')"

Open PowerShell as Administrator.

Go to the project:

cd "C:\Users\<YOUR_USERNAME>\Desktop\DPI-Python"

Run:

python live_dpi.py

Generate browser traffic.

Watch for detected SNI.

Stop with:

Ctrl + C
🧾 VALIDATION SUMMARY

The current implementation has been validated with:

88 automated tests

and a real PCAP containing:

77 packets
5738 bytes
73 TCP packets
4 UDP packets

Normal processing:

Processed : 77
Forwarded : 77
Dropped   : 0

Application classification and blocking behavior have also been tested.

The live Windows implementation has been tested separately with real WinDivert traffic, but remains experimental and has limitations around:

IPv6
QUIC
HTTP/3
ECH
TLS visibility
Connection reuse
Modern browser traffic