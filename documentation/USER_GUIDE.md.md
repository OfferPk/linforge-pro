# User Guide & Operations Manual: LINForge Pro

## 1\. Quick Start

LINForge Pro operates as both an interactive web application studio and a standalone zero-dependency Python CLI tool.

### Running the Web Studio

Open `index.html` in any web browser:

open product\_165/source-code/index.html

\# or serve locally

python3 \-m http.server 8080 \--directory product\_165/source-code

### Running the Standalone CLI

The CLI requires Python 3.8+ and no third-party packages:

./product\_165/build/linforge-cli.py \--help

---

## 2\. Core Capabilities

### 2.1 Frame Dissector

Dissect raw LIN byte streams from oscilloscopes, UART loggers, or SocketCAN captures:

./product\_165/build/linforge-cli.py \--dissect "55201285004AFD"

### 2.2 LIN Frame Synthesis

Generate valid frames with automatic PID parity bit generation and Enhanced checksums:

\# Synthesize Frame ID 0x20 with 4 data bytes

./product\_165/build/linforge-cli.py \--build-frame 0x20 "12 85 00 4A"

### 2.3 Diagnostic Request & Response Synthesis

Synthesize Master Diagnostic Requests (`0x3C`) and Slave Responses (`0x3D`):

\# Read Data by Identifier (SID 0x22, DID 0xF190) from NAD 0x01

./product\_165/build/linforge-cli.py \--build-diag-req 0x01 0x22 "F190"

\# Positive Response (RSID 0x62) with VIN snippet

./product\_165/build/linforge-cli.py \--build-diag-resp 0x01 0x62 "F1904431"

### 2.4 Libpcap 2.4 Export

Export synthesized frames directly into Wireshark-compatible SocketCAN `.pcap` files:

./product\_165/build/linforge-cli.py \--export-pcap 0x20 "1285004A" lin\_capture.pcap

---

## 3\. ISO 21434 Cybersecurity Auditing

Evaluate automotive LIN configurations against 10 critical security controls:

./product\_165/build/linforge-cli.py \--audit