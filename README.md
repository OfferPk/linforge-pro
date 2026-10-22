# LINForge Pro (v1.0.0)

> **Automotive Local Interconnect Network (LIN 2.2A / ISO 17987\) Studio, LDF Compiler, PID & Checksum Codec, Diagnostic Transport Engine (0x3C/0x3D), & ISO 21434 Cybersecurity Auditor**

---

## Features

- **Protected Identifier (PID) Parity Codec**: Real-time calculation and validation of P0/P1 parity bits across all frame identifiers (`0..63`).  
- **Classic & Enhanced Checksum Engine**: Inverted modulo-256 addition with carry wrap-around supporting both Classic (LIN 1.3 / diagnostic) and Enhanced (LIN 2.x / ISO 17987\) modes.  
- **Diagnostic Transport Layer**: Full implementation of Master Request (`0x3C`) and Slave Response (`0x3D`) frames with NAD, Single Frame PCI, SID/RSID, and UDS routing.  
- **LIN Description File (LDF) Parser**: Syntax validator, signal mapper, and master schedule table inspector.  
- **Libpcap 2.4 Exporter**: Directly synthesizes Wireshark-compatible SocketCAN `.pcap` capture files from live LIN frames.  
- **ISO 21434 & UNECE R155 Security Auditor**: 10-point audit evaluating SecOC authentication, diagnostic seed-key controls, wake-up flood DoS, and central gateway filtering.  
- **Automotive Gateway & IDS Generator**: Produces CAN-to-LIN central gateway routing allowlists and Suricata/Zeek intrusion detection signatures.

---

## Directory Structure

product\_165/

├── README.md

├── source-code/

│   ├── index.html

│   ├── app.js

│   ├── lin-forge.css

│   ├── lin-protocol-engine.js

│   ├── lin-security-auditor.js

│   └── lin-config-synthesizer.js

├── build/

│   ├── linforge-cli.py

│   └── linforge-pro-v1.0.0.zip

├── documentation/

│   ├── ARCHITECTURE.md

│   ├── USER\_GUIDE.md

│   ├── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md

│   └── PROGRESS\_REPORT.md

└── screenshots/

    ├── lin-studio-preview.svg

    └── lin-architecture-diagram.svg

---

## Quick Start

\# Run automated test suite

python3 test\_linforge.py \-v

\# Run standalone CLI

./product\_165/build/linforge-cli.py \--build-frame 0x20 "12 85 00 4A"

./product\_165/build/linforge-cli.py \--build-diag-req 0x01 0x22 "F190"

./product\_165/build/linforge-cli.py \--audit

---

## License

Commercial Proprietary \- Autonomous Digital Product Factory (Product Record \#165).