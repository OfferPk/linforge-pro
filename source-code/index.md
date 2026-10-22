

LIN

# 

LINForge Pro

Automotive Local Interconnect Network Studio, LDF Compiler, PID & Checksum Codec, & ISO 21434 Security Auditor  
ISO 17987:2016 LIN 2.2A / SAE J2602 ISO 21434 / UNECE R155  
Packet Dissector Frame & PID Builder Diagnostic Transport (0x3C / 0x3D) LDF & Schedule Studio ISO 21434 Security Auditor Gateway & IDS Rules

Raw UART / LIN Stream Preset: Door Control Status (ID 0x20) Preset: HVAC Flap Actuator (ID 0x24) Preset: Master Diagnostic ReadById (PID 0x3C) Preset: Slave Diagnostic Response (PID 0x7D) Preset: Steering Wheel Button Cluster (ID 0x18)  
Raw Frame Hex (Sync \+ PID \+ Data \+ Checksum)  
Dissect Frame Export to PCAP Clear

LIN Protocol Dissection Tree

Select a preset or enter raw hex and click "Dissect Frame".

LIN Frame Synthesizer  
Frame Identifier (0 to 63 / 0x00 to 0x3F)  
Checksum Algorithm Mode Enhanced Checksum (LIN 2.0+ / ISO 17987 \- includes PID) Classic Checksum (LIN 1.3 / Diagnostic 0x3C/0x3D)  
Data Payload (1 to 8 Hex Bytes)  
Synthesize Frame

Synthesized Wire Representation  
Wire Sequence (Sync \+ PID \+ Data \+ Checksum)  
Click "Synthesize Frame" to generate.

PID Parity Breakdown  
\-

LIN Diagnostic Transport Generator  
Frame Type Master Request (PID 0x3C) Slave Response (PID 0x7D)  
Node Address (NAD \- Hex)  
Service ID (SID / RSID \- Hex)  
Parameters / Payload (Hex Bytes)  
Synthesize Diagnostic Frame

Diagnostic Frame Breakdown  
\-

\-

LIN Description File (LDF) Inspector  
LDF Definition Code LIN\_description\_file; LIN\_protocol\_version \= "2.2"; LIN\_language\_version \= "2.2"; LIN\_speed \= 19.2 kbps; Nodes { Master: BCM, 5.0 ms, 0.1 ms; Slaves: DoorECU, ClimateECU, RLS\_Node; } Signals { WindowPosition: 8, 0, DoorECU, BCM; DoorLockStatus: 1, 0, DoorECU, BCM; BlowerSpeed: 8, 0, ClimateECU, BCM; RainIntensity: 8, 0, RLS\_Node, BCM; } Frames { DoorControl: 0x20, DoorECU, 4; ClimateStatus: 0x24, ClimateECU, 4; RainLightStatus: 0x22, RLS\_Node, 2; } Schedule\_tables { NormalSchedule { DoorControl delay 10.0 ms; ClimateStatus delay 10.0 ms; RainLightStatus delay 20.0 ms; } }  
Parse & Validate LDF

Parsed LDF Topology & Signals  
\-

ISO 21434 / UNECE R155 Automotive Cybersecurity Audit Run Security Audit

70  
COMPLIANCE SCORE  
**MODERATE POSTURE**  
6 of 10 security controls currently pass ISO 21434 requirements.

| Rule ID | Security Control Title | Standard | Severity | Status | Remediation Strategy   |
| :---- | :---- | :---- | :---- | :---- | :---- |

Central Gateway Routing Allowlist  
CAN-to-LIN gateway boundary protection rule definition.

Automotive IVN-IDS Rules (Suricata / Zeek)  
Signatures for wake-up flood, dynamic NAD injection, and routine control attacks.