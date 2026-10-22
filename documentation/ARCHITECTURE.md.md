# Architecture & Technical Specification: LINForge Pro

## 1\. Executive Protocol Overview

**LINForge Pro** is an automotive protocol engineering suite, dissector, LIN Description File (LDF) compiler, and ISO 21434 / UNECE R155 cybersecurity auditor. It models the **Local Interconnect Network (LIN)** protocol standardized under **ISO 17987:2016** (Parts 1–7), **LIN 2.2A**, **LIN 2.1**, and **SAE J2602**.

LIN is the universal single-wire automotive sub-bus deployed across billions of electronic control units (ECUs) in passenger, commercial, and electric vehicles worldwide. It provides a cost-effective, deterministic sensor/actuator networking layer for body control, mechatronics, and smart switches where CAN or Ethernet would be prohibitively expensive.

\+-------------------------------------------------------------------------------+

\|                       LIN Application & Signal Layer                          \|

\|    Door Control \| HVAC Climate Flaps \| Seat Motors \| Rain/Light \| Steering    \|

\+-------------------------------------------------------------------------------+

\|                 LIN Description File (LDF) Signal Mapping                     \|

\|           Signals (1..16 bits) \-\> Frame Byte Offsets (1..8 bytes)             \|

\+----------------------------------------------------+--------------------------+

\|       Unconditional Signal Frames (IDs 0..59)      \| Diagnostic (0x3C / 0x3D) \|

\+----------------------------------------------------+--------------------------+

\|                  Protected Identifier (PID) & Parity (P0/P1)                  \|

\|                 Classic Checksum (1.3) / Enhanced Checksum (2.x)              \|

\+-------------------------------------------------------------------------------+

\|                     LIN Physical Layer (ISO 17987-4)                          \|

\|            Single-Wire 12V Battery Line \| 1.0 to 20.0 kbps (19.2k typical)    \|

\+-------------------------------------------------------------------------------+

---

## 2\. Frame Architecture & Timing Specification

A complete LIN transaction consists of a **Header** transmitted by the Master node, followed by a **Response** transmitted by either a designated Slave node or the Master itself:

\[ Synch Break \] \[ Sync Byte: 0x55 \] \[ Protected ID: PID \] \[ Data 1..8 Bytes \] \[ Checksum \]

\| \<----------------- Master Header \----------------\> \| \<------- Response Payload \-------\> \|

### 2.1 Sync Break & Delimiter

- **Break**: Dominant low signal lasting at least 13 nominal bit times (typically 14 to 20 bits) to signal the start of a new frame.  
- **Delimiter**: Recessive high signal lasting at least 1 bit time separating the break from the synchronization byte.

### 2.2 Synchronization Byte

- Strict fixed value `0x55` (`01010101b`). Slaves measure the time between falling edges to calibrate internal RC oscillators without requiring expensive external quartz crystals.

### 2.3 Protected Identifier (PID)

Combines a 6-bit Frame ID (`0..63` / `0x00..0x3F`) with 2 parity bits:

- `P0 = ID0 ^ ID1 ^ ID2 ^ ID4`  
- `P1 = !(ID1 ^ ID3 ^ ID4 ^ ID5)`  
- `PID = (ID & 0x3F) | (P0 << 6) | (P1 << 7)`

Frame ID Categories:

- **0 to 59 (`0x00` to `0x3B`)**: Unconditional signal communication.  
- **60 (`0x3C`, PID `0x3C`)**: Master Request Diagnostic Frame.  
- **61 (`0x3D`, PID `0x7D`)**: Slave Response Diagnostic Frame.  
- **62 (`0x3E`, PID `0xFE`)**: User-defined extensions.  
- **63 (`0x3F`, PID `0xBF`)**: Reserved.

---

## 3\. Checksum Mathematics

LIN implements inverted modulo-256 addition with carry wrap-around:

Sum \= (Enhanced ? PID : 0\) \+ Data\[0\] \+ ... \+ Data\[N-1\]

While Sum \> 255:

    Sum \= (Sum & 0xFF) \+ (Sum \>\> 8\)

Checksum \= (\~Sum) & 0xFF

- **Classic Checksum**: Sums data bytes only. Mandatory for LIN 1.3 and all Diagnostic frames (`0x3C` and `0x3D`).  
- **Enhanced Checksum**: Includes the PID in the sum. Mandatory for all unconditional signal frames under LIN 2.0, 2.1, 2.2A, and ISO 17987\.

---

## 4\. Diagnostic Transport Layer (UDS over LIN)

Diagnostic communication operates over fixed PIDs `0x3C` (Master Request) and `0x7D` (Slave Response):

- **NAD (Node Address)**: `0x01` to `0x7F` (target slave address), `0x7E` (functional / all slaves), `0x7F` (broadcast).  
- **PCI (Protocol Control Information)**: Defines Single Frame (SF), First Frame (FF), and Consecutive Frame (CF) segmentation.  
- **Standard Diagnostic Services**:  
  - `0xB0`: Assign NAD  
  - `0xB2`: Read by Identifier  
  - `0xB3`: Conditional Change NAD  
  - `0x10`: Diagnostic Session Control (UDS)  
  - `0x22`: Read Data by Identifier (UDS)  
  - `0x2E`: Write Data by Identifier (UDS)  
  - `0x27`: Security Access Seed-Key (UDS)