# LoRa-Based Decentralized Network System

**Firmware Version:** 2.11
**Platform:** Raspberry Pi Pico
**LoRa Module:** SX1278
**Frequency:** 433 MHz

A decentralized LoRa-based communication network designed for multi-node communication without requiring a central server or access point.

The firmware provides mesh networking, dynamic route discovery, encrypted communication, replay protection, acknowledgements, persistent message queuing, neighbor discovery, and Bluetooth/Serial application interfaces.

---

## Features

* 📡 **LoRa communication** using SX1278
* 🔗 **Decentralized mesh networking**
* 🛣️ Dynamic route discovery using RREQ/RREP
* 🔐 AES-256-GCM authenticated encryption
* 🔑 Curve25519-based session key establishment
* 🛡️ Anti-replay protection using a sliding window
* ✅ Message acknowledgements
* 🔄 Automatic retransmission with exponential backoff
* 💾 Persistent transmission queue using EEPROM
* 📶 Neighbor discovery and monitoring
* 🚨 Route error detection and propagation
* 📱 Bluetooth application interface
* 🖥️ Serial interface for debugging and control
* 📢 Encrypted broadcast messaging

---

## Hardware

### Required Components

| Component         | Description              |
| ----------------- | ------------------------ |
| Raspberry Pi Pico | Main microcontroller     |
| SX1278            | 433 MHz LoRa transceiver |
| Bluetooth Module  | Application interface    |
| Antenna           | 433 MHz LoRa antenna     |

The firmware is configured for the Raspberry Pi Pico and SX1278 combination.

---

## Hardware Connections

The current SPI and control pins are:

| SX1278   | Raspberry Pi Pico |
| -------- | ----------------: |
| NSS / SS |            GPIO 8 |
| RESET    |            GPIO 9 |
| DIO0     |           GPIO 10 |
| SCK      |            GPIO 2 |
| MISO     |            GPIO 4 |
| MOSI     |            GPIO 3 |

Bluetooth communication uses:

```cpp
#define BLE Serial1
```

---

## LoRa Configuration

The current firmware uses:

```text
Frequency:        433 MHz
TX Power:         17 dBm
Spreading Factor: 10
Bandwidth:        125 kHz
Coding Rate:      4/5
CRC:              Enabled
```

These parameters are configured during system initialization.

---

# Network Architecture

Each node operates independently and maintains its own routing, neighbor, security, and message state.

```text
                    ┌───────────────────┐
                    │   Mobile / PC     │
                    │   Application     │
                    └─────────┬─────────┘
                              │
                         Bluetooth
                              │
                    ┌─────────▼─────────┐
                    │  Raspberry Pi Pico│
                    │                   │
                    │ Authentication    │
                    │ Routing           │
                    │ Encryption       │
                    │ Message Queue     │
                    │ Replay Protection │
                    └─────────┬─────────┘
                              │ SPI
                    ┌─────────▼─────────┐
                    │      SX1278       │
                    │   LoRa Transceiver│
                    └─────────┬─────────┘
                              │
                         433 MHz LoRa
                              │
             ┌────────────────┼────────────────┐
             │                │                │
        ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
        │  Node 1 │◄────►│  Node 2 │◄────►│  Node 3 │
        └─────────┘      └─────────┘      └─────────┘
```

There is no central routing server. Each node maintains its own network state.

---

# Packet Types

The firmware defines the following packet types:

| Type | Name             | Purpose                          |
| ---: | ---------------- | -------------------------------- |
|    1 | `TYPE_TEXT`      | Text/application message         |
|    2 | `TYPE_ACK`       | Message acknowledgement          |
|    3 | `TYPE_ECDH_REQ`  | Curve25519 key exchange request  |
|    4 | `TYPE_ECDH_RESP` | Curve25519 key exchange response |
|    5 | `TYPE_RREQ`      | Route request                    |
|    6 | `TYPE_RREP`      | Route reply                      |
|    7 | `TYPE_HELLO`     | Neighbor discovery               |
|    8 | `TYPE_RERR`      | Route error                      |

---

# Mesh Routing

The network uses a route-discovery mechanism based on **RREQ** and **RREP** packets.

If a node does not have a valid route to the destination, it broadcasts an RREQ.

```text
Node A
  │
  │ RREQ
  ▼
Node B
  │
  │ RREQ
  ▼
Node C
  │
  │ RREP
  ▼
Node B
  │
  │ RREP
  ▼
Node A
```

Once the route has been discovered, it is stored in the routing table.

Each route contains:

```cpp
struct RouteEntry {
    uint8_t dest;
    uint8_t nextHop;
    uint8_t hops;
    unsigned long lastUsed;
};
```

### Routing Parameters

```text
Maximum hops:       5
Maximum routes:     30
Route lifetime:     5 minutes
```

---

# Neighbor Discovery

Nodes periodically transmit `HELLO` packets to identify active neighbors.

```text
HELLO interval:       10 seconds
Neighbor timeout:     30 seconds
Maximum neighbors:    10
```

When a packet is received, the sender's `lastHeard` time is updated.

If a neighbor is not heard from within the timeout period, it is considered unavailable and routes using that neighbor are invalidated.

---

# Security

## AES-256-GCM

Encrypted messages use **AES-256-GCM**.

Each established node relationship maintains a 256-bit session key:

```cpp
uint8_t sessionKey[32];
```

AES-GCM provides:

* Confidentiality
* Integrity
* Authentication

The following packet fields are also authenticated:

```text
FROM
TO
TYPE
PACKET_ID
```

These fields are supplied as GCM additional authenticated data.

---

# Curve25519 Key Exchange

The firmware uses **Curve25519** to establish session keys between nodes.

Each node generates a Curve25519 key pair:

```text
Private Key
Public Key
```

The public key is exchanged using:

```text
TYPE_ECDH_REQ
TYPE_ECDH_RESP
```

Conceptually:

```text
              Node A                     Node B

           Private Key A             Private Key B
                 │                         │
                 ▼                         ▼
            Public Key A              Public Key B
                 │                         │
                 └─────────┬───────────────┘
                           │
                     Curve25519 ECDH
                           │
                           ▼
                    Shared Session Key
                           │
                           ▼
                       AES-256-GCM
```

---

# Anti-Replay Protection

The firmware implements a **32-packet sliding replay window**.

```cpp
#define REPLAY_WINDOW_SIZE 32
```

Each node maintains:

```text
lastSeqNum
replayWindowBitmask
```

The sequence number is stored in the first four bytes of the packet IV.

Packets that fall outside the accepted replay window or have already been processed are rejected.

Example:

```text
REPLAY BLOCKED: Unicast sequence out of window alignment.
```

---

# Message Format

Messages sent from the application use:

```text
<destination>:<message>
```

For example:

```text
2:Hello Node 2
```

This means:

```text
Destination → Node 2
Message     → Hello Node 2
```

---

# Authentication

Before sending application messages, the local application must authenticate with the node.

The authentication format is:

```text
AUTH:<password>
```

Example:

```text
AUTH:3333
```

A successful authentication generates:

```text
APP_STATUS:AUTH_SUCCESS
```

An incorrect password generates:

```text
APP_STATUS:AUTH_FAILED_INCORRECT_PASSWORD
```

The authentication session expires automatically after the configured timeout.

---

# Broadcast Messages

Destination `0` is treated as a broadcast request.

Example:

```text
0:Hello everyone
```

The firmware converts the destination to:

```text
0xFF
```

Broadcast messages are encrypted using the shared network group key.

The receiver also performs anti-replay and GCM authentication checks before accepting the message.

---

# Message Reliability

Unicast messages are stored in a transmission queue.

Current configuration:

```text
Maximum queue size:    30
Maximum retries:        5
Initial retry timeout:  3 seconds
```

The retry timeout increases exponentially:

```text
3 seconds
6 seconds
12 seconds
24 seconds
48 seconds
```

If the message is not acknowledged after the maximum number of retries:

```text
APP_STATUS:<ID>:FAILED_NO_ACK
```

The corresponding route is invalidated.

---

# Acknowledgements

When a destination successfully receives a unicast message, it sends an encrypted ACK back to the sender.

Successful delivery is reported as:

```text
APP_STATUS:<message_id>:DELIVERED
```

This distinguishes between a message being transmitted and a message being successfully acknowledged.

---

# Persistent Message Queue

The transmission queue is stored in EEPROM.

This allows queued messages to survive a reboot.

At startup:

```cpp
EEPROM.get(0, txQueue);
```

The firmware checks the restored queue and removes invalid entries.

Queue changes are saved back to EEPROM.

---

# Duplicate Packet Detection

The firmware maintains a circular buffer containing recently seen packets.

```cpp
#define MAX_SEEN_PACKETS 50
```

Packets are identified using:

```text
Source + Packet ID
```

If the same combination is received again, the packet is ignored.

This prevents duplicate processing and unnecessary packet forwarding.

---

# Packet Structure

The basic LoRa header is:

```text
+--------+-----+-----+---------+------+----------+
| Net ID | SRC | DST | NextHop | Type | PacketID |
+--------+-----+-----+---------+------+----------+
```

Encrypted packets additionally contain:

```text
+---------+---------+--------+-------------+
| IV      | GCM Tag | Length | Ciphertext  |
| 12 byte | 16 byte | 1 byte | Variable    |
+---------+---------+--------+-------------+
```

The packet header is authenticated using AES-GCM.

---

# Radio Diagnostics

Received messages include LoRa radio information:

```text
RSSI
SNR
```

Example:

```text
[FROM:2 TO:255 HOPS:1 RSSI:-72 SNR:8.5] Hello everyone
```

This provides basic information about the quality of the received LoRa link.

---

# Application Status

The firmware reports important events through both Serial and Bluetooth.

Examples:

```text
APP_STATUS:AUTH_SUCCESS
APP_STATUS:AUTH_REQUIRED
APP_STATUS:AUTH_FAILED_INCORRECT_PASSWORD

APP_STATUS:<ID>:SENT
APP_STATUS:<ID>:DELIVERED
APP_STATUS:<ID>:FAILED_NO_ACK
```

---

# Configuration

Each physical node should have a unique node ID.

For example:

```cpp
#define MY_NODE_ID 1
```

Another node could use:

```cpp
#define MY_NODE_ID 2
```

and another:

```cpp
#define MY_NODE_ID 3
```

The node ID is used by the routing and packet-processing system to identify individual nodes.

---

# System Limits

| Parameter               |      Value |
| ----------------------- | ---------: |
| Maximum Nodes           |         30 |
| Maximum Routes          |         30 |
| Maximum Neighbors       |         10 |
| Maximum Queued Messages |         30 |
| Seen Packet Entries     |         50 |
| Maximum Hops            |          5 |
| Route Lifetime          |  5 minutes |
| HELLO Interval          | 10 seconds |
| Neighbor Timeout        | 30 seconds |
| Maximum Retries         |          5 |
| Initial Retry Timeout   |  3 seconds |
| Replay Window           | 32 packets |

---

# Software Dependencies

The firmware uses:

```cpp
#include <SPI.h>
#include <LoRa.h>
#include <Crypto.h>
#include <GCM.h>
#include <AES.h>
#include <string.h>
#include <EEPROM.h>
#include <Curve25519.h>
```

Install the corresponding Arduino libraries before compiling.

---

# Installation

## 1. Connect the Hardware

Connect the SX1278 to the Raspberry Pi Pico according to the pin configuration above.

## 2. Install the Libraries

Install the required dependencies in the Arduino IDE.

## 3. Configure the Node

Set a unique node ID:

```cpp
#define MY_NODE_ID 1
```

Configure the local application password.

## 4. Compile and Upload

Select the appropriate Raspberry Pi Pico board and upload the firmware.

## 5. Open Serial Monitor

Use:

```text
115200 baud
```

## 6. Start Multiple Nodes

Power multiple nodes within LoRa communication range.

The nodes will begin discovering neighboring nodes using HELLO packets.

## 7. Authenticate

Send:

```text
AUTH:<password>
```

## 8. Send a Message

Send:

```text
<destination>:<message>
```

Example:

```text
2:Hello from Node 1
```

---

# Startup

After successful initialization, the node reports:

```text
=================================
LoRa AES-256-GCM MESH ONLINE
NODE ID: <ID>
=================================
```

---

# Runtime Architecture

The main firmware loop continuously performs:

```text
┌─────────────────────────────┐
│ Authentication Timeout      │
├─────────────────────────────┤
│ Bluetooth Input             │
├─────────────────────────────┤
│ Serial Input                │
├─────────────────────────────┤
│ LoRa Packet Processing      │
├─────────────────────────────┤
│ Transmission Queue          │
├─────────────────────────────┤
│ HELLO / Neighbor Discovery  │
├─────────────────────────────┤
│ Neighbor Timeout Detection  │
└─────────────────────────────┘
```

---

# Communication Flow

A typical unicast transmission follows:

```text
Application
     │
     ▼
Authentication
     │
     ▼
Message Queue
     │
     ▼
Check Session Key
     │
     ├── No Key ──► ECDH
     │
     ▼
Check Route
     │
     ├── No Route ──► RREQ/RREP
     │
     ▼
AES-256-GCM Encryption
     │
     ▼
LoRa Transmission
     │
     ▼
Destination
     │
     ▼
GCM Verification
     │
     ▼
Message Delivered
     │
     ▼
Encrypted ACK
     │
     ▼
Queue Entry Removed
```

---

# Security Notes

This implementation contains multiple security mechanisms, but it should be considered a **research/experimental networking implementation** unless it has undergone a formal security audit.

In particular:

* The group encryption key is embedded in the firmware.
* The application password is embedded in the firmware.
* Randomness and key generation should be reviewed before production deployment.
* Private keys are generated during initialization.
* Key persistence and re-keying behavior should be reviewed for long-term deployments.
* Cryptographic library implementations should be independently evaluated.
* Physical access to a node may expose secrets stored in firmware or memory.

Do not use the current configuration for security-critical deployments without further security review.

---

# Project Structure

A recommended repository structure is:

```text
LoRa-Decentralized-Network/
│
├── README.md
│
├── firmware/
│   └── LoRa_Decentralized_Network.ino
│
├── hardware/
│   └── pinout.md
│
├── docs/
│   ├── protocol.md
│   ├── security.md
│   └── network_architecture.md
│
└── LICENSE
```

---

# Project Status

**Firmware Version:** 2.11

The current implementation includes:

* [x] LoRa communication
* [x] Multi-node networking
* [x] Dynamic route discovery
* [x] Route error handling
* [x] Neighbor discovery
* [x] AES-256-GCM encryption
* [x] Curve25519 key exchange
* [x] Anti-replay protection
* [x] Message acknowledgements
* [x] Automatic retries
* [x] Persistent message queue
* [x] Duplicate packet detection
* [x] Bluetooth interface
* [x] Serial interface
* [x] Broadcast messaging

---

## Author

**Pritam Dutta**

LoRa-based decentralized networking and embedded systems project.
