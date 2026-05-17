# IoT Light Monitoring System

A distributed IoT system for real-time ambient light measurement and monitoring, built as a final year engineering project (PFE - *Projet de Fin d'Etudes*). The system consists of two ESP32-S3 nodes: a sensor node that reads and displays light levels, and a gateway node that serves a live web dashboard with built-in DDoS protection.

---

## System Architecture

```
Light Source
    |
BH1750 Sensor (Node 1)
    |
ESP32-S3 -- OLED Display
    |
UART (TX -> RX)
    |
ESP32-S3 (Node 2)
    |
WiFi + Web Server
    |
Browser Dashboard (SSE)
```

---

## Hardware Requirements

| Component | Details |
|---|---|
| Microcontroller | ESP32-S3 DevKit-C1 (x2) |
| Light Sensor | BH1750 (I2C) |
| Display | Adafruit SH110X OLED 128x64px (I2C) |
| Communication | UART serial (115200 baud, 8N1) |

---

## Project Structure

```
PFE/
|-- Node 1/                         # Sensor node
|   |-- src/
|   |   `-- main.cpp                # Sensor firmware
|   |-- include/
|   |-- lib/
|   |-- test/
|   `-- platformio.ini
|
`-- node2_final/                    # Gateway node
    |-- src/
    |   `-- main_final_real_cleaned.cpp  # Gateway firmware
    `-- platformio.ini
```

---

## Node 1 - Sensor Node

Reads ambient light levels and transmits them to Node 2 over UART.

**Features:**
- Reads BH1750 in continuous high-resolution mode (200ms intervals)
- Categorizes light: *Very Dark, Dim, Well-Lit, Bright, Sunlight*
- Displays real-time lux value on the 128x64 OLED screen
- Transmits formatted data over UART: `LUX:XX.XX\n`

**Pin Configuration:**

| Signal | GPIO |
|---|---|
| I2C SDA | GPIO 8 |
| I2C SCL | GPIO 9 |
| UART TX | GPIO 17 |

---

## Node 2 - Gateway Node

Receives sensor data over UART and serves a live web dashboard with DDoS protection.

**Features:**
- Connects to WiFi with automatic reconnection (5s retry)
- Syncs time via NTP for timestamped logging
- Persists last 100 lux readings in NVS (survives reboots)
- Serves an embedded HTML dashboard with real-time SSE updates
- Dual-core architecture (Core 0: network task / Core 1: UART reception)
- Thread-safe inter-task communication using FreeRTOS mutexes and atomic variables

**Pin Configuration:**

| Signal | GPIO |
|---|---|
| UART RX | GPIO 16 |

### Web Dashboard

Accessible at `http://<device-ip>/` once connected to WiFi.

| Endpoint | Description |
|---|---|
| `GET /` | Embedded HTML dashboard |
| `GET /events` | Server-Sent Events stream for real-time updates |

**SSE Event Types:**

| Event | Payload |
|---|---|
| `lux` | Current light reading (float) |
| `history` | JSON array of timestamped readings (up to 100 entries) |
| `banned` | JSON array of currently banned IPs |

### DDoS Protection

Node 2 implements a multi-layer mitigation system:

- **Per-IP rate limiting**: auto-ban after 10 requests/second
- **Global rate alert**: triggered at 200 requests/second
- **TCP-level filtering**: blocks banned IPs before HTTP processing
- **Sliding window algorithm**: tracks request rates per IP
- **Periodic cleanup**: removes inactive IP entries every 30 seconds
- **IP table limit**: caps tracking at 200 concurrent IPs

### Watchdog Timers

| Watchdog | Trigger Condition | Action |
|---|---|---|
| Attack watchdog | Active DDoS for 30+ seconds | Reboot |
| WiFi watchdog | WiFi dead for 120+ seconds | Reboot |

History is saved to NVS before any reboot.

---

## Prerequisites

- [PlatformIO](https://platformio.org/) (VSCode extension or CLI)
- Python 3.x
- USB cables for both boards
- ESP32 USB-to-UART drivers installed

---

## Build & Flash

### Node 1

```bash
# Build
pio run -e node_a

# Flash
pio run -e node_a -t upload

# Monitor serial output
pio device monitor -e node_a -b 115200
```

### Node 2

```bash
# Build
pio run -e node_b

# Flash
pio run -e node_b -t upload

# Monitor serial output
pio device monitor -e node_b -b 115200
```

---

## Configuration

### WiFi Credentials (Node 2)

WiFi credentials are hardcoded in `node2_final/src/main_final_real_cleaned.cpp`. Update before flashing:

```cpp
const char* ssid     = "YOUR_SSID";
const char* password = "YOUR_PASSWORD";
```

### UART Protocol

Both nodes must be configured for the same UART settings:

| Parameter | Value |
|---|---|
| Baud rate | 115200 |
| Data bits | 8 |
| Parity | None |
| Stop bits | 1 |
| Message format | `LUX:XX.XX\n` |

---

## Libraries

| Library | Used By | Purpose |
|---|---|---|
| `BH1750` | Node 1 | Light sensor driver |
| `Adafruit SH110X` | Node 1 | OLED display driver |
| `Adafruit GFX` | Node 1 | Graphics rendering |
| `Adafruit BusIO` | Node 1 | I2C/SPI bus abstraction |
| `AsyncTCP` | Node 2 | Async TCP/IP stack |
| `ESPAsyncWebServer` | Node 2 | Non-blocking HTTP server |

---

## Data Flow Summary

1. BH1750 sensor measures ambient light (lux) via I2C on Node 1
2. Node 1 displays the reading on the OLED and sends `LUX:XX.XX\n` over UART
3. Node 2 receives the value over UART and stores it atomically
4. Node 2 broadcasts updates to connected browsers via Server-Sent Events
5. The web dashboard renders live lux values and historical data with timestamps
