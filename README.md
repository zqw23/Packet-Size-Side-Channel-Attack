# Wi-Fi Injection Research Prototypes

This repository bundles two C++ research prototypes that explore Wi-Fi packet-size side channels:

- `TCP Injection/`: infer TCP connection parameters and perform forged TCP actions.
- `UDP Injection/`: infer UDP client source port(s) and inject forged UDP payloads.

## Legal and Ethical Notice

This code is provided for authorized security research and controlled lab testing only.
Do not use it on networks, devices, or services without explicit permission.

## Repository Layout

| Directory | Purpose | Main File |
| --- | --- | --- |
| `TCP Injection/` | TCP port/SEQ/ACK inference and injection/reset stage | `main.cpp` |
| `UDP Injection/` | UDP port-range inference and UDP payload injection | `main.cpp` |

## Requirements

- Linux environment recommended.
- C++11+ compiler (for example, `g++`).
- [libtins](https://libtins.github.io/) and `libpcap`.
- Root privileges (`sudo`) for raw packet send/sniff operations.
- Wireless interface(s) in monitor mode and tuned to the target Wi-Fi channel.

Example dependency install (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y build-essential libtins-dev libpcap-dev
```

## Build

Build TCP prototype:

```bash
cd "TCP Injection"
g++ -std=c++11 -O2 main.cpp PortFinder.cpp SeqFinder.cpp AckFinder.cpp Attack.cpp -o tcp_injection -ltins -pthread
cd ..
```

Build UDP prototype:

```bash
cd "UDP Injection"
g++ -std=c++11 -O2 main.cpp PortFinder.cpp FastPacketSender.cpp Attack.cpp -o udp_injection -ltins -pthread
cd ..
```

## Configuration

Before running, edit parameters in each subproject's `main.cpp`:

- target identifiers (`client_mac`, `client_ip`, `server_ip`, `server_port`)
- interface names (`send_if_name`, `sniff_if_name`)
- scan range and tuning parameters (`start_port`, `end_port`, `step_size`, repeat counts)
- attack options (for TCP: `attack_type`)

## Run

Run TCP prototype:

```bash
cd "TCP Injection"
sudo ./tcp_injection
```

Run UDP prototype:

```bash
cd "UDP Injection"
sudo ./udp_injection
```

## Subproject Docs

- [TCP Injection README](./TCP%20Injection/README.md)
- [UDP Injection README](./UDP%20Injection/README.md)
