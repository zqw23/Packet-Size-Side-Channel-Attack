# TCP Injection (Research Prototype)

This directory contains a C++ prototype that infers TCP connection parameters and then performs packet injection based on a Wi-Fi packet-size side channel.

## Legal and Ethical Notice

This code is for authorized security research and controlled lab experiments only.
Do not use it on any network, device, or service without explicit permission.

## What This Prototype Does

The program runs in four stages:
1. Infer the client TCP source port (`PortFinder`).
2. Infer a sequence number accepted in the server receive window (`SeqFinder`).
3. Infer an acknowledgement number accepted in the server receive window (`AckFinder`).
4. Execute an attack action (`Attacker`):
   - `Inject`: send forged TCP payloads into the connection.
   - `DoS`: send forged RST packets to disrupt/reset the connection.

## Project Structure

- `main.cpp`: experiment entry and parameters.
- `PortFinder.h/.cpp`: client port inference.
- `SeqFinder.h/.cpp`: sequence-number inference.
- `AckFinder.h/.cpp`: acknowledgement-number inference.
- `Attacker.h` + `Attack.cpp`: final packet injection / reset stage.
- `Candidate.h`: helper data structure for candidate port ranges.

## Requirements

- Linux environment recommended.
- A C++11+ compiler (e.g., `g++`).
- [libtins](https://libtins.github.io/) and `libpcap`.
- Root privileges (`sudo`) for raw packet injection/sniffing.
- Wireless NIC(s) configured for monitor mode and tuned to the target channel.

Example dependency install (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y build-essential libtins-dev libpcap-dev
```

## Build

From this directory:

```bash
g++ -std=c++11 -O2 main.cpp PortFinder.cpp SeqFinder.cpp AckFinder.cpp Attack.cpp -o tcp_injection -ltins -pthread
```

## Configuration

Edit parameters in `main.cpp` before running:

- Target identifiers:
  - `client_mac`
  - `client_ip`
  - `server_ip`
  - `server_port`
- Interfaces:
  - `send_if_name`
  - `sniff_if_name` (one or more monitor interfaces)
- Ephemeral port range:
  - Linux example: `32768-60999`
  - macOS example: `49152-65535`
- Scan parameters:
  - `step_size`
  - `packet_repeat`
- Attack behavior:
  - `attack_type = "Inject"` or `"DoS"`

## Run

```bash
sudo ./tcp_injection
```

The program prints inferred connection fields and then executes the selected attack mode.

## Notes

- Interface names in `main.cpp` must match your local system.
- All sniff interfaces should be on the same Wi-Fi channel as the target traffic.
- Timing and capture quality affect inference reliability; tune `step_size` and repeat counts as needed.
