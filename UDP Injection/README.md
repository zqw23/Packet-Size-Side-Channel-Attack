# UDP Injection (Research Prototype)

This directory contains a C++ prototype for UDP port inference and packet injection based on a Wi-Fi packet-size side channel.

The workflow is:
1. Scan a UDP source-port range with crafted packet batches.
2. Capture Wi-Fi frames on monitor interfaces and detect size-correlated responses.
3. Iteratively narrow the candidate range and verify suspicious ports.
4. Send UDP payload(s) to the inferred client port(s).

## Legal and Ethical Notice

This code is for authorized security research and controlled lab experiments only.
Do not run it against networks, devices, or services without explicit permission.

## Project Structure

- `main.cpp`: Entry point and experiment configuration.
- `PortFinder.h/.cpp`: Port-range scanning, packet capture, and candidate verification.
- `FastPacketSender.h/.cpp`: High-throughput packet sender (single-thread and multi-thread modes).
- `Attack.h/.cpp`: Final UDP injection logic for inferred client ports.

## Requirements

- Linux environment (recommended for monitor-mode workflow).
- A C++11+ compiler (e.g., `g++`).
- [libtins](https://libtins.github.io/) and libpcap.
- Root privileges (`sudo`) for raw packet send/sniff operations.
- Wireless interface(s) configured for monitor mode and tuned to the target channel.

Example dependency installation (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y build-essential libtins-dev libpcap-dev
```

## Build

From this folder:

```bash
g++ -std=c++11 -O2 main.cpp PortFinder.cpp FastPacketSender.cpp Attack.cpp -o udp_injection -ltins -pthread
```

## Configuration

Before running, edit parameters in `main.cpp`:

- `client_ip`, `server_ip`
- `server_port`
- `start_port`, `end_port`
- `send_if_name`
- `sniff_if_name` (can include multiple monitor interfaces)
- `client_mac`
- `step_size`, `packet_repeat`
- `base_payload_size`, `base_frame_size`
- `nic_rate`
- `attack_payload`, `inject_repeat`

## Run

```bash
sudo ./udp_injection
```

## Output

- Console logs:
  - scan progress
  - detected subranges
  - verified UDP client port(s)
  - injection status
- If at least one valid port is found, metrics are appended to:
  - `udp_port_data.txt`

## Notes

- `sniff_if_name` must match real interface names on your machine.
- Packet-size detection logic depends on environmental calibration.
- If scan quality is unstable, adjust `nic_rate`, payload/frame baseline, and interface/channel setup.
