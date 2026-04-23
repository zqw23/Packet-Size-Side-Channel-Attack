#include "Attack.h"

#include <iostream>
#include <tins/tins.h>

using namespace Tins;

void Attacker::UDP_inject() const {
    PacketSender sender;

    for (int i = 0; i < packet_repeat; ++i) {
        IP packet = IP(client_ip, server_ip) / UDP(client_port, server_port) / RawPDU(payload);
        sender.send(packet, send_if_name);
    }

    std::cout << "[+] UDP injection sent: " << packet_repeat
              << " packet(s), client_port=" << client_port
              << ", server_port=" << server_port << std::endl;
}
