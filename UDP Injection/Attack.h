#ifndef ATTACK_H
#define ATTACK_H

#include <string>
#include <cstdint>

class Attacker {
public:
    Attacker(const std::string& client_ip,
             const std::string& server_ip,
             uint16_t client_port,
             uint16_t server_port,
             const std::string& send_if_name,
             const std::string& payload,
             int packet_repeat)
        : client_ip(client_ip),
          server_ip(server_ip),
          client_port(client_port),
          server_port(server_port),
          send_if_name(send_if_name),
          payload(payload),
          packet_repeat(packet_repeat) {}

    void UDP_inject() const;

private:
    std::string client_ip;
    std::string server_ip;
    uint16_t client_port;
    uint16_t server_port;
    std::string send_if_name;
    std::string payload;
    int packet_repeat;
};

#endif
