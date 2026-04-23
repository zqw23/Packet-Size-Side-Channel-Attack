#ifndef PORTFINDER_H
#define PORTFINDER_H

#include "FastPacketSender.h"
#include <string>
#include <vector>
#include <deque>
#include <queue>
#include <set>
#include <memory>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <tins/tins.h>

struct PortRange {
    uint32_t start;
    uint32_t end;
    int depth;
    
    PortRange(uint32_t s, uint32_t e, int d) : start(s), end(e), depth(d) {}
};

class PortFinder {
public:
    PortFinder(const std::string& client_ip, const std::string& server_ip,
               uint16_t server_port, uint16_t start_port, uint16_t end_port,
               const std::string& send_if_name, const std::vector<std::string>& sniff_if_name,
               const std::string& client_mac, uint16_t step_size, int packet_repeat,
               int base_payload_size, int base_frame_size, int nic_rate)
    : client_ip(client_ip), server_ip(server_ip), server_port(server_port), start_port(start_port),
      end_port(end_port), send_if_name(send_if_name), sniff_if_name(sniff_if_name), client_mac(client_mac), 
      step_size(step_size), packet_repeat(packet_repeat), base_payload_size(base_payload_size),
      base_frame_size(base_frame_size), repeat_time(2), stop(false), port_range_end(false), 
      verification_repeats(3), max_scan_depth(20), nic_rate(nic_rate) {
        
        initialize_sender(send_if_name, 100, 4, std::chrono::microseconds(0));
    }

    PortFinder(const std::vector<std::string>& sniff_if_name, const std::string& client_mac) 
    : sniff_if_name(sniff_if_name), client_mac(client_mac), base_payload_size(200), 
      base_frame_size(282), verification_repeats(3), max_scan_depth(20) {
        
        if (!sniff_if_name.empty()) {
            send_if_name = sniff_if_name[0]; 
        }
        initialize_sender(send_if_name, 100, 4, std::chrono::microseconds(0));
    }

    PortFinder() : base_payload_size(200), base_frame_size(282), verification_repeats(3), 
      max_scan_depth(20) {
        
    }

    void run();
    
    
    std::vector<int> getResults() const {
        return results;
    }
    
    
    int getResult() const {
        return results.empty() ? -1 : results[0];
    }

    void write_data();
    
    
    void initialize_sender(const std::string& interface_name, 
                          size_t batch_size = 100,
                          size_t thread_count = 4,
                          std::chrono::microseconds delay = std::chrono::microseconds(0)) {
        try {
            
            sender.reset(new FastPacketSender(interface_name, 
                                            batch_size, thread_count, delay));
            send_if_name = interface_name;
        } catch (const std::exception& e) {
            
            throw std::runtime_error("Failed to initialize FastPacketSender: " + std::string(e.what()));
        }
    }

    
    void set_sender_params(const std::string& interface_name,
                          size_t batch_size = 100,
                          size_t thread_count = 4,
                          std::chrono::microseconds delay = std::chrono::microseconds(0)) {
        initialize_sender(interface_name, batch_size, thread_count, delay);
    }

    
    void set_send_interface(const std::string& interface_name) {
        if (sender) {
            sender->set_interface(interface_name);
            send_if_name = interface_name;
        } else {
            initialize_sender(interface_name);
        }
    }

    
    bool is_sender_initialized() const {
        return sender != nullptr;
    }

    
    const std::string& get_send_interface() const {
        return send_if_name;
    }

private:
    std::unique_ptr<FastPacketSender> sender;  

    std::string client_mac;
    std::string client_ip;
    std::string server_ip;
    int client_port;
    uint16_t server_port;
    uint16_t start_port;
    uint16_t current_port;
    uint16_t end_port;
    std::string send_if_name;
    std::vector<std::string> sniff_if_name;
    uint16_t step_size;
    int packet_repeat;
    int repeat_time;
    bool stop;
    bool port_range_end;
    std::vector<uint16_t> candidate_list;
    int send_num;
    int send_byte;
    double cost_time;
    double send_rate;
    
    
    std::vector<int> results;
    
    
    int base_payload_size;
    int base_frame_size;
    int verification_repeats;
    std::set<int> detected_frame_sizes;
    std::vector<int> potential_port_list;
    std::vector<uint16_t> current_port_list;
    int nic_rate;  
    int frame_header_size;
    
    
    int max_scan_depth;
    std::queue<PortRange> scan_queue;

    void capturePackets(std::vector<Tins::Packet>& pkts, int sniff_if_index, int sniff_time);
    
    bool verify_suspicious_port(uint16_t port);
    void find_port();
    
    
    std::vector<uint16_t> iterative_port_scan(uint32_t range_start, uint32_t range_end);
    std::vector<std::pair<uint32_t, uint32_t>> divide_port_range(uint32_t start, uint32_t end, int num_subranges = 10);
    std::vector<int> scan_subranges(const std::vector<std::pair<uint32_t, uint32_t>>& subranges);

    
    FastPacketSender& get_sender() {
        if (!sender) {
            throw std::runtime_error("FastPacketSender not initialized. Call initialize_sender() first.");
        }
        return *sender;
    }

    
    int randomInt_q(int min, int max);
};

#endif
