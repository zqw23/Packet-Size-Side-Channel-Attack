#include "PortFinder.h"
#include <iostream>
#include <fstream>
#include <tins/tins.h>
#include <vector>
#include <deque>
#include <queue>
#include <chrono>
#include <random>
#include <thread>
#include <algorithm>
#include <cmath>
#include <map>
#include <set>


using namespace Tins;


int PortFinder::randomInt_q(int min, int max){
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(min, max);
    return dis(gen);
}


std::vector<std::pair<uint32_t, uint32_t>> PortFinder::divide_port_range(uint32_t start, uint32_t end, int num_subranges) {
    std::vector<std::pair<uint32_t, uint32_t>> subranges;
    
    if (end <= start) {
        return subranges;
    }
    
    uint32_t total_range = end - start;
    uint32_t subrange_size = total_range / num_subranges;
    
    
    if (subrange_size == 0) {
        
        for (uint32_t port = start; port < end; ++port) {
            subranges.push_back({port, port+1});
        }
        return subranges;
    }
    
    for (int i = 0; i < num_subranges; i++) {
        uint32_t subrange_start = start + i * subrange_size;
        uint32_t subrange_end;
        
        if (i == num_subranges - 1) {
            subrange_end = end;
        } else {
            subrange_end = start + (i + 1) * subrange_size;
        }
        
        subranges.push_back({subrange_start, subrange_end});
    }
    
    return subranges;
}

std::vector<int> PortFinder::scan_subranges(const std::vector<std::pair<uint32_t, uint32_t>>& subranges) {
    if (subranges.empty()) {
        return {};
    }
    
    std::cout << "[*] Scanning " << subranges.size() << " subranges..." << std::endl;
    
    current_port_list.clear();
    
    
    uint32_t total_ports = 0;
    for (const auto& subrange : subranges) {
        uint32_t range_size = subrange.second - subrange.first;
        total_ports += range_size;
    }
    
    std::cout << "[*] Total ports to scan: " << total_ports << std::endl;
    
    
    std::vector<std::vector<Packet>> sniff_pkts_vec;
    int sniff_pkts_vec_num = sniff_if_name.size();
    
    for (int i = 0; i < sniff_pkts_vec_num; i++) {
        std::vector<Packet> sniff_pkts;
        sniff_pkts_vec.push_back(sniff_pkts);
    }

    std::vector<std::thread> sniff_thread_vec;

    const int safe_nic_rate = nic_rate > 0 ? nic_rate : 1;
    if (nic_rate <= 0) {
        std::cout << "[!] Invalid nic_rate=" << nic_rate << ", fallback to 1 pkt/s for timing." << std::endl;
    }
    int sniff_time = 100 + static_cast<int>(static_cast<double>(total_ports) * 1000 / safe_nic_rate);
    std::cout << "[*] Estimated sniffing time: " << sniff_time << " ms" << std::endl;

    for (size_t i = 0; i < sniff_pkts_vec.size(); i++) {
        sniff_thread_vec.emplace_back(&PortFinder::capturePackets, this, 
                                    std::ref(sniff_pkts_vec[i]), i, sniff_time);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    

    auto packet_send_time_start = std::chrono::system_clock::now();

    for (size_t i = 0; i < subranges.size(); i++) {
        const auto& subrange = subranges[i];
        
        
        int payload_size = base_payload_size + static_cast<int>(i);
        
        
        
        
        
        
        
        
        std::vector<IP> subrange_packets;
        uint32_t subrange_size = subrange.second - subrange.first;
        
        try {
            subrange_packets.reserve(subrange_size);  
        } catch (const std::exception& e) {
            std::cerr << "[!] Error reserving memory for subrange " << i << ": " << e.what() << std::endl;
            continue;
        }
        
        
        std::string payload;
        try {
            payload.reserve(payload_size);
            payload.assign(payload_size, 'A');
        } catch (const std::exception& e) {
            std::cerr << "[!] Error creating payload of size " << payload_size << ": " << e.what() << std::endl;
            continue;
        }
        
        
        for (uint32_t port = subrange.first; port < subrange.second; ++port) {
            if (port > 65535) {
                continue;
            }
            const uint16_t u16_port = static_cast<uint16_t>(port);
            current_port_list.push_back(u16_port);
            
            try {
                IP packet = IP(client_ip, server_ip) / UDP(u16_port, server_port) / RawPDU(payload);
                subrange_packets.emplace_back(std::move(packet));
            } catch (const std::exception& e) {
                std::cerr << "[!] Error creating packet for port " << port << ": " << e.what() << std::endl;
                
                if (!current_port_list.empty()) {
                    current_port_list.pop_back();
                }
                continue;
            }
        }
        
        
        if (!subrange_packets.empty()) {
            
            send_num += subrange_packets.size();
            for (const IP& pkt : subrange_packets) {
                send_byte += pkt.size();
            }
            
            
            try {
                get_sender().send_all(subrange_packets);
                
                
            } catch (const std::exception& e) {
                std::cerr << "[!] Error sending subrange " << i << ": " << e.what() << std::endl;
            }
        }
        
        
        subrange_packets.clear();
        subrange_packets.shrink_to_fit();
        
        
        
        
        
    }
    
    auto packet_send_time_end = std::chrono::system_clock::now();
    std::chrono::duration<double> send_duration = packet_send_time_end - packet_send_time_start;
    std::cout << "[*] Packet sending completed in " << send_duration.count() << " seconds" << std::endl;

    std::cout << "[*] All packets sent, total packets: " << send_num << std::endl;

    
    std::this_thread::sleep_for(std::chrono::milliseconds(sniff_time));

    
    try {
        std::vector<IP> noise_packets;
        std::string noise_payload = "NOISE";  
        for(int i = 0; i < 3; i++){
            noise_packets.emplace_back(IP(client_ip, server_ip) / UDP(1234, 52194) / RawPDU(noise_payload));
        }
        get_sender().send_all(noise_packets);
        
        
        noise_packets.clear();
        noise_packets.shrink_to_fit();
    } catch (const std::exception& e) {
        std::cerr << "[!] Error sending noise packets: " << e.what() << std::endl;
    }

    for (auto& t : sniff_thread_vec) {
        if (t.joinable()) {
            t.join();
        }
    }

    
    std::vector<Packet> sniff_pkts_merge;
    try {
        for (size_t i = 0; i < sniff_pkts_vec.size(); i++) {
            sniff_pkts_merge.insert(sniff_pkts_merge.end(), 
                                  sniff_pkts_vec[i].begin(), sniff_pkts_vec[i].end());
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error merging packets: " << e.what() << std::endl;
        return {};
    }

    std::cout << "[*] Captured " << sniff_pkts_merge.size() << " packets total" << std::endl;

    
    int detected_subrange_size = subranges.size();
    std::vector<int> detected_subrange_indexes(detected_subrange_size, 0);
    

    for (auto& packet : sniff_pkts_merge) {
        try {
            if(packet.pdu()->find_pdu<Dot11QoSData>()){
                if(packet.pdu()->find_pdu<RawPDU>()){
                    int frame_size = packet.pdu()->rfind_pdu<RawPDU>().size();

                    int index = frame_size - base_frame_size;

                    if(index >= 0 && index < detected_subrange_size){
                        detected_subrange_indexes[index]++;
                    }
                }
            }
        } catch (const std::exception& e) {
            
            continue;
        }
    }

    
    sniff_pkts_merge.clear();
    sniff_pkts_merge.shrink_to_fit();



    
    std::vector<int> detected_subranges;
    for (size_t i = 0; i < detected_subrange_indexes.size(); i++) {
        if(detected_subrange_indexes[i] > 0){
            std::cout << "[+] Detected response in subrange " << i 
                      << " (ports " << subranges[i].first << "-" << (subranges[i].second - 1)
                      << "), count: " << detected_subrange_indexes[i] << std::endl;
            detected_subranges.push_back(i);
        }
    }
    
    
    if (detected_subranges.empty()) {
        std::cout << "[-] No matching frame sizes detected" << std::endl;
    } else if (detected_subranges.size() == 1) {
        std::cout << "[*] Single subrange detected: " << detected_subranges[0] << std::endl;
    } else {
        std::cout << "[*] Multiple subranges detected: ";
        for (size_t i = 0; i < detected_subranges.size(); i++) {
            std::cout << detected_subranges[i];
            if (i < detected_subranges.size() - 1) std::cout << ", ";
        }
        std::cout << std::endl;
    }
    
    return detected_subranges;
}


std::vector<uint16_t> PortFinder::iterative_port_scan(uint32_t range_start, uint32_t range_end) {
    std::vector<uint16_t> found_ports;
    

    while (!scan_queue.empty()) {
        scan_queue.pop();
    }
    
    scan_queue.push(PortRange(range_start, range_end, 0));
    
    std::cout << "[*] Starting iterative port scan from " << range_start << " to " << range_end << std::endl;
    
    int processed_ranges = 0;
    const int max_processed_ranges = 200;  
    
    while (!scan_queue.empty() && processed_ranges < max_processed_ranges) {
        PortRange current_range = scan_queue.front();
        scan_queue.pop();
        processed_ranges++;
        
        std::cout << "\n[*] === Processing depth " << current_range.depth 
                  << " (range " << processed_ranges << "/" << max_processed_ranges << ") ===" << std::endl;
        std::cout << "[*] Scanning port range: " << current_range.start << " - " << (current_range.end - 1)
                  << " (total: " << (current_range.end - current_range.start) << " ports)" << std::endl;
        
        if (current_range.depth >= max_scan_depth || current_range.end - current_range.start <= 1) {
            std::cout << "[*] Reached verification condition, verifying port: " << current_range.start << std::endl;
            if (current_range.start > 65535) {
                std::cout << "[-] Skip out-of-range port: " << current_range.start << std::endl;
                continue;
            }
            const uint16_t candidate_port = static_cast<uint16_t>(current_range.start);
            if (verify_suspicious_port(candidate_port)) {
                found_ports.push_back(candidate_port);
                std::cout << "[+] Verified and added port: " << current_range.start << std::endl;
            } else {
                std::cout << "[-] Port verification failed: " << current_range.start << std::endl;
            }
            continue;
        }
        
        try {
            
            auto subranges = divide_port_range(current_range.start, current_range.end,20);
            
            if (subranges.empty()) {
                continue;
            }
            
            
            std::vector<int> detected_subranges = scan_subranges(subranges);
            
            if (detected_subranges.empty()) {
                std::cout << "[-] No response detected in any subrange at depth " << current_range.depth << std::endl;
                continue;
            }
            
            
            for (int subrange_idx : detected_subranges) {
                if (subrange_idx >= 0 && subrange_idx < static_cast<int>(subranges.size())) {
                    const auto& target_subrange = subranges[subrange_idx];
                    std::cout << "[+] Adding subrange " << subrange_idx << " to scan queue: " 
                              << target_subrange.first << " - " << (target_subrange.second - 1) << std::endl;
                    
                    scan_queue.push(PortRange(target_subrange.first, target_subrange.second, current_range.depth + 1));
                }
            }
            
        } catch (const std::exception& e) {
            std::cerr << "[!] Error processing range at depth " << current_range.depth << ": " << e.what() << std::endl;
            continue;
        }
        
        std::cout << "[*] Completed processing depth " << current_range.depth 
                  << ", queue size: " << scan_queue.size() << std::endl;
    }
    
    if (processed_ranges >= max_processed_ranges) {
        std::cout << "[!] Reached maximum processed ranges limit to prevent excessive memory usage" << std::endl;
    }
    
    return found_ports;
}

void PortFinder::capturePackets(std::vector<Packet>& pkts, int sniff_if_index, int sniff_time) {
    try {
        SnifferConfiguration config;
        config.set_filter("wlan addr1 " + client_mac);
        config.set_immediate_mode(true);
        Sniffer sniffer(sniff_if_name[sniff_if_index], config);

        auto s_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::milliseconds(sniff_time);  

        while (std::chrono::high_resolution_clock::now() - s_time < duration) {
            try {
                Packet packet = sniffer.next_packet();
                pkts.push_back(packet);
                
                
                if (pkts.size() > 10000) {
                    std::cout << "[!] Packet buffer full, stopping capture" << std::endl;
                    break;
                }
            } catch (const std::exception& e) {
                break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error in packet capture: " << e.what() << std::endl;
    }
}

bool PortFinder::verify_suspicious_port(uint16_t port) {
    const int expected_payload_size = 10;  
    const int expected_frame_size = expected_payload_size + 105;
    std::cout << "[*] Verifying port: " << port << " with payload size: " << expected_payload_size << std::endl;

    try {
        std::string payload(expected_payload_size, 'A');
        std::vector<IP> send_list;
        
        IP packet = IP(client_ip, server_ip) / UDP(port, server_port) / RawPDU(payload);
        send_list.emplace_back(packet);
        
        int successful_detections = 0;
        const int verification_rounds = 2;
        
        for (int i = 0; i < verification_rounds; ++i) {
            send_num += send_list.size();
            for (const IP& pkt : send_list) {
                send_byte += pkt.size();
            }

            std::vector<std::vector<Packet>> sniff_pkts_vec;
            int sniff_pkts_vec_num = sniff_if_name.size();
            
            for (int k = 0; k < sniff_pkts_vec_num; k++) {
                std::vector<Packet> sniff_pkts;
                sniff_pkts_vec.push_back(sniff_pkts);
            }

            std::vector<std::thread> sniff_thread_vec;
            int sniff_time = 100;
            std::cout << "[*] Verification round " << (i + 1) 
                      << ", estimated sniffing time: " << sniff_time << " ms" << std::endl;

            for (size_t k = 0; k < sniff_pkts_vec.size(); k++) {
                sniff_thread_vec.emplace_back(&PortFinder::capturePackets, this, 
                                            std::ref(sniff_pkts_vec[k]), k, sniff_time);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            get_sender().send_all(send_list);
            std::this_thread::sleep_for(std::chrono::milliseconds(sniff_time));

            
            std::vector<IP> noise_packets;
            std::string noise_payload = "END";
            for(int k = 0; k < 2; k++){
                noise_packets.emplace_back(IP(client_ip, server_ip) / UDP(1234, 52194) / RawPDU(noise_payload));
            }
            get_sender().send_all(noise_packets);

            for (auto& t : sniff_thread_vec) {
                if (t.joinable()) {
                    t.join();
                }
            }

            
            std::vector<Packet> sniff_pkts_merge;
            for (size_t k = 0; k < sniff_pkts_vec.size(); k++) {
                sniff_pkts_merge.insert(sniff_pkts_merge.end(), 
                                    sniff_pkts_vec[k].begin(), sniff_pkts_vec[k].end());
            }

            for (auto& packet : sniff_pkts_merge) {
                try {
                    if(packet.pdu()->find_pdu<Dot11QoSData>()){
                        if(packet.pdu()->find_pdu<RawPDU>()){
                            int frame_size = packet.pdu()->rfind_pdu<RawPDU>().size();
                            if (frame_size == expected_frame_size){
                                successful_detections++;
                                std::cout << "[+] Verification " << (i + 1) << " successful for port " << port << std::endl;
                                break;
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    continue;
                }
            }
        }
        
        std::cout << "[*] Port " << port << " verification result: " 
                  << successful_detections << "/" << verification_rounds << std::endl;

        return successful_detections > 0;
        
    } catch (const std::exception& e) {
        std::cerr << "[!] Error verifying port " << port << ": " << e.what() << std::endl;
        return false;
    }
}

void PortFinder::find_port() {
    std::cout << "++++++++++ Try to find UDP connection ports using iterative scanning ++++++++++" << std::endl;
    std::cout << "[*] Using conservative memory settings to prevent allocation errors" << std::endl;
    
    try {
        const uint32_t scan_start = static_cast<uint32_t>(start_port);
        const uint32_t scan_end_exclusive = static_cast<uint32_t>(end_port) + 1u;
        std::vector<uint16_t> found_ports = iterative_port_scan(scan_start, scan_end_exclusive);
        
        if (!found_ports.empty()) {
            std::cout << "[+] Successfully found " << found_ports.size() << " valid UDP port(s): ";
            for (size_t i = 0; i < found_ports.size(); i++) {
                std::cout << found_ports[i];
                if (i < found_ports.size() - 1) std::cout << ", ";
            }
            std::cout << std::endl;
            
            results.clear();
            for (uint16_t port : found_ports) {
                results.push_back(static_cast<int>(port));
            }
            
            std::cout << "[+] All found ports stored in results" << std::endl;
            stop = true;
        } else {
            std::cout << "[-] Failed to find valid UDP port in the given range" << std::endl;
            results.clear();
            stop = true;
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error in find_port: " << e.what() << std::endl;
        results.clear();
        stop = true;
    }
}

void PortFinder::write_data() {
    try {
        std::ofstream file("udp_port_data.txt", std::ios::app);

        if (!file.is_open()) {
            std::cerr << "Cannot open file!" << std::endl;
            return;
        }

        file << cost_time << " " << send_rate << " " << send_byte << " " 
             << send_num << " ";
        
        if (results.empty()) {
            file << "-1";
        } else {
            file << "[";
            for (size_t i = 0; i < results.size(); i++) {
                file << results[i];
                if (i < results.size() - 1) file << ",";
            }
            file << "]";
        }
        
        file << std::endl;
        file.close();
    } catch (const std::exception& e) {
        std::cerr << "[!] Error writing data: " << e.what() << std::endl;
    }
}

void PortFinder::run() {
    auto time_start = std::chrono::system_clock::now();
    
    current_port = start_port;
    stop = false;
    send_num = 0;
    send_byte = 0;
    cost_time = 0;
    results.clear();

    find_port();
    
    auto time_end = std::chrono::system_clock::now();
    cost_time = std::chrono::duration<double>(time_end - time_start).count();
    
    if (send_byte > 0) {
        send_rate = static_cast<double>(send_byte) / cost_time;
    } else {
        send_rate = 0.0;
    }
    
    std::cout << "=== UDP Port Discovery Results ===" << std::endl;
    
    if (!results.empty()) {
        std::cout << "Found " << results.size() << " UDP client port(s): ";
        for (size_t i = 0; i < results.size(); i++) {
            std::cout << results[i];
            if (i < results.size() - 1) std::cout << ", ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "No valid UDP ports found" << std::endl;
    }
    
    std::cout << "Sent packets: " << send_num << std::endl;
    std::cout << "Sent bytes: " << send_byte << " (Bytes)" << std::endl;
    std::cout << "Cost time: " << cost_time << " (s)" << std::endl;
    std::cout << "Send rate: " << send_rate << " (Byte/s)" << std::endl;

    if (!results.empty()) {
        write_data();
    }
    
    std::cout << "===================================" << std::endl;
}
