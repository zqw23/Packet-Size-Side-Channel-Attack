#ifndef FAST_PACKET_SENDER_H
#define FAST_PACKET_SENDER_H

#include <tins/tins.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <memory>

class FastPacketSender {
private:
    std::vector<Tins::IP> packets_;  
    std::string interface_name_;
    size_t batch_size_;
    size_t thread_count_;
    std::chrono::microseconds delay_between_batches_;
    
    void send_batch(size_t start_idx, size_t end_idx);

public:
    explicit FastPacketSender(const std::string& interface_name, 
                             size_t batch_size = 100,
                             size_t thread_count = 0,
                             std::chrono::microseconds delay = std::chrono::microseconds(0));
    
    template<typename Container>
    void prepare_packets(Container& packets);
    
    template<typename PDU>
    void add_packet(PDU& pkt);
    
    void clear_packets();
    void send_all_single_thread();
    void send_all_multi_thread();
    void send_all();  
    
    
    template<typename Container>
    void send_all(Container& packets);
    
    
    size_t packet_count() { return packets_.size(); }
    size_t thread_count() { return thread_count_; }
    std::string& interface_name() { return interface_name_; }
    
    
    void set_batch_size(size_t batch_size) { batch_size_ = batch_size; }
    void set_thread_count(size_t thread_count);
    void set_delay_between_batches(std::chrono::microseconds delay) { delay_between_batches_ = delay; }
    void set_interface(const std::string& interface_name) { interface_name_ = interface_name; }
};


template<typename Container>
void FastPacketSender::prepare_packets(Container& packets) {
    packets_.clear();
    packets_.reserve(packets.size());
    
    for (auto& pkt : packets) {
        packets_.push_back(pkt);  
    }
}

template<typename PDU>
void FastPacketSender::add_packet(PDU& pkt) {
    packets_.push_back(pkt);
}


template<typename Container>
void FastPacketSender::send_all(Container& packets) {
    prepare_packets(packets);  
    send_all();                
}

#endif 
