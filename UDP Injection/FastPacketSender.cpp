#include "FastPacketSender.h"

FastPacketSender::FastPacketSender(const std::string& interface_name, 
                                   size_t batch_size,
                                   size_t thread_count,
                                   std::chrono::microseconds delay)
    : interface_name_(interface_name)
    , batch_size_(batch_size)
    , thread_count_(thread_count == 0 ? std::thread::hardware_concurrency() : thread_count)
    , delay_between_batches_(delay) {
    if (thread_count_ == 0) {
        thread_count_ = 1;
    }
}

void FastPacketSender::send_batch(size_t start_idx, size_t end_idx) {
    Tins::NetworkInterface iface(interface_name_);
    Tins::PacketSender sender;
    
    for (size_t i = start_idx; i < end_idx; ++i) {
        sender.send(packets_[i], iface);
        
        if (delay_between_batches_.count() > 0 && (i + 1) % batch_size_ == 0) {
            std::this_thread::sleep_for(delay_between_batches_);
        }
    }
}

void FastPacketSender::clear_packets() {
    packets_.clear();
}

void FastPacketSender::send_all_single_thread() {
    if (packets_.empty()) return;
    send_batch(0, packets_.size());
}

void FastPacketSender::send_all_multi_thread() {
    if (packets_.empty()) return;
    if (thread_count_ == 0) {
        thread_count_ = 1;
    }
    
    size_t total_packets = packets_.size();
    size_t packets_per_thread = total_packets / thread_count_;
    size_t remainder = total_packets % thread_count_;
    
    std::vector<std::thread> threads;
    threads.reserve(thread_count_);
    
    size_t current_start = 0;
    for (size_t i = 0; i < thread_count_; ++i) {
        size_t current_end = current_start + packets_per_thread;
        if (i == thread_count_ - 1) {
            current_end += remainder;
        }
        
        if (current_start < total_packets) {
            threads.emplace_back(&FastPacketSender::send_batch, this, 
                               current_start, current_end);
        }
        
        current_start = current_end;
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
}

void FastPacketSender::send_all() {
    if (packets_.size() < 1000 || thread_count_ == 1) {
        send_all_single_thread();
    } else {
        send_all_multi_thread();
    }
}

void FastPacketSender::set_thread_count(size_t thread_count) {
    thread_count_ = thread_count == 0 ? std::thread::hardware_concurrency() : thread_count;
    if (thread_count_ == 0) {
        thread_count_ = 1;
    }
}
