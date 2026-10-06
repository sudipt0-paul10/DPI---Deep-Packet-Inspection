#include "load_balancer.h"
#include <iostream>
#include <chrono>

namespace DPI {

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(int lb_id,
                           std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                           int fp_start_id,
                           int total_workers)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(fp_queues.size()),
      total_workers_(total_workers),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      per_fp_counts_(num_fps_) {
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    
    std::cout << "[LB" << lb_id_ << "] Started (serving FP" 
              << fp_start_id_ << "-FP" << (fp_start_id_ + num_fps_ - 1) << ")\n";
}

void LoadBalancer::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[LB" << lb_id_ << "] Stopped\n";
}

void LoadBalancer::run() {
    while (running_) {
        // Get packet from input queue (with timeout to check running flag)
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            continue;  // Timeout or shutdown
        }
        
        packets_received_++;
        
        // Select target FP based on five-tuple hash
        int fp_index = selectFP(job_opt->tuple);
        
        // Push to selected FP's queue
        fp_queues_[fp_index]->push(std::move(*job_opt));
        
        packets_dispatched_++;
        per_fp_counts_[fp_index].fetch_add(1, std::memory_order_relaxed);
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    // Select from the global worker set first, then convert to this LB's
    // local FP index. This avoids the old two-level modulo collision where
    // hash % num_lbs and hash % fps_per_lb were correlated and could starve
    // workers (e.g. with 2 LBs x 2 FPs, only FP0 and FP3 were reachable).
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    const int global_worker = static_cast<int>(hash % static_cast<size_t>(total_workers_));
    return global_worker - fp_start_id_;
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    
    stats.per_fp_packets.reserve(per_fp_counts_.size());
    for (const auto& c : per_fp_counts_) {
        stats.per_fp_packets.push_back(c.load(std::memory_order_relaxed));
    }
    
    return stats;
}

// ============================================================================
// LBManager Implementation
// ============================================================================

LBManager::LBManager(int num_lbs, int fps_per_lb,
                     std::vector<ThreadSafeQueue<PacketJob>*> fp_queues)
    : fps_per_lb_(fps_per_lb) {
    
    // Create load balancers, each handling a subset of FPs
    for (int lb_id = 0; lb_id < num_lbs; lb_id++) {
        std::vector<ThreadSafeQueue<PacketJob>*> lb_fp_queues;
        int fp_start = lb_id * fps_per_lb;
        
        for (int i = 0; i < fps_per_lb; i++) {
            lb_fp_queues.push_back(fp_queues[fp_start + i]);
        }
        
        lbs_.push_back(std::make_unique<LoadBalancer>(lb_id, lb_fp_queues, fp_start,
                                                       num_lbs * fps_per_lb));
    }
    
    std::cout << "[LBManager] Created " << num_lbs << " load balancers, "
              << fps_per_lb << " FPs each\n";
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    // Map the flow onto one global worker, then select the LB owning that
    // worker's contiguous FP range. The selected LB will derive the same
    // global worker and choose the matching local FP queue.
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    const int total_workers = static_cast<int>(lbs_.size()) * fps_per_lb_;
    const int global_worker = static_cast<int>(hash % static_cast<size_t>(total_workers));
    const int lb_index = global_worker / fps_per_lb_;
    return *lbs_[lb_index];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    
    return stats;
}

} // namespace DPI
