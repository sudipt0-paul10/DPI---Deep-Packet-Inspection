#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "types.h"
#include "thread_safe_queue.h"
#include <thread>
#include <vector>
#include <atomic>
#include <memory>

namespace DPI {

// ============================================================================
// Load Balancer Thread
// ============================================================================
//
// Architecture:
//   Reader Thread -> LB Queues -> LB Threads -> FP Queues -> FP Threads
//
// Each LB thread:
// 1. Receives packets from its input queue (fed by reader)
// 2. Extracts five-tuple from packet
// 3. Hashes the tuple to determine target FP
// 4. Forwards packet to appropriate FP queue
//
// Load Balancing Strategy:
// - 5-tuple hashing for flow affinity: hash(five_tuple) % total_workers
//   selects the global worker; this LB maps that worker to its local FP queue.
// - This keeps per-flow state thread-local, so the FP never needs a lock
//   to read or update it.
// - Note: the hash is direction-sensitive, so the two directions of one
//   connection may map to different FPs. Affinity is per unidirectional flow.
//
// Example with 2 LBs and 4 FPs:
//   global_worker = hash % 4
//   LB = global_worker / 2
//   FP = global_worker % 2
//
// ============================================================================

class LoadBalancer {
public:
    // Constructor
    // lb_id: ID of this load balancer (0, 1, ...)
    // fp_queues: Pointers to FP input queues that this LB serves
    // fp_start_id: Starting FP ID for this LB's pool
    LoadBalancer(int lb_id, 
                 std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                 int fp_start_id,
                 int total_workers);
    
    ~LoadBalancer();
    
    // Start the LB thread
    void start();
    
    // Stop the LB thread
    void stop();
    
    // Get input queue (for reader to push packets)
    ThreadSafeQueue<PacketJob>& getInputQueue() { return input_queue_; }
    
    // Get statistics
    struct LBStats {
        uint64_t packets_received;
        uint64_t packets_dispatched;
        std::vector<uint64_t> per_fp_packets;  // Packets sent to each FP
    };
    
    LBStats getStats() const;
    
    // Get LB ID
    int getId() const { return lb_id_; }
    
    // Check if running
    bool isRunning() const { return running_; }

private:
    int lb_id_;
    int fp_start_id_;
    int num_fps_;
    int total_workers_;
    
    // Input queue from reader
    ThreadSafeQueue<PacketJob> input_queue_;
    
    // Output queues to FP threads
    std::vector<ThreadSafeQueue<PacketJob>*> fp_queues_;
    
    // Statistics
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> packets_dispatched_{0};
    // Written by the LB thread, read by getStats() from other threads.
    std::vector<std::atomic<uint64_t>> per_fp_counts_;
    
    // Thread control
    std::atomic<bool> running_{false};
    std::thread thread_;
    
    // Main processing loop
    void run();
    
    // Determine target FP for a packet based on five-tuple hash
    int selectFP(const FiveTuple& tuple);
};

// ============================================================================
// LB Manager - Creates and manages multiple LB threads
// ============================================================================
class LBManager {
public:
    // Create LB manager
    // num_lbs: Number of load balancer threads
    // fps_per_lb: Number of FP threads per LB
    // fp_queues: Raw pointers to FP input queues
    LBManager(int num_lbs, int fps_per_lb,
              std::vector<ThreadSafeQueue<PacketJob>*> fp_queues);
    
    ~LBManager();
    
    // Start all LB threads
    void startAll();
    
    // Stop all LB threads
    void stopAll();
    
    // Get LB for a given packet (based on hash)
    LoadBalancer& getLBForPacket(const FiveTuple& tuple);
    
    // Get specific LB
    LoadBalancer& getLB(int id) { return *lbs_[id]; }
    
    // Get number of LBs
    int getNumLBs() const { return lbs_.size(); }
    
    // Get aggregated stats
    struct AggregatedStats {
        uint64_t total_received;
        uint64_t total_dispatched;
    };
    
    AggregatedStats getAggregatedStats() const;

private:
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    int fps_per_lb_;
};

} // namespace DPI

#endif // LOAD_BALANCER_H
