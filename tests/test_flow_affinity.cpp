// Tests for five-tuple identity, hashing, and the flow-affinity property the
// load balancer depends on.
//
// The dispatch rule under test is the one the engine actually implements:
//   LB  = hash(five_tuple) % num_lbs
//   FP  = hash(five_tuple) % fps_per_lb
// i.e. plain modulo hashing, not consistent hashing. What it buys us is flow
// affinity: the same 5-tuple always reaches the same worker, so per-flow state
// stays thread-local.
#include "test_support.h"
#include "types.h"

#include <vector>
#include <set>
#include <cstdint>

using namespace DPI;

namespace {

FiveTuple makeTuple(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp, uint8_t proto = 6) {
    FiveTuple t;
    t.src_ip = sip;
    t.dst_ip = dip;
    t.src_port = sp;
    t.dst_port = dp;
    t.protocol = proto;
    return t;
}

// Mirrors LoadBalancer::selectFP / LBManager::getLBForPacket.
int selectWorker(const FiveTuple& t, int num_workers) {
    return static_cast<int>(FiveTupleHash{}(t) % static_cast<size_t>(num_workers));
}

}  // namespace

int main() {
    std::cout << "flow_affinity\n";

    const FiveTuple a = makeTuple(0xC0A80164, 0x5DB8D822, 54321, 443);

    // --- Equality ----------------------------------------------------------
    {
        const FiveTuple same = makeTuple(0xC0A80164, 0x5DB8D822, 54321, 443);
        CHECK_MSG(a == same, "identical tuples compare equal");

        CHECK_MSG(!(a == makeTuple(0xC0A80165, 0x5DB8D822, 54321, 443)), "src_ip is significant");
        CHECK_MSG(!(a == makeTuple(0xC0A80164, 0x5DB8D823, 54321, 443)), "dst_ip is significant");
        CHECK_MSG(!(a == makeTuple(0xC0A80164, 0x5DB8D822, 54322, 443)), "src_port is significant");
        CHECK_MSG(!(a == makeTuple(0xC0A80164, 0x5DB8D822, 54321, 444)), "dst_port is significant");
        CHECK_MSG(!(a == makeTuple(0xC0A80164, 0x5DB8D822, 54321, 443, 17)),
                  "protocol is significant");
    }

    // --- Hash determinism --------------------------------------------------
    {
        FiveTupleHash h;
        const FiveTuple same = makeTuple(0xC0A80164, 0x5DB8D822, 54321, 443);
        CHECK_EQ_MSG(h(a), h(same), "equal tuples hash equally");

        bool stable = true;
        const size_t first = h(a);
        for (int i = 0; i < 1000; i++) {
            if (h(a) != first) stable = false;
        }
        CHECK_MSG(stable, "hash is stable across repeated calls");
    }

    // --- Flow affinity: the property the design actually relies on ----------
    {
        // Every packet of one flow must reach the same worker, for any pool size.
        bool affine = true;
        for (int workers = 1; workers <= 16; workers++) {
            const int expected = selectWorker(a, workers);
            for (int packet = 0; packet < 500; packet++) {
                if (selectWorker(a, workers) != expected) affine = false;
            }
        }
        CHECK_MSG(affine, "a flow maps to the same worker on every packet, for 1..16 workers");

        // The result is always a valid worker index.
        bool in_range = true;
        for (int workers = 1; workers <= 16; workers++) {
            for (uint16_t port = 1024; port < 1124; port++) {
                const int w = selectWorker(makeTuple(0xC0A80164, 0x5DB8D822, port, 443), workers);
                if (w < 0 || w >= workers) in_range = false;
            }
        }
        CHECK_MSG(in_range, "worker index always lies in [0, num_workers)");
    }

    // --- Direction sensitivity: a documented limitation, asserted here ------
    {
        // The hash combines src and dst asymmetrically, so the two directions of
        // one connection are distinct keys and may land on different workers.
        // This is why the engine does unidirectional flow tracking. If this ever
        // changes, this test should fail and the README should be updated.
        const FiveTuple reverse = a.reverse();
        CHECK_MSG(!(a == reverse), "forward and reverse tuples are different keys");
        CHECK_EQ_MSG(reverse.src_ip, a.dst_ip, "reverse() swaps addresses");
        CHECK_EQ_MSG(reverse.src_port, a.dst_port, "reverse() swaps ports");
        CHECK_EQ_MSG(reverse.protocol, a.protocol, "reverse() keeps the protocol");

        bool ever_differs = false;
        for (uint16_t port = 1024; port < 2048; port++) {
            const FiveTuple f = makeTuple(0xC0A80164, 0x5DB8D822, port, 443);
            if (selectWorker(f, 4) != selectWorker(f.reverse(), 4)) ever_differs = true;
        }
        CHECK_MSG(ever_differs,
                  "the two directions of a connection can map to different workers "
                  "(affinity is per unidirectional flow)");
    }

    // --- Distribution sanity ------------------------------------------------
    {
        // Not a quality-of-hash benchmark, just a check that dispatch is not
        // degenerate: 2000 distinct flows across 4 workers must use all 4.
        std::set<int> used;
        std::vector<int> counts(4, 0);
        for (uint16_t port = 1024; port < 3024; port++) {
            const int w = selectWorker(makeTuple(0xC0A80164, 0x5DB8D822, port, 443), 4);
            used.insert(w);
            counts[static_cast<size_t>(w)]++;
        }
        CHECK_EQ_MSG(used.size(), size_t{4}, "2000 distinct flows reach all 4 workers");

        bool none_starved = true;
        for (int c : counts) {
            if (c < 100) none_starved = false;  // deliberately loose
        }
        CHECK_MSG(none_starved, "no worker receives a negligible share of 2000 flows");
    }

    TEST_MAIN("flow_affinity");
}
