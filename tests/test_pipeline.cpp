// End-to-end test of the multithreaded engine.
//
// This drives the real DPIEngine over the sample capture: reader thread,
// load-balancer threads, fast-path workers, and the output writer. It checks
// that classification works, that rules actually drop packets, that the output
// PCAP is well-formed, and -- importantly -- that the drain barrier loses
// nothing on shutdown.
//
// The capture path is passed in as argv[1] by CTest.
#include "test_support.h"
#include "dpi_engine.h"
#include "pcap_reader.h"

#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>

using namespace DPI;

namespace {

struct PcapSummary {
    bool readable = false;
    size_t packets = 0;
    uint32_t linktype = 0;
};

PcapSummary summarize(const std::string& path) {
    PcapSummary s;
    PacketAnalyzer::PcapReader reader;
    if (!reader.open(path)) return s;
    s.readable = true;
    s.linktype = reader.getGlobalHeader().network;
    PacketAnalyzer::RawPacket raw;
    while (reader.readNextPacket(raw)) s.packets++;
    reader.close();
    return s;
}

DPIEngine::Config config(int lbs, int fps) {
    DPIEngine::Config c;
    c.num_load_balancers = lbs;
    c.fps_per_lb = fps;
    return c;
}

}  // namespace

int main(int argc, char** argv) {
    std::cout << "pipeline (end-to-end)\n";

    if (argc < 2) {
        std::cerr << "usage: test_pipeline <input.pcap>\n";
        return EXIT_FAILURE;
    }
    const std::string input = argv[1];

    const PcapSummary in = summarize(input);
    CHECK_MSG(in.readable, "sample capture is readable: " + input);
    if (!in.readable) TEST_MAIN("pipeline");
    CHECK_MSG(in.packets > 0, "sample capture contains packets");
    CHECK_EQ_MSG(in.linktype, 1u, "sample capture is Ethernet (linktype 1)");

    // --- Baseline: no rules, nothing should be dropped ----------------------
    uint64_t baseline_forwarded = 0;
    uint64_t baseline_total = 0;
    {
        const std::string out = "pipeline_baseline.pcap";
        DPIEngine engine(config(2, 2));
        CHECK_MSG(engine.processFile(input, out), "engine processes the capture");

        const auto& st = engine.getStats();
        baseline_total = st.total_packets.load();
        baseline_forwarded = st.forwarded_packets.load();

        CHECK_MSG(baseline_total > 0, "engine counted TCP/UDP packets");
        CHECK_EQ_MSG(st.dropped_packets.load(), uint64_t{0}, "no rules -> nothing dropped");
        CHECK_EQ_MSG(baseline_forwarded, baseline_total,
                     "no rules -> every counted packet is forwarded");
        CHECK_MSG(st.tcp_packets.load() > 0, "capture contained TCP");
        CHECK_MSG(st.udp_packets.load() > 0, "capture contained UDP");
        CHECK_EQ_MSG(st.tcp_packets.load() + st.udp_packets.load(), baseline_total,
                     "TCP + UDP accounts for every counted packet");

        // The drain barrier must leave nothing behind.
        const PcapSummary o = summarize(out);
        CHECK_MSG(o.readable, "output PCAP is readable");
        CHECK_EQ_MSG(o.packets, baseline_forwarded,
                     "every forwarded packet reached the output file (drain is complete)");
        CHECK_EQ_MSG(o.linktype, in.linktype, "output preserves the input link type");
        std::remove(out.c_str());
    }

    // --- Classification: the capture contains known SNIs --------------------
    {
        const std::string out = "pipeline_classify.pcap";
        DPIEngine engine(config(2, 2));
        engine.processFile(input, out);

        const std::string report = engine.generateClassificationReport();
        CHECK_MSG(!report.empty(), "classification report is produced");
        CHECK_MSG(report.find("YouTube") != std::string::npos,
                  "TLS SNI classification identified YouTube traffic");
        CHECK_MSG(report.find("Google") != std::string::npos,
                  "TLS SNI classification identified Google traffic");
        CHECK_MSG(report.find("GitHub") != std::string::npos,
                  "TLS SNI classification identified GitHub traffic");
        CHECK_MSG(report.find("DNS") != std::string::npos,
                  "DNS traffic was classified");
        std::remove(out.c_str());
    }

    // --- Blocking by application actually drops packets ---------------------
    {
        const std::string out = "pipeline_block_app.pcap";
        DPIEngine engine(config(2, 2));
        engine.blockApp(std::string("YouTube"));
        engine.processFile(input, out);

        const auto& st = engine.getStats();
        CHECK_MSG(st.dropped_packets.load() > 0, "blocking YouTube drops packets");
        CHECK_MSG(st.forwarded_packets.load() < baseline_forwarded,
                  "fewer packets forwarded than the unfiltered baseline");
        CHECK_EQ_MSG(st.forwarded_packets.load() + st.dropped_packets.load(),
                     st.total_packets.load(),
                     "forwarded + dropped accounts for every packet");

        const PcapSummary o = summarize(out);
        CHECK_MSG(o.readable, "filtered output PCAP is readable");
        CHECK_EQ_MSG(o.packets, st.forwarded_packets.load(),
                     "filtered output contains exactly the forwarded packets");
        CHECK_MSG(o.packets < in.packets, "filtered output is smaller than the input");
        std::remove(out.c_str());
    }

    // --- Blocking by domain -------------------------------------------------
    {
        const std::string out = "pipeline_block_domain.pcap";
        DPIEngine engine(config(2, 2));
        engine.blockDomain("*.facebook.com");
        engine.processFile(input, out);

        CHECK_MSG(engine.getStats().dropped_packets.load() > 0,
                  "blocking *.facebook.com drops packets");
        std::remove(out.c_str());
    }

    // --- Thread-count independence -----------------------------------------
    {
        // Flow affinity means results must not depend on how many workers run.
        // Packet *order* in the output may differ; the counts must not.
        const std::vector<std::pair<int, int>> shapes{{1, 1}, {2, 2}, {4, 4}};
        bool consistent = true;
        for (const auto& shape : shapes) {
            const std::string out = "pipeline_threads.pcap";
            DPIEngine engine(config(shape.first, shape.second));
            engine.processFile(input, out);

            const auto& st = engine.getStats();
            if (st.total_packets.load() != baseline_total) consistent = false;
            if (st.forwarded_packets.load() != baseline_forwarded) consistent = false;
            if (summarize(out).packets != baseline_forwarded) consistent = false;
            std::remove(out.c_str());
        }
        CHECK_MSG(consistent,
                  "packet counts are identical for 1x1, 2x2 and 4x4 worker layouts");
    }

    TEST_MAIN("pipeline");
}
