// Tests for the Ethernet / IPv4 / TCP / UDP parser.
#include "test_support.h"
#include "packet_parser.h"

#include <vector>
#include <cstdint>

using namespace PacketAnalyzer;

namespace {

// Build an Ethernet + IPv4 + TCP/UDP frame with the given payload.
std::vector<uint8_t> buildFrame(uint8_t protocol,
                                uint16_t src_port,
                                uint16_t dst_port,
                                const std::vector<uint8_t>& payload,
                                uint8_t tcp_flags = 0x18) {
    std::vector<uint8_t> f;

    // Ethernet: dst MAC, src MAC, EtherType 0x0800 (IPv4)
    for (int i = 0; i < 6; i++) f.push_back(0xAA);
    for (int i = 0; i < 6; i++) f.push_back(0xBB);
    f.push_back(0x08);
    f.push_back(0x00);

    // IPv4 header (20 bytes, IHL = 5)
    const size_t ip_start = f.size();
    f.push_back(0x45);                 // version 4, IHL 5
    f.push_back(0x00);                 // DSCP/ECN
    f.push_back(0x00); f.push_back(0x00);  // total length (patched below)
    f.push_back(0x00); f.push_back(0x00);  // identification
    f.push_back(0x40); f.push_back(0x00);  // flags/fragment
    f.push_back(64);                   // TTL
    f.push_back(protocol);             // protocol
    f.push_back(0x00); f.push_back(0x00);  // checksum (not verified by parser)
    // src 192.168.1.100
    f.push_back(192); f.push_back(168); f.push_back(1); f.push_back(100);
    // dst 93.184.216.34
    f.push_back(93); f.push_back(184); f.push_back(216); f.push_back(34);

    // Transport header
    if (protocol == Protocol::TCP) {
        f.push_back(static_cast<uint8_t>(src_port >> 8));
        f.push_back(static_cast<uint8_t>(src_port & 0xFF));
        f.push_back(static_cast<uint8_t>(dst_port >> 8));
        f.push_back(static_cast<uint8_t>(dst_port & 0xFF));
        for (int i = 0; i < 4; i++) f.push_back(0x00);  // seq
        for (int i = 0; i < 4; i++) f.push_back(0x00);  // ack
        f.push_back(0x50);       // data offset 5 (20 bytes), reserved
        f.push_back(tcp_flags);  // flags
        f.push_back(0xFF); f.push_back(0xFF);  // window
        f.push_back(0x00); f.push_back(0x00);  // checksum
        f.push_back(0x00); f.push_back(0x00);  // urgent pointer
    } else {
        f.push_back(static_cast<uint8_t>(src_port >> 8));
        f.push_back(static_cast<uint8_t>(src_port & 0xFF));
        f.push_back(static_cast<uint8_t>(dst_port >> 8));
        f.push_back(static_cast<uint8_t>(dst_port & 0xFF));
        f.push_back(0x00); f.push_back(0x00);  // length
        f.push_back(0x00); f.push_back(0x00);  // checksum
    }

    f.insert(f.end(), payload.begin(), payload.end());

    // Patch IPv4 total length
    const uint16_t ip_total = static_cast<uint16_t>(f.size() - ip_start);
    f[ip_start + 2] = static_cast<uint8_t>(ip_total >> 8);
    f[ip_start + 3] = static_cast<uint8_t>(ip_total & 0xFF);
    return f;
}

RawPacket wrap(std::vector<uint8_t> data) {
    RawPacket raw;
    raw.header.ts_sec = 1700000000;
    raw.header.ts_usec = 123456;
    raw.header.incl_len = static_cast<uint32_t>(data.size());
    raw.header.orig_len = static_cast<uint32_t>(data.size());
    raw.data = std::move(data);
    return raw;
}

}  // namespace

int main() {
    std::cout << "packet_parser\n";

    // --- TCP ---------------------------------------------------------------
    {
        const std::vector<uint8_t> payload{'h', 'e', 'l', 'l', 'o'};
        RawPacket raw = wrap(buildFrame(Protocol::TCP, 54321, 443, payload));
        ParsedPacket p;

        CHECK(PacketParser::parse(raw, p));
        CHECK_EQ_MSG(p.ether_type, EtherType::IPv4, "TCP: EtherType is IPv4");
        CHECK_MSG(p.has_ip, "TCP: IP layer parsed");
        CHECK_MSG(p.has_tcp, "TCP: TCP layer parsed");
        CHECK_MSG(!p.has_udp, "TCP: UDP not flagged");
        CHECK_EQ_MSG(p.src_ip, std::string("192.168.1.100"), "TCP: source IP");
        CHECK_EQ_MSG(p.dest_ip, std::string("93.184.216.34"), "TCP: dest IP");
        CHECK_EQ_MSG(p.src_port, 54321, "TCP: source port");
        CHECK_EQ_MSG(p.dest_port, 443, "TCP: dest port");
        CHECK_EQ_MSG(p.ttl, 64, "TCP: TTL");
        CHECK_EQ_MSG(p.payload_length, payload.size(), "TCP: payload length");
        CHECK_MSG(p.payload_data != nullptr && p.payload_data[0] == 'h',
                  "TCP: payload points at the payload bytes");
        CHECK_EQ_MSG(p.timestamp_sec, 1700000000u, "TCP: timestamp preserved");
    }

    // --- TCP flags ---------------------------------------------------------
    {
        RawPacket raw = wrap(buildFrame(Protocol::TCP, 1234, 80, {}, TCPFlags::SYN));
        ParsedPacket p;
        CHECK(PacketParser::parse(raw, p));
        CHECK_MSG((p.tcp_flags & TCPFlags::SYN) != 0, "flags: SYN decoded");
        CHECK_MSG((p.tcp_flags & TCPFlags::ACK) == 0, "flags: ACK absent");
        CHECK_EQ_MSG(PacketParser::tcpFlagsToString(TCPFlags::SYN | TCPFlags::ACK),
                     std::string("SYN ACK"), "flags: rendered as text");
    }

    // --- UDP ---------------------------------------------------------------
    {
        const std::vector<uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF};
        RawPacket raw = wrap(buildFrame(Protocol::UDP, 5353, 53, payload));
        ParsedPacket p;

        CHECK(PacketParser::parse(raw, p));
        CHECK_MSG(p.has_udp, "UDP: UDP layer parsed");
        CHECK_MSG(!p.has_tcp, "UDP: TCP not flagged");
        CHECK_EQ_MSG(p.dest_port, 53, "UDP: dest port");
        CHECK_EQ_MSG(p.payload_length, payload.size(), "UDP: payload length");
    }

    // --- Malformed / truncated input must be rejected, not crash ------------
    {
        ParsedPacket p;

        CHECK_MSG(!PacketParser::parse(wrap({}), p), "reject: empty frame");
        CHECK_MSG(!PacketParser::parse(wrap(std::vector<uint8_t>(13, 0)), p),
                  "reject: frame shorter than an Ethernet header");

        // Valid Ethernet header, but the IPv4 header is cut short.
        std::vector<uint8_t> short_ip = buildFrame(Protocol::TCP, 1, 2, {});
        short_ip.resize(14 + 10);
        CHECK_MSG(!PacketParser::parse(wrap(short_ip), p), "reject: truncated IPv4 header");

        // Valid IPv4 header, but the TCP header is cut short.
        std::vector<uint8_t> short_tcp = buildFrame(Protocol::TCP, 1, 2, {});
        short_tcp.resize(14 + 20 + 10);
        CHECK_MSG(!PacketParser::parse(wrap(short_tcp), p), "reject: truncated TCP header");

        // Non-IPv4 EtherType (ARP) parses the Ethernet layer but sets no IP.
        std::vector<uint8_t> arp = buildFrame(Protocol::TCP, 1, 2, {});
        arp[12] = 0x08; arp[13] = 0x06;
        ParsedPacket a;
        CHECK_MSG(PacketParser::parse(wrap(arp), a), "accept: ARP frame parses Ethernet");
        CHECK_MSG(!a.has_ip, "ARP: no IP layer claimed");

        // IPv6 EtherType is likewise not treated as IPv4.
        std::vector<uint8_t> v6 = buildFrame(Protocol::TCP, 1, 2, {});
        v6[12] = 0x86; v6[13] = 0xDD;
        ParsedPacket six;
        CHECK_MSG(PacketParser::parse(wrap(v6), six), "accept: IPv6 frame parses Ethernet");
        CHECK_MSG(!six.has_ip, "IPv6: not parsed as IPv4 (documented limitation)");

        // An IPv4 header claiming IHL < 5 is invalid.
        std::vector<uint8_t> bad_ihl = buildFrame(Protocol::TCP, 1, 2, {});
        bad_ihl[14] = 0x44;  // version 4, IHL 4 -> 16 bytes, below the minimum
        CHECK_MSG(!PacketParser::parse(wrap(bad_ihl), p), "reject: IPv4 IHL below minimum");
    }

    TEST_MAIN("packet_parser");
}
