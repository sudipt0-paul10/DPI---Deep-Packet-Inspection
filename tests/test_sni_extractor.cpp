// Tests for TLS ClientHello SNI extraction, HTTP Host extraction and DNS
// query-name extraction, plus the SNI -> application mapping.
#include "test_support.h"
#include "sni_extractor.h"
#include "types.h"

#include <vector>
#include <string>
#include <cstdint>

using namespace DPI;

namespace {

void push16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

// Build a TLS record containing a ClientHello whose SNI extension carries
// `hostname`. Layout follows RFC 8446 / RFC 6066.
std::vector<uint8_t> buildClientHello(const std::string& hostname,
                                      bool include_sni = true) {
    // --- SNI extension body ---
    std::vector<uint8_t> sni_ext;
    push16(sni_ext, static_cast<uint16_t>(hostname.size() + 3));  // server name list length
    sni_ext.push_back(0x00);                                      // name type: host_name
    push16(sni_ext, static_cast<uint16_t>(hostname.size()));      // name length
    sni_ext.insert(sni_ext.end(), hostname.begin(), hostname.end());

    // --- extensions block ---
    std::vector<uint8_t> exts;
    // A decoy extension first, so the parser has to walk past one.
    push16(exts, 0x000B);            // ec_point_formats
    push16(exts, 2);
    exts.push_back(0x01);
    exts.push_back(0x00);
    if (include_sni) {
        push16(exts, 0x0000);        // server_name
        push16(exts, static_cast<uint16_t>(sni_ext.size()));
        exts.insert(exts.end(), sni_ext.begin(), sni_ext.end());
    }

    // --- ClientHello body ---
    std::vector<uint8_t> body;
    push16(body, 0x0303);                        // client version TLS 1.2
    for (int i = 0; i < 32; i++) body.push_back(static_cast<uint8_t>(i));  // random
    body.push_back(0x00);                        // session id length
    push16(body, 2);                             // cipher suites length
    push16(body, 0x1301);                        // one cipher suite
    body.push_back(0x01);                        // compression methods length
    body.push_back(0x00);                        // null compression
    push16(body, static_cast<uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    // --- handshake header ---
    std::vector<uint8_t> hs;
    hs.push_back(0x01);                                            // ClientHello
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    // --- TLS record header ---
    std::vector<uint8_t> rec;
    rec.push_back(0x16);            // handshake
    push16(rec, 0x0301);            // record version
    push16(rec, static_cast<uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

}  // namespace

int main() {
    std::cout << "sni_extractor\n";

    // --- TLS SNI happy path ------------------------------------------------
    {
        for (const std::string& host : {std::string("www.google.com"),
                                        std::string("github.com"),
                                        std::string("a.b.c.d.example.co.uk")}) {
            const auto ch = buildClientHello(host);
            CHECK_MSG(SNIExtractor::isTLSClientHello(ch.data(), ch.size()),
                      "recognises ClientHello for " + host);
            const auto sni = SNIExtractor::extract(ch.data(), ch.size());
            CHECK_MSG(sni.has_value(), "extracts SNI for " + host);
            if (sni) CHECK_EQ_MSG(*sni, host, "SNI value for " + host);
        }
    }

    // --- ClientHello with no SNI extension ---------------------------------
    {
        const auto ch = buildClientHello("ignored.example", /*include_sni=*/false);
        CHECK_MSG(!SNIExtractor::extract(ch.data(), ch.size()).has_value(),
                  "no SNI extension -> no value");
    }

    // --- Non-TLS and malformed input must be rejected safely ---------------
    {
        const auto http = bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        CHECK_MSG(!SNIExtractor::isTLSClientHello(http.data(), http.size()),
                  "HTTP request is not a ClientHello");
        CHECK_MSG(!SNIExtractor::extract(http.data(), http.size()).has_value(),
                  "HTTP request yields no SNI");

        const std::vector<uint8_t> empty;
        CHECK_MSG(!SNIExtractor::extract(empty.data(), 0).has_value(),
                  "empty payload yields no SNI");

        // Application data record, not a handshake.
        const std::vector<uint8_t> appdata{0x17, 0x03, 0x03, 0x00, 0x10, 0x01, 0, 0, 0, 0};
        CHECK_MSG(!SNIExtractor::extract(appdata.data(), appdata.size()).has_value(),
                  "TLS application data yields no SNI");

        // ServerHello (handshake type 0x02) is not a ClientHello.
        auto sh = buildClientHello("example.com");
        sh[5] = 0x02;
        CHECK_MSG(!SNIExtractor::extract(sh.data(), sh.size()).has_value(),
                  "ServerHello yields no SNI");

        // Truncate a valid ClientHello at every length: none may crash.
        const auto full = buildClientHello("www.example.com");
        for (size_t n = 0; n < full.size(); n++) {
            (void)SNIExtractor::extract(full.data(), n);
        }
        CHECK_MSG(true, "every truncation of a ClientHello is handled without crashing");
    }

    // --- HTTP Host ---------------------------------------------------------
    {
        const auto req = bytes("GET /index.html HTTP/1.1\r\n"
                               "User-Agent: test\r\n"
                               "Host: example.com\r\n\r\n");
        const auto host = HTTPHostExtractor::extract(req.data(), req.size());
        CHECK_MSG(host.has_value(), "extracts HTTP Host header");
        if (host) CHECK_EQ_MSG(*host, std::string("example.com"), "HTTP Host value");

        const auto lower = bytes("POST /x HTTP/1.1\r\nhost: httpbin.org:8080\r\n\r\n");
        const auto h2 = HTTPHostExtractor::extract(lower.data(), lower.size());
        CHECK_MSG(h2.has_value(), "Host header match is case-insensitive");
        if (h2) CHECK_EQ_MSG(*h2, std::string("httpbin.org"), "port stripped from Host");

        const auto notreq = bytes("random bytes that are not an HTTP request");
        CHECK_MSG(!HTTPHostExtractor::extract(notreq.data(), notreq.size()).has_value(),
                  "non-HTTP payload yields no Host");
    }

    // --- DNS ---------------------------------------------------------------
    {
        std::vector<uint8_t> q{0x12, 0x34,              // transaction id
                               0x01, 0x00,              // flags: standard query
                               0x00, 0x01,              // QDCOUNT = 1
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        for (const std::string& label : {std::string("www"), std::string("example"),
                                         std::string("com")}) {
            q.push_back(static_cast<uint8_t>(label.size()));
            q.insert(q.end(), label.begin(), label.end());
        }
        q.push_back(0x00);
        push16(q, 0x0001);  // QTYPE A
        push16(q, 0x0001);  // QCLASS IN

        const auto name = DNSExtractor::extractQuery(q.data(), q.size());
        CHECK_MSG(name.has_value(), "extracts DNS query name");
        if (name) CHECK_EQ_MSG(*name, std::string("www.example.com"), "DNS query name");

        // A response (QR bit set) is not a query.
        auto resp = q;
        resp[2] = 0x81;
        CHECK_MSG(!DNSExtractor::extractQuery(resp.data(), resp.size()).has_value(),
                  "DNS response is not treated as a query");
    }

    // --- SNI -> application mapping ----------------------------------------
    {
        CHECK_EQ_MSG(appTypeToString(sniToAppType("www.youtube.com")), appTypeToString(AppType::YOUTUBE), "youtube.com -> YouTube");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("r1---sn-abc.googlevideo.com")), appTypeToString(AppType::YOUTUBE),
                     "googlevideo.com -> YouTube, not Google");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("yt3.ggpht.com")), appTypeToString(AppType::YOUTUBE),
                     "yt3.ggpht.com -> YouTube, not Google");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("www.google.com")), appTypeToString(AppType::GOOGLE), "google.com -> Google");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("fonts.gstatic.com")), appTypeToString(AppType::GOOGLE), "gstatic -> Google");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("WWW.FACEBOOK.COM")), appTypeToString(AppType::FACEBOOK),
                     "matching is case-insensitive");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("github.com")), appTypeToString(AppType::GITHUB), "github.com -> GitHub");
        // A ClientHello we cannot attribute to a known application is still
        // known to be HTTPS -- that is the documented fallback, not UNKNOWN.
        CHECK_EQ_MSG(appTypeToString(sniToAppType("no-such-domain.invalid")),
                     appTypeToString(AppType::HTTPS),
                     "unrecognised SNI falls back to HTTPS");
        CHECK_EQ_MSG(appTypeToString(sniToAppType("")), appTypeToString(AppType::UNKNOWN), "empty SNI -> UNKNOWN");
    }

    TEST_MAIN("sni_extractor");
}
