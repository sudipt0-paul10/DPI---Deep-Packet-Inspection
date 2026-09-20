// Tests for rule storage, matching, and rule-file parsing.
#include "test_support.h"
#include "rule_manager.h"
#include "types.h"

#include <fstream>
#include <cstdio>
#include <string>

using namespace DPI;

namespace {

void writeFile(const std::string& path, const std::string& contents) {
    std::ofstream f(path, std::ios::binary);
    f << contents;
}

}  // namespace

int main() {
    std::cout << "rule_manager\n";

    // --- IP rules ----------------------------------------------------------
    {
        RuleManager rm;
        rm.blockIP(std::string("192.168.1.50"));
        CHECK_MSG(rm.isIPBlocked(rm.parseIP("192.168.1.50")), "blocked IP matches");
        CHECK_MSG(!rm.isIPBlocked(rm.parseIP("192.168.1.51")), "other IP does not match");

        rm.unblockIP(std::string("192.168.1.50"));
        CHECK_MSG(!rm.isIPBlocked(rm.parseIP("192.168.1.50")), "unblocked IP no longer matches");
    }

    // --- Application rules -------------------------------------------------
    {
        RuleManager rm;
        rm.blockApp(AppType::YOUTUBE);
        CHECK_MSG(rm.isAppBlocked(AppType::YOUTUBE), "blocked app matches");
        CHECK_MSG(!rm.isAppBlocked(AppType::GITHUB), "other app does not match");

        rm.unblockApp(AppType::YOUTUBE);
        CHECK_MSG(!rm.isAppBlocked(AppType::YOUTUBE), "unblocked app no longer matches");
    }

    // --- Domain rules ------------------------------------------------------
    {
        RuleManager rm;

        // A bare domain is an EXACT match only.
        rm.blockDomain("facebook.com");
        CHECK_MSG(rm.isDomainBlocked("facebook.com"), "bare rule matches the exact domain");
        CHECK_MSG(!rm.isDomainBlocked("www.facebook.com"),
                  "bare rule does NOT match subdomains (wildcard required)");
        CHECK_MSG(!rm.isDomainBlocked("example.com"), "unrelated domain does not match");

        // Subdomains require an explicit wildcard.
        RuleManager wild;
        wild.blockDomain("*.tiktok.com");
        CHECK_MSG(wild.isDomainBlocked("www.tiktok.com"), "wildcard matches a subdomain");
        CHECK_MSG(wild.isDomainBlocked("cdn.eu.tiktok.com"), "wildcard matches a deep subdomain");
        CHECK_MSG(wild.isDomainBlocked("tiktok.com"), "wildcard also matches the bare domain");
        CHECK_MSG(wild.isDomainBlocked("WWW.TIKTOK.COM"), "wildcard matching is case-insensitive");
        CHECK_MSG(!wild.isDomainBlocked("nottiktok.com"),
                  "wildcard does not match an unrelated domain with the same suffix text");
    }

    // --- Port rules --------------------------------------------------------
    {
        RuleManager rm;
        rm.blockPort(8080);
        CHECK_MSG(rm.isPortBlocked(8080), "blocked port matches");
        CHECK_MSG(!rm.isPortBlocked(443), "other port does not match");
    }

    // --- shouldBlock combines the rule types -------------------------------
    {
        RuleManager rm;
        rm.blockApp(AppType::YOUTUBE);
        rm.blockDomain("*.facebook.com");
        rm.blockPort(8080);
        rm.blockIP(std::string("10.0.0.7"));

        CHECK_MSG(!rm.shouldBlock(rm.parseIP("10.0.0.1"), 443, AppType::GITHUB, "github.com")
                       .has_value(),
                  "traffic matching no rule is allowed");
        CHECK_MSG(rm.shouldBlock(rm.parseIP("10.0.0.7"), 443, AppType::GITHUB, "github.com")
                      .has_value(),
                  "blocked source IP is caught");
        CHECK_MSG(rm.shouldBlock(rm.parseIP("10.0.0.1"), 8080, AppType::GITHUB, "github.com")
                      .has_value(),
                  "blocked port is caught");
        CHECK_MSG(rm.shouldBlock(rm.parseIP("10.0.0.1"), 443, AppType::YOUTUBE, "youtube.com")
                      .has_value(),
                  "blocked application is caught");
        CHECK_MSG(rm.shouldBlock(rm.parseIP("10.0.0.1"), 443, AppType::UNKNOWN,
                                 "www.facebook.com")
                      .has_value(),
                  "blocked domain is caught");
    }

    // --- Rule file: valid --------------------------------------------------
    {
        const std::string path = "test_rules_valid.conf";
        writeFile(path,
                  "# a comment line\n"
                  "\n"
                  "[BLOCKED_APPS]\n"
                  "YouTube\n"
                  "  Facebook  \n"          // surrounding whitespace
                  "\n"
                  "[BLOCKED_DOMAINS]\n"
                  "*.tiktok.com   # trailing comment\n"
                  "\n"
                  "[BLOCKED_PORTS]\n"
                  "8080\n"
                  "[BLOCKED_IPS]\n"
                  "192.168.1.50\n");

        RuleManager rm;
        CHECK_MSG(rm.loadRules(path), "loads a well-formed rule file");
        CHECK_MSG(rm.isAppBlocked(AppType::YOUTUBE), "file: YouTube blocked");
        CHECK_MSG(rm.isAppBlocked(AppType::FACEBOOK), "file: whitespace-padded entry parsed");
        CHECK_MSG(rm.isDomainBlocked("www.tiktok.com"), "file: trailing comment stripped");
        CHECK_MSG(rm.isPortBlocked(8080), "file: port parsed");
        CHECK_MSG(rm.isIPBlocked(rm.parseIP("192.168.1.50")), "file: IP parsed");
        std::remove(path.c_str());
    }

    // --- Rule file: malformed input must not throw or abort -----------------
    {
        const std::string path = "test_rules_bad.conf";
        writeFile(path,
                  "[BLOCKED_PORTS]\n"
                  "not-a-number\n"          // std::stoi would throw
                  "99999\n"                 // out of range for a port
                  "-1\n"
                  "\n"
                  "[BLOCKED_APPS]\n"
                  "NoSuchApplication\n"     // unknown app name
                  "\n"
                  "[UNKNOWN_SECTION]\n"
                  "whatever\n"
                  "\n"
                  "orphan entry with no section\n"
                  "\n"
                  "[BLOCKED_PORTS]\n"
                  "443\n");                 // the one good rule

        RuleManager rm;
        CHECK_MSG(rm.loadRules(path), "malformed rule file still loads without throwing");
        CHECK_MSG(rm.isPortBlocked(443), "valid rule after bad ones is still applied");
        CHECK_MSG(!rm.isPortBlocked(0), "invalid port entries were skipped");
        std::remove(path.c_str());
    }

    // --- Rule file: missing ------------------------------------------------
    {
        RuleManager rm;
        CHECK_MSG(!rm.loadRules("this_file_does_not_exist.conf"),
                  "missing rule file reports failure");
    }

    // --- Round trip --------------------------------------------------------
    {
        const std::string path = "test_rules_roundtrip.conf";
        RuleManager writer;
        writer.blockApp(AppType::NETFLIX);
        writer.blockDomain("example.com");
        writer.blockPort(1234);
        CHECK_MSG(writer.saveRules(path), "saves rules to file");

        RuleManager reader;
        CHECK_MSG(reader.loadRules(path), "reloads saved rules");
        CHECK_MSG(reader.isAppBlocked(AppType::NETFLIX), "round trip: app preserved");
        CHECK_MSG(reader.isDomainBlocked("example.com"), "round trip: domain preserved");
        CHECK_MSG(reader.isPortBlocked(1234), "round trip: port preserved");
        std::remove(path.c_str());
    }

    TEST_MAIN("rule_manager");
}
