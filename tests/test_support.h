// Minimal assertion helpers.
//
// The project deliberately has no external dependencies, so the tests do not
// pull in a framework either. Each test file is its own executable; CTest
// reports one pass/fail per file based on the exit code.
#ifndef DPI_TEST_SUPPORT_H
#define DPI_TEST_SUPPORT_H

#include <iostream>
#include <string>
#include <cstdlib>

namespace dpitest {

inline int& failures() {
    static int count = 0;
    return count;
}

inline void report(bool ok, const std::string& what, const std::string& file, int line) {
    if (ok) {
        std::cout << "  [ok]   " << what << "\n";
    } else {
        std::cout << "  [FAIL] " << what << "\n"
                  << "         at " << file << ":" << line << "\n";
        ++failures();
    }
}

template <typename A, typename B>
void reportEq(const A& actual, const B& expected, const std::string& what,
              const std::string& file, int line) {
    if (actual == expected) {
        std::cout << "  [ok]   " << what << "\n";
    } else {
        std::cout << "  [FAIL] " << what << "\n"
                  << "         expected: " << expected << "\n"
                  << "         actual:   " << actual << "\n"
                  << "         at " << file << ":" << line << "\n";
        ++failures();
    }
}

inline int summarize(const std::string& suite) {
    if (failures() == 0) {
        std::cout << suite << ": all checks passed\n";
        return EXIT_SUCCESS;
    }
    std::cout << suite << ": " << failures() << " check(s) FAILED\n";
    return EXIT_FAILURE;
}

}  // namespace dpitest

#define CHECK(cond) ::dpitest::report((cond), #cond, __FILE__, __LINE__)
#define CHECK_MSG(cond, msg) ::dpitest::report((cond), (msg), __FILE__, __LINE__)
#define CHECK_EQ(actual, expected) \
    ::dpitest::reportEq((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
#define CHECK_EQ_MSG(actual, expected, msg) \
    ::dpitest::reportEq((actual), (expected), (msg), __FILE__, __LINE__)
#define TEST_MAIN(suite) return ::dpitest::summarize(suite)

#endif  // DPI_TEST_SUPPORT_H
