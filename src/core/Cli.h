#pragma once

#include "core/Check.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dbench {

// The parsed command line. Pure data, so parsing is a pure function the tests
// drive with argument vectors.
struct CliOptions {
    bool json = false;                     // --json
    bool loop = false;                     // --loop
    std::uint32_t loopMs = 1000;           // --loop [ms], default one second
    std::optional<CheckClass> onlyClass;   // --only <class>
    bool help = false;                     // --help / -h
    bool version = false;                  // --version
    std::optional<std::string> error;      // set when the command line is malformed
};

// Parse argv (without argv[0]). On a bad argument, error is set and the rest of
// the fields are left at their defaults.
[[nodiscard]] CliOptions parseCli(const std::vector<std::string>& args);

// The usage text, printed for --help and for a parse error.
[[nodiscard]] std::string usageText();

} // namespace dbench
