#pragma once

#include "core/Check.h"

#include <string>
#include <vector>

namespace dbench {

// The default output: an aligned table, grouped by class, with a one-line
// summary of how many checks fired. Lines are separated by "\n".
[[nodiscard]] std::string formatTable(const std::vector<CheckResult>& results);

// The --json output: a JSON array of {id, name, class, detected, detail,
// explanation}, one object per check. Values are escaped.
[[nodiscard]] std::string formatJson(const std::vector<CheckResult>& results);

// How many of the results fired.
[[nodiscard]] std::size_t detectedCount(const std::vector<CheckResult>& results);

} // namespace dbench
