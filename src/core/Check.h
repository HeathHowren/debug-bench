#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace dbench {

// The class a check belongs to. Checks are grouped by class in the table, and
// --only takes one of these names.
enum class CheckClass {
    Api,         // documented Win32 / Nt query functions
    Peb,         // fields read straight out of the Process Environment Block
    Exception,   // deliberately raised exceptions a debugger tends to swallow
    Timing,      // wall-clock or cycle-count gaps left by stepping or breaking
    Context,     // the debug registers and thread flags in the thread CONTEXT
    Environment, // what is around the process: parent, windows, modules, host
};

// The lowercase name used in the table and accepted by --only.
[[nodiscard]] std::string_view className(CheckClass cls);

// Parse a --only argument. Returns false if the name is not a known class.
[[nodiscard]] bool parseClass(std::string_view name, CheckClass& out);

// Every class in table order.
[[nodiscard]] const std::vector<CheckClass>& allClasses();

// The outcome of running one check: whether it fired, and a short line of
// evidence (the raw value it read, so the reader can see why).
struct Outcome {
    bool detected = false;
    std::string detail;
};

// The result the tool reports for one check. Its shape is the {id, name, class,
// detected, detail} contract in the README plus the explanation, so --json and
// the table are built from the same record.
struct CheckResult {
    std::string id;
    std::string name;
    CheckClass cls = CheckClass::Api;
    bool detected = false;
    std::string detail;
    std::string explanation; // what it detects, its false positives, how it is neutralized
};

} // namespace dbench
