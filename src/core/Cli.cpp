#include "core/Cli.h"
#include "core/Checks.h"

#include <charconv>

namespace dbench {

CliOptions parseCli(const std::vector<std::string>& args) {
    CliOptions options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--json") {
            options.json = true;
        } else if (arg == "--help" || arg == "-h" || arg == "/?") {
            options.help = true;
        } else if (arg == "--version") {
            options.version = true;
        } else if (arg == "--loop") {
            options.loop = true;
            // An optional milliseconds value may follow. Only consume the next
            // argument when it is all digits, so "--loop --json" still works.
            if (i + 1 < args.size()) {
                const std::string& next = args[i + 1];
                if (!next.empty() && next.find_first_not_of("0123456789") == std::string::npos) {
                    std::uint32_t value = 0;
                    const auto* first = next.data();
                    const auto* last = next.data() + next.size();
                    if (std::from_chars(first, last, value).ec == std::errc{} && value > 0) {
                        options.loopMs = value;
                    } else {
                        options.error = "loop interval out of range: " + next;
                        return options;
                    }
                    ++i;
                }
            }
        } else if (arg == "--only") {
            if (i + 1 >= args.size()) {
                options.error = "--only needs a class name";
                return options;
            }
            CheckClass cls{};
            if (!parseClass(args[i + 1], cls)) {
                options.error = "unknown class: " + args[i + 1];
                return options;
            }
            options.onlyClass = cls;
            ++i;
        } else {
            options.error = "unknown argument: " + arg;
            return options;
        }
    }
    return options;
}

std::string usageText() {
    return "debug-bench - anti-debug and anti-injection self-test\n"
           "\n"
           "Runs the standard catalog of debugger and injection checks against\n"
           "this process and reports which ones fire.\n"
           "\n"
           "Usage:\n"
           "  debug-bench [options]\n"
           "\n"
           "Options:\n"
           "  --json            emit the results as a JSON array\n"
           "  --loop [ms]       re-run every ms (default 1000) so you can attach\n"
           "                    a debugger and watch checks flip; Ctrl+C to stop\n"
           "  --only <class>    run only one class: api, peb, exception, timing,\n"
           "                    context, environment\n"
           "  --version         print the version and exit\n"
           "  -h, --help        print this help and exit\n";
}

} // namespace dbench
