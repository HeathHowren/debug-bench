#include "core/Checks.h"
#include "core/Cli.h"
#include "core/LiveProbe.h"
#include "core/Report.h"

#include "Version.h"

#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    const dbench::CliOptions options = dbench::parseCli(args);

    if (options.error) {
        std::fprintf(stderr, "error: %s\n\n%s", options.error->c_str(), dbench::usageText().c_str());
        return 2;
    }
    if (options.help) {
        std::fputs(dbench::usageText().c_str(), stdout);
        return 0;
    }
    if (options.version) {
        std::printf("debug-bench %s\n", DBENCH_VERSION_STRING);
        return 0;
    }

    const dbench::LiveProbe probe;
    unsigned cycle = 0;
    do {
        const std::vector<dbench::CheckResult> results = dbench::runAll(probe, options.onlyClass);
        const std::string text = options.json ? dbench::formatJson(results) : dbench::formatTable(results);
        if (options.loop && !options.json) {
            std::printf("== debug-bench %s  cycle %u ==\n", DBENCH_VERSION_STRING, cycle++);
        }
        std::fputs(text.c_str(), stdout);
        std::fflush(stdout);
        if (options.loop) {
            std::fputc('\n', stdout);
            Sleep(options.loopMs);
        }
    } while (options.loop);

    return 0;
}
