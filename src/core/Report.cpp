#include "core/Report.h"
#include "core/Checks.h"

#include <algorithm>
#include <cstdio>

namespace dbench {

namespace {

std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buffer[8];
                std::snprintf(buffer, sizeof(buffer), "\\u%04X", static_cast<unsigned>(static_cast<unsigned char>(c)));
                out += buffer;
            } else {
                out += c;
            }
        }
    }
    return out;
}

} // namespace

std::size_t detectedCount(const std::vector<CheckResult>& results) {
    return static_cast<std::size_t>(std::count_if(results.begin(), results.end(), [](const CheckResult& r) { return r.detected; }));
}

std::string formatTable(const std::vector<CheckResult>& results) {
    std::size_t idWidth = 0;
    for (const auto& r : results) {
        idWidth = std::max(idWidth, r.id.size());
    }

    const std::string resultLabel = "DETECTED"; // the widest status word
    const std::size_t statusWidth = resultLabel.size();

    std::string out;
    for (CheckClass cls : allClasses()) {
        bool wroteHeader = false;
        for (const auto& r : results) {
            if (r.cls != cls) {
                continue;
            }
            if (!wroteHeader) {
                out += std::string(className(cls));
                out += "\n";
                wroteHeader = true;
            }
            std::string status = r.detected ? resultLabel : "clean";
            status.resize(statusWidth, ' ');
            std::string id = r.id;
            id.resize(std::max(idWidth, id.size()), ' ');
            out += "  " + status + "  " + id + "  " + r.detail + "\n";
        }
        if (wroteHeader) {
            out += "\n";
        }
    }

    const std::size_t fired = detectedCount(results);
    out += std::to_string(fired) + " of " + std::to_string(results.size()) + " checks fired.\n";
    return out;
}

std::string formatJson(const std::vector<CheckResult>& results) {
    std::string out = "[\n";
    for (std::size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        out += "  {\n";
        out += "    \"id\": \"" + jsonEscape(r.id) + "\",\n";
        out += "    \"name\": \"" + jsonEscape(r.name) + "\",\n";
        out += "    \"class\": \"" + std::string(className(r.cls)) + "\",\n";
        out += std::string("    \"detected\": ") + (r.detected ? "true" : "false") + ",\n";
        out += "    \"detail\": \"" + jsonEscape(r.detail) + "\",\n";
        out += "    \"explanation\": \"" + jsonEscape(r.explanation) + "\"\n";
        out += "  }";
        out += (i + 1 < results.size()) ? ",\n" : "\n";
    }
    out += "]\n";
    return out;
}

} // namespace dbench
