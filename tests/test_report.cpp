#include "FakeProbe.h"

#include "core/Checks.h"
#include "core/Report.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace dbench;
using dbench::test::FakeProbe;

namespace {
bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}
} // namespace

TEST_CASE("the table groups by class, marks results and ends with a summary", "[report]") {
    const std::string text = formatTable(runAll(FakeProbe::debuggerPresent()));

    // A header line for each class, in table order.
    CHECK(contains(text, "api\n"));
    CHECK(contains(text, "peb\n"));
    CHECK(contains(text, "exception\n"));
    CHECK(contains(text, "timing\n"));
    CHECK(contains(text, "context\n"));
    CHECK(contains(text, "environment\n"));

    // The status word and an id and its detail on one row.
    CHECK(contains(text, "DETECTED  api.isdebuggerpresent"));
    CHECK(contains(text, "IsDebuggerPresent() = TRUE"));

    // The summary counts every check.
    CHECK(contains(text, std::to_string(catalog().size()) + " of " + std::to_string(catalog().size()) + " checks fired."));
}

TEST_CASE("a clean run marks rows clean and reports zero fired", "[report]") {
    const std::string text = formatTable(runAll(FakeProbe::clean()));
    CHECK(contains(text, "clean"));
    CHECK_FALSE(contains(text, "DETECTED"));
    CHECK(contains(text, "0 of " + std::to_string(catalog().size()) + " checks fired."));
}

TEST_CASE("ids line up under a class in the table", "[report]") {
    const std::vector<CheckResult> results = runAll(FakeProbe::clean(), CheckClass::Api);
    const std::string text = formatTable(results);
    // Every id is padded to the same width, so the detail columns align. Find
    // the two-space gap that follows the widest id.
    std::size_t widest = 0;
    for (const auto& r : results) {
        widest = std::max(widest, r.id.size());
    }
    CHECK(contains(text, "api.isdebuggerpresent" + std::string(widest - std::string("api.isdebuggerpresent").size(), ' ') + "  "));
}

TEST_CASE("json emits one object per check with the contract fields", "[report]") {
    const std::string json = formatJson(runAll(FakeProbe::debuggerPresent()));

    CHECK(json.front() == '[');
    CHECK(contains(json, "\"id\": \"api.isdebuggerpresent\""));
    CHECK(contains(json, "\"name\": \"IsDebuggerPresent\""));
    CHECK(contains(json, "\"class\": \"api\""));
    CHECK(contains(json, "\"detected\": true"));
    CHECK(contains(json, "\"detail\":"));
    CHECK(contains(json, "\"explanation\":"));

    // One object per check, counted by the "id" field.
    std::size_t objects = 0;
    for (std::size_t at = json.find("\"id\":"); at != std::string::npos; at = json.find("\"id\":", at + 1)) {
        ++objects;
    }
    CHECK(objects == catalog().size());
}

TEST_CASE("json escapes quotes and backslashes", "[report]") {
    CheckResult r;
    r.id = "escape.test";
    r.name = "Escaper";
    r.cls = CheckClass::Environment;
    r.detected = false;
    r.detail = "path c:\\temp and a \"quote\"";
    r.explanation = "n/a";
    const std::string json = formatJson({r});
    CHECK(contains(json, "c:\\\\temp"));
    CHECK(contains(json, "\\\"quote\\\""));
}

TEST_CASE("detectedCount matches the fired rows", "[report]") {
    CHECK(detectedCount(runAll(FakeProbe::clean())) == 0);
    CHECK(detectedCount(runAll(FakeProbe::debuggerPresent())) == catalog().size());
}
