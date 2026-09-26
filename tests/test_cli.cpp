#include "core/Checks.h"
#include "core/Cli.h"

#include <catch2/catch_test_macros.hpp>

using namespace dbench;

TEST_CASE("no arguments is the default table run", "[cli]") {
    const CliOptions o = parseCli({});
    CHECK_FALSE(o.error.has_value());
    CHECK_FALSE(o.json);
    CHECK_FALSE(o.loop);
    CHECK_FALSE(o.help);
    CHECK_FALSE(o.onlyClass.has_value());
}

TEST_CASE("the --json flag is recognized", "[cli]") {
    const CliOptions o = parseCli({"--json"});
    CHECK(o.json);
    CHECK_FALSE(o.error.has_value());
}

TEST_CASE("the --loop interval is optional", "[cli]") {
    const CliOptions bare = parseCli({"--loop"});
    CHECK(bare.loop);
    CHECK(bare.loopMs == 1000);

    const CliOptions withMs = parseCli({"--loop", "250"});
    CHECK(withMs.loop);
    CHECK(withMs.loopMs == 250);

    // A non-numeric token after --loop is not consumed, so --loop --json works.
    const CliOptions withFlag = parseCli({"--loop", "--json"});
    CHECK(withFlag.loop);
    CHECK(withFlag.loopMs == 1000);
    CHECK(withFlag.json);
}

TEST_CASE("a zero --loop interval is rejected", "[cli]") {
    const CliOptions o = parseCli({"--loop", "0"});
    // "0" is numeric, so it is consumed and then rejected as out of range.
    REQUIRE(o.error.has_value());
}

TEST_CASE("the --only flag takes a class name", "[cli]") {
    const CliOptions api = parseCli({"--only", "api"});
    REQUIRE(api.onlyClass.has_value());
    CHECK(*api.onlyClass == CheckClass::Api);

    const CliOptions env = parseCli({"--only", "environment"});
    REQUIRE(env.onlyClass.has_value());
    CHECK(*env.onlyClass == CheckClass::Environment);
}

TEST_CASE("a missing or unknown --only class is rejected", "[cli]") {
    CHECK(parseCli({"--only"}).error.has_value());
    CHECK(parseCli({"--only", "nonsense"}).error.has_value());
}

TEST_CASE("help and version are recognized", "[cli]") {
    CHECK(parseCli({"--help"}).help);
    CHECK(parseCli({"-h"}).help);
    CHECK(parseCli({"--version"}).version);
}

TEST_CASE("an unknown argument is an error", "[cli]") {
    const CliOptions o = parseCli({"--wat"});
    REQUIRE(o.error.has_value());
    CHECK(o.error->find("--wat") != std::string::npos);
}

TEST_CASE("flags combine", "[cli]") {
    const CliOptions o = parseCli({"--json", "--only", "timing", "--loop", "500"});
    CHECK(o.json);
    CHECK(o.loop);
    CHECK(o.loopMs == 500);
    REQUIRE(o.onlyClass.has_value());
    CHECK(*o.onlyClass == CheckClass::Timing);
    CHECK_FALSE(o.error.has_value());
}

TEST_CASE("usage text names every class and option", "[cli]") {
    const std::string usage = usageText();
    CHECK(usage.find("--json") != std::string::npos);
    CHECK(usage.find("--loop") != std::string::npos);
    CHECK(usage.find("--only") != std::string::npos);
    for (CheckClass cls : allClasses()) {
        CHECK(usage.find(std::string(className(cls))) != std::string::npos);
    }
}
