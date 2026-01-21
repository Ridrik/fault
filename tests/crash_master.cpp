#include "fault/attributes.h"

#include <csignal>
#define BOOST_TEST_MODULE ProcessCrashTests
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/readable_pipe.hpp>
#include <boost/exception/detail/type_info.hpp>
#include <boost/process.hpp>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/stdio.hpp>
#include <boost/test/included/unit_test.hpp>
#include <boost/test/tools/old/interface.hpp>
#include <fault/fault.hpp>

namespace {

#ifndef CRASH_TARGET_PATH
#define CRASH_TARGET_PATH "crash_target"
#endif

#ifndef CRASH_REPORT_DIR
#define CRASH_REPORT_DIR "crash"
#endif

enum class AbstractFault : std::uint8_t {
    kSegmentationFault,
    kOverflow,
    kStdTerminate,
    kPanic,
    kAssertionFailure,
    kAbort
};

[[nodiscard]] std::string_view faultToStr(AbstractFault fault) {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
            return "Segmentation Fault";
        case AbstractFault::kOverflow:
            return "Overflow";
        case AbstractFault::kStdTerminate:
            return "std::terminate";
        case AbstractFault::kPanic:
            return "Panic";
        case AbstractFault::kAssertionFailure:
            return "Assertion Failure";
        case AbstractFault::kAbort:
            return "Abort";
    }
    FAULT_UNREACHABLE();
}

[[nodiscard]] std::string formatVector(const std::vector<std::string>& v) {
    std::string result = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        result += std::format("{}", v[i]);
        if (i + 1 < v.size()) {
            result += ", ";
        }
    }
    result += "]";
    return result;
}

struct TestCase {
    std::vector<std::string> args;

    AbstractFault fault;
    std::function<bool(const std::string&)> evalStderrOverride{nullptr};

    [[nodiscard]] std::string print() const {
        return std::format("Test: injecting fault '{}', with args '{}'", faultToStr(fault),
                           formatVector(args));
    }
};

struct ProcessFixture {
    boost::asio::io_context ctx;
    boost::filesystem::path exePath;

    ProcessFixture() : exePath{CRASH_TARGET_PATH} {
        ProcessFixture::removeLogs();
        // boost::process::environment::find_executable(CRASH_TARGET_PATH);
        if (exePath.empty()) {
            BOOST_FAIL("Could not find executable: " << CRASH_TARGET_PATH);
        }
    }
    ProcessFixture(const ProcessFixture&) = delete;
    ProcessFixture& operator=(const ProcessFixture&) = delete;
    ProcessFixture(ProcessFixture&&) = delete;
    ProcessFixture& operator=(ProcessFixture&&) = delete;
    ~ProcessFixture() {
        ProcessFixture::removeLogs();
    }

    static void removeLogs() {
        try {
            if (boost::filesystem::exists(CRASH_REPORT_DIR)) {
                boost::filesystem::remove_all(CRASH_REPORT_DIR);
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to clean up crash subdirectory: " << e.what() << '\n';
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(CrashTestSuite, ProcessFixture)

[[nodiscard]] bool checkCommonErrMessage(std::string_view s) {
#if defined(__linux__)
    static constexpr std::array<std::string_view, 7> kExpectedKeywords{
        {"FAULT REPORT", fault::kDefaultErrorMessage, "Fault Date", "Fault Time", "Unix Epoch",
         "Uptime", "FAULT END"}};
#elif defined(_WIN32)
    static constexpr std::array<std::string_view, 8> kExpectedKeywords{
        {"FAULT REPORT", fault::kDefaultErrorMessage, "Description: ", "Fault Date", "Fault Time",
         "Unix Epoch", "Uptime", "FAULT END"}};
#endif
    return std::ranges::all_of(kExpectedKeywords, [&s](const auto& keyword) {
        return s.find(keyword) != std::string_view::npos;
    });
}

#if defined(__linux__)

constexpr auto kFaultToKeyword = [](AbstractFault fault) -> std::vector<std::string_view> {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
        case AbstractFault::kOverflow:
            return {"Signal Event: SIGSEGV", "Reason: ", "Fault address: "};
        case AbstractFault::kStdTerminate:
            return {"Terminate"};
        case AbstractFault::kPanic:
            return {};
        case AbstractFault::kAssertionFailure:
            return {"Assertion failed"};
        case AbstractFault::kAbort:
            return {"Signal Event: SIGABRT", "Reason: SIGNAL_UNKNOWN", "Fault address: "};
    }
    FAULT_UNREACHABLE();
};

[[nodiscard]] bool checkErrMsgPosix(std::string_view s, AbstractFault fault) noexcept {
    const auto keywords = kFaultToKeyword(fault);
    return std::ranges::all_of(
        keywords, [s](const auto& keyword) { return s.find(keyword) != std::string_view::npos; });
}

[[nodiscard]] int faultToCodePosix(AbstractFault fault, bool withReRaise = true) noexcept {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
        case AbstractFault::kOverflow:
            return SIGSEGV + (withReRaise ? 0 : 128);
        case AbstractFault::kAbort:
        case AbstractFault::kStdTerminate:
        case AbstractFault::kAssertionFailure:
        case AbstractFault::kPanic:
            return SIGABRT + (withReRaise ? 0 : 128);
    }
}

#elif defined(_WIN32)
constexpr auto kCodeToStr = [](DWORD code) -> std::string_view {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
            return "Access Violation (Segmentation Fault)";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            return "Array Index Out of Bounds";
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            return "Datatype Misalignment";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            return "Division by Zero";
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            return "Illegal Instruction";
        case EXCEPTION_IN_PAGE_ERROR:
            return "In-Page Error (Disk/Memory Issue)";
        case EXCEPTION_STACK_OVERFLOW:
            return "Stack Overflow";
        case EXCEPTION_PRIV_INSTRUCTION:
            return "Private Instruction";
        default:
            return "Unknown Fatal Error";
    }
    FAULT_UNREACHABLE();
};

constexpr auto kFaultToKeyword = [](AbstractFault fault) -> std::vector<std::string_view> {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
            return {kCodeToStr(EXCEPTION_ACCESS_VIOLATION)};
        case AbstractFault::kOverflow:
            return {kCodeToStr(EXCEPTION_STACK_OVERFLOW)};
        case AbstractFault::kStdTerminate:
            return {"Terminate"};
        case AbstractFault::kPanic:
            return {};
        case AbstractFault::kAssertionFailure:
            return {"Assertion failed"};
        case AbstractFault::kAbort:
            return {"Abort called"};
    }
    FAULT_UNREACHABLE();
};

[[nodiscard]] bool checkErrMsgWin(std::string_view s, AbstractFault fault) noexcept {
    const auto keywords = kFaultToKeyword(fault);
    return std::ranges::all_of(
        keywords, [s](const auto& keyword) { return s.find(keyword) != std::string_view::npos; });
}

[[nodiscard]] int faultToCodeWin(AbstractFault fault) noexcept {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
            return static_cast<int>(EXCEPTION_ACCESS_VIOLATION);
        case AbstractFault::kOverflow:
            return static_cast<int>(EXCEPTION_STACK_OVERFLOW);
        case AbstractFault::kStdTerminate:
        case AbstractFault::kPanic:
        case AbstractFault::kAssertionFailure:
        case AbstractFault::kAbort:
            return 3;
    }
    FAULT_UNREACHABLE();
}

#endif

[[nodiscard]] bool checkErrMsg(std::string_view s, AbstractFault fault) noexcept {
#if defined(_WIN32)
    return checkErrMsgWin(s, fault);
#else
    return checkErrMsgPosix(s, fault);
#endif
}

[[nodiscard]] int faultToCode(AbstractFault fault, bool withReRaise = true) noexcept {
#if defined(_WIN32)
    return faultToCodeWin(fault);
#else
    return faultToCodePosix(fault, withReRaise);
#endif
}

BOOST_AUTO_TEST_CASE(ExecuteTestCases) {
    try {
        const std::vector<TestCase> testCases = {
            {.args = {"--mode", "segfault"}, .fault = AbstractFault::kSegmentationFault},
            {.args = {"--mode", "overflow"}, .fault = AbstractFault::kOverflow},
            {.args = {"--mode", "throw"}, .fault = AbstractFault::kStdTerminate},
            {.args = {"--mode", "terminate"}, .fault = AbstractFault::kStdTerminate},
            {.args = {"--mode", "abort"}, .fault = AbstractFault::kAbort},
            {.args = {"--mode", "panic"}, .fault = AbstractFault::kPanic},
            {.args = {"--mode", "panic", "--message", "This shouldn't have happened"},
             .fault = AbstractFault::kPanic,
             .evalStderrOverride =
                 [](const std::string& err) {
                     return err.find("This shouldn't have happened") != std::string::npos;
                 }},
            {.args = {"--mode", "assertion_failure"}, .fault = AbstractFault::kAssertionFailure},
            {.args = {"--mode", "try_catch_panic", "--message", "A runtime error has occured"},
             .fault = AbstractFault::kPanic,
             .evalStderrOverride = [](const std::string& err) {
                 return err.find("A runtime error has occured") != std::string::npos;
             }}};

        for (const auto& test : testCases) {
            BOOST_TEST_CONTEXT(test.print()) {
                boost::asio::readable_pipe errPipe{ctx};
                std::string errData;
                std::string buffer;
                buffer.resize(4096);

                auto proc = boost::process::process{
                    ctx, exePath, test.args,
                    boost::process::process_stdio{.in = nullptr, .out = {}, .err = errPipe}};

                const std::function<void(boost::system::error_code, std::size_t)> do_read =
                    [&](boost::system::error_code ec, std::size_t len) {
                        if (!ec) {
                            errData.append(buffer.data(), len);
                            errPipe.async_read_some(boost::asio::buffer(buffer), do_read);
                        }
                    };
                errPipe.async_read_some(boost::asio::buffer(buffer), do_read);

                bool timedOut = false;
                boost::asio::steady_timer timer(ctx, std::chrono::seconds(5));
                timer.async_wait([&](const boost::system::error_code& ec) {
                    if (!ec) {
                        timedOut = true;
                        proc.terminate();
                    }
                });

                int exitCode{-1};
                proc.async_wait([&](boost::system::error_code ec, int native_exit_code) {
                    timer.cancel();
                    errPipe.close();  // Stop the reading loop
                    exitCode = native_exit_code;
                });

                // Run the context for this specific iteration
                ctx.run();
                ctx.restart();

                // 5. Boost.Test Assertions (Replaces manual asserts)
                BOOST_CHECK_MESSAGE(!timedOut, "Process timed out after 5 seconds");

#ifdef _WIN32
                BOOST_CHECK_EQUAL(static_cast<unsigned int>(exitCode),
                                  static_cast<unsigned int>(faultToCode(test.fault)));
#else
                BOOST_CHECK_EQUAL(exitCode, faultToCode(test.fault));
#endif
                if (!checkCommonErrMessage(errData)) {
                    BOOST_FAIL("stderr common evaluation failed. Captured " << errData);
                }
                if (!checkErrMsg(errData, test.fault)) {
                    BOOST_FAIL("stderr fault evaluation failed. Captured: " << errData);
                }
                if (test.evalStderrOverride != nullptr) {
                    BOOST_CHECK_MESSAGE(test.evalStderrOverride(errData),
                                        "stderr override evaluation failed. Captured: " << errData);
                }
            }
        }
    } catch (const std::exception& e) {
        BOOST_FAIL(std::format("Exception caught: {}", e.what()));
    } catch (...) {
        BOOST_FAIL("Internal Error");
    }
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace