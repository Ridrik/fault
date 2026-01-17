#include "fault/attributes.h"
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

struct TestCase {
    std::string arg;

    AbstractFault fault;
    std::function<bool(const std::string&)> evalStderrOverride{nullptr};

    [[nodiscard]] std::string print() const {
        return std::format("Test: injecting fault '{}', with arg '{}'", faultToStr(fault), arg);
    }
};

struct ProcessFixture {
    boost::asio::io_context ctx;
    boost::filesystem::path exePath;

    ProcessFixture() {
        ProcessFixture::removeLogs();
        exePath = boost::process::environment::find_executable(CRASH_TARGET_PATH);
        if (exePath.empty()) {
            BOOST_FAIL("Could not find executable: " << CRASH_TARGET_PATH);
        }
    }
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
    static constexpr std::array<std::string_view, 8> kExpectedKeywords{
        {"FAULT REPORT", fault::kDefaultErrorMessage, "Description: ", "Fault Date", "Fault Time",
         "Unix Epoch", "Uptime", "FAULT END"}};
    return std::ranges::all_of(kExpectedKeywords, [&s](const auto& keyword) {
        return s.find(keyword) != std::string_view::npos;
    });
}

#if defined(_WIN32)
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

#else

[[nodiscard]] bool checkErrMsgPosix(std::string_view s, AbstractFault fault) noexcept {
    return true;
}

[[nodiscard]] int faultToCodePosix(AbstractFault fault) noexcept {
    switch (fault) {
        case AbstractFault::kSegmentationFault:
            return 139;
    }
}

#endif

[[nodiscard]] bool checkErrMsg(std::string_view s, AbstractFault fault) noexcept {
#if defined(_WIN32)
    return checkErrMsgWin(s, fault);
#else
    return checkErrMsgPosix(s, fault);
#endif
}

[[nodiscard]] int faultToCode(AbstractFault fault) noexcept {
#if defined(_WIN32)
    return faultToCodeWin(fault);
#else
    return faultToCodePosix(fault);
#endif
}

BOOST_AUTO_TEST_CASE(ExecuteTestCases) {
    try {
        const std::vector<TestCase> testCases = {
            {.arg = "segfault", .fault = AbstractFault::kSegmentationFault},
            {.arg = "overflow", .fault = AbstractFault::kOverflow},
            {.arg = "throw", .fault = AbstractFault::kStdTerminate},
            {.arg = "terminate", .fault = AbstractFault::kStdTerminate},
            {.arg = "abort", .fault = AbstractFault::kAbort},
            {.arg = "panic", .fault = AbstractFault::kPanic},
            {.arg = "assertion_failure", .fault = AbstractFault::kAssertionFailure}};

        for (const auto& test : testCases) {
            BOOST_TEST_CONTEXT(test.print()) {
                boost::asio::readable_pipe errPipe{ctx};
                std::string errData;
                std::string buffer;
                buffer.resize(4096);

                boost::process::process proc(
                    ctx, exePath, {"--mode", test.arg},
                    boost::process::process_stdio{.in = nullptr, .out = {}, .err = errPipe});

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
                BOOST_CHECK_EQUAL(exitCode, test.expectedCode);
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