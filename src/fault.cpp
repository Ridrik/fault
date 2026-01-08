#include "fault/fault.hpp"

#include "fault/fault.h"

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <pthread.h>
#include <source_location>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <utility>

#include <cpptrace/basic.hpp>
#include <cpptrace/cpptrace.hpp>
#include <cpptrace/forward.hpp>
#include <cpptrace/from_current.hpp>
#include <cpptrace/utils.hpp>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <windows.h>
// clang-format on
#include <consoleapi.h>
#include <errhandlingapi.h>
#include <excpt.h>
#include <handleapi.h>
#include <processthreadsapi.h>
#include <strsafe.h>
#include <synchapi.h>
#else
#include <cstdio>
#include <fcntl.h>

#include <sys/ucontext.h>
#include <sys/wait.h>
#endif

namespace fault {

namespace {

static_assert(std::atomic<int>::is_always_lock_free,
              "std::atomic<int> may not be lock free. Use volatile std::sig_atomic_t "
              "instead.");

#define FORCE_INLINE inline __attribute__((always_inline))

namespace utils {

inline std::string_view getSafeView(const char* ptr) noexcept {
    if (ptr == nullptr) {
        return "";
    }
    return std::string_view{ptr};
}

ObjectTrace fromCppTrace(const cpptrace::object_trace& cppTrace) {
    ObjectTrace trace;
    trace.frames.reserve(cppTrace.frames.size());
    for (const auto& cppFrame : cppTrace.frames) {
        trace.frames.push_back(Frame{.rawAddress = cppFrame.raw_address,
                                     .objAddress = cppFrame.object_address,
                                     .objPath = cppFrame.object_path});
    }
    return trace;
}

cpptrace::object_trace toCppTrace(const ObjectTrace& trace) {
    cpptrace::object_trace cppTrace;
    cppTrace.frames.reserve(trace.frames.size());
    for (const auto& frame : trace.frames) {
        cppTrace.frames.push_back(cpptrace::object_frame{.raw_address = frame.rawAddress,
                                                         .object_address = frame.objAddress,
                                                         .object_path = frame.objPath});
    }
    return cppTrace;
}

constexpr const char* const kHexChars = "0123456789abcdef";

void safeWriteHex(std::uintptr_t value, std::array<char, 19>& buf) noexcept {
    buf[0] = '0';
    buf[1] = 'x';
    for (int i{0}; i < 16; ++i) {
        buf[17 - i] = kHexChars[(value >> (i * 4)) & 0xF];
    }
    buf[18] = '\0';
}

constexpr void safeAppend(char* buffer, std::size_t& offset, std::size_t capacity,
                          const char* str) noexcept {
    if (str == nullptr) {
        return;
    }
    while (*str != '\0' && offset < capacity - 1) {
        buffer[offset++] = *str++;
    }
    buffer[offset] = '\0';
}

constexpr void safeAppend(char* buffer, std::size_t& offset, std::size_t capacity, const char* str,
                          std::size_t length) noexcept {
    if (str == nullptr) {
        return;
    }
    std::size_t appended{0};
    while (appended++ < length && offset < capacity - 1) {
        buffer[offset++] = *str++;
    }
    buffer[offset] = '\0';
}

void itoaSafeAppend(char* buffer, std::size_t& offset, std::size_t capacity,
                    std::uint64_t value) noexcept {
    if (offset >= capacity - 1) {
        return;
    }
    if (value == 0) {
        buffer[offset++] = '0';
        buffer[offset] = '\0';
        return;
    }
    std::size_t len{0};
    for (std::uint64_t temp = value; temp > 0; temp /= 10) {
        len++;
    }
    if (offset + len >= capacity - 1) {
        return;
    }
    for (std::size_t i = len; i > 0; --i) {
        buffer[offset + i - 1] = static_cast<char>(value % 10 + '0');
        value /= 10;
    }
    offset += len;
    buffer[offset] = '\0';
}

void fmt2d(char* buf, std::uint32_t val) {
    buf[0] = static_cast<char>((val / 10) + '0');
    buf[1] = static_cast<char>((val % 10) + '0');
}

void getNowSafe(std::int64_t& outSec, std::int64_t& outNsec) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Windows Epoch (1601) to Unix Epoch (1970) offset
    constexpr std::uint64_t kUnixOffset{11644473600ULL};
    outSec = static_cast<std::int64_t>((uli.QuadPart / 10000000ULL) - kUnixOffset);
    outNsec = static_cast<std::int64_t>(((uli.QuadPart % 10000000ULL) * 100));
#else
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    outSec = ts.tv_sec;
    outNsec = ts.tv_nsec;
#endif
}

#if defined(__linux__)

inline void safePrint(const char* str, std::size_t len, int fd = STDERR_FILENO) noexcept {
    write(fd, str, len);
}

inline void safePrint(const char* str, int fd = STDERR_FILENO) noexcept {
    write(fd, str, std::strlen(str));
}

void safeWriteHex(std::uintptr_t value, int fd = STDERR_FILENO) noexcept {
    std::array<char, 18> buf{};  // "0x" + 16 chars
    buf[0] = '0';
    buf[1] = 'x';
    for (int i{0}; i < 16; ++i) {
        buf[17 - i] = kHexChars[(value >> (i * 4)) & 0xF];
    }
    safePrint(buf.data(), buf.size(), fd);
}

#else

const HANDLE hFileDefault = GetStdHandle(STD_ERROR_HANDLE);

inline void safePrint(const char* str, std::size_t len, HANDLE hFile = hFileDefault) noexcept {
    if (str == nullptr) {
        return;
    }
    DWORD written{};
    WriteFile(hFile, str, static_cast<DWORD>(len), &written, nullptr);
}

inline void safePrint(const char* str, HANDLE hFile = hFileDefault) noexcept {
    if (str == nullptr) {
        return;
    }
    DWORD written{};
    // We use strlen here; it is safe as it only reads memory
    WriteFile(hFile, str, static_cast<DWORD>(std::strlen(str)), &written, nullptr);
}

inline bool utf8ToUtf16Stack(const char* utf8, wchar_t* out, int outLen) noexcept {
    const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out, outLen);
    return written > 0;
}

void safeWriteHex(std::uintptr_t value, HANDLE hFile = hFileDefault) noexcept {
    std::array<char, 18> buf{};
    buf[0] = '0';
    buf[1] = 'x';
    for (int i{0}; i < 16; ++i) {
        buf[17 - i] = kHexChars[(value >> (i * 4)) & 0xF];
    }
    safePrint(buf.data(), buf.size(), hFile);
}

#endif

void writePreciseTimeSafe(char* buffer, std::size_t& offset, std::size_t capacity,
                          const char* initDateStr, std::int64_t initSecondsSinceEpoch,
                          std::int64_t initNanoSecondsSinceEpoch) {
    std::int64_t tvSec{};
    std::int64_t tvNSec{};
    getNowSafe(tvSec, tvNSec);
    std::array<char, 12> tempBuf{};
    const auto daysSinceEpoch = static_cast<std::int64_t>(tvSec / 86400);
    auto s = static_cast<std::uint32_t>(tvSec % 86400);
    fmt2d(tempBuf.data(), s / 3600);  // HH
    tempBuf[2] = ':';
    fmt2d(&tempBuf[3], (s % 3600) / 60);  // MM
    tempBuf[5] = ':';
    fmt2d(&tempBuf[6], s % 60);  // SS
    std::uint64_t ms = tvNSec / 1000000;
    tempBuf[8] = '.';
    tempBuf[9] = static_cast<char>((ms / 100) + '0');
    tempBuf[10] = static_cast<char>(((ms / 10) % 10) + '0');
    tempBuf[11] = static_cast<char>((ms % 10) + '0');
    safeAppend(buffer, offset, capacity, "Fault Date: ");
    safeAppend(buffer, offset, capacity, initDateStr, 10);
    const auto initDaysSinceEpoch = initSecondsSinceEpoch / 86400;
    if (initDaysSinceEpoch > daysSinceEpoch) {
        safeAppend(buffer, offset, capacity, " + ");
        itoaSafeAppend(buffer, offset, capacity, initDaysSinceEpoch - daysSinceEpoch);
        safeAppend(buffer, offset, capacity, " days\n");
    } else {
        safeAppend(buffer, offset, capacity, "\n");
    }
    safeAppend(buffer, offset, capacity, "Fault Time: ");
    safeAppend(buffer, offset, capacity, tempBuf.data(), 12);
    safeAppend(buffer, offset, capacity, " UTC\n");
    safeAppend(buffer, offset, capacity, "Unix Epoch: ");
    itoaSafeAppend(buffer, offset, capacity, tvSec);
    std::int64_t uptimeSec = tvSec - initSecondsSinceEpoch;
    std::int64_t uptimeNSec = tvNSec - initNanoSecondsSinceEpoch;
    if (uptimeNSec < 0) {
        uptimeSec -= 1;
        uptimeSec += 1000000000L;
    }
    const std::int64_t uptimeMilliSec = uptimeNSec / 1000000;
    std::array<char, 3> msBuf{};
    msBuf[0] = static_cast<char>((uptimeMilliSec / 100) + '0');
    msBuf[1] = static_cast<char>(((uptimeMilliSec / 10) % 10) + '0');
    msBuf[2] = static_cast<char>((uptimeMilliSec % 10) + '0');
    safeAppend(buffer, offset, capacity, "\nUptime: ");
    itoaSafeAppend(buffer, offset, capacity, uptimeSec);
    safeAppend(buffer, offset, capacity, ".");
    safeAppend(buffer, offset, capacity, msBuf.data(), msBuf.size());
    safeAppend(buffer, offset, capacity, " sec\n");
}

void safePrint(const cpptrace::safe_object_frame& frame,
#if defined(__linux__)
               int fd = STDERR_FILENO
#else
               HANDLE fd = GetStdHandle(STD_ERROR_HANDLE)
#endif
               ) noexcept {
    safeWriteHex(frame.raw_address, fd);
    safePrint(" ", fd);
    safeWriteHex(frame.address_relative_to_object_start, fd);
    safePrint(" ", fd);
    safePrint(&frame.object_path[0], fd);
}

inline std::size_t strSafeCopy(char* dest, std::size_t maxLen, std::string_view src) {
    const auto baseLen = std::min(maxLen - 1, src.size());
    std::memcpy(dest, src.data(), baseLen);
    dest[baseLen] = '\0';
    return baseLen;
}

bool verifyWriteAccess(const std::string& p) noexcept {
    std::error_code ec;
    std::ofstream testFile(p, std::ios::app);

    if (!testFile.is_open()) {
        return false;
    }

    testFile << "";
    return true;
}

ConfigWarning setCrashWriteDir(std::string_view dirStr, std::string_view fileName,
                               std::span<char> writeDir, bool prefixDate,
                               const std::tm& timeInfo) noexcept {
    try {
        std::string finalPathStr;
        std::string fullFileName;
        if (prefixDate) {
            std::array<char, 64> tempTime{};
            const auto writtenSize =
                std::strftime(tempTime.data(), tempTime.size(), "%Y-%m-%d_%H-%M-%S_", &timeInfo);
            tempTime[writtenSize] = '\0';
            fullFileName += tempTime.data();  // std::format("{:%Y-%m-%d_%H-%M-%S}_", now);
        }
        fullFileName += std::string{fileName};
        std::error_code ec;
        const auto dir = dirStr.empty() ? std::filesystem::current_path()
                                        : std::filesystem::absolute(dirStr, ec);
        if (!ec) {
            std::filesystem::create_directories(dir, ec);
        }
        if (!ec) {
            finalPathStr = (dir / fullFileName).string();
        } else {
            ec.clear();
            auto fallbackPath = std::filesystem::absolute(fullFileName, ec);
            if (ec) {
                finalPathStr = fullFileName;
            } else {
                finalPathStr = std::move(fallbackPath).string();
            }
        }
        if (finalPathStr.size() >= writeDir.size()) {
            return ConfigWarning::kReportPathTooLong;
        }
        if (!verifyWriteAccess(finalPathStr)) {
            return ConfigWarning::kReportPathWriteTestFailed;
        }
        strSafeCopy(writeDir.data(), writeDir.size(), std::string_view{finalPathStr});
        return ConfigWarning::kNone;
    } catch (...) {
        return ConfigWarning::kInternalError;
    }
}

}  // namespace utils

namespace _internal {

std::array<char, 64> gInitTimeStr{};  // NOLINT
struct RawTime {
    std::int64_t tvSec;
    std::int64_t tvNsec;
} gInitTimeRaw;  // NOLINT

std::tm timeInit() {
    const auto now = std::chrono::system_clock::now();
    const auto duration = now.time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(duration);
    gInitTimeRaw.tvSec = secs.count();
    gInitTimeRaw.tvNsec = static_cast<long>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration - secs).count());

    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmInfo{};
#ifdef _WIN32
    gmtime_s(&tmInfo, &t);
#else
    gmtime_r(&t, &tmInfo);
#endif
    std::array<char, 24> baseTime{};
    std::strftime(baseTime.data(), baseTime.size(), "%Y-%m-%d %H:%M:%S", &tmInfo);
    const auto ms = static_cast<int>(gInitTimeRaw.tvNsec / 1000000);
    std::snprintf(gInitTimeStr.data(), gInitTimeStr.size(), "%s.%03d UTC", baseTime.data(), ms);
    return tmInfo;
}

struct Config {
    struct TerminateSettings {
        bool enable{true};
        std::optional<TerminateHook> userHook{std::nullopt};
    };
    struct SignalSettings {
        bool enable{true};
        bool raiseDefaultAfterwards{false};
    };
    struct PanicSettings {
        bool printMsgToStdErr{true};
        bool showPopUp{true};
        bool writeReport{true};
    };
    std::array<char, 512> baseErrorMessage{'\0'};
    std::array<char, 128> appName{'\0'};
    std::array<char, 128> buildID{'\0'};
    std::array<char, 512> crashPath{"crash_report.raw"};
    std::atomic<bool> isReportWritable{true};
    bool showPopUp{true};
    bool printMsgToStdErr{true};
    bool useUnsafeStacktraceOnSignalFallback{false};
    bool resolveNonSignalTrace{false};
    SignalSettings signal;
    TerminateSettings terminate;
    PanicSettings panic;

    [[nodiscard]] InitResult fromAPI(const ::fault::Config& config) {
        InitResult result{.success = true, .warnings = ConfigWarning::kNone};
        const auto baseErrorMsgToCopy =
            config.baseErrorMsg.empty() ? kDefaultErrorMessage : config.baseErrorMsg;
        if (utils::strSafeCopy(baseErrorMessage.data(), baseErrorMessage.size(),
                               baseErrorMsgToCopy) < config.baseErrorMsg.size()) {
            result.warnings = result.warnings | ConfigWarning::kBaseErrMsgTruncated;
        }
        utils::strSafeCopy(appName.data(), appName.size(), config.appName);
        utils::strSafeCopy(buildID.data(), buildID.size(), config.buildID);
        const auto fileNameStr =
            config.reportFileName.empty() ? "crash_report.log" : config.reportFileName;
        const auto tmInfo = timeInit();
        const auto reportDirFlags = utils::setCrashWriteDir(config.crashDir, fileNameStr, crashPath,
                                                            config.prefixDateOnFilename, tmInfo);
        result.warnings = result.warnings | reportDirFlags;
        if (reportDirFlags != ConfigWarning::kNone) {
            result.success = false;
            return result;
        }
        showPopUp = config.showPopUp;
        printMsgToStdErr = config.printMsgToStdErr;
        useUnsafeStacktraceOnSignalFallback = config.useUnsafeStacktraceOnSignalFallback;
        resolveNonSignalTrace = config.resolveNonSignalTrace;
        signal = SignalSettings{.enable = config.signal.enable,
                                .raiseDefaultAfterwards = config.signal.raiseDefaultAfterwards};
        terminate = TerminateSettings{.enable = config.terminate.enable,
                                      .userHook = config.terminate.userHook};
        panic = PanicSettings{.printMsgToStdErr = config.panic.printMsgToStdErr,
                              .showPopUp = config.panic.showPopUp,
                              .writeReport = config.panic.writeReport};
        return result;
    }
};

Config config;  // NOLINT

}  // namespace _internal

namespace ExitHandler {

static_assert(std::atomic<bool>::is_always_lock_free,
              "std::atomic<bool> is not guaranteed to be async signal safe.");

#if defined(__linux__)
std::array<char, 256> zenityPath{"/usr/bin/zenity"};    // NOLINT
std::atomic<int> canReadZenityPath{1};                  // NOLINT
std::array<char, 256> kDialogPath{"/usr/bin/kdialog"};  // NOLINT
std::atomic<int> canReadKDialogPath{1};                 // NOLINT
#endif

[[noreturn]] FORCE_INLINE void shutdown(int code = EXIT_FAILURE) noexcept {
#ifdef _WIN32
    TerminateProcess(GetCurrentProcess(), code);
#else
    std::_Exit(code);
#endif
    FAULT_UNREACHABLE();
}

[[noreturn]] inline void parkThreadForever() noexcept {
#ifdef _WIN32
    Sleep(INFINITE);
#else
    while (true) {
        pause();
    }
#endif
    // Safety net in case Pause/Sleep returns
    ExitHandler::shutdown();
    FAULT_UNREACHABLE();
}

void writeToStdErr(std::string_view message) {
    static std::atomic<bool> hasBeenHandled{false};
    bool expected{false};
    if (!hasBeenHandled.compare_exchange_strong(expected, true)) {
        parkThreadForever();
        FAULT_UNREACHABLE();
    }
    utils::safePrint(message.data(), message.size());
}

bool writeReport(std::string_view errContext,
                 const std::optional<cpptrace::object_trace>& exceptionTrace = std::nullopt,
                 bool writeResolved = false) {
    static std::atomic<bool> hasBeenHandled{false};
    bool expected{false};
    if (!hasBeenHandled.compare_exchange_strong(expected, true)) {
        parkThreadForever();
        FAULT_UNREACHABLE();
    }
    const auto& config = _internal::config;
    if (!config.isReportWritable) {
        return false;
    }
#if defined(__linux__)
    const int fd = open(config.crashPath.data(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
#else
    std::array<wchar_t, config.crashPath.size()> crashPathWide{};
    const HANDLE fd = utils::utf8ToUtf16Stack(config.crashPath.data(), crashPathWide.data(),
                                              crashPathWide.size())
                          ? CreateFileW(crashPathWide.data(),  // File name
                                        GENERIC_WRITE,         // Access mode
                                        FILE_SHARE_READ,       // Share mode
                                        nullptr,               // Security attributes
                                        CREATE_ALWAYS,         // Creation disposition
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,  // Flags
                                        nullptr  // Template
                                        )
                          : INVALID_HANDLE_VALUE;
    if (fd == INVALID_HANDLE_VALUE) {
#endif
        return false;
    }
    utils::safePrint("Build ID: ", fd);
    utils::safePrint(config.buildID.data(), fd);
    utils::safePrint("\nInit Timestamp: ", fd);
    utils::safePrint(_internal::gInitTimeStr.data(), fd);
    utils::safePrint("\n\n", fd);
    utils::safePrint(errContext.data(), errContext.size(), fd);
    utils::safePrint("\nStackTrace:\n", fd);

    if (exceptionTrace.has_value()) {
        // Exception: Program is not inside restrictive posix signal handling.
        if (writeResolved) {
            const auto resolvedTraceStr = (*exceptionTrace).resolve().to_string();
            utils::safePrint(resolvedTraceStr.c_str(), fd);
            utils::safePrint("\n(Regular resolved stacktrace used)\n", fd);
        } else {
            for (const auto& frame : exceptionTrace->frames) {
                utils::safeWriteHex(frame.raw_address, fd);
                utils::safePrint(" ", fd);
                utils::safeWriteHex(frame.object_address, fd);
                utils::safePrint(" ", fd);
                utils::safePrint(frame.object_path.c_str(), fd);
                utils::safePrint("\n", fd);
            }
            utils::safePrint("(Regular unwind used)\n", fd);
        }
    } else if (writeResolved) {
        const auto resolvedTraceStr = cpptrace::generate_trace().to_string();
        utils::safePrint(resolvedTraceStr.c_str(), fd);
        utils::safePrint("\n(Regular resolved stacktrace used)\n", fd);
    } else if (canSafeTraceBeCollected()) {
        // Program is inside restrictive signal handling (Possibly linux posix). Collect
        // stacktrace and print safely
        std::array<cpptrace::frame_ptr, 128> buffer{};
        const auto size = cpptrace::safe_generate_raw_trace(buffer.data(), buffer.size());
        for (std::size_t i{0}; i < size; ++i) {
            cpptrace::safe_object_frame objFrame{};
            cpptrace::get_safe_object_frame(buffer[i], &objFrame);
            objFrame.resolve();
            utils::safePrint(objFrame, fd);
            utils::safePrint("\n", fd);
        }
        utils::safePrint("(Safe unwind used)\n", fd);
    } else if (config.useUnsafeStacktraceOnSignalFallback) {
        // The program is inside restrictive signal handling, and no guaranteed safe trace can
        // be collected. Allow for risky operation by collecting the object trace normally:
        // Should work reliably inside windows vectoring handler (a bit more permissive), while
        // in linux posix it risks issues like deadlock if the reason for signal was heap
        // corruption or if any lock (e.g I/O) is being held. The risk is allowed to exist
        // noting that an alarm is set before hand should this deadlock. ()
        const auto objectTrace = cpptrace::generate_object_trace();
        for (const cpptrace::object_frame& frame : objectTrace) {
            utils::safeWriteHex(frame.raw_address, fd);
            utils::safePrint(" ", fd);
            utils::safeWriteHex(frame.object_address, fd);
            utils::safePrint(" ", fd);
            utils::safePrint(frame.object_path.c_str(), fd);
            utils::safePrint("\n", fd);
        }
        utils::safePrint("(Regular unwind used)\n", fd);
    } else {
        utils::safePrint(
            "Could not safely generate object trace (regular generation flag not activated)\n", fd);
    }
#if defined(__linux__)
    close(fd);
#else
    CloseHandle(fd);
#endif
    return true;
}

void showPopUp(const char* title, const char* message) noexcept {
    static std::atomic<bool> hasBeenHandled{false};
    bool expected{false};
    if (!hasBeenHandled.compare_exchange_strong(expected, true)) {
        ExitHandler::parkThreadForever();
        FAULT_UNREACHABLE();
    }
#ifdef _WIN32
    std::array<wchar_t, 128> titleWide{};
    std::array<wchar_t, 1024> messageWide{};
    utils::utf8ToUtf16Stack(title, titleWide.data(), titleWide.size());
    utils::utf8ToUtf16Stack(message, messageWide.data(), messageWide.size());
    MessageBoxW(nullptr, messageWide.data(), titleWide.data(),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST);
#else
    if (ExitHandler::canReadZenityPath == 0 && ExitHandler::canReadKDialogPath == 0) {
        return;
    }
    const pid_t pid = _Fork();  // Async signal safe.
    if (pid == 0) {
        if (ExitHandler::canReadZenityPath != 0) {
            execl(ExitHandler::zenityPath.data(), "zenity", "--error", "--title", title, "--text",
                  message, nullptr);
        } else if (ExitHandler::canReadKDialogPath != 0) {
            execl(ExitHandler::kDialogPath.data(), "kdialog", "--title", title, "--error", message,
                  nullptr);
        }
        ExitHandler::shutdown(EXIT_FAILURE);
        FAULT_UNREACHABLE();
    } else if (pid > 0) {
        waitpid(pid, nullptr, 0);  // Wait for user to close box
    }
#endif
}

}  // namespace ExitHandler

#ifdef _WIN32

void safeAppendVEHInfo(struct _EXCEPTION_POINTERS* pExc, char* buffer, std::size_t& offset,
                       std::size_t capacity) noexcept {
    if ((pExc == nullptr) || (pExc->ExceptionRecord == nullptr) ||
        (pExc->ContextRecord == nullptr)) {
        return;
    }

    const EXCEPTION_RECORD& rec = *pExc->ExceptionRecord;
    const CONTEXT& ctx = *pExc->ContextRecord;
    std::array<char, 19> regBuff{};

    utils::safeAppend(buffer, offset, capacity, "\nException Code: ");
    utils::safeWriteHex(static_cast<std::uintptr_t>(rec.ExceptionCode), regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    // If it's an Access Violation, ExceptionInformation[1] is the faulting address
    if (rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec.NumberParameters >= 2) {
        utils::safeAppend(buffer, offset, capacity, "\nFault Address: ");
        utils::safeWriteHex(static_cast<std::uintptr_t>(rec.ExceptionInformation[1]), regBuff);
        utils::safeAppend(buffer, offset, capacity, regBuff.data());
    }

    // 'Where'
    utils::safeAppend(buffer, offset, capacity, "\n\nRegisters (x64):");

    static constexpr auto kAddReg = [](const char* name, DWORD64 val, char* buf, std::size_t& ofs,
                                       std::size_t cap, std::array<char, 19>& buff) {
        utils::safeAppend(buf, ofs, cap, name);
        utils::safeWriteHex(static_cast<std::uintptr_t>(val), buff);
        utils::safeAppend(buf, ofs, cap, buff.data());
    };

    kAddReg("\nRIP=", ctx.Rip, buffer, offset, capacity, regBuff);
    kAddReg(" RSP=", ctx.Rsp, buffer, offset, capacity, regBuff);
    kAddReg(" RBP=", ctx.Rbp, buffer, offset, capacity, regBuff);
    kAddReg("\nRAX=", ctx.Rax, buffer, offset, capacity, regBuff);
    kAddReg(" RBX=", ctx.Rbx, buffer, offset, capacity, regBuff);
    kAddReg(" RCX=", ctx.Rcx, buffer, offset, capacity, regBuff);
    kAddReg("\nRDX=", ctx.Rdx, buffer, offset, capacity, regBuff);
    kAddReg(" RDI=", ctx.Rdi, buffer, offset, capacity, regBuff);
    kAddReg(" RSI=", ctx.Rsi, buffer, offset, capacity, regBuff);

    // Flags and Error Context
    utils::safeAppend(buffer, offset, capacity, "\nEFLAGS=");
    utils::safeWriteHex(static_cast<std::uintptr_t>(ctx.EFlags), regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());
    utils::safeAppend(buffer, offset, capacity, "\n");
}

const char* getExceptionString(DWORD code) noexcept {
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
}

struct WindowsHandling {
   private:
    static inline std::array<char, 128> titleBuffer{};
    static inline std::array<char, 1024> finalBuffer{};
    static inline std::size_t offsetForMsg{0};
    static inline std::atomic<bool> hasAnyCodeBeenReceived{false};
    static inline std::atomic<bool> reportDone{false};
    static inline bool showPopUp{true};
    static thread_local inline std::sig_atomic_t tryCount{0};
    static inline HANDLE hCrashEvent{nullptr};
    static inline HANDLE hWatchdogThread{nullptr};
    static constexpr DWORD kTimerMilliseconds{3000};

    static DWORD WINAPI watchdogFunction(LPVOID /*lpParam*/) noexcept {
        WaitForSingleObject(
            hCrashEvent,
            INFINITE);  // Waiting indefinitely until it is woken by the crashing process
        Sleep(kTimerMilliseconds);
        if (WindowsHandling::reportDone) {
            return EXIT_FAILURE;
        }
        if (WindowsHandling::showPopUp) {
            if (WindowsHandling::offsetForMsg >=
                std::strlen(_internal::config.baseErrorMessage.data())) {
                WindowsHandling::finalBuffer[WindowsHandling::offsetForMsg] = '\0';
                ExitHandler::showPopUp(WindowsHandling::titleBuffer.data(),
                                       WindowsHandling::finalBuffer.data());
            } else {
                ExitHandler::showPopUp("Fatal Error", _internal::config.baseErrorMessage.data());
            }
        }
        ExitHandler::shutdown();
        FAULT_UNREACHABLE();
    }

    [[nodiscard]] static bool checkPermissions() noexcept {
        bool expected{false};
        if (!WindowsHandling::hasAnyCodeBeenReceived.compare_exchange_strong(expected, true)) {
            if (WindowsHandling::tryCount ==
                0) {  // New thread on regular execution triggered handler, have it wait
                // for process shutdown
                ExitHandler::parkThreadForever();
                FAULT_UNREACHABLE();
            }
            // Same thread that was working on the report triggered handler again, skip report and
            // go to popup + shutdown
            if (WindowsHandling::offsetForMsg >=
                std::strlen(_internal::config.baseErrorMessage.data())) {
                WindowsHandling::finalBuffer[WindowsHandling::offsetForMsg] = '\0';
                if (WindowsHandling::showPopUp) {
                    ExitHandler::showPopUp(WindowsHandling::titleBuffer.data(),
                                           WindowsHandling::finalBuffer.data());
                }
                return false;
            }
            if (WindowsHandling::showPopUp) {
                ExitHandler::showPopUp("Fatal Error", _internal::config.baseErrorMessage.data());
            }
            return false;
        }
        ++WindowsHandling::tryCount;
        return true;
    }

    static void doWriteReport(std::size_t size, bool printToStderr, bool writeReport,
                              const std::optional<cpptrace::object_trace>& exceptionTrace,
                              bool resolveTrace) noexcept {
        const auto written = writeReport
                                 ? ExitHandler::writeReport(
                                       std::string_view{WindowsHandling::finalBuffer.data(), size},
                                       exceptionTrace, resolveTrace)
                                 : false;
        if (printToStderr) {
            std::array<char, 2048> stdErrBfr{};
            std::size_t offset{0};
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              "\n=== [FAULT BEGIN] ===\n");
            WindowsHandling::finalBuffer[WindowsHandling::offsetForMsg] = '\0';
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              WindowsHandling::finalBuffer.data());  // stdcerr
            if (written) {
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(), "\nFull log at: ");
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                                  _internal::config.crashPath.data());
            } else if (writeReport) {
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                                  "\nCould not generate report.\n");
            }
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              "\n=== [FAULT END] ===\n");
            ExitHandler::writeToStdErr(std::string_view{stdErrBfr.data(), offset});
        }
        WindowsHandling::reportDone = true;
    }

    static void writeSummaryMessageToBuffer(DWORD code, std::string_view msg,
                                            std::size_t& offset) noexcept {
        {
            std::size_t titleOffset{0};
            utils::safeAppend(WindowsHandling::titleBuffer.data(), titleOffset,
                              WindowsHandling::titleBuffer.size(), _internal::config.appName.data(),
                              _internal::config.appName.size());
            utils::safeAppend(WindowsHandling::titleBuffer.data(), titleOffset,
                              WindowsHandling::titleBuffer.size(), " Fatal Error");
        }
        char* pszDestEnd = nullptr;
        std::size_t remaining{0};
        if (!SUCCEEDED(StringCchPrintfExA(
                WindowsHandling::finalBuffer.data(), WindowsHandling::finalBuffer.size(),
                &pszDestEnd, &remaining, 0,
                "%s\n\nError Code: "
                "0x%08X\nDescription: %s\n\n",
                _internal::config.baseErrorMessage.data(), code, msg.data(), msg.size()))) {
            utils::safeAppend(WindowsHandling::finalBuffer.data(), offset,
                              WindowsHandling::finalBuffer.size(),
                              _internal::config.baseErrorMessage.data());
            utils::safeAppend(WindowsHandling::finalBuffer.data(), offset,
                              WindowsHandling::finalBuffer.size(), "\n\n");
        } else {
            offset = pszDestEnd - WindowsHandling::finalBuffer.data();
        }
        utils::writePreciseTimeSafe(WindowsHandling::finalBuffer.data(), offset,
                                    WindowsHandling::finalBuffer.size(),
                                    _internal::gInitTimeStr.data(), _internal::gInitTimeRaw.tvSec,
                                    _internal::gInitTimeRaw.tvNsec);
    }

    static void commonActions(std::size_t offset, bool printToStderr, bool writeReport,
                              const std::optional<cpptrace::object_trace>& exceptionTrace,
                              bool resolveTrace) {
        if (hCrashEvent != nullptr && hCrashEvent != INVALID_HANDLE_VALUE) {
            SetEvent(hCrashEvent);
        }
        WindowsHandling::doWriteReport(offset, printToStderr, writeReport, exceptionTrace,
                                       resolveTrace);
        WindowsHandling::finalBuffer[WindowsHandling::offsetForMsg] = '\0';
        if (WindowsHandling::showPopUp) {
            ExitHandler::showPopUp(WindowsHandling::titleBuffer.data(),
                                   WindowsHandling::finalBuffer.data());
        }
    }

    static void windowsCommonProcessSignalEvent(PEXCEPTION_POINTERS exceptionInfo, DWORD code,
                                                std::string_view description) {
        if (!WindowsHandling::checkPermissions()) {
            return;
        }
        WindowsHandling::showPopUp = _internal::config.showPopUp;
        std::size_t offset{0};
        WindowsHandling::writeSummaryMessageToBuffer(code, description, offset);
        WindowsHandling::offsetForMsg = offset;
        safeAppendVEHInfo(exceptionInfo, WindowsHandling::finalBuffer.data(), offset,
                          WindowsHandling::finalBuffer.size());
        constexpr bool kWriteReport{true};
        constexpr bool kResolveTrace{false};
        WindowsHandling::commonActions(offset, _internal::config.printMsgToStdErr, kWriteReport,
                                       std::nullopt, kResolveTrace);
    }

    static void initHandles() noexcept {
        WindowsHandling::hCrashEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        // Pre-spawn the thread while the system is healthy, it immediately goes to sleep until
        // needed
        WindowsHandling::hWatchdogThread =
            CreateThread(nullptr, 0, WindowsHandling::watchdogFunction, nullptr, 0, nullptr);
        if (WindowsHandling::hWatchdogThread != nullptr) {
            SetThreadPriority(WindowsHandling::hWatchdogThread, THREAD_PRIORITY_TIME_CRITICAL);
        }
    }

    [[noreturn]] static void winAbortHandler(int /*sig*/) {
        constexpr DWORD kAbortCode{SIGABRT};
        constexpr PEXCEPTION_POINTERS kNoContextPtr{nullptr};
        WindowsHandling::windowsCommonProcessSignalEvent(
            kNoContextPtr, kAbortCode,
            "Abort called");  // trace, stdcerr error, gui popup
        ExitHandler::shutdown(kAbortCode);
        FAULT_UNREACHABLE();
    }

    static LONG WINAPI windowsExceptionHandler(PEXCEPTION_POINTERS exceptionInfo) {
        const DWORD code = exceptionInfo->ExceptionRecord->ExceptionCode;
        const bool fatal =
            code == EXCEPTION_STACK_OVERFLOW || code == EXCEPTION_ACCESS_VIOLATION ||
            code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_IN_PAGE_ERROR ||
            code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED || code == EXCEPTION_DATATYPE_MISALIGNMENT ||
            code == EXCEPTION_INT_DIVIDE_BY_ZERO || code == EXCEPTION_FLT_DIVIDE_BY_ZERO ||
            code == EXCEPTION_PRIV_INSTRUCTION;

        if (!fatal) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        const char* const description = getExceptionString(code);
        WindowsHandling::windowsCommonProcessSignalEvent(
            exceptionInfo, code,
            description);  // trace, stdcerr error, gui popup
        return EXCEPTION_EXECUTE_HANDLER;
    }

   public:
    [[nodiscard]] static bool hasAnySignalBeenTriggered() noexcept {
        return WindowsHandling::hasAnyCodeBeenReceived;
    }

    [[noreturn]] static void fromTerminate(
        std::string_view msg, int code, bool printToStderr, bool writeReport,
        const std::optional<cpptrace::object_trace>& exceptionTrace, bool showPopUp,
        bool resolveTrace) {
        if (!WindowsHandling::checkPermissions()) {
            ExitHandler::shutdown(code);
            FAULT_UNREACHABLE();
        }
        WindowsHandling::showPopUp = showPopUp;
        std::size_t offset{0};
        WindowsHandling::writeSummaryMessageToBuffer(code, msg, offset);
        WindowsHandling::offsetForMsg = offset;
        WindowsHandling::commonActions(offset, printToStderr, writeReport, exceptionTrace,
                                       resolveTrace);
        ExitHandler::shutdown(code);
        FAULT_UNREACHABLE();
    }

    static void setup(bool enableHandlers) noexcept {
        constexpr auto kBytesToReserve = static_cast<std::size_t>(64U * 1024U);
        auto stackSize = static_cast<ULONG>(kBytesToReserve);
        SetThreadStackGuarantee(&stackSize);
        WindowsHandling::initHandles();
        WindowsHandling::tryCount =
            0;  // Explicit load (in case thread_local would behave in a lazy way)
        if (enableHandlers) {
            SetUnhandledExceptionFilter(WindowsHandling::windowsExceptionHandler);
            std::signal(SIGABRT, WindowsHandling::winAbortHandler);
        }
    }
};

#else

inline const char* safePrintSiCode(int sig, int code) noexcept {
    switch (sig) {
        case SIGSEGV:
            switch (code) {
                case SEGV_MAPERR:
                    return "SEGV_MAPERR (Address not mapped)";
                case SEGV_ACCERR:
                    return "SEGV_ACCERR (Invalid permissions)";
                case SEGV_BNDERR:
                    return "SEGV_BNDERR (Hardware bounds violation)";
                case SEGV_PKUERR:
                    return "SEGV_PKUERR (Access denied by memory protection keys)";
                default:
                    return "SEGV_UNKNOWN";
            }

        case SIGBUS:
            switch (code) {
                case BUS_ADRALN:
                    return "BUS_ADRALN (Alignment fault)";
                case BUS_ADRERR:
                    return "BUS_ADRERR (Non-existent physical address)";
                case BUS_OBJERR:
                    return "BUS_OBJERR (Object-specific hardware/mapping error)";
                default:
                    return "BUS_UNKNOWN";
            }

        case SIGFPE:
            switch (code) {
                case FPE_INTDIV:
                    return "FPE_INTDIV (Integer divide by zero)";
                case FPE_INTOVF:
                    return "FPE_INTOVF (Integer overflow)";
                case FPE_FLTDIV:
                    return "FPE_FLTDIV (Floating-point divide by zero)";
                case FPE_FLTINV:
                    return "FPE_FLTINV (Floating-point invalid operation)";
                default:
                    return "FPE_UNKNOWN";
            }

        case SIGILL:
            switch (code) {
                case ILL_ILLOPC:
                    return "ILL_ILLOPC (Illegal opcode)";
                case ILL_PRVREG:
                    return "ILL_PRVREG (Privileged register access)";
                default:
                    return "ILL_UNKNOWN";
            }
        default:
            return "SIGNAL_UNKNOWN";
    }
    FAULT_UNREACHABLE();
}

void safeAppendRegisters(const ucontext_t* ctx, char* buffer, std::size_t& offset,
                         std::size_t capacity) noexcept {
#if defined(__x86_64__)
    if (ctx == nullptr) {
        return;
    }

    const auto& g = ctx->uc_mcontext.gregs;
    std::array<char, 19> regBuff{};

    // 1. Instruction and Stack Pointers (The "Big Three")
    utils::safeAppend(buffer, offset, capacity, "\nRegisters:\nRIP=");
    utils::safeWriteHex(g[REG_RIP], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RSP=");
    utils::safeWriteHex(g[REG_RSP], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RBP=");
    utils::safeWriteHex(g[REG_RBP], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    // 2. Common General Purpose Registers (Helpful for finding null pointers/args)
    utils::safeAppend(buffer, offset, capacity, "\nRAX=");
    utils::safeWriteHex(g[REG_RAX], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RBX=");
    utils::safeWriteHex(g[REG_RBX], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RCX=");
    utils::safeWriteHex(g[REG_RCX], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RDX=");
    utils::safeWriteHex(g[REG_RDX], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    // 3. Argument Registers (RDI/RSI often contain the pointers being processed)
    utils::safeAppend(buffer, offset, capacity, "\nRDI=");
    utils::safeWriteHex(g[REG_RDI], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, " RSI=");
    utils::safeWriteHex(g[REG_RSI], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    // 4. Hardware Error Code (Very useful for SEGV analysis)
    utils::safeAppend(buffer, offset, capacity, " ERR=");
    utils::safeWriteHex(g[REG_ERR], regBuff);
    utils::safeAppend(buffer, offset, capacity, regBuff.data());

    utils::safeAppend(buffer, offset, capacity, "\n");
#endif
}

bool findProgramInPath(std::string_view programName, char* outBuffer,
                       std::size_t bufferSize) noexcept {
    if (programName.empty() || outBuffer == nullptr) {
        return false;
    }

    const char* pathEnv = std::getenv("PATH");
    if (pathEnv == nullptr) {
        return false;
    }

    try {
        std::string pathStr(pathEnv);
        std::size_t start{0};
        std::size_t end = pathStr.find(':');

        while (true) {
            // Extract the directory from the PATH string
            std::string dir = pathStr.substr(start, end - start);
            if (dir.empty()) {
                dir = ".";
            }

            std::error_code ec;
            std::filesystem::path fullPath = std::filesystem::path(dir) / programName;
            if (std::filesystem::exists(fullPath, ec) && access(fullPath.c_str(), X_OK) == 0) {
                std::string absolutePath = fullPath.string();

                if (absolutePath.length() < bufferSize) {
                    std::strncpy(outBuffer, absolutePath.c_str(), bufferSize - 1);
                    outBuffer[bufferSize - 1] = '\0';  // Ensure null termination
                    return true;
                }
            }

            if (end == std::string::npos) {
                break;
            }
            start = end + 1;
            end = pathStr.find(':', start);
        }

        return false;
    } catch (...) {
        return false;
    }
}

struct LinuxHandling {
    static_assert(std::atomic<pid_t>::is_always_lock_free,
                  "std::atomic<pid_t> may not be lock free. Remove std::atomic from it.");

    static inline stack_t gAltstack{};

   private:
    static inline std::array<char, 128> titleBuffer{};
    static inline std::array<char, 2048> finalBuffer{};
    static inline std::size_t offsetForMsg{0};
    static inline std::atomic<pid_t> tracePid{-1};
    static inline std::atomic<bool> hasAnySignalBeenReceived{false};
    static thread_local inline std::sig_atomic_t tryCount{};
    static inline std::sig_atomic_t signal{-1};
    // static inline bool writeToStdErr{true};
    // static inline bool writeReport{true};
    static inline bool showPopUp{true};
    static inline bool shouldReRaiseSignal{true};

    [[noreturn]] static void reRaiseSignal(int sig) noexcept {
        struct sigaction sa{};
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(sig, &sa, nullptr);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
        std::raise(sig);
        ExitHandler::shutdown(sig);
        FAULT_UNREACHABLE();
    }

    [[noreturn]] static void popUpAndExit([[maybe_unused]] int sig = -1) noexcept {
        if (LinuxHandling::tracePid > 0) {  // Something went wrong during trace logging, kill it as
                                            // to not become a zombie process
            kill(LinuxHandling::tracePid, SIGKILL);
            LinuxHandling::tracePid = -1;
        }
        if (LinuxHandling::offsetForMsg >= std::strlen(_internal::config.baseErrorMessage.data())) {
            LinuxHandling::finalBuffer[LinuxHandling::offsetForMsg] = '\0';
            if (LinuxHandling::showPopUp) {
                ExitHandler::showPopUp(LinuxHandling::titleBuffer.data(),
                                       LinuxHandling::finalBuffer.data());
            }
            if (LinuxHandling::shouldReRaiseSignal) {
                LinuxHandling::reRaiseSignal(LinuxHandling::signal);
                FAULT_UNREACHABLE();
            }
            ExitHandler::shutdown(128 + LinuxHandling::signal);
            FAULT_UNREACHABLE();
        }
        if (LinuxHandling::showPopUp) {
            ExitHandler::showPopUp("Fatal Error", _internal::config.baseErrorMessage.data());
        }
        if (LinuxHandling::shouldReRaiseSignal) {
            LinuxHandling::reRaiseSignal(LinuxHandling::signal);
            FAULT_UNREACHABLE();
        }
        ExitHandler::shutdown(128 + LinuxHandling::signal);
        FAULT_UNREACHABLE();
    };

    static void writeSummaryMessageToBuffer(std::string_view description,
                                            std::size_t& offset) noexcept {
        {
            std::size_t titleOffset{0};
            utils::safeAppend(LinuxHandling::titleBuffer.data(), titleOffset,
                              LinuxHandling::titleBuffer.size(), _internal::config.appName.data());
            utils::safeAppend(LinuxHandling::titleBuffer.data(), titleOffset,
                              LinuxHandling::titleBuffer.size(), " Fatal Error");
        }
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(),
                          _internal::config.baseErrorMessage.data());
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(), "\n\nDescription: ");
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(), description.data(),
                          description.size());
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(), "\n\n");
        utils::writePreciseTimeSafe(LinuxHandling::finalBuffer.data(), offset,
                                    LinuxHandling::finalBuffer.size(),
                                    _internal::gInitTimeStr.data(), _internal::gInitTimeRaw.tvSec,
                                    _internal::gInitTimeRaw.tvNsec);
    }

    static void writeSummaryMessageToBuffer(int sig, const siginfo_t* info,
                                            std::size_t& offset) noexcept {
        {
            std::size_t titleOffset{0};
            utils::safeAppend(LinuxHandling::titleBuffer.data(), titleOffset,
                              LinuxHandling::titleBuffer.size(), _internal::config.appName.data());
            utils::safeAppend(LinuxHandling::titleBuffer.data(), titleOffset,
                              LinuxHandling::titleBuffer.size(), " Fatal Error");
        }
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(),
                          _internal::config.baseErrorMessage.data());
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(), "\n\nSignal Event: ");
        switch (sig) {
            case SIGSEGV:
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "SIGSEGV");
                break;
            case SIGABRT:
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "SIGABRT");
                break;
            case SIGFPE:
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "SIGFPE");
                break;
            case SIGILL:
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "SIGILL");
                break;
            case SIGBUS:
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "SIGBUS");
                break;
            default: {
                utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                                  LinuxHandling::finalBuffer.size(), "Unknown signal");
                break;
            }
        }
        utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                          LinuxHandling::finalBuffer.size(), "\n");
        if (info != nullptr) {
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(), "Reason: ");
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(),
                              safePrintSiCode(sig, info->si_code));
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(), "\n");
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(), "Fault address: ");
            std::array<char, 19> addrBuff{};
            utils::safeWriteHex(reinterpret_cast<std::uintptr_t>(info->si_addr), addrBuff);
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(), addrBuff.data());
            utils::safeAppend(LinuxHandling::finalBuffer.data(), offset,
                              LinuxHandling::finalBuffer.size(), "\n\n");
        }
        utils::writePreciseTimeSafe(LinuxHandling::finalBuffer.data(), offset,
                                    LinuxHandling::finalBuffer.size(),
                                    _internal::gInitTimeStr.data(), _internal::gInitTimeRaw.tvSec,
                                    _internal::gInitTimeRaw.tvNsec);
    }

    static void writeReportDetailsToBuffer(const ucontext_t* ctx, std::size_t& offset) noexcept {
        safeAppendRegisters(ctx, LinuxHandling::finalBuffer.data(), offset,
                            LinuxHandling::finalBuffer.size());
    }

    [[noreturn]] static void doWriteToFile(
        std::size_t size, bool printToStderr, bool writeReport,
        const cpptrace::object_trace* exceptionTrace = nullptr) noexcept {
        const auto written =
            writeReport
                ? ExitHandler::writeReport(
                      std::string_view{LinuxHandling::finalBuffer.data(), size}, exceptionTrace)
                : false;
        if (printToStderr) {
            std::array<char, 2048> stdErrBfr{};
            std::size_t offset{0};
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              "\n=== [FAULT BEGIN] ===\n");
            LinuxHandling::finalBuffer[LinuxHandling::offsetForMsg] = '\0';
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              LinuxHandling::finalBuffer.data());  // stdcerr
            if (written) {
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(), "\nFull log at: ");
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                                  _internal::config.crashPath.data());
            } else if (writeReport) {
                utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                                  "\nCould not generate report.\n");
            }
            utils::safeAppend(stdErrBfr.data(), offset, stdErrBfr.size(),
                              "\n=== [FAULT END] ===\n");
            ExitHandler::writeToStdErr(std::string_view{stdErrBfr.data(), offset});
        }
        ExitHandler::shutdown();
        FAULT_UNREACHABLE();
    }

    static void checkPermissions() noexcept {
        if (LinuxHandling::tracePid ==
            0) {  // Child that got hit with new signal during trace collection
            ExitHandler::shutdown();
            FAULT_UNREACHABLE();
        }
        bool expected{false};
        if (!LinuxHandling::hasAnySignalBeenReceived.compare_exchange_strong(expected, true)) {
            if (LinuxHandling::tryCount ==
                0) {  // New thread on regular execution triggered handler, have it wait
                // for process shutdown
                ExitHandler::parkThreadForever();
                FAULT_UNREACHABLE();
            }
            // Same thread that was working on the report triggered handler again, skip report and
            // go to popup + shutdown
            LinuxHandling::popUpAndExit();
            FAULT_UNREACHABLE();
        }
        ++LinuxHandling::tryCount;
    }

    [[noreturn]] static void linuxSignalHandler(int sig, siginfo_t* info, void* uctx) {
        LinuxHandling::checkPermissions();
        LinuxHandling::signal = sig;
        LinuxHandling::showPopUp = _internal::config.showPopUp;
        LinuxHandling::shouldReRaiseSignal = _internal::config.signal.raiseDefaultAfterwards;
        std::size_t offset{0};
        LinuxHandling::writeSummaryMessageToBuffer(LinuxHandling::signal, info, offset);
        LinuxHandling::offsetForMsg = offset;
        LinuxHandling::writeReportDetailsToBuffer(static_cast<const ucontext_t*>(uctx), offset);
        LinuxHandling::commonActions(offset, _internal::config.printMsgToStdErr, true, nullptr);
        FAULT_UNREACHABLE();
    }

    [[noreturn]] static void commonActions(std::size_t offset, bool printToStderr, bool writeReport,
                                           const cpptrace::object_trace* exceptionTrace) {
        struct sigaction sa{};
        sigfillset(&sa.sa_mask);
        sa.sa_handler = LinuxHandling::popUpAndExit;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGALRM, &sa, nullptr);    // Protect against deadlocks
        LinuxHandling::tracePid = _Fork();   // Async signal safe.
        if (LinuxHandling::tracePid == 0) {  // Child process
            LinuxHandling::doWriteToFile(offset, printToStderr, writeReport, exceptionTrace);
            FAULT_UNREACHABLE();
        } else if (LinuxHandling::tracePid > 0) {  // Parent process
            alarm(3);
            waitpid(LinuxHandling::tracePid, nullptr,
                    0);  // Wait for trace collection, or until alarm hits
            alarm(0);
            LinuxHandling::tracePid = -1;
        }
        LinuxHandling::popUpAndExit();
        FAULT_UNREACHABLE();
    }

   public:
    [[nodiscard]] static pid_t getTracePid() noexcept {
        return LinuxHandling::tracePid;
    }
    [[nodiscard]] static bool hasAnySignalBeenTriggered() noexcept {
        return LinuxHandling::hasAnySignalBeenReceived;
    }

    [[noreturn]] static void fromTerminate(std::string_view msg, int code, bool printToStderr,
                                           bool writeReport,
                                           const cpptrace::object_trace* exceptionTrace,
                                           bool showPopUp) {
        LinuxHandling::checkPermissions();
        LinuxHandling::signal = code;
        LinuxHandling::showPopUp = showPopUp;
        LinuxHandling::shouldReRaiseSignal = false;
        std::size_t offset{0};
        LinuxHandling::writeSummaryMessageToBuffer(msg, offset);
        LinuxHandling::offsetForMsg = offset;
        LinuxHandling::commonActions(offset, printToStderr, writeReport, exceptionTrace);
    }

    static void setup(bool enableHandlers) noexcept {
        ExitHandler::canReadZenityPath = 0;
        ExitHandler::canReadZenityPath = static_cast<int>(findProgramInPath(
            "zenity", ExitHandler::zenityPath.data(), ExitHandler::zenityPath.size()));
        ExitHandler::canReadKDialogPath = 0;
        ExitHandler::canReadKDialogPath = static_cast<int>(findProgramInPath(
            "kdialog", ExitHandler::kDialogPath.data(), ExitHandler::kDialogPath.size()));
        LinuxHandling::tryCount = 0;  // Explicit load
        if (!enableHandlers) {
            return;
        }
        // Stack safety
        constexpr auto kBytesToReserve = static_cast<std::size_t>(64U * 1024U);
        static std::array<std::uint8_t, kBytesToReserve> altstackMem;
        LinuxHandling::gAltstack.ss_sp = altstackMem.data();
        LinuxHandling::gAltstack.ss_size = sizeof(altstackMem);
        LinuxHandling::gAltstack.ss_flags = 0;
        sigaltstack(&LinuxHandling::gAltstack, nullptr);

        // Signal handlers
        struct sigaction sa{};
        sa.sa_sigaction = LinuxHandling::linuxSignalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        const std::array<int, 5> sigs = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
        for (int s : sigs) {
            sigaction(s, &sa, nullptr);
        }

        std::signal(SIGINT, [](int /*sig*/) { fault::setShutdownRequest(); });
        std::signal(SIGTERM, [](int /*sig*/) { fault::setShutdownRequest(); });
    }
};
#endif

// If any abnormal signal has been hit, the handler is in-processing and about to exit the
// process. Therefore, this can be used to halt execution of a concurrent mechanism, such as
// terminate handler or user requested controlled termination
[[nodiscard]] inline bool hasAnySignalBeenTriggered() noexcept {
#ifdef _WIN32
    return WindowsHandling::hasAnySignalBeenTriggered();
#else
    return LinuxHandling::hasAnySignalBeenTriggered();
#endif
}

[[nodiscard]] inline bool needsImmediateShutdown() noexcept {
#ifdef _WIN32
    return false;
#else
    return LinuxHandling::getTracePid() ==
           0;  // C++ exception happened in signal handler child while attempting to write regular
               // (risky) object trace to file  (we are in undefined behaviour territory, exit
               // immediately)
#endif
}

struct TerminateHandling {
   private:
    static inline std::atomic<bool> hasBeenTriggered{
        false};  // Protection against multi threading calling std::terminate concurrently
    static inline TerminateHook terminateHook{nullptr};

    [[nodiscard]] static bool shouldExecuteHandler() noexcept {
        bool expected{false};
        // Another thread has concurrently hit either a terminate handler or a signal handler
        // (higher priority)
        return !hasAnySignalBeenTriggered() &&
               TerminateHandling::hasBeenTriggered.compare_exchange_strong(expected, true);
    }

    [[noreturn]] static void customTerminator() {
        if (needsImmediateShutdown()) {  // Signal forked child has hit terminate condition
            ExitHandler::shutdown();
            FAULT_UNREACHABLE();
        }
        if (!TerminateHandling::shouldExecuteHandler()) {  // Another thread has been hit
                                                           // with terminate or signal, wait for
                                                           // it to exit the process
            ExitHandler::parkThreadForever();
            FAULT_UNREACHABLE();
        }

        // While std::current_exception() can potentially point to throwing destructors,
        // std::uncaught_exceptions() yields only exceptions that were subject to stack unwind.
        // The most clear example is throwing destructors: these call std::terminate instead,
        // making it so that they are registered by current_exception but not by
        // uncaught_exceptions.
        const std::exception_ptr exPtr =
            std::current_exception();  // Last exception (Could be from regular
                                       // code or throwing destructor)
        const auto uncaughtExp = std::uncaught_exceptions();
        auto trace = cpptrace::generate_object_trace();
        if (uncaughtExp > 0) {
            // Unwind was happening due to an exception (not counting any throws on destructors
            // that instead trigger std::terminate) In this case,
            // cpptrace::generate_object_trace() yields only stacktrace on local context. We
            // need trace from current exception to get full (or at least better) snapshot
            auto exceptionTrace =
                cpptrace::raw_trace_from_current_exception().resolve_object_trace();
            if (!exceptionTrace.frames.empty()) {  // Probably redundant
                trace.frames.push_back(
                    cpptrace::object_frame{.raw_address = 0,
                                           .object_address = 0,
                                           .object_path = {"====== UPSTREAM ======"}});
                trace.frames.insert(trace.frames.end(),
                                    std::make_move_iterator(exceptionTrace.frames.begin()),
                                    std::make_move_iterator(exceptionTrace.frames.end()));
            }
        }

        std::string userMessage;
        userMessage.reserve(128);
        if (exPtr) {
            try {
                std::rethrow_exception(exPtr);
            } catch (const std::exception& e) {
                userMessage +=
                    std::format("Terminate called due to an unhandled exception: {}.", e.what());
            } catch (...) {
                userMessage += "Terminate called due to an unhandled exception.";
            }
        } else {
            userMessage += "Terminate called.";
        }

        if (TerminateHandling::terminateHook != nullptr) {
            ObjectTrace faultTrace = utils::fromCppTrace(trace);
            TerminateHandling::terminateHook(userMessage, faultTrace);
            trace = utils::toCppTrace(faultTrace);
        }
        if (hasAnySignalBeenTriggered()) {
            ExitHandler::parkThreadForever();
            FAULT_UNREACHABLE();
        }
        constexpr bool kWriteReport{true};
        TerminateHandling::controlledShutdown(userMessage, _internal::config.printMsgToStdErr,
                                              kWriteReport, trace, _internal::config.showPopUp,
                                              _internal::config.resolveNonSignalTrace);
        FAULT_UNREACHABLE();
    }

   public:
    [[nodiscard]] static bool hasTerminateOrHigherBeenReached() noexcept {
        return hasAnySignalBeenTriggered() || TerminateHandling::hasBeenTriggered;
    }
    [[noreturn]] static void controlledShutdown(
        std::string_view message, bool printToStderr, bool writeReport,
        const std::optional<cpptrace::object_trace>& exceptionTrace, bool showPopUp,
        bool resolveTrace = false) {
#if defined(__linux__)
        constexpr int kTerminateCode{SIGABRT};
        LinuxHandling::fromTerminate(message, kTerminateCode, printToStderr, writeReport,
                                     exceptionTrace, showPopUp);
#else
        constexpr int kTerminateCode{3};
        WindowsHandling::fromTerminate(message, kTerminateCode, printToStderr, writeReport,
                                       exceptionTrace, showPopUp, resolveTrace);
#endif
        FAULT_UNREACHABLE();
    }

    static void setup() noexcept {
        const auto& config = _internal::config;
        const auto& terminateConfig = config.terminate;
        if (terminateConfig.userHook.has_value()) {
            TerminateHandling::terminateHook = *terminateConfig.userHook;
        }
        std::set_terminate(TerminateHandling::customTerminator);
    }
};

void warmupCpptrace() noexcept {
    std::array<cpptrace::frame_ptr, 10> buffer{};
    std::size_t _ = cpptrace::safe_generate_raw_trace(buffer.data(), buffer.size());
    cpptrace::safe_object_frame frame{};
    cpptrace::get_safe_object_frame(buffer[0], &frame);
}

void setup(bool enableHandlers) noexcept {
#ifdef _WIN32
    WindowsHandling::setup(enableHandlers);
#else
    LinuxHandling::setup(enableHandlers);
#endif
}

void doInit() {
    warmupCpptrace();  // If cpptrace is a shared library (it is currently), ensures proper
                       // dynamic page loading in case it would otherwise behave in a lazy
                       // implementation that could compromise it's use in a signal handler
    const auto& config = _internal::config;
    if (config.terminate.enable) {
        TerminateHandling::setup();
    }
    setup(config.signal.enable);
}

[[nodiscard]] InitResult tryInit(const Config& config) noexcept {
    // enum class InitStatus : std::uint8_t { kUninit, kInitializing, kFailed, kInit };
    // static std::atomic<InitStatus> initStatus{InitStatus::kUninit};
    static std::atomic<bool> isInit{false};
    bool expected{false};
    if (!isInit.compare_exchange_strong(expected, true)) {
        return {.success = true, .warnings = ConfigWarning::kAlreadyInitialized};
    }
    const auto res = _internal::config.fromAPI(config);
    if (!res) {
        isInit = false;
        return res;
    }
    doInit();
    return res;
}

static std::atomic<bool> shutdownRequest{false};  // NOLINT

}  // namespace

bool setShutdownRequest() noexcept {
    bool expected{false};
    return shutdownRequest.compare_exchange_strong(expected, true);
}

bool hasShutdownRequest() noexcept {
    return shutdownRequest;
}

bool canSafeTraceBeCollected() noexcept {
    return cpptrace::can_signal_safe_unwind() && cpptrace::can_get_safe_object_frame();
}

InitResult init(const Config& config) noexcept {
    return tryInit(config);
}

void panic(std::string_view message, const std::optional<ObjectTrace>& exceptionTrace) {
    std::optional<cpptrace::object_trace> optCppObjTrace{std::nullopt};
    if (exceptionTrace.has_value()) {
        optCppObjTrace = utils::toCppTrace(*exceptionTrace);
    }
    TerminateHandling::controlledShutdown(
        message, _internal::config.panic.printMsgToStdErr, _internal::config.panic.writeReport,
        optCppObjTrace, _internal::config.panic.showPopUp, _internal::config.resolveNonSignalTrace);
    FAULT_UNREACHABLE();
}

void assertionFailure(std::string_view expr, std::string_view file, std::uint32_t line,
                      std::string_view func, std::string_view userMsg) {
    std::array<char, 2048> msg{};
    std::size_t offset{0};
    utils::safeAppend(msg.data(), offset, msg.size(), "Assertion '");
    utils::safeAppend(msg.data(), offset, msg.size(), expr.data(), expr.size());
    utils::safeAppend(msg.data(), offset, msg.size(), "' Failed");
    if (!userMsg.empty()) {
        utils::safeAppend(msg.data(), offset, msg.size(), " | Message: ");
        utils::safeAppend(msg.data(), offset, msg.size(), userMsg.data(), userMsg.size());
    }
    utils::safeAppend(msg.data(), offset, msg.size(), " at ");
    utils::safeAppend(msg.data(), offset, msg.size(), file.data(), file.size());
    utils::safeAppend(msg.data(), offset, msg.size(), ":");
    utils::itoaSafeAppend(msg.data(), offset, msg.size(), line);
    utils::safeAppend(msg.data(), offset, msg.size(), " in ");
    utils::safeAppend(msg.data(), offset, msg.size(), func.data(), func.size());

    constexpr bool kWriteReport{true};
    constexpr std::optional<cpptrace::object_trace> kNoExceptionTrace{std::nullopt};
    TerminateHandling::controlledShutdown(
        std::string_view{msg.data(), offset}, _internal::config.printMsgToStdErr, kWriteReport,
        kNoExceptionTrace, _internal::config.showPopUp, _internal::config.resolveNonSignalTrace);
    FAULT_UNREACHABLE();
}

void assertionFailure(std::string_view expr, std::source_location loc, std::string_view userMsg) {
    assertionFailure(expr, loc.file_name(), loc.line(), loc.function_name(), userMsg);
    FAULT_UNREACHABLE();
}

::FaultInitResult fromCppInitResult(InitResult cppRes) {
    return ::FaultInitResult{
        .success = cppRes.success,
        .warnings = static_cast<::FaultConfigWarning>(static_cast<std::uint8_t>(cppRes.warnings))};
}

}  // namespace fault

extern "C" {

bool faultCanSafeTraceBeCollected() FAULT_NOEXCEPT {
    return fault::canSafeTraceBeCollected();
}

FaultConfig faultGetDefaultConfig() FAULT_NOEXCEPT {
    fault::Config config{};
    return FaultConfig{
        .appName = config.appName.data(),
        .buildID = config.buildID.data(),
        .crashDir = config.crashDir.data(),
        .reportFileName = config.reportFileName.data(),
        .prefixDateOnFilename = config.prefixDateOnFilename,
        .baseErrorMsg = config.baseErrorMsg.data(),
        .showPopUp = config.showPopUp,
        .printMsgToStdErr = config.printMsgToStdErr,
        .useUnsafeStacktraceOnSignalFallback = config.useUnsafeStacktraceOnSignalFallback,
        .resolveNonSignalTrace = config.resolveNonSignalTrace,
        .signal = {.enable = config.signal.enable,
                   .raiseDefaultAfterwards = config.signal.raiseDefaultAfterwards},
        .panic = {.printMsgToStdErr = config.panic.printMsgToStdErr,
                  .showPopUp = config.panic.showPopUp,
                  .writeReport = config.panic.writeReport}};
}

FaultInitResult faultInit(const FaultConfig* config) FAULT_NOEXCEPT {
    if (config == nullptr) {
        return fault::fromCppInitResult(fault::tryInit(fault::Config{}));
    }

    fault::Config cppConfig{
        .appName{fault::utils::getSafeView(config->appName)},
        .buildID{fault::utils::getSafeView(config->buildID)},
        .crashDir{fault::utils::getSafeView(config->crashDir)},
        .reportFileName{fault::utils::getSafeView(config->reportFileName)},
        .prefixDateOnFilename = config->prefixDateOnFilename,
        .baseErrorMsg{fault::utils::getSafeView(config->baseErrorMsg)},
        .showPopUp = config->showPopUp,
        .printMsgToStdErr = config->printMsgToStdErr,
        .useUnsafeStacktraceOnSignalFallback = config->useUnsafeStacktraceOnSignalFallback,
        .resolveNonSignalTrace = config->resolveNonSignalTrace,
        .signal{.enable = config->signal.enable,
                .raiseDefaultAfterwards = config->signal.raiseDefaultAfterwards},
        .terminate{.enable = false},
        .panic{.printMsgToStdErr = config->panic.printMsgToStdErr,
               .showPopUp = config->panic.showPopUp,
               .writeReport = config->panic.writeReport}};
    return fault::fromCppInitResult(fault::tryInit(cppConfig));
}

void faultPanic(const char* message) {
    constexpr std::optional<fault::ObjectTrace> kNoExceptionTrace{std::nullopt};
    fault::panic(std::string_view{message}, kNoExceptionTrace);
    FAULT_UNREACHABLE();
}

void faultAssertionFailure(const char* expr, const char* file, uint32_t line, const char* func,
                           const char* userMsg) {
    fault::assertionFailure(expr, file, line, func, userMsg);
    FAULT_UNREACHABLE();
}

}  // extern "C"
