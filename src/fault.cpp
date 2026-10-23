#include "fault/fault.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <ranges>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <windows.h>
#include <errhandlingapi.h>
#include <excpt.h>
#include <handleapi.h>
#include <processthreadsapi.h>
#include <strsafe.h>
#include <synchapi.h>
#include <dbghelp.h>
#include <psdk_inc/_dbg_common.h>
#include <stringapiset.h>
#include <fileapi.h>
#include <sysinfoapi.h>
#include <processenv.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <winerror.h>
#include <winnls.h>
#include <winnt.h>
// clang-format on
#else
#include <cstdio>
#include <fcntl.h>
#include <signal.h>  // NOLINT
#include <time.h>    // NOLINT
#include <unistd.h>

#include <bits/time.h>
#include <bits/types/siginfo_t.h>
#include <bits/types/sigset_t.h>
#include <bits/types/stack_t.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#endif

#include <cpptrace/basic.hpp>
#include <cpptrace/cpptrace.hpp>
#include <cpptrace/exceptions.hpp>
#include <cpptrace/forward.hpp>
#include <cpptrace/from_current.hpp>
#include <cpptrace/utils.hpp>

#include "fault/adapter/stacktrace.hpp"
#include "fault/attributes.h"
#include "fault/core.hpp"
#include "fault/fault.h"
#include "fault/macros.h"
#include "fault/version.h"

#ifdef __cpp_exceptions
#define FAULT_EXCEPTIONS 1
#else
#define FAULT_EXCEPTIONS 0
#endif

namespace fault {

namespace {

namespace utils {

static_assert(std::atomic<bool>::is_always_lock_free,
              "std::atomic<bool> may not be lock free. Use volatile std::sig_atomic_t "
              "instead.");
static_assert(std::atomic<int>::is_always_lock_free,
              "std::atomic<int> may not be lock free. Use volatile std::sig_atomic_t "
              "instead.");

constexpr const char* const kHexChars = "0123456789abcdef";

constexpr void safeWriteHex(std::uintptr_t value, std::array<char, 18>& buf) noexcept {
    buf[0] = '0';
    buf[1] = 'x';
    for (int i{0}; i < 16; ++i) {
        buf[17 - i] = kHexChars[(value >> (i * 4)) & 0xF];
    }
}

struct Itoa {
    std::uint64_t val{};
};

struct InlineStringSpan;

template <std::size_t N>
struct InlineString {
    [[nodiscard]] constexpr auto getCapacity() const noexcept {
        return data_.size();
    }
    [[nodiscard]] auto getSize() const noexcept {
        return size_;
    }

    [[nodiscard]] constexpr const auto* getData() const noexcept {
        return data_.data();
    }
    [[nodiscard]] constexpr auto* getData() noexcept {
        return data_.data();
    }

    [[nodiscard]] auto empty() const noexcept {
        return getSize() == 0;
    }

    [[nodiscard]] InlineStringSpan span() noexcept;

    explicit operator std::string_view() const noexcept {
        return std::string_view{data_.data(), size_};
    }

    void setSize(std::size_t newSize) noexcept {
        if (newSize >= size_) {
            return;
        }
        data_[newSize] = '\0';
        size_ = newSize;
    }

    void clear() noexcept {
        setSize(0);
    }

    constexpr void append(char c) noexcept {
        if (c == '\0' || size_ >= getCapacity() - 1) {
            return;
        }
        data_[size_++] = c;
        data_[size_] = '\0';
    }

    template <std::size_t N_Other>
    constexpr void append(const char (&str)[N_Other]) noexcept {  // NOLINT
        if (size_ >= getCapacity() - 1) {
            return;
        }
        const std::size_t toAppend = std::min(getCapacity() - size_ - 1, N_Other - 1);
        for (std::size_t i{0}; i < toAppend; ++i) {
            data_[size_++] = str[i];
        }
        data_[size_] = '\0';
    }

    template <typename... Args>
    constexpr void appendFmt(std::format_string<Args...> fmt, Args&&... args) noexcept {
        if (size_ >= N - 1) {
            return;
        }
        const auto r =
            std::format_to_n(data_.data() + size_, N - size_ - 1, fmt, std::forward<Args>(args)...);
        size_ += r.size;
        data_[size_] = '\0';
    }

    constexpr void append(std::span<const char> str) noexcept {
        if (str.empty() || size_ >= getCapacity() - 1) {
            return;
        }
        std::size_t appended{0};
        const std::size_t toAppend = std::min(getCapacity() - size_ - 1, str.size());
        for (std::size_t i{0}; i < toAppend; ++i) {
            data_[size_++] = str[i];
        }
        data_[size_] = '\0';
    }

    constexpr void append(std::string_view str) noexcept {
        append(std::span<const char>{str});
    }

    template <std::size_t N_Other>
    constexpr void append(const InlineString<N_Other>& str) noexcept {
        append(std::span{str.data_.data(), str.getSize()});
    }

    constexpr void append(std::uintptr_t value) noexcept {
        std::array<char, 18> buf{};
        safeWriteHex(value, buf);
        append(std::span{buf});
    }

    constexpr void append(Itoa val) noexcept {
        auto& value = val.val;
        if (size_ >= N - 1) {
            return;
        }
        if (value == 0) {
            data_[size_++] = '0';
            data_[size_] = '\0';
            return;
        }
        std::size_t len{0};
        for (std::uint64_t temp = value; temp > 0; temp /= 10) {
            len++;
        }
        if (size_ + len >= N - 1) {
            return;
        }
        for (std::size_t i = len; i > 0; --i) {
            data_[size_ + i - 1] = static_cast<char>(value % 10 + '0');
            value /= 10;
        }
        size_ += len;
        data_[size_] = '\0';
    }

    constexpr void append(const std::source_location& loc) {
        appendMulti(" @ ", loc.file_name(), ':', Itoa{static_cast<std::uint64_t>(loc.line())});
        if (loc.function_name() != nullptr) {
            appendMulti(" (", loc.function_name(), ')');
        }
    }

    constexpr void appendMulti(auto&&... args) noexcept {
        (append(std::forward<decltype(args)>(args)), ...);  // NOLINT
    }

    constexpr auto& operator+=(auto&& arg) noexcept {
        append(std::forward<decltype(arg)>(arg));
        return *this;
    }

   private:
    friend InlineStringSpan;

    std::array<char, N> data_{};
    std::size_t size_{};
};

struct InlineStringSpan {
   public:
    InlineStringSpan() = delete;

    template <std::size_t N>
    InlineStringSpan(InlineString<N>& str)
        : data_{str.data_.data(), str.data_.size()}, size_{std::ref(str.size_)} {}

    [[nodiscard]] constexpr auto getCapacity() const noexcept {
        return data_.size();
    }
    [[nodiscard]] constexpr auto getSize() const noexcept {
        return size_.get();
    }
    [[nodiscard]] constexpr const auto* getData() const noexcept {
        return data_.data();
    }

    [[nodiscard]] constexpr auto empty() const noexcept {
        return getSize() == 0;
    }

    explicit operator std::string_view() const noexcept {
        return std::string_view{data_.data(), size_};
    }

    void setSize(std::size_t newSize) noexcept {
        if (newSize >= size_) {
            return;
        }
        data_[newSize] = '\0';
        size_ = newSize;
    }

    constexpr void append(char c) noexcept {
        if (c == '\0' || size_ >= getCapacity() - 1) {
            return;
        }
        data_[size_++] = c;
        data_[size_] = '\0';
    }

    template <std::size_t N_Other>
    constexpr void append(const char (&str)[N_Other]) noexcept {  // NOLINT
        if (size_ >= getCapacity() - 1) {
            return;
        }
        const std::size_t toAppend = std::min(getCapacity() - size_ - 1, N_Other - 1);
        for (std::size_t i{0}; i < toAppend; ++i) {
            data_[size_++] = str[i];
        }
        data_[size_] = '\0';
    }

    template <typename... Args>
    constexpr void appendFmt(std::format_string<Args...> fmt, Args&&... args) noexcept {
        if (size_ >= getCapacity() - 1) {
            return;
        }
        const auto r = std::format_to_n(data_.data() + size_, getCapacity() - size_ - 1, fmt,
                                        std::forward<Args>(args)...);
        size_ += r.size;
        data_[size_] = '\0';
    }

    constexpr void append(std::span<const char> str) noexcept {
        if (str.empty() || size_ >= getCapacity() - 1) {
            return;
        }
        std::size_t appended{0};
        const std::size_t toAppend = std::min(getCapacity() - size_ - 1, str.size());
        for (std::size_t i{0}; i < toAppend; ++i) {
            data_[size_++] = str[i];
        }
        data_[size_] = '\0';
    }

    constexpr void append(std::string_view str) noexcept {
        append(std::span<const char>{str});
    }

    constexpr void append(const InlineStringSpan& str) noexcept {
        append(std::span{str.getData(), str.getSize()});
    }

    constexpr void append(std::uintptr_t value) noexcept {
        std::array<char, 18> buf{};
        safeWriteHex(value, buf);
        append(std::span{buf});
    }

    constexpr void append(Itoa val) noexcept {
        auto& value = val.val;
        if (size_ >= getCapacity() - 1) {
            return;
        }
        if (value == 0) {
            data_[size_++] = '0';
            data_[size_] = '\0';
            return;
        }
        std::size_t len{0};
        for (std::uint64_t temp = value; temp > 0; temp /= 10) {
            len++;
        }
        if (size_ + len >= getCapacity() - 1) {
            return;
        }
        for (std::size_t i = len; i > 0; --i) {
            data_[size_ + i - 1] = static_cast<char>(value % 10 + '0');
            value /= 10;
        }
        size_ += len;
        data_[size_] = '\0';
    }

    constexpr void append(const std::source_location& loc) {
        appendMulti(" @ ", loc.file_name(), ':', Itoa{static_cast<std::uint64_t>(loc.line())});
        if (loc.function_name() != nullptr) {
            appendMulti(" (", loc.function_name(), ')');
        }
    }

    constexpr void appendMulti(auto&&... args) {
        (append(std::forward<decltype(args)>(args)), ...);  // NOLINT
    }

    constexpr auto& operator+=(auto&& arg) noexcept {
        append(std::forward<decltype(arg)>(arg));
        return *this;
    }

   private:
    std::span<char> data_;
    std::reference_wrapper<std::size_t> size_;
};

template <std::size_t N>
InlineStringSpan InlineString<N>::span() noexcept {
    return InlineStringSpan{*this};
}

inline std::string_view getSafeView(const char* ptr) noexcept {
    if (ptr == nullptr) {
        return "";
    }
    return std::string_view{ptr};
}

void fmt2d(char* buf, std::uint32_t val) noexcept {
    buf[0] = static_cast<char>((val / 10) + '0');
    buf[1] = static_cast<char>((val % 10) + '0');
}

void getNowSafe(std::int64_t& outSec, std::int64_t& outNsec) noexcept {
#ifdef _WIN32
    ::FILETIME ft;
    ::GetSystemTimePreciseAsFileTime(&ft);
    ::ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Windows Epoch (1601) to Unix Epoch (1970) offset
    constexpr std::uint64_t kUnixOffset{11644473600ULL};
    outSec = static_cast<std::int64_t>((uli.QuadPart / 10000000ULL) - kUnixOffset);
    outNsec = static_cast<std::int64_t>(((uli.QuadPart % 10000000ULL) * 100));
#else
    struct ::timespec ts{};
    ::clock_gettime(CLOCK_REALTIME, &ts);
    outSec = ts.tv_sec;
    outNsec = ts.tv_nsec;
#endif
}

#ifdef __linux__

inline void safePrint(const char* str, std::size_t len, int fd = STDERR_FILENO) noexcept {
    [[maybe_unused]] ssize_t bytes = ::write(fd, str, len);
}

inline void safePrint(const char* str, int fd = STDERR_FILENO) noexcept {
    [[maybe_unused]] ssize_t bytes = ::write(fd, str, std::strlen(str));
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

inline auto getStdHandle(::DWORD nStdHandle) noexcept {
    return ::GetStdHandle(nStdHandle);
}

const ::HANDLE hFileDefault = getStdHandle(STD_ERROR_HANDLE);

inline void safePrint(const char* str, std::size_t len, ::HANDLE hFile = hFileDefault) noexcept {
    if (str == nullptr) {
        return;
    }
    ::DWORD written{};
    ::WriteFile(hFile, str, static_cast<::DWORD>(len), &written, nullptr);
}

inline void safePrint(const char* str, ::HANDLE hFile = hFileDefault) noexcept {
    if (str == nullptr) {
        return;
    }
    ::DWORD written{};
    // We use strlen here; it is safe as it only reads memory
    ::WriteFile(hFile, str, static_cast<::DWORD>(std::strlen(str)), &written, nullptr);
}

inline bool utf8ToUtf16Stack(const char* utf8, wchar_t* out, int outLen) noexcept {
    const int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out, outLen);
    return written > 0;
}

void safeWriteHex(std::uintptr_t value, ::HANDLE hFile = hFileDefault) noexcept {
    std::array<char, 18> buf{};
    buf[0] = '0';
    buf[1] = 'x';
    for (int i{0}; i < 16; ++i) {
        buf[17 - i] = kHexChars[(value >> (i * 4)) & 0xF];
    }
    safePrint(buf.data(), buf.size(), hFile);
}

#endif

void writePreciseTimeSafe(InlineStringSpan str, const char* initDateStr,
                          std::int64_t initSecondsSinceEpoch,
                          std::int64_t initNanoSecondsSinceEpoch, bool initWritten) noexcept {
    std::int64_t tvSec{};
    std::int64_t tvNSec{};
    getNowSafe(tvSec, tvNSec);
    std::array<char, 12> tempBuf{};
    const auto daysSinceEpoch = static_cast<std::int64_t>(tvSec / 86400);  // NOLINT
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
    if (initWritten) {
        str.append("Fault Date: ");
        constexpr std::size_t kInitDateLenUpToDay{10};
        str.append(std::span{initDateStr, std::min(kInitDateLenUpToDay, std::strlen(initDateStr))});
        const auto initDaysSinceEpoch = initSecondsSinceEpoch / 86400;
        if (daysSinceEpoch > initDaysSinceEpoch) {
            str.appendMulti(" + ",
                            utils::Itoa{static_cast<uint64_t>(daysSinceEpoch - initDaysSinceEpoch)},
                            " days\n");
        } else {
            str.append('\n');
        }
    }
    str.appendMulti("Fault Time: ", std::span{tempBuf},
                    " UTC\nUnix Epoch: ", utils::Itoa{static_cast<uint64_t>(tvSec)});
    if (!initWritten) {
        str.append('\n');
        return;
    }
    std::int64_t uptimeSec = tvSec - initSecondsSinceEpoch;
    std::int64_t uptimeNSec = tvNSec - initNanoSecondsSinceEpoch;
    if (uptimeNSec < 0) {
        uptimeSec -= 1;
        uptimeNSec += 1000000000L;
    }
    const std::int64_t uptimeMilliSec = uptimeNSec / 1000000;
    std::array<char, 3> msBuf{};
    msBuf[0] = static_cast<char>((uptimeMilliSec / 100) + '0');
    msBuf[1] = static_cast<char>(((uptimeMilliSec / 10) % 10) + '0');
    msBuf[2] = static_cast<char>((uptimeMilliSec % 10) + '0');
    str.appendMulti("\nUptime: ", Itoa{static_cast<uint64_t>(uptimeSec)}, '.', std::span{msBuf},
                    " sec\n");
}

void safePrint(const cpptrace::safe_object_frame& frame,
#ifdef __linux__
               int fd = STDERR_FILENO
#else
               ::HANDLE fd = getStdHandle(STD_ERROR_HANDLE)
#endif
               ) noexcept {
    safeWriteHex(frame.raw_address, fd);
    safePrint(" ", fd);
    safeWriteHex(frame.address_relative_to_object_start, fd);
    safePrint(" ", fd);
    safePrint(&frame.object_path[0], fd);
}

inline std::size_t strSafeCopy(char* dest, std::size_t maxLen, std::string_view src) noexcept {
    const auto baseLen = std::min(maxLen - 1, src.size());
    std::memcpy(dest, src.data(), baseLen);
    dest[baseLen] = '\0';
    return baseLen;
}

bool verifyWriteAccess(const std::string& p) noexcept {
    {
        auto testFile = std::ofstream{p, std::ios::out | std::ios::trunc};
        if (!testFile.is_open()) {
            return false;
        }
        testFile << "test";
        testFile.flush();
        if (!testFile) {
            return false;
        }
    }
    std::error_code ec;
    if (!std::filesystem::remove(p, ec)) {
        return false;
    }
    return !ec;
}

v1::ConfigWarning setCrashWriteDir(std::string_view dirStr, std::string_view fileName,
                                   std::span<char> writeDir, bool prefixDate,
                                   const std::tm& timeInfo, std::string_view extension) noexcept {
#if FAULT_EXCEPTIONS
    try {
#endif
        std::string finalPathStr;
        std::string fullFileName;
        if (prefixDate) {
            std::array<char, 64> tempTime{};
            const auto writtenSize =
                std::strftime(tempTime.data(), tempTime.size(), "%Y-%m-%d_%H-%M-%S_", &timeInfo);
            tempTime[writtenSize] = '\0';
            fullFileName += tempTime.data();
        }
        fullFileName += std::string{fileName};
        std::error_code ec;
        const auto dir = dirStr.empty() ? std::filesystem::current_path()
                                        : std::filesystem::absolute(dirStr, ec);
        if (!ec) {
            std::filesystem::create_directories(dir, ec);
        }
        if (!ec) {
            auto finalPath = dir / fullFileName;
            finalPath.replace_extension(extension);
            finalPathStr = finalPath.string();
        } else {
            ec.clear();
            auto fallbackPath = std::filesystem::absolute(fullFileName, ec);
            fallbackPath.replace_filename(extension);
            if (ec) {
                return v1::ConfigWarning::kInvalidPath;
            }
            finalPathStr = std::move(fallbackPath).string();
        }
        if (finalPathStr.size() >= writeDir.size()) {
            return v1::ConfigWarning::kReportPathTooLong;
        }
        if (!verifyWriteAccess(finalPathStr)) {
            return v1::ConfigWarning::kReportPathWriteTestFailed;
        }
        strSafeCopy(writeDir.data(), writeDir.size(), std::string_view{finalPathStr});
        return v1::ConfigWarning::kNone;
#if FAULT_EXCEPTIONS
    } catch (...) {
        return v1::ConfigWarning::kInternalError;
    }
#endif
}

[[nodiscard]] std::optional<cpptrace::object_trace> tryGetObjectTraceFromException() noexcept {
    // Strangely, this throws if a resolved trace from exception has been called from user
    // beforehand
#if FAULT_EXCEPTIONS
    try {
#endif
        auto trace = cpptrace::raw_trace_from_current_exception().resolve_object_trace();
        if (trace.frames.empty()) {
            return std::nullopt;
        }
        return std::optional{std::move(trace)};
#if FAULT_EXCEPTIONS
    } catch (...) {
        return std::nullopt;
    }
#endif
}

[[nodiscard]] inline std::optional<cpptrace::object_trace> getSafeObjectTrace() noexcept {
#if FAULT_EXCEPTIONS
    try {
#endif
        return cpptrace::generate_object_trace();
#if FAULT_EXCEPTIONS
    } catch (...) {
        return std::nullopt;
    }
#endif
}

}  // namespace utils

namespace exceptions {

class TracedException : public std::exception {
   public:
    TracedException(std::string msg, std::optional<cpptrace::object_trace> trace,
                    std::optional<std::string> excpTypeStr)
        : msg_{std::move(msg)}, trace_{std::move(trace)}, excpTypeStr_{std::move(excpTypeStr)} {}

    [[nodiscard]] std::optional<cpptrace::object_trace> getTrace() && noexcept {
        return std::move(trace_);
    }

    [[nodiscard]] std::optional<std::string> getExceptionStringType() && noexcept {
        return std::move(excpTypeStr_);
    }

    [[nodiscard]] const char* what() const noexcept override {
        return msg_.c_str();
    }

    [[nodiscard]] std::string str() && noexcept {
        return std::move(msg_);
    }

   private:
    std::string msg_;
    std::optional<cpptrace::object_trace> trace_;
    std::optional<std::string> excpTypeStr_;
};

std::exception_ptr pendingException{nullptr};  // NOLINT
std::mutex mutex;                              // NOLINT

void saveException(std::string_view msg, const std::optional<v1::ObjectTrace>& customTrace,
                   std::optional<std::string> excpTypeStr) noexcept {
    std::scoped_lock lock{mutex};
    std::optional<cpptrace::object_trace> trace{};
    bool generateTrace{!customTrace.has_value()};
    if (customTrace.has_value()) {
        auto optCustomTrace = adapter::v1::to_cpptrace(*customTrace);
        if (!optCustomTrace.has_value()) {
            generateTrace = true;
        } else {
            trace = std::move(optCustomTrace);
        }
    }
    if (generateTrace) {
        if (auto optTraceFromException = utils::tryGetObjectTraceFromException();
            optTraceFromException.has_value()) {
            trace = std::move(optTraceFromException);
        } else {
            trace = utils::getSafeObjectTrace();
        }
    }
    pendingException =
        std::make_exception_ptr(TracedException{!msg.empty() ? std::string{msg} : "<Unspecified>",
                                                std::move(trace), std::move(excpTypeStr)});
}

#if FAULT_EXCEPTIONS
void rethrowAndAppendSavedExceptionTrace(std::optional<cpptrace::object_trace>& baseTrace,
                                         utils::InlineStringSpan msg,
                                         utils::InlineStringSpan details) noexcept {
    std::scoped_lock lock{mutex};
    if (pendingException == nullptr) {
        return;
    }
    try {
        std::rethrow_exception(pendingException);
    } catch (TracedException& e) {
        auto savedTrace = std::move(e).getTrace();
        const auto exTypeStr = std::move(e).getExceptionStringType();
        if (savedTrace.has_value()) {
            if (!baseTrace.has_value()) {
                baseTrace = cpptrace::object_trace{};
            }
            baseTrace->frames.push_back({.raw_address = 0,
                                         .object_address = 0,
                                         .object_path = {"====== PROPAGATED ======"}});
            baseTrace->frames.insert(baseTrace->frames.end(),
                                     std::make_move_iterator(savedTrace->frames.begin()),
                                     std::make_move_iterator(savedTrace->frames.end()));
        }
        const auto& str = std::move(e).str();
        utils::InlineString<128> optExTypeStr;
        if (exTypeStr.has_value()) {
            optExTypeStr.appendFmt(", of (mangled) type {}.", *exTypeStr);
        } else {
            optExTypeStr += '.';
        }
        if (str.empty()) {
            msg.append("\nPropagated from upstream exception.");
            details.appendFmt(
                "A saved exception was retrieved with no message "
                "provided{}\nIt should be "
                "visible in "
                "the object/stack trace, under the delimiter '====== "
                "PROPAGATED ======' "
                "artifitial frame.\n",
                std::string_view{optExTypeStr});
        } else {
            msg.appendFmt("\nPropagated from upstream exception: {}.", str);
            details.appendFmt(
                "A saved exception was retrieved with message: {}{}\nIt should "
                "be visible in "
                "the object/stack trace, under the delimiter '====== "
                "PROPAGATED ======' "
                "artifitial frame.\n",
                str, std::string_view{optExTypeStr});
        }
    }
}
#endif

}  // namespace exceptions

namespace hook {

struct CallbackWithLoc {
    PanicHook f;
    std::optional<std::source_location> loc;

    void release() noexcept {
        f = nullptr;
        loc = std::nullopt;
    }
};

constexpr std::size_t kMaxPanicHooks{16};
thread_local std::array<CallbackWithLoc, kMaxPanicHooks> threadCallbacks{};  // NOLINT
std::array<CallbackWithLoc, kMaxPanicHooks> globalCallbacks{};               // NOLINT

struct {
    utils::InlineString<2048> buffer;
    std::size_t counter{0};
} unWindStorage{};  // NOLINT

std::mutex globalMutex;  // NOLINT

void resetBuffer() noexcept {
    std::scoped_lock lock{globalMutex};
    unWindStorage.counter = 0;
    unWindStorage.buffer.setSize(0);
}

void invokeAndSaveUnwind(const PanicHook& f,
                         const std::optional<std::source_location>& loc = std::nullopt) noexcept {
    std::scoped_lock lock{hook::globalMutex};

    unWindStorage.buffer.appendMulti(utils::Itoa{1 + unWindStorage.counter++}, ": ");
#if FAULT_EXCEPTIONS
    try {
#endif
        if (const auto str = f(); str.empty()) {
            unWindStorage.buffer.append("<No message provided>");
        } else {
            unWindStorage.buffer.append(std::string_view{str});
        }
#if FAULT_EXCEPTIONS
    } catch (...) {
        unWindStorage.buffer.append("<Exception thrown on user callback>");
    }
#endif
    if (loc.has_value()) {
        unWindStorage.buffer.append(*loc);
    }
    unWindStorage.buffer.append('\n');
}

bool invokeAndSave(utils::InlineStringSpan buf) noexcept {
    {
        std::scoped_lock lock{globalMutex};
        if (!hook::unWindStorage.buffer.empty()) {
            buf.appendMulti("\nUser provided unwind callback messages:\n",
                            hook::unWindStorage.buffer.span(), '\n');
        }
    }

    bool anyInvoked{false};
    std::size_t called{0};
    for (const auto& callback : std::ranges::reverse_view(threadCallbacks)) {
        if (callback.f == nullptr) {
            continue;
        }
        if (!anyInvoked) {
            buf.append("\nUser provided panic/fail callback messages:\n");
            anyInvoked = true;
        }
        std::string_view effectiveMsg{};
        std::string str{};
#if FAULT_EXCEPTIONS
        try {
#endif
            str = callback.f();
            if (!str.empty()) {
                effectiveMsg = std::string_view{str};
            } else {
                effectiveMsg = "<Empty message on user callback>";
            }
#if FAULT_EXCEPTIONS
        } catch (...) {
            effectiveMsg = "<Exception thrown on user callback>";
        }
#endif
        buf.appendMulti("( Thread Local ) ", utils::Itoa{1 + called++}, ": ", effectiveMsg);
        if (callback.loc.has_value()) {
            buf.append(*callback.loc);
        }
        buf.append('\n');
    }
    {
        std::scoped_lock lock{globalMutex};
        for (const auto& callback : std::ranges::reverse_view(globalCallbacks)) {
            if (callback.f == nullptr) {
                continue;
            }
            if (!anyInvoked) {
                buf.append("\nUser provided panic/fail callback messages:\n");
                anyInvoked = true;
            }
            std::string_view effectiveMsg{};
            std::string str{};
#if FAULT_EXCEPTIONS
            try {
#endif
                str = callback.f();
                if (!str.empty()) {
                    effectiveMsg = std::string_view{str};
                } else {
                    effectiveMsg = "<Empty message on user callback>";
                }
#if FAULT_EXCEPTIONS
            } catch (...) {
                effectiveMsg = "<Exception thrown on user callback>";
            }
#endif
            buf.appendMulti("(    GLOBAL    ) ", utils::Itoa{1 + called++}, ": ", effectiveMsg);
            if (callback.loc.has_value()) {
                buf.append(*callback.loc);
            }
            buf.append('\n');
        }
    }
    return anyInvoked;
}

}  // namespace hook

namespace _internal {

struct {
    std::array<char, 64> str{};
    std::int64_t tvSec{};
    std::int64_t tvNsec{};
    bool written{false};
} gInitTime{};  // NOLINT

std::tm timeInit() noexcept {
    const auto now = std::chrono::system_clock::now();
    const auto duration = now.time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(duration);
    gInitTime.tvSec = secs.count();
    gInitTime.tvNsec = static_cast<long>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(duration - secs).count());

    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tmInfo{};
#ifdef _WIN32
    ::gmtime_s(&tmInfo, &t);
#else
    ::gmtime_r(&t, &tmInfo);
#endif
    std::array<char, 24> baseTime{};
    std::strftime(baseTime.data(), baseTime.size(), "%Y-%m-%d %H:%M:%S", &tmInfo);
    const auto ms = static_cast<int>(gInitTime.tvNsec / 1000000);
    std::snprintf(gInitTime.str.data(), gInitTime.str.size(), "%s.%03d UTC", baseTime.data(), ms);
    gInitTime.written = true;
    return tmInfo;
}

struct Config {
    static constexpr int kAlarmSeconds{5};
    struct TerminateSettings {
        bool enable{true};
        std::optional<v1::TerminateHook> userHook{std::nullopt};
    };
    struct SignalSettings {
        bool enable{true};
        bool raiseDefaultAfterwards{false};
        bool enableShutdownRequest{true};
    };
    struct PanicSettings {
        bool printMsgToStdErr{true};
        bool showPopUp{true};
        bool writeReport{true};
    };
    struct Windows {
        static inline bool canWriteDump{false};
        static inline std::array<char, 512> dumpPath{"crash_dump.dmp"};
    };
    std::array<char, 512> baseErrorMessage{
        "The application encountered a fatal error and must close. If the problem persists, please "
        "contact the program maintainer."};
    std::array<char, 128> appName{};
    std::array<char, 128> buildID{};
    static constexpr std::size_t kCrashPathSize{512};
    std::array<char, kCrashPathSize> crashPath{"crash_report.log"};
    std::atomic<bool> isReportWritable{true};
    bool showPopUp{true};
    bool printMsgToStdErr{true};
    bool useUnsafeStacktraceOnSignalFallback{false};
    bool resolveNonSignalTrace{false};
    SignalSettings signal;
    TerminateSettings terminate;
    PanicSettings panic;

    [[nodiscard]] v1::InitResult fromAPI(const ::fault::v1::Config& config) noexcept {
        v1::InitResult result{.success = true, .warnings = v1::ConfigWarning::kNone};
        const auto baseErrorMsgToCopy =
            config.baseErrorMsg.empty() ? kDefaultErrorMessage : config.baseErrorMsg;
        if (utils::strSafeCopy(baseErrorMessage.data(), baseErrorMessage.size(),
                               baseErrorMsgToCopy) < config.baseErrorMsg.size()) {
            result.warnings = result.warnings | v1::ConfigWarning::kBaseErrMsgTruncated;
        }
        utils::strSafeCopy(appName.data(), appName.size(), config.appName);
        utils::strSafeCopy(buildID.data(), buildID.size(), config.buildID);
        const auto fileNameStr =
            config.reportBaseFileName.empty() ? "crash_report" : config.reportBaseFileName;
        const auto tmInfo = timeInit();
        const auto reportDirFlags = utils::setCrashWriteDir(
            config.crashDir, fileNameStr, crashPath, config.prefixDateOnFilename, tmInfo, ".log");
#ifdef _WIN32
        if (config.generateMiniDumpWindows &&
            utils::setCrashWriteDir(config.crashDir, fileNameStr, Windows::dumpPath,
                                    config.prefixDateOnFilename, tmInfo,
                                    ".dmp") == v1::ConfigWarning::kNone) {
            Windows::canWriteDump = true;
        }
#endif
        result.warnings = result.warnings | reportDirFlags;
        if (reportDirFlags != v1::ConfigWarning::kNone) {
            result.success = false;
            return result;
        }
        showPopUp = config.showPopUp;
        printMsgToStdErr = config.printMsgToStdErr;
        useUnsafeStacktraceOnSignalFallback = config.useUnsafeStacktraceOnSignalFallback;
        resolveNonSignalTrace = config.resolveNonSignalTrace;
        signal = SignalSettings{.enable = config.signal.enable,
                                .raiseDefaultAfterwards = config.signal.raiseDefaultAfterwards,
                                .enableShutdownRequest = config.signal.storeShutdownRequests};
        terminate = TerminateSettings{
            .enable = config.terminate.enable,
            .userHook = config.terminate.userHook != nullptr
                            ? std::optional<v1::TerminateHook>(config.terminate.userHook)
                            : std::nullopt};
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

#ifdef __linux__
std::array<char, 256> zenityPath{"/usr/bin/zenity"};    // NOLINT
std::atomic<bool> canReadZenityPath{true};              // NOLINT
std::array<char, 256> kDialogPath{"/usr/bin/kdialog"};  // NOLINT
std::atomic<bool> canReadKDialogPath{true};             // NOLINT
#endif

#ifdef _MSC_VER
#define FAULT_FORCE_INLINE __forceinline
#else
#define FAULT_FORCE_INLINE __attribute__((always_inline)) inline
#endif

[[noreturn]] FAULT_FORCE_INLINE void shutdown(int code = EXIT_FAILURE) noexcept {
#ifdef _WIN32
    ::TerminateProcess(GetCurrentProcess(), code);
#else
    std::_Exit(code);
#endif
    FAULT_UNREACHABLE();
}

[[noreturn]] inline void parkThreadForever() noexcept {
#ifdef _WIN32
    ::Sleep(INFINITE);
#else
    while (true) {
        ::pause();
    }
#endif
    // Safety net in case Pause/Sleep returns
    ExitHandler::shutdown();
    FAULT_UNREACHABLE();
}

void writeToStdErr(std::string_view message) noexcept {
    static std::atomic<bool> hasBeenHandled{false};
    bool expected{false};
    if (!hasBeenHandled.compare_exchange_strong(expected, true)) {
        parkThreadForever();
        FAULT_UNREACHABLE();
    }
    utils::safePrint(message.data(), message.size());
}

// Note on noexcept: when coming from panic or std::terminate, trace is already provided and will
// not be generated here. Coming from signals where unsafe trace is collected, it can theoretically
// throw, and noexcept is strategically placed so as to now let it escape (it's undefined
// behaviour already, best-effort approach)
bool writeReport(std::string_view errContext,
                 const std::optional<cpptrace::object_trace>& customTrace = std::nullopt,
                 bool writeResolved = false) noexcept {
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
#ifdef __linux__
    const int fd = ::open(config.crashPath.data(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
#else
    std::array<wchar_t, _internal::Config::kCrashPathSize> crashPathWide{};
    const ::HANDLE fd =
        utils::utf8ToUtf16Stack(config.crashPath.data(), crashPathWide.data(),
                                crashPathWide.size())
            ? ::CreateFileW(crashPathWide.data(),  // File name
                            GENERIC_WRITE,         // Access mode
                            FILE_SHARE_READ,       // Share mode
                            nullptr,               // Security attributes
                            CREATE_ALWAYS,         // Creation disposition
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,  // Flags
                            nullptr                                           // Template
                            )
            : INVALID_HANDLE_VALUE;
    if (fd == INVALID_HANDLE_VALUE) {
#endif
        return false;
    }
    utils::safePrint("--- FAULT REPORT v", fd);
    utils::safePrint(version::kString, fd);
    utils::safePrint(" ---\n", fd);
    utils::safePrint("App Name: ", fd);
    utils::safePrint(config.appName.data(), fd);
    utils::safePrint("\nBuild ID: ", fd);
    utils::safePrint(config.buildID.data(), fd);
    if (_internal::gInitTime.written) {
        utils::safePrint("\nInit Timestamp: ", fd);
        utils::safePrint(_internal::gInitTime.str.data(), fd);
    }
    utils::safePrint("\n\n", fd);
    utils::safePrint(errContext.data(), errContext.size(), fd);
    utils::safePrint("\n", fd);
    if (customTrace.has_value()) {
        // Panic or std::terminate: Program is not inside restrictive posix signal handling.
        const auto& trace = *customTrace;
        if (trace.frames.empty()) {
            utils::safePrint("(No object trace is present for display)\n", fd);
        } else if (writeResolved) {
            try {  // Not signal handler, safe to try/catch
                const auto resolvedTrace = trace.resolve();
                utils::safePrint("Stack Trace:\n", fd);
                for (const auto& frame : resolvedTrace) {
                    utils::safePrint(frame.to_string().c_str(), fd);
                    utils::safePrint("\n", fd);
                }
                utils::safePrint("(Regular resolved stacktrace used)\n", fd);
            } catch (...) {
                utils::safePrint(
                    "[Internal error while resolving trace. Defaulting to log unresolved trace]\n",
                    fd);
                utils::safePrint("Object Trace:\n", fd);
                for (const auto& frame : trace.frames) {
                    utils::safeWriteHex(frame.raw_address, fd);
                    utils::safePrint(" ", fd);
                    utils::safeWriteHex(frame.object_address, fd);
                    utils::safePrint(" ", fd);
                    utils::safePrint(frame.object_path.c_str(), fd);
                    utils::safePrint("\n", fd);
                }
                utils::safePrint("(Regular unwind used)\n", fd);
            }
        } else {
            utils::safePrint("Object Trace:\n", fd);
            for (const auto& frame : trace.frames) {
                utils::safeWriteHex(frame.raw_address, fd);
                utils::safePrint(" ", fd);
                utils::safeWriteHex(frame.object_address, fd);
                utils::safePrint(" ", fd);
                utils::safePrint(frame.object_path.c_str(), fd);
                utils::safePrint("\n", fd);
            }
            utils::safePrint("(Regular unwind used)\n", fd);
        }
    } else if (can_collect_safe_trace()) {
        utils::safePrint("Object Trace:\n", fd);
        // Program may be inside restrictive signal handling (Possibly linux posix). Collect
        // stacktrace and print safely
        std::array<cpptrace::frame_ptr, 128> buffer{};
        const auto size = cpptrace::safe_generate_raw_trace(buffer.data(), buffer.size());
        for (std::size_t i{0}; i < size; ++i) {
            cpptrace::safe_object_frame objFrame{};
            cpptrace::get_safe_object_frame(buffer[i], &objFrame);
            utils::safePrint(objFrame, fd);
            utils::safePrint("\n", fd);
        }
        utils::safePrint("(Safe unwind used)\n", fd);
    } else if (config.useUnsafeStacktraceOnSignalFallback) {
        utils::safePrint("Object Trace:\n", fd);
        // If the program is inside restrictive signal handling, it will attempt here to collect a
        // regular trace. This is a best-effor approach: it may throw, or deadlock, or recursively
        // crash. Fault mitigates this with prior alarms and protection agains recursion
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
#ifdef __linux__
    ::close(fd);
#else
    ::CloseHandle(fd);
#endif
    return true;
}

void showPopUp(const char* title, const char* message) noexcept {
    static std::atomic<bool> hasBeenHandled{false};
    bool expected{false};
    if (!hasBeenHandled.compare_exchange_strong(expected, true)) {
        return;
    }
#ifdef _WIN32
    std::array<wchar_t, 128> titleWide{};
    std::array<wchar_t, 2048> messageWide{};
    if (!utils::utf8ToUtf16Stack(title, titleWide.data(), titleWide.size()) ||
        !utils::utf8ToUtf16Stack(message, messageWide.data(), messageWide.size())) {
        // Not expected to ever fail, but for 100% correctness
        constexpr const wchar_t* const kWideMsg{
            // This is a literal copy of kDefaultErrorMessage in wide char
            L"The application encountered a fatal error and must close. If the problem "
            "persists, please "
            "contact the program maintainer."};
        ::MessageBoxW(nullptr, kWideMsg, L"Fatal Error",
                      MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST);
    } else {
        ::MessageBoxW(nullptr, messageWide.data(), titleWide.data(),
                      MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST);
    }
#else
    if (!ExitHandler::canReadZenityPath && !ExitHandler::canReadKDialogPath) {
        return;
    }
    const ::pid_t pid = ::_Fork();  // Async signal safe.
    if (pid == 0) {
        if (ExitHandler::canReadZenityPath) {
            ::execl(ExitHandler::zenityPath.data(), "zenity", "--error", "--title", title,
                    "--no-markup", "--text", message, nullptr);
        } else if (ExitHandler::canReadKDialogPath) {
            ::execl(ExitHandler::kDialogPath.data(), "kdialog", "--title", title, "--error",
                    message, nullptr);
        }
        ExitHandler::shutdown(EXIT_FAILURE);
        FAULT_UNREACHABLE();
    } else if (pid > 0) {
        ::waitpid(pid, nullptr, 0);  // Wait for user to close box
    }
#endif
}

}  // namespace ExitHandler

#ifdef _WIN32

void safeAppendVEHInfo(struct ::_EXCEPTION_POINTERS* pExc, utils::InlineStringSpan str) noexcept {
    if ((pExc == nullptr) || (pExc->ExceptionRecord == nullptr) ||
        (pExc->ContextRecord == nullptr)) {
        return;
    }
    const ::CONTEXT& ctx = *pExc->ContextRecord;
    std::array<char, 18> regBuff{};
    str.append("\n\nRegisters (x64):");

    static constexpr auto kAddReg = [](const char* name, ::DWORD64 val, utils::InlineStringSpan str,
                                       std::array<char, 18>& buff) {
        str.append(name);
        utils::safeWriteHex(static_cast<std::uintptr_t>(val), buff);
        str.append(std::span{buff});
    };

    kAddReg("\nRIP=", ctx.Rip, str, regBuff);
    kAddReg(" RSP=", ctx.Rsp, str, regBuff);
    kAddReg(" RBP=", ctx.Rbp, str, regBuff);
    kAddReg("\nRAX=", ctx.Rax, str, regBuff);
    kAddReg(" RBX=", ctx.Rbx, str, regBuff);
    kAddReg(" RCX=", ctx.Rcx, str, regBuff);
    kAddReg("\nRDX=", ctx.Rdx, str, regBuff);
    kAddReg(" RDI=", ctx.Rdi, str, regBuff);
    kAddReg(" RSI=", ctx.Rsi, str, regBuff);

    // Flags and Error Context
    str.append("\nEFLAGS=");
    utils::safeWriteHex(static_cast<std::uintptr_t>(ctx.EFlags), regBuff);
    str.appendMulti(std::span{regBuff}, '\n');
}

const char* getExceptionString(::DWORD code) noexcept {
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
    static inline utils::InlineString<128> titleBuffer{};
    static inline utils::InlineString<2048> finalBuffer{};
    static inline std::size_t offsetForMsg{0};
    static inline std::atomic<bool> hasAnyCodeBeenReceived{false};
    static inline std::atomic<bool> reportDone{false};
    static inline std::atomic<bool> popUpReached{false};
    static inline bool wasDumpWritten{false};
    static inline bool showPopUp{true};
    static thread_local inline std::sig_atomic_t tryCount{0};
    static inline ::HANDLE hCrashEvent{nullptr};
    static inline ::HANDLE hWatchdogThread{nullptr};
    static constexpr ::DWORD kTimerMilliseconds{
        static_cast<::DWORD>(_internal::Config::kAlarmSeconds * 1000)};

    static void popUpAction(bool exitAftewards = false) noexcept {
        bool expected{false};
        if (!popUpReached.compare_exchange_strong(expected, true)) {
            ExitHandler::parkThreadForever();
            FAULT_UNREACHABLE();
        }
        if (WindowsHandling::showPopUp) {
            if (WindowsHandling::offsetForMsg >=
                std::strlen(_internal::config.baseErrorMessage.data())) {
                WindowsHandling::finalBuffer.setSize(WindowsHandling::offsetForMsg);
                ExitHandler::showPopUp(WindowsHandling::titleBuffer.getData(),
                                       WindowsHandling::finalBuffer.getData());
            } else {
                ExitHandler::showPopUp("Fatal Error", _internal::config.baseErrorMessage.data());
            }
        }
        if (exitAftewards) {
            ExitHandler::shutdown();
            FAULT_UNREACHABLE();
        }
    }

    static ::DWORD WINAPI watchdogFunction(::LPVOID /*lpParam*/) noexcept {
        ::WaitForSingleObject(
            hCrashEvent,
            INFINITE);  // Waiting indefinitely until it is woken by the crashing process
        ::Sleep(kTimerMilliseconds);
        if (WindowsHandling::reportDone) {
            return EXIT_FAILURE;
        }
        constexpr bool kExit{true};
        WindowsHandling::popUpAction(kExit);
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
            constexpr bool kExit{false};
            WindowsHandling::popUpAction(kExit);
            return false;
        }
        ++WindowsHandling::tryCount;
        return true;
    }

    static bool writeMiniDump(const ::PEXCEPTION_POINTERS exceptionPtrs = nullptr) noexcept {
        std::array<wchar_t, _internal::Config::Windows::dumpPath.size()> dumpPathW{};
        const ::HANDLE hFile = utils::utf8ToUtf16Stack(_internal::Config::Windows::dumpPath.data(),
                                                       dumpPathW.data(), dumpPathW.size())
                                   ? ::CreateFileW(dumpPathW.data(), GENERIC_WRITE, 0, nullptr,
                                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)
                                   : INVALID_HANDLE_VALUE;
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        ::MINIDUMP_EXCEPTION_INFORMATION mei;
        ::MINIDUMP_EXCEPTION_INFORMATION* pMei{nullptr};

        if (exceptionPtrs != nullptr) {
            mei.ThreadId = ::GetCurrentThreadId();
            mei.ExceptionPointers = exceptionPtrs;
            mei.ClientPointers = FALSE;
            pMei = &mei;
        }

        const auto res = ::MiniDumpWriteDump(::GetCurrentProcess(), ::GetCurrentProcessId(), hFile,
                                             MiniDumpNormal, pMei, nullptr, nullptr);

        ::CloseHandle(hFile);

        return res != 0;
    }

    static void doWriteReport(bool printToStderr, bool writeReport,
                              const std::optional<cpptrace::object_trace>& customTrace,
                              bool resolveTrace) noexcept {
        const auto written =
            writeReport ? ExitHandler::writeReport(std::string_view{WindowsHandling::finalBuffer},
                                                   customTrace, resolveTrace)
                        : false;
        if (printToStderr) {
            utils::InlineString<2048> stdErrBfr{};
            stdErrBfr.appendMulti("\n--- FAULT REPORT v", version::kString, " ---\n");
            WindowsHandling::finalBuffer.setSize(WindowsHandling::offsetForMsg);
            stdErrBfr.append(WindowsHandling::finalBuffer);
            if (written) {
                stdErrBfr.appendMulti("\nFull log at: ", _internal::config.crashPath.data());
            } else if (writeReport) {
                stdErrBfr.append("\nCould not generate report.");
            }
            if (WindowsHandling::wasDumpWritten) {
                stdErrBfr.appendMulti("\nMini dump generated at: ",
                                      _internal::Config::Windows::dumpPath.data());
            }
            stdErrBfr.append("\n--- FAULT END ---\n");
            ExitHandler::writeToStdErr(std::string_view{stdErrBfr});
        }
        WindowsHandling::reportDone = true;
    }

    static void writeSummaryMessageToBuffer(const ::PEXCEPTION_POINTERS pExc, std::string_view msg,
                                            std::string_view details) noexcept {
        WindowsHandling::titleBuffer.appendMulti(_internal::config.appName.data(), " Fatal Error");
        char* pszDestEnd = nullptr;
        std::size_t remaining{0};
        const auto filteredMsg = msg.empty() ? "<no message>" : msg;
        WindowsHandling::finalBuffer.appendFmt(
            "{}\n\nDescription: {}\n", std::string_view{_internal::config.baseErrorMessage.data()},
            std::string_view{filteredMsg.data(), filteredMsg.size()});
        if ((pExc != nullptr) && (pExc->ExceptionRecord != nullptr)) {
            const ::EXCEPTION_RECORD& rec = *pExc->ExceptionRecord;
            WindowsHandling::finalBuffer.appendMulti(
                "Exception Code: ", static_cast<std::uintptr_t>(rec.ExceptionCode), '\n');
            // If it's an Access Violation, ExceptionInformation[1] is the faulting address
            if (rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec.NumberParameters >= 2) {
                WindowsHandling::finalBuffer.appendMulti(
                    "Fault Address: ", static_cast<std::uintptr_t>(rec.ExceptionInformation[1]),
                    '\n');
            }
        }
        WindowsHandling::finalBuffer.append('\n');
        utils::writePreciseTimeSafe(WindowsHandling::finalBuffer.span(),
                                    _internal::gInitTime.str.data(), _internal::gInitTime.tvSec,
                                    _internal::gInitTime.tvNsec, _internal::gInitTime.written);
        WindowsHandling::offsetForMsg = WindowsHandling::finalBuffer.getSize();
        if (!details.empty()) {
            WindowsHandling::finalBuffer.appendMulti("\nTechnical comments:\n", details);
        }
        safeAppendVEHInfo(pExc, WindowsHandling::finalBuffer.span());
    }

    static void commonActions(const ::PEXCEPTION_POINTERS exceptionInfo, bool printToStderr,
                              bool writeReport,
                              const std::optional<cpptrace::object_trace>& customTrace,
                              bool resolveTrace) noexcept {
        if (hCrashEvent != nullptr && hCrashEvent != INVALID_HANDLE_VALUE) {
            ::SetEvent(hCrashEvent);
        }
        if (_internal::Config::Windows::canWriteDump) {
            WindowsHandling::wasDumpWritten = WindowsHandling::writeMiniDump(exceptionInfo);
        }
        WindowsHandling::doWriteReport(printToStderr, writeReport, customTrace, resolveTrace);
        constexpr bool kExit{false};
        WindowsHandling::popUpAction(kExit);
    }

    static void windowsCommonProcessSignalEvent(const ::PEXCEPTION_POINTERS exceptionInfo,
                                                std::string_view description) noexcept {
        if (!WindowsHandling::checkPermissions()) {
            return;
        }
        WindowsHandling::showPopUp = _internal::config.showPopUp;
        constexpr std::string_view kDetails{};
        WindowsHandling::writeSummaryMessageToBuffer(exceptionInfo, description, kDetails);
        constexpr bool kWriteReport{true};
        constexpr bool kResolveTrace{false};
        const std::optional<cpptrace::object_trace> kTrace{std::nullopt};
        WindowsHandling::commonActions(exceptionInfo, _internal::config.printMsgToStdErr,
                                       kWriteReport, kTrace, kResolveTrace);
    }

    static void initHandles() noexcept {
        WindowsHandling::hCrashEvent = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);
        // Pre-spawn the thread while the system is healthy, it immediately goes to sleep until
        // needed
        WindowsHandling::hWatchdogThread =
            ::CreateThread(nullptr, 0, WindowsHandling::watchdogFunction, nullptr, 0, nullptr);
        if (WindowsHandling::hWatchdogThread != nullptr) {
            ::SetThreadPriority(WindowsHandling::hWatchdogThread, THREAD_PRIORITY_HIGHEST);
        }
    }

    [[noreturn]] static void winAbortHandler(int /*sig*/) noexcept {
        constexpr ::DWORD kAbortCode{3};
        constexpr ::PEXCEPTION_POINTERS kNoContextPtr{nullptr};
        WindowsHandling::windowsCommonProcessSignalEvent(
            kNoContextPtr,
            "Abort called");  // trace, stdcerr error, gui popup
        ExitHandler::shutdown(kAbortCode);
        FAULT_UNREACHABLE();
    }

    static ::LONG WINAPI
    windowsExceptionHandler(const ::PEXCEPTION_POINTERS exceptionInfo) noexcept {
        const ::DWORD code = exceptionInfo->ExceptionRecord->ExceptionCode;
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
            exceptionInfo,
            description);  // trace, stdcerr error, gui popup
        return EXCEPTION_EXECUTE_HANDLER;
    }

   public:
    [[nodiscard]] static bool hasAnySignalBeenTriggered() noexcept {
        return WindowsHandling::hasAnyCodeBeenReceived;
    }

    [[noreturn]] static void fromTerminate(std::string_view msg, std::string_view details, int code,
                                           bool printToStderr, bool writeReport,
                                           const std::optional<cpptrace::object_trace>& customTrace,
                                           bool showPopUp, bool resolveTrace) noexcept {
        if (!WindowsHandling::checkPermissions()) {
            ExitHandler::shutdown(code);
            FAULT_UNREACHABLE();
        }
        WindowsHandling::showPopUp = showPopUp;
        constexpr ::PEXCEPTION_POINTERS kPExceptionInfo{nullptr};
        WindowsHandling::writeSummaryMessageToBuffer(kPExceptionInfo, msg, details);
        WindowsHandling::commonActions(kPExceptionInfo, printToStderr, writeReport, customTrace,
                                       resolveTrace);
        ExitHandler::shutdown(code);
        FAULT_UNREACHABLE();
    }

    static void setup(bool enableHandlers, bool enableShutdownRequest) noexcept {
        constexpr auto kBytesToReserve = static_cast<std::size_t>(64U * 1024U);
        auto stackSize = static_cast<ULONG>(kBytesToReserve);
        ::SetThreadStackGuarantee(&stackSize);
        WindowsHandling::initHandles();
        WindowsHandling::tryCount =
            0;  // Explicit load (in case thread_local would behave in a lazy way)
        if (enableHandlers) {
            ::SetUnhandledExceptionFilter(WindowsHandling::windowsExceptionHandler);
            std::signal(SIGABRT, WindowsHandling::winAbortHandler);
        }
        if (enableShutdownRequest) {
            std::signal(SIGINT, [](int /*sig*/) { fault::set_shutdown_request(); });
            std::signal(SIGTERM, [](int /*sig*/) { fault::set_shutdown_request(); });
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

void safeAppendRegisters(const ::ucontext_t* ctx, utils::InlineStringSpan str) noexcept {
#ifdef __x86_64__
    if (ctx == nullptr) {
        return;
    }

    const auto& g = ctx->uc_mcontext.gregs;
    std::array<char, 18> regBuff{};
    utils::safeWriteHex(g[REG_RIP], regBuff);

    // 1. Instruction and Stack Pointers (The "Big Three")
    str.appendMulti("\nRegisters:\nRIP=", std::span{regBuff});

    utils::safeWriteHex(g[REG_RSP], regBuff);
    str.appendMulti(" RSP=", std::span{regBuff});
    utils::safeWriteHex(g[REG_RBP], regBuff);
    str.appendMulti(" RBP=", std::span{regBuff});

    // 2. Common General Purpose Registers (Helpful for finding null pointers/args)
    utils::safeWriteHex(g[REG_RAX], regBuff);
    str.appendMulti("\nRAX=", std::span{regBuff});
    utils::safeWriteHex(g[REG_RBX], regBuff);
    str.appendMulti(" RBX=", std::span{regBuff});
    utils::safeWriteHex(g[REG_RCX], regBuff);
    str.appendMulti(" RCX=", std::span{regBuff});
    utils::safeWriteHex(g[REG_RDX], regBuff);
    str.appendMulti(" RDX=", std::span{regBuff});

    // 3. Argument Registers (RDI/RSI often contain the pointers being processed)
    utils::safeWriteHex(g[REG_RDI], regBuff);
    str.appendMulti("\nRDI=", std::span{regBuff});
    utils::safeWriteHex(g[REG_RSI], regBuff);
    str.appendMulti(" RSI=", std::span{regBuff});

    // 4. Hardware Error Code (Very useful for SEGV analysis)
    utils::safeWriteHex(g[REG_ERR], regBuff);
    str.appendMulti(" ERR=", std::span{regBuff}, '\n');
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
#if FAULT_EXCEPTIONS
    try {
#endif
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
            if (std::filesystem::exists(fullPath, ec) && ::access(fullPath.c_str(), X_OK) == 0) {
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
#if FAULT_EXCEPTIONS
    } catch (...) {
        return false;
    }
#endif
}

struct LinuxHandling {
    static_assert(std::atomic<::pid_t>::is_always_lock_free,
                  "std::atomic<pid_t> may not be lock free. Remove std::atomic from it.");

    static inline ::stack_t gAltstack{};

   private:
    static inline utils::InlineString<128> titleBuffer{};
    static inline utils::InlineString<2048> finalBuffer{};
    static inline std::size_t offsetForMsg{0};
    static inline std::atomic<::pid_t> tracePid{-1};
    static inline std::atomic<bool> hasAnySignalBeenReceived{false};
    static thread_local inline std::sig_atomic_t tryCount{};
    static inline std::sig_atomic_t signal{-1};
    static inline std::atomic<bool> popUpReached{false};
    static inline bool showPopUp{true};
    static inline bool shouldReRaiseSignal{true};

    [[noreturn]] static void reRaiseSignal(int sig) noexcept {
        struct ::sigaction sa{};
        sa.sa_handler = SIG_DFL;
        ::sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        ::sigaction(sig, &sa, nullptr);
        ::sigset_t set;
        ::sigemptyset(&set);
        ::sigaddset(&set, sig);
        ::pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
        std::raise(sig);
        ExitHandler::shutdown(128 + sig);
        FAULT_UNREACHABLE();
    }

    [[noreturn]] static void popUpAndExit([[maybe_unused]] int sig = -1) noexcept {
        if (LinuxHandling::tracePid > 0) {  // Something went wrong during trace logging, kill it as
                                            // to not become a zombie process
            ::kill(LinuxHandling::tracePid, SIGKILL);
            LinuxHandling::tracePid = -1;
        }
        bool expected{false};
        if (!LinuxHandling::popUpReached.compare_exchange_strong(expected, true))
            [[unlikely]] {  // In case alarm and report would trigger concurrently
            ExitHandler::parkThreadForever();
            FAULT_UNREACHABLE();
        }
        if (LinuxHandling::offsetForMsg >= std::strlen(_internal::config.baseErrorMessage.data()))
            [[likely]] {
            LinuxHandling::finalBuffer.setSize(LinuxHandling::offsetForMsg);
            if (LinuxHandling::showPopUp) {
                ExitHandler::showPopUp(LinuxHandling::titleBuffer.getData(),
                                       LinuxHandling::finalBuffer.getData());
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

    static void writeSummaryMessageToBuffer(std::string_view description) noexcept {
        LinuxHandling::titleBuffer.clear();  // Redundancy
        LinuxHandling::titleBuffer.appendMulti(_internal::config.appName.data(), " Fatal Error");
        LinuxHandling::finalBuffer.appendMulti(_internal::config.baseErrorMessage.data(),
                                               "\n\nDescription: ");
        const auto filteredMsg = description.empty() ? "<no message>" : description;
        LinuxHandling::finalBuffer.appendMulti(filteredMsg, "\n\n");
        utils::writePreciseTimeSafe(LinuxHandling::finalBuffer.span(),
                                    _internal::gInitTime.str.data(), _internal::gInitTime.tvSec,
                                    _internal::gInitTime.tvNsec, _internal::gInitTime.written);
    }

    static void writeSummaryMessageToBuffer(const ::siginfo_t* info) noexcept {
        LinuxHandling::titleBuffer.appendMulti(_internal::config.appName.data(), " Fatal Error");
        LinuxHandling::finalBuffer.appendMulti(_internal::config.baseErrorMessage.data(),
                                               "\n\nSignal Event: ");
        switch (LinuxHandling::signal) {
            case SIGSEGV:
                LinuxHandling::finalBuffer.append("SIGSEGV");
                break;
            case SIGABRT:
                LinuxHandling::finalBuffer.append("SIGABRT");
                break;
            case SIGFPE:
                LinuxHandling::finalBuffer.append("SIGFPE");
                break;
            case SIGILL:
                LinuxHandling::finalBuffer.append("SIGILL");
                break;
            case SIGBUS:
                LinuxHandling::finalBuffer.append("SIGBUS");
                break;
            default: {
                LinuxHandling::finalBuffer.append("Unknown signal");
                break;
            }
        }
        LinuxHandling::finalBuffer.append('\n');
        if (info != nullptr) {
            LinuxHandling::finalBuffer.appendMulti(
                "Reason: ", safePrintSiCode(LinuxHandling::signal, info->si_code),
                "\nFault address: ");
            std::array<char, 18> addrBuff{};
            utils::safeWriteHex(reinterpret_cast<std::uintptr_t>(info->si_addr), addrBuff);
            LinuxHandling::finalBuffer.appendMulti(std::span{addrBuff}, "\n\n");
        }
        utils::writePreciseTimeSafe(LinuxHandling::finalBuffer.span(),
                                    _internal::gInitTime.str.data(), _internal::gInitTime.tvSec,
                                    _internal::gInitTime.tvNsec, _internal::gInitTime.written);
    }

    static void writeReportDetailsToBuffer(const ::ucontext_t* ctx) noexcept {
        safeAppendRegisters(ctx, LinuxHandling::finalBuffer.span());
    }

    [[noreturn]] static void doWriteToFile(
        bool printToStderr, bool writeReport,
        const std::optional<cpptrace::object_trace>& customTrace = std::nullopt,
        bool resolveTrace = false) noexcept {
        const auto written =
            writeReport ? ExitHandler::writeReport(std::string_view{LinuxHandling::finalBuffer},
                                                   customTrace, resolveTrace)
                        : false;
        if (printToStderr) {
            utils::InlineString<2048> stdErrBfr{};
            stdErrBfr.appendMulti("\n--- FAULT REPORT v", version::kString, " ---\n");
            LinuxHandling::finalBuffer.setSize(LinuxHandling::offsetForMsg);
            stdErrBfr.appendMulti(LinuxHandling::finalBuffer);
            if (written) {
                stdErrBfr.appendMulti("\nFull log at: ", _internal::config.crashPath.data());
            } else if (writeReport) {
                stdErrBfr.append("\nCould not generate report.\n");
            }
            stdErrBfr.append("\n--- FAULT END ---\n");
            ExitHandler::writeToStdErr(std::string_view{stdErrBfr});
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

    [[noreturn]] static void linuxSignalHandler(int sig, ::siginfo_t* info, void* uctx) noexcept {
        LinuxHandling::checkPermissions();
        LinuxHandling::signal = sig;
        LinuxHandling::showPopUp = _internal::config.showPopUp;
        LinuxHandling::shouldReRaiseSignal = _internal::config.signal.raiseDefaultAfterwards;
        LinuxHandling::writeSummaryMessageToBuffer(info);
        LinuxHandling::offsetForMsg = LinuxHandling::finalBuffer.getSize();
        LinuxHandling::writeReportDetailsToBuffer(static_cast<const ::ucontext_t*>(uctx));
        constexpr bool kResolveTrace{false};
        constexpr std::optional<cpptrace::object_trace> kTrace{std::nullopt};
        constexpr bool kWriteReport{true};
        LinuxHandling::commonActions(_internal::config.printMsgToStdErr, kWriteReport, kTrace,
                                     kResolveTrace);
        FAULT_UNREACHABLE();
    }

    [[noreturn]] static void commonActions(bool printToStderr, bool writeReport,
                                           const std::optional<cpptrace::object_trace>& customTrace,
                                           bool resolveTrace) noexcept {
        struct ::sigaction sa{};
        ::sigfillset(&sa.sa_mask);
        sa.sa_handler = LinuxHandling::popUpAndExit;
        ::sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        ::sigaction(SIGALRM, &sa, nullptr);   // Protect against deadlocks
        LinuxHandling::tracePid = ::_Fork();  // Async signal safe.
        if (LinuxHandling::tracePid == 0) {   // Child process
            LinuxHandling::doWriteToFile(printToStderr, writeReport, customTrace, resolveTrace);
            FAULT_UNREACHABLE();
        } else if (LinuxHandling::tracePid > 0) {  // Parent process
            ::alarm(_internal::Config::kAlarmSeconds);
            ::waitpid(LinuxHandling::tracePid, nullptr,
                      0);  // Wait for trace collection, or until alarm hits
            ::alarm(0);
            LinuxHandling::tracePid = -1;
        }
        LinuxHandling::popUpAndExit();
        FAULT_UNREACHABLE();
    }

   public:
    [[nodiscard]] static ::pid_t getTracePid() noexcept {
        return LinuxHandling::tracePid;
    }
    [[nodiscard]] static bool hasAnySignalBeenTriggered() noexcept {
        return LinuxHandling::hasAnySignalBeenReceived;
    }

    [[noreturn]] static void fromTerminate(std::string_view msg, std::string_view details, int code,
                                           bool printToStderr, bool writeReport,
                                           const std::optional<cpptrace::object_trace>& customTrace,
                                           bool showPopUp, bool resolveTrace) noexcept {
        LinuxHandling::checkPermissions();
        LinuxHandling::signal = code;
        LinuxHandling::showPopUp = showPopUp;
        LinuxHandling::shouldReRaiseSignal = true;
        LinuxHandling::writeSummaryMessageToBuffer(msg);
        LinuxHandling::offsetForMsg = LinuxHandling::finalBuffer.getSize();
        if (!details.empty()) {
            LinuxHandling::finalBuffer.appendMulti("\nTechnical comments: ", details);
        }
        LinuxHandling::commonActions(printToStderr, writeReport, customTrace, resolveTrace);
        FAULT_UNREACHABLE();
    }

    static void setup(bool enableHandlers, bool enableShutdownRequest) noexcept {
        ExitHandler::canReadZenityPath = false;
        ExitHandler::canReadZenityPath = findProgramInPath("zenity", ExitHandler::zenityPath.data(),
                                                           ExitHandler::zenityPath.size());
        ExitHandler::canReadKDialogPath = false;
        ExitHandler::canReadKDialogPath = findProgramInPath(
            "kdialog", ExitHandler::kDialogPath.data(), ExitHandler::kDialogPath.size());
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
        ::sigaltstack(&LinuxHandling::gAltstack, nullptr);

        // Signal handlers
        struct ::sigaction sa{};
        sa.sa_sigaction = LinuxHandling::linuxSignalHandler;
        ::sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        const std::array<int, 5> sigs = {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT};
        for (int s : sigs) {
            ::sigaction(s, &sa, nullptr);
        }
        if (enableShutdownRequest) {
            std::signal(SIGINT, [](int /*sig*/) { fault::set_shutdown_request(); });
            std::signal(SIGTERM, [](int /*sig*/) { fault::set_shutdown_request(); });
        }
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
   public:
    struct Settings {
        bool writeReport{true};
        bool printToStdErr{true};
        bool showPopUp{true};
    };

   private:
    static inline std::atomic<bool> hasBeenTriggered{
        false};  // Protection against multi threading calling std::terminate concurrently
    static inline v1::TerminateHook terminateHook{nullptr};

    [[nodiscard]] static bool shouldExecuteHandler() noexcept {
        bool expected{false};
        // Another thread has concurrently hit either a terminate handler or a signal handler
        // (higher priority)
        return !hasAnySignalBeenTriggered() &&
               TerminateHandling::hasBeenTriggered.compare_exchange_strong(expected, true);
    }

    static void retrieveCurrentException(utils::InlineStringSpan msg,
                                         utils::InlineStringSpan detail) noexcept {
#if FAULT_EXCEPTIONS
        try {
            const std::exception_ptr exPtr =
                std::current_exception();  // Last exception (Could be from regular code or
                                           // throwing destructor)
            if (exPtr) {
                std::rethrow_exception(exPtr);
            }
            msg.append("Terminate called.");
            detail.append("Terminate was reached without an active exception.\n");
        } catch (const std::exception& e) {
            msg.appendFmt("Terminate called due to an unhandled exception: {}.", e.what());
            detail.appendFmt(
                "Terminate called due to an unhandled exception.\n"
                "Type (mangled): {}\nMessage: {}\n",
                typeid(e).name(), e.what());
        } catch (...) {
            msg.append("Terminate called due to an unhandled exception.");
            detail.append(
                "Terminate called due to an unhandled exception of non-std::exception type.\n");
        }
#else
        msg.append("Terminate called.");
        detail.append(
            "Terminate was reached. Exception type cannot be retrieved (Given 'No "
            "Exception' flag).\n");
#endif
    }

    static void runTerminateHook(utils::InlineStringSpan msg, utils::InlineStringSpan detail,
                                 std::optional<cpptrace::object_trace>& trace) noexcept {
        if (TerminateHandling::terminateHook == nullptr) {
            return;
        }
#if FAULT_EXCEPTIONS
        try {
#endif
            std::optional<v1::ObjectTrace> faultTrace =
                trace.has_value() ? adapter::v1::from_cpptrace(*trace) : std::nullopt;
            TerminateHandling::terminateHook(std::string_view{msg}, faultTrace);
            trace = faultTrace.has_value() ? adapter::v1::to_cpptrace(*faultTrace) : std::nullopt;
#if FAULT_EXCEPTIONS
        } catch (...) {
            detail.append(
                "Note: user provided terminate hook incurred in an "
                "exception, and may not have "
                "been properly handled. This will not affect the report.\n");
        }
#endif
    }

    [[nodiscard]] static std::optional<cpptrace::object_trace> retrieveTraceWithMsg(
        utils::InlineStringSpan detail,
        const std::optional<v1::ObjectTrace>& customTrace) noexcept {
        std::optional<cpptrace::object_trace> cppObjTrace{};
        bool generateTrace{!customTrace.has_value()};
        if (customTrace.has_value()) {
            const auto& refCustomTrace = *customTrace;
            if (refCustomTrace.frames.empty()) {
                detail.append("Note: user provided empty trace. Generating a default one.\n");
                generateTrace = true;
            } else if (auto optAdaptTrace = adapter::to_cpptrace(*customTrace);
                       !optAdaptTrace.has_value()) {
                detail.append(
                    "Note: Internal error on user provided trace. "
                    "Generating a default one.\n");
                generateTrace = true;
            } else {
                cppObjTrace = std::move(optAdaptTrace).value();
            }
        }
        if (!generateTrace) {
            return cppObjTrace;
        }
        if (cppObjTrace = utils::getSafeObjectTrace(); !cppObjTrace.has_value()) {
            detail.append(
                "Note: an internal error has occured while generating an object "
                "trace. Base trace won't be reported.\n");
        }
        return cppObjTrace;
    }

    // Appends messages and traces for uncaught exceptions and for user saved traces/exceptions
    static void checkCommonExceptions([[maybe_unused]] utils::InlineStringSpan msg,
                                      utils::InlineStringSpan detail,
                                      std::optional<cpptrace::object_trace>& trace) noexcept {
#if FAULT_EXCEPTIONS
        try {
#endif
            const auto uncaughtExp = std::uncaught_exceptions();
            if (uncaughtExp > 0) {
                detail.appendFmt(
                    "Note: Stack unwinding was in progress when std::terminate was called "
                    "(std::uncaught_exceptions = {}).\n",
                    uncaughtExp);
                if (auto optExceptionTrace = utils::tryGetObjectTraceFromException();
                    optExceptionTrace
                        .has_value()) {  // Will only exist when cpptrace intercepted it
                                         // (implies consumer uses cpptrace try/catch)
                    auto& exceptionTrace = *optExceptionTrace;
                    if (!trace.has_value()) {
                        trace = cpptrace::object_trace{};
                    }
                    trace->frames.push_back(
                        cpptrace::object_frame{.raw_address = 0,
                                               .object_address = 0,
                                               .object_path = {"====== UPSTREAM ======"}});
                    trace->frames.insert(trace->frames.end(),
                                         std::make_move_iterator(exceptionTrace.frames.begin()),
                                         std::make_move_iterator(exceptionTrace.frames.end()));
                    detail.append(
                        "The initial unwind was saved and should be displayed "
                        "below, under '====== "
                        "UPSTREAM ======' artifitial frame.\n");
                }
            }
#if FAULT_EXCEPTIONS
            exceptions::rethrowAndAppendSavedExceptionTrace(trace, msg, detail);
        } catch (...) {
            detail.append(
                "\n[Internal error while appending data from uncaught exception and "
                "saved exceptions]\n");
        }
#endif
        hook::invokeAndSave(detail);
    }

    [[nodiscard]] static bool hasTerminateOrHigherBeenReached() noexcept {
        return hasAnySignalBeenTriggered() || TerminateHandling::hasBeenTriggered;
    }
    [[noreturn]] static void controlledShutdown(
        std::string_view message, std::string_view details, const Settings& settings,
        const std::optional<cpptrace::object_trace>& customTrace) noexcept {
#ifdef __linux__
        constexpr int kTerminateCode{SIGABRT};
        LinuxHandling::fromTerminate(message, details, kTerminateCode, settings.printToStdErr,
                                     settings.writeReport, customTrace, settings.showPopUp,
                                     _internal::config.resolveNonSignalTrace);
#else
        constexpr int kTerminateCode{3};
        WindowsHandling::fromTerminate(message, details, kTerminateCode, settings.printToStdErr,
                                       settings.writeReport, customTrace, settings.showPopUp,
                                       _internal::config.resolveNonSignalTrace);
#endif
        FAULT_UNREACHABLE();
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
        const std::optional<std::string_view> startMsg{std::nullopt};
        constexpr std::optional<const v1::ObjectTrace> kTrace{std::nullopt};
        TerminateHandling::terminateImpl(
            startMsg, Type::kStdTerminate,
            Settings{.writeReport = true,
                     .printToStdErr = _internal::config.printMsgToStdErr,
                     .showPopUp = _internal::config.showPopUp},
            kTrace);
        FAULT_UNREACHABLE();
    }

   public:
    enum class Type : std::uint8_t { kStdTerminate, kPanic };

    static void terminateImpl(std::optional<std::string_view> startMsg, Type type,
                              const Settings& settings,
                              const std::optional<v1::ObjectTrace>& customTrace) noexcept {
        utils::InlineString<1024> userMsg{};
        utils::InlineString<2048> details{};
        details.append(type == Type::kStdTerminate ? "Reason: std::terminate triggered.\n"
                                                   : "Reason: panic triggered.\n");

        if (startMsg.has_value()) {
            const auto& startMsgVal = *startMsg;
            if (!startMsgVal.empty()) {
                userMsg.append(startMsgVal);
            } else {
                userMsg.append("<no message>");
            }
        }
        auto cppObjTrace = TerminateHandling::retrieveTraceWithMsg(details.span(), customTrace);
        if (type == Type::kStdTerminate) {
            TerminateHandling::retrieveCurrentException(userMsg.span(), details.span());
        }
        TerminateHandling::checkCommonExceptions(userMsg.span(), details.span(), cppObjTrace);
        if (type == Type::kStdTerminate) {
            TerminateHandling::runTerminateHook(userMsg.span(), details.span(), cppObjTrace);
        }
        if (hasAnySignalBeenTriggered()) {
            ExitHandler::parkThreadForever();
            FAULT_UNREACHABLE();
        }
        TerminateHandling::controlledShutdown(std::string_view{userMsg}, std::string_view{details},
                                              settings, cppObjTrace);
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
    [[maybe_unused]] std::size_t frames =
        cpptrace::safe_generate_raw_trace(buffer.data(), buffer.size());
    cpptrace::safe_object_frame frame{};
    cpptrace::get_safe_object_frame(buffer[0], &frame);
}

void setup(bool enableHandlers, bool enableShutdownRequest) noexcept {
#ifdef _WIN32
    WindowsHandling::setup(enableHandlers, enableShutdownRequest);
#else
    LinuxHandling::setup(enableHandlers, enableShutdownRequest);
#endif
}

void doInit() noexcept {
    warmupCpptrace();  // If cpptrace is a shared library (it is currently), ensures proper
                       // dynamic page loading in case it would otherwise behave in a lazy
                       // implementation that could compromise it's use in a signal handler
    const auto& config = _internal::config;
    if (config.terminate.enable) {
        TerminateHandling::setup();
    }
    setup(config.signal.enable, config.signal.enableShutdownRequest);
}

[[nodiscard]] InitResult tryInit(const v1::Config& config) noexcept {
    static std::atomic<bool> isInit{false};
    bool expected{false};
    if (!isInit.compare_exchange_strong(expected, true)) {
        return {.success = true, .warnings = v1::ConfigWarning::kAlreadyInitialized};
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

MAYBE_INLINED_NAMESPACE_V1 {
    namespace {

    ::FaultInitResultV1 fromCppInitResult(InitResult cppRes) noexcept {
        return ::FaultInitResultV1{.success = cppRes.success,
                                   .warnings = static_cast<::FaultConfigWarningV1>(
                                       static_cast<std::uint8_t>(cppRes.warnings))};
    }

    }  // namespace

    bool set_shutdown_request() noexcept {
        bool expected{false};
        return shutdownRequest.compare_exchange_strong(expected, true);
    }

    bool has_shutdown_request() noexcept {
        return shutdownRequest.load(std::memory_order_acquire);
    }

    bool can_collect_safe_trace() noexcept {
        return cpptrace::can_signal_safe_unwind() && cpptrace::can_get_safe_object_frame();
    }

    bool has_saved_traced_exception() noexcept {
        return exceptions::pendingException != nullptr;
    }

    InitResult init(const Config& config) noexcept {
        return tryInit(config);
    }

    void save_traced_exception(std::string_view msg, const std::optional<ObjectTrace>& customTrace,
                               std::optional<std::string> excpTypeStr) noexcept {
        exceptions::saveException(msg, customTrace, std::move(excpTypeStr));
    }

    void panic_impl(std::string_view message,
                    const std::optional<ObjectTrace>& customTrace) noexcept {
        TerminateHandling::terminateImpl(
            std::optional{message}, TerminateHandling::Type::kPanic,
            TerminateHandling::Settings{.writeReport = _internal::config.panic.writeReport,
                                        .printToStdErr = _internal::config.panic.printMsgToStdErr,
                                        .showPopUp = _internal::config.panic.showPopUp},
            customTrace);
        FAULT_UNREACHABLE();
    }

    void panic_at(std::string_view expr, std::string_view file, std::uint32_t line,
                  std::string_view func, std::string_view userMsg) noexcept {
        utils::InlineString<1024> msg{};
        msg.append("Assertion failed");
        if (!expr.empty()) {
            msg.appendMulti(": ", expr);
        }
        if (!userMsg.empty()) {
            msg.appendMulti(" | ", userMsg);
        }
        msg.appendMulti(" @ ", file, ':', utils::Itoa{line});
        if (!func.empty()) {
            msg.appendMulti(" (", func, ')');
        }

        constexpr const std::optional<const ObjectTrace> kNoExceptionTrace{std::nullopt};
        panic_impl(std::string_view{msg}, kNoExceptionTrace);
        FAULT_UNREACHABLE();
    }

    void panic_at(std::string_view expr, std::source_location loc,
                  std::string_view userMsg) noexcept {
        panic_at(expr, loc.file_name(), loc.line(), loc.function_name(), userMsg);
        FAULT_UNREACHABLE();
    }

    void try_catch(std::function<void()> body, [[maybe_unused]] CatchPolicy catchPolicy,
                   [[maybe_unused]] std::function<std::string(
                       std::exception_ptr ep, const std::optional<ObjectTrace>& trace)>
                       onException) noexcept {
#if FAULT_EXCEPTIONS
        bool onExceptionCalled{
            false};  // cpptrace actually recursively wraps lambda pairs until a remaining pair
                     // exist, meaning that for the 3 current callables, unwind interceptor will be
                     // in place twice, and it's possible for both catch callables to be called in
                     // an edge case scenario where the first catch also throws. Therefore, this is
                     // to protect against the user callback being called twice.

        const auto kOnCatch = [&onException, &onExceptionCalled, catchPolicy](
                                  std::string_view msg = "",
                                  std::optional<std::string> excpTypeName = std::nullopt) {
            auto cppObjTrace = utils::tryGetObjectTraceFromException();
            if (!cppObjTrace.has_value()) {
                cppObjTrace = utils::getSafeObjectTrace();
            }
            const auto objectTrace =
                cppObjTrace.has_value()
                    ? std::optional<ObjectTrace>(fault::adapter::from_cpptrace(*cppObjTrace))
                    : std::optional<ObjectTrace>{std::nullopt};
            auto effectiveMsg = msg;
            std::string userMsg;
            try {
                if (!onExceptionCalled && onException != nullptr) {
                    onExceptionCalled = true;
                    userMsg = onException(std::current_exception(), objectTrace);
                    if (!userMsg.empty()) {
                        effectiveMsg = userMsg;
                    }
                }
            } catch (...) {
                effectiveMsg = msg;
            }
            switch (catchPolicy) {
                case CatchPolicy::kPanic: {
                    panic_impl(effectiveMsg, objectTrace);
                    FAULT_UNREACHABLE();
                }
                case CatchPolicy::kSaveExceptionWithShutdownRequest: {
                    save_traced_exception(effectiveMsg, objectTrace, std::move(excpTypeName));
                    set_shutdown_request();
                    return;
                }
                case CatchPolicy::kNothing:
                    return;
            }
            FAULT_UNREACHABLE();
        };
        cpptrace::try_catch(
            std::move(body),
            [&kOnCatch](const std::exception& e) { kOnCatch(e.what(), typeid(e).name()); },
            [&kOnCatch]() { kOnCatch(); });
#else
        body();
#endif
    }

    PanicGuardBase::PanicGuardBase(PanicHook callback, HookScope scope,
                                   const std::optional<std::source_location>& loc)
        : scope_{scope} {
        if (scope == HookScope::kThreadLocal) {
            for (std::size_t i{0}; i < hook::kMaxPanicHooks; ++i) {
                if (!hook::threadCallbacks[i].f) {
                    hook::threadCallbacks[i] = {.f = std::move(callback), .loc = loc};
                    idx_ = i;
                    active_ = true;
                    return;
                }
            }
            return;
        }
        std::scoped_lock lock{hook::globalMutex};
        for (std::size_t i{0}; i < hook::kMaxPanicHooks; ++i) {
            if (!hook::globalCallbacks[i].f) {
                hook::globalCallbacks[i] = {.f = std::move(callback), .loc = loc};
                idx_ = i;
                active_ = true;
                return;
            }
        }
    }

    void PanicGuardBase::release() noexcept {
        if (!active_) {
            return;
        }
        if (scope_ == HookScope::kThreadLocal) {
            hook::threadCallbacks[idx_].release();
            active_ = false;
            return;
        }
        std::scoped_lock lock{hook::globalMutex};
        hook::globalCallbacks[idx_].release();
        active_ = false;
    }

    PanicGuardBase::~PanicGuardBase() noexcept {
        release();
    }

    UnwindGuardBase::UnwindGuardBase(PanicHook callback, std::optional<std::source_location> loc)
        : callback_{std::move(callback)},
          sourceLoc_{loc},
          uncaughtExps_{std::uncaught_exceptions()} {}

    UnwindGuardBase::~UnwindGuardBase() noexcept {
        if (std::uncaught_exceptions() <= uncaughtExps_ || callback_ == nullptr) {
            return;
        }
        hook::invokeAndSaveUnwind(callback_, sourceLoc_);
    }

    void UnwindGuardBase::release() noexcept {
        callback_ = nullptr;
    }

    void UnwindGuardBase::resetBuffer() noexcept {
        hook::resetBuffer();
    }

    FailGuardBase::FailGuardBase(PanicHook callback, HookScope scope,
                                 std::optional<std::source_location> loc)
        : scope_{scope}, uncaughtExps_{std::uncaught_exceptions()} {
        if (scope == HookScope::kThreadLocal) {
            for (std::size_t i{0}; i < hook::threadCallbacks.size(); ++i) {
                if (!hook::threadCallbacks[i].f) {
                    hook::threadCallbacks[i] = {.f = std::move(callback), .loc = loc};
                    idx_ = i;
                    active_ = true;
                    return;
                }
            }
            return;
        }
        std::scoped_lock lock{hook::globalMutex};
        for (std::size_t i{0}; i < hook::kMaxPanicHooks; ++i) {
            if (!hook::globalCallbacks[i].f) {
                hook::globalCallbacks[i] = {.f = std::move(callback), .loc = loc};
                idx_ = i;
                active_ = true;
                return;
            }
        }
    }

    void FailGuardBase::release() noexcept {
        if (!active_) {
            return;
        }
        if (scope_ == HookScope::kThreadLocal) {
            hook::threadCallbacks[idx_].release();
            active_ = false;
            return;
        }
        std::scoped_lock lock{hook::globalMutex};
        hook::globalCallbacks[idx_].release();
        active_ = false;
    }

    void FailGuardBase::resetBuffer() noexcept {
        hook::resetBuffer();
    }

    FailGuardBase::~FailGuardBase() noexcept {
        if (!active_ || std::uncaught_exceptions() <= uncaughtExps_) {
            release();
            return;
        }
        if (scope_ == HookScope::kThreadLocal) {
            if (hook::threadCallbacks[idx_].f == nullptr) {
                return;
            }
            hook::invokeAndSaveUnwind(hook::threadCallbacks[idx_].f,
                                      hook::threadCallbacks[idx_].loc);
            hook::threadCallbacks[idx_].release();
            active_ = false;
            return;
        }
        std::unique_lock lock{hook::globalMutex};
        if (hook::globalCallbacks[idx_].f == nullptr) {
            return;
        }
        lock.unlock();
        hook::invokeAndSaveUnwind(hook::globalCallbacks[idx_].f, hook::globalCallbacks[idx_].loc);
        lock.lock();
        hook::globalCallbacks[idx_].release();
        active_ = false;
    }

}  // namespace v1

}  // namespace fault

extern "C" {

bool fault_can_collect_safe_trace() FAULT_NOEXCEPT {
    return fault::v1::can_collect_safe_trace();
}

FaultConfigV1 fault_get_default_config_v1() FAULT_NOEXCEPT {
    fault::v1::Config config{};
    return FaultConfigV1{
        .appName = config.appName.data(),
        .buildID = config.buildID.data(),
        .crashDir = config.crashDir.data(),
        .reportBaseFileName = config.reportBaseFileName.data(),
        .prefixDateOnFilename = config.prefixDateOnFilename,
        .baseErrorMsg = config.baseErrorMsg.data(),
        .showPopUp = config.showPopUp,
        .printMsgToStdErr = config.printMsgToStdErr,
        .useUnsafeStacktraceOnSignalFallback = config.useUnsafeStacktraceOnSignalFallback,
        .resolveNonSignalTrace = config.resolveNonSignalTrace,
        .generateMiniDumpWindows = config.generateMiniDumpWindows,
        .enableTerminate = false,
        .signal = {.enable = config.signal.enable,
                   .raiseDefaultAfterwards = config.signal.raiseDefaultAfterwards,
                   .storeShutdownRequests = config.signal.storeShutdownRequests},
        .panic = {.printMsgToStdErr = config.panic.printMsgToStdErr,
                  .showPopUp = config.panic.showPopUp,
                  .writeReport = config.panic.writeReport}};
}

FaultInitResultV1 fault_init_v1(const FaultConfigV1* config) FAULT_NOEXCEPT {
    if (config == nullptr) {
        return fault::v1::fromCppInitResult(fault::tryInit(fault::v1::Config{}));
    }

    fault::v1::Config cppConfig{
        .appName{fault::utils::getSafeView(config->appName)},
        .buildID{fault::utils::getSafeView(config->buildID)},
        .crashDir{fault::utils::getSafeView(config->crashDir)},
        .reportBaseFileName{fault::utils::getSafeView(config->reportBaseFileName)},
        .prefixDateOnFilename = config->prefixDateOnFilename,
        .baseErrorMsg{fault::utils::getSafeView(config->baseErrorMsg)},
        .showPopUp = config->showPopUp,
        .printMsgToStdErr = config->printMsgToStdErr,
        .useUnsafeStacktraceOnSignalFallback = config->useUnsafeStacktraceOnSignalFallback,
        .resolveNonSignalTrace = config->resolveNonSignalTrace,
        .generateMiniDumpWindows = config->generateMiniDumpWindows,
        .signal{.enable = config->signal.enable,
                .raiseDefaultAfterwards = config->signal.raiseDefaultAfterwards,
                .storeShutdownRequests = config->signal.storeShutdownRequests},
        .terminate{.enable = config->enableTerminate},
        .panic{.printMsgToStdErr = config->panic.printMsgToStdErr,
               .showPopUp = config->panic.showPopUp,
               .writeReport = config->panic.writeReport}};
    return fault::v1::fromCppInitResult(fault::tryInit(cppConfig));
}

void fault_panic_v1(const char* message) FAULT_NOEXCEPT {
    constexpr const std::optional<fault::v1::ObjectTrace> kNoExceptionTrace{std::nullopt};
    fault::v1::panic_impl(fault::utils::getSafeView(message), kNoExceptionTrace);
    FAULT_UNREACHABLE();
}

void fault_panic_at_v1(const char* expr, const char* file, uint32_t line, const char* func,
                       const char* userMsg) FAULT_NOEXCEPT {
    fault::v1::panic_at(fault::utils::getSafeView(expr), fault::utils::getSafeView(file), line,
                        fault::utils::getSafeView(func), fault::utils::getSafeView(userMsg));
    FAULT_UNREACHABLE();
}

fault_panic_guard_handle_v1 fault_register_hook_v1(fault_panic_callback_t_v1 cb, void* userData,
                                                   FaultHookScopeV1 scope) FAULT_NOEXCEPT {
#if FAULT_EXCEPTIONS
    try {
#endif
        auto* guard = new fault::v1::PanicGuard(
            [cb, userData] {
                std::array<char, 256> bf{};
                cb(bf.data(), bf.size(), userData);
                return std::string{bf.data()};
            },
            static_cast<fault::v1::HookScope>(static_cast<std::uint8_t>(scope)));
        return reinterpret_cast<fault_panic_guard_handle_v1>(guard);
#if FAULT_EXCEPTIONS
    } catch (...) {
        return nullptr;
    }
#endif
}

void fault_release_hook_v1(fault_panic_guard_handle_v1* handle) FAULT_NOEXCEPT {
    if (handle == nullptr || *handle == nullptr) {
        return;
    }
    auto* panicGuard = reinterpret_cast<fault::v1::PanicGuard*>(*handle);
    delete panicGuard;  // NOLINT(cppcoreguidelines-owning-memory)
    *handle = nullptr;
}

}  // extern "C"
