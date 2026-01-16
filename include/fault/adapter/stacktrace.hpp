#ifndef FAULT_ADAPTER_STACKTRACE_HPP
#define FAULT_ADAPTER_STACKTRACE_HPP

#if __has_include(<cpptrace/basic.hpp>)

#include <cpptrace/basic.hpp>
#include <fault/core.hpp>

namespace fault::adapter {  // NOLINT(modernize-concat-nested-namespaces)

#if FAULT_API_VERSION == 1
inline
#endif
    namespace v1 {

[[nodiscard]] inline ObjectTrace from_cpptrace(const cpptrace::object_trace& cppTrace) {
    ObjectTrace trace;
    trace.frames.reserve(cppTrace.frames.size());
    for (const auto& cppFrame : cppTrace.frames) {
        trace.frames.push_back(Frame{.rawAddress = cppFrame.raw_address,
                                     .objAddress = cppFrame.object_address,
                                     .objPath = cppFrame.object_path});
    }
    return trace;
}

[[nodiscard]] inline cpptrace::object_trace to_cpptrace(const ObjectTrace& trace) {
    cpptrace::object_trace cppTrace;
    cppTrace.frames.reserve(trace.frames.size());
    for (const auto& frame : trace.frames) {
        cppTrace.frames.push_back(cpptrace::object_frame{.raw_address = frame.rawAddress,
                                                         .object_address = frame.objAddress,
                                                         .object_path = frame.objPath});
    }
    return cppTrace;
}

}  // namespace v1

}  // namespace fault::adapter

#else

#error \
    "fault/adapter/stacktrace.hpp requires cpptrace, which is not propagated by default from fault::fault. Please link to fault::fault_adapter or ensure that cpptrace is installed in your project"

#endif

#endif  // FAULT_ADAPTER_STACKTRACE_HPP