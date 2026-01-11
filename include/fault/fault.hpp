/*
 * fault - A C++ and C fault handling library for Linux and Windows, containing signal and
 * exception handlers, as well as user assertions and panic options, generating reports with
 * metadata, raw or resolved traces, and more
 * https://github.com/Ridrik/fault
 *
 * Licensed under the MIT License.
 */

/**
   @brief Linux Signal Handling:
    Searches for `zenity` and `kdialog` on `$PATH`, recording their locations, if any.
    sets signal handlers for: SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT. Each handler
    does the following if triggered: 1. Generate and write object trace to crash report
    directory, 2. prints summary error message on stderr, 3. Displays user popup if available
    (trying zenity, then kdialog). 4. If set, reraises default signal, else exits with no further
    cleanup.

   @brief Windows Exception Handling:
    sets signal handler for SIGABRT and sets an unhandled exception filter. The following codes are
    intercepted: EXCEPTION_STACK_OVERFLOW, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
    EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_FLT_DIVIDE_BY_ZERO,
    EXCEPTION_ILLEGAL_INSTRUCTION, and EXCEPTION_PRIV_INSTRUCTION. Both for these codes and for
    Abort signal, the following steps are made:
    1. Generate and write object trace to crash report directory (see setCrashWriteDir); 2. Writes
    summary error message to stderr (if enabled) 3. Displays user popup with termination status;
    4. Returns from Windows Handler with execute handler comand, or Terminates Process if on abort
    handler

   @brief Both platforms Signal / Exception handling
    @Note Thread-safe
    @Note Signal safety is prioritized, noting that safe trace generation is only available on
    certain configurations. User may choose to set a config flag to collect a regular(signal unsafe)
    trace as fallback, to which the report will become a best - effort attempt.This library attempts
    to mitigate this action with deadlock expiration safeguards, so that the expected termination
    behaviour is seen nonetheless.

   @brief Terminate Handling Sets std::terminate handler. Performs the following, depending on init
    config flags: Creates object trace and message with unhandled exception; runs user hook; writes
    the crash report, prints summary message to stderr, and displays user popup, followed by
    raising default abort() if on linux, or terminating process on Windows. On windows, it also
    writes a minidump to a corresponding .dmp file of same name and path as the report.

    @Note On Linux,
    popup is dependent on either zenity or kdialog being found on `$PATH`

 */

#ifndef FAULT_FAULT_HPP
#define FAULT_FAULT_HPP

#include <fault/core.hpp>
#include <fault/format.hpp>

#endif  // FAULT_HPP