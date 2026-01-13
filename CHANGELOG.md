## v0.1.1 - January 2026
### Added
- std::terminate and panic analysis: `fault` will now log wether terminate or panic was called as a result of an ongoing unwind process (i.e some early code threw but was interrupted before reaching its `catch`)

- Postponed **Exceptions & Traces**. `fault` allows users to save a trace and message for a later shutdown. Example: save exception occured in a thread, signal for shutdown. Then, your main thread can decide to clean critical resources first before panicking. (**Note**) any time a trace is saved, it will be automatically displayed at either `panic`, or even on its std::terminate handler.

## v0.1.0 - January 2026
Initial tag release
### Added
- Linux posix signal handlers, Windows SEH filter and abort handler, std::terminate handler, `panic` function and panic-based assertions.
- Ability to write a report, print summary to stderr, and display a visual popup to alert users.