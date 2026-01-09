#include <stdio.h>

#include <fault/fault.h>

void infinite_recursion() {
    volatile char buffer[256];
    infinite_recursion();
    buffer[0] = 0;
}

int main() {
    FaultConfig config = fault_get_default_config();
    config.appName = "MyApp";
    config.buildID = "MyBuildID";
    config.crashDir = "crash";
    config.useUnsafeStacktraceOnSignalFallback = true;
    const FaultInitResult res = fault_init(&config);
    if (!res.success) {
        printf("Failed to init libfault\n");
        return 1;
    }

    infinite_recursion();  // Triggers seg fault on linux

    printf("C API test passed\n");
    return 0;
}