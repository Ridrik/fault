#include <stdio.h>

#include <fault/fault.h>

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
    fault_verify(2 == 1, "Logic failure in C");

    printf("C API test passed\n");
    return 0;
}