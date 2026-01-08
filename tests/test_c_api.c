#include <stdio.h>

#include <fault/fault.h>

int main() {
    FaultConfig config = faultGetDefaultConfig();
    config.appName = "MyApp";
    config.buildID = "MyBuildID";
    config.crashDir = "crash";
    config.useUnsafeStacktraceOnSignalFallback = true;
    const FaultInitResult res = faultInit(&config);
    if (!res.success) {
        printf("Failed to init libfault\n");
        return 1;
    }
    faultVerify(2 == 1, "Logic failure in C");

    printf("C API test passed\n");
    return 0;
}