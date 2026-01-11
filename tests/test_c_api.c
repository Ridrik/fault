#include <stdio.h>

#include <fault/fault.h>

void infinite_recursion() {
    volatile char buffer[256];
    infinite_recursion();
    buffer[0] = 0;
}

const char* on_panic(void* data) {
    int* val = (int*)data;
    if (*val == 404) {
        return "Resource not found";
    }
    return "Unknown system failure";
}

int main() {
    FaultConfig config = fault_get_default_config();
    config.appName = "MyApp";
    config.buildID = "MyBuildID";
    config.crashDir = "crash";
    config.useUnsafeStacktraceOnSignalFallback = true;
    const FaultInitResult res =
        fault_init(&config);  // if no config changes wanted, user can call fault_init(NULL)
    if (!res.success) {
        printf("Failed to init fault\n");
        return 1;
    }

    int status = 404;
    fault_verify_c(status == 200, on_panic, &status);

    infinite_recursion();  // Triggers seg fault on linux & stack overflow on windows

    printf("C API test passed\n");
    return 0;
}