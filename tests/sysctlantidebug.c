// 
// test sysctl anti-debug trick
//
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>

// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
static bool AmIBeingDebugged(void) {
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;
    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.
    info.kp_proc.p_flag = 0;
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    mib[0] = CTL_KERN; // 1
    mib[1] = KERN_PROC; // 14
    mib[2] = KERN_PROC_PID; // 1
    mib[3] = getpid();
    // Call sysctl.
    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    // We're being debugged if the P_TRACED flag (0x00000800) is set.
    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        printf("ALERT: Debugger found :-(\n");
        exit(1);
    } 

    printf("No debugger found :-)\n");
    return 0;
}

int main(void) {
    AmIBeingDebugged();
    return 0;
}
