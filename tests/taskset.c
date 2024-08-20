//
// from https://alexomara.com/blog/defeating-anti-debug-techniques-macos-mach-exception-port-stealing/
// 
// to test this, set a breakpoint on main and step until remove_debugger() call
// without anti-anti-debugging lldb will lose control after that call is executed
// with anti-anti-debugging active lldb still has control after that call
//
#include <stdlib.h>
#include <stdio.h>
#include <mach/host_priv.h>
#include <mach/mach.h>
#include <mach/host_special_ports.h>
#include "TargetConditionals.h"

int remove_debugger() {
    mach_port_t service;
    kern_return_t kr;
    ipc_space_t selftask = mach_task_self();

    kr = mach_port_allocate(
        selftask,
        MACH_PORT_RIGHT_RECEIVE,
        &service
    );
    if (kr != KERN_SUCCESS) {
        printf("mach_port_allocate: %s\n", mach_error_string(kr));
        return 1;
    }

    kr = mach_port_insert_right(
        selftask,
        service,
        service,
        MACH_MSG_TYPE_MAKE_SEND
    );
    if (kr != KERN_SUCCESS) {
        printf("mach_port_insert_right: %s\n", mach_error_string(kr));
        return 1;
    }

    exception_mask_t exception_mask =
        EXC_MASK_BAD_ACCESS |
        EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_ARITHMETIC |
        EXC_MASK_EMULATION |
        EXC_MASK_SOFTWARE |
        EXC_MASK_BREAKPOINT |
        EXC_MASK_SYSCALL |
        EXC_MASK_MACH_SYSCALL |
        EXC_MASK_RPC_ALERT;
    kr = task_set_exception_ports(
        selftask,
        exception_mask,
        service,
        EXCEPTION_STATE,
#if TARGET_CPU_X86_64
        x86_THREAD_STATE64
#elif TARGET_CPU_ARM64
        ARM_THREAD_STATE64
#endif
    );
    if (kr != KERN_SUCCESS) {
        printf("task_set_exception_ports: %s\n", mach_error_string(kr));
        return 1;
    }
    return 0;
}

int main(int argc, const char * argv[]) {
    if (remove_debugger()) {
        printf("Error\n");
        return 1;
    }

    printf("No debugger found :-)\n");
    return 0;
}
