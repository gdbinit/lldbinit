//
// test PT_DENY_ATTACH
//
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>

int main(void) {
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    // if a debugger is attached the process will exit with error 45 before reaching here
    printf("No debugger found :-)\n");
}
