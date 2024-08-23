//
// https://cardaci.xyz/blog/2018/02/12/a-macos-anti-debug-technique-using-ptrace/
// $ clang -framework Foundation syscall.m -o syscall
//
// ref 1: https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/kern/syscalls.master
// ref 2: https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/i386/syscall_sw.h.auto.html
//

#import <Foundation/Foundation.h>

@interface Foo : NSObject
@end

@implementation Foo

+(void)load {
    NSLog (@"-- LOAD");

#if TARGET_CPU_X86_64
    asm("movq $0, %rcx");
    asm("movq $0, %rdx");
    asm("movq $0, %rsi");
    asm("movq $0x1f, %rdi");      /* PT_DENY_ATTACH 31 (0x1f)*/
    asm("movq $0x200001a, %rax"); /* ptrace syscall number 26 (0x1a) */
                                  /* The syscall number for ptrace is 0x1a, but by definition in syscall_sw.h, 0x200001a must be set. */
    asm("syscall");
#elif TARGET_CPU_ARM64
    asm("mov X0, #0x1f");              /* PT_DENY_ATTACH 31 (0x1f)*/
    asm("movz X16, #0x001a");          /* ptrace syscall number 26 (0x1a) */
    asm("movk X16, #0x0200, lsl #16"); /* The syscall number for ptrace is 0x1a, but by definition in syscall_sw.h, 0x200001a must be set. */
    asm("svc 0");
#endif
}

@end

int main (int argc, const char * argv[]) {
    NSLog (@"-- MAIN");
    return 0;
}
