These are just simple anti-debugging examples to test the anti-anti-debugging lldbinit features.

Build them and run under lldb with the `antidebug` command on and off.

Available tests:

* sysctl: test the P_TRACED flag from classic AmIBeingDebugged example
* ptrace: ptrace PT_DENY_ATTACH example
* taskget: debugger detection via mach exception ports
* taskset: get rid of the debugger by setting the exception port

To test under lldb, start the target with `process launch -s` and execute the `antidebug` command on `_dyld_start` first breakpoint.
Resume execution and the anti-debug test shouldn't detect the debugger if everything went ok.
