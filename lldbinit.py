'''
.____    .____     ________ __________.__ _______  ._____________
|    |   |    |    \______ \\______   \__|\      \ |__\__    ___/
|    |   |    |     |    |  \|    |  _/  |/   |   \|  | |    |   
|    |___|    |___  |    `   \    |   \  /    |    \  | |    |   
|_______ \_______ \/_______  /______  /__\____|__  /__| |____|   
        \/       \/        \/       \/           \/              LLDBINIT v1.0

A gdbinit clone for LLDB aka how to make LLDB a bit more useful and less crappy

(c) Deroko 2014, 2015, 2016
(c) fG! 2017, 2018 - reverser@put.as - https://reverse.put.as

https://github.com/gdbinit/lldbinit

No original license by Deroko so I guess this is do whatever you want with this
as long you keep original credits and sources references.

Original lldbinit code by Deroko @ https://github.com/deroko/lldbinit
gdbinit available @ https://github.com/gdbinit/Gdbinit

Huge thanks to Deroko for his original effort!

To list all implemented commands use 'lldbinitcmds' command.

How to install it:
------------------
cp lldbinit.py /Library/Python/2.7/site-packages
in $HOME/.lldbinit add:
command script import lldbinit

or
cp lldbinit.py ~
echo "command script import  ~/lldbinit.py" >>~/.lldbinit

or

just copy it somewhere and use **command script import path_to_script** when you want to load it.

TODO:
-----
- better ARM support and testing - this version is focused on x86/x64
- shortcut to dump memory to file
- check sbthread class: stepoveruntil for example
- help for aliases
- error checking on many return values for lldb objects (target, frame, thread, etc) - verify if frame value is valid on the beginning of each command?
- add source window?
- add threads window?
- remove that ugly stop information (deroko's trick doesn't seem to work anymore, lldb forces that over our captured input?)

BUGS:
-----
- Disassembler output with API GetInstructions is all wrong for code not in main executable
The reason is that the section information is bad
    context = frame.GetSymbolContext(lldb.eSymbolContextEverything)
    print context
     Module: file = "/usr/lib/system/libsystem_blocks.dylib", arch = "x86_64"
     Symbol: id = {0x0000000e}, range = [0x00000000000008ec-0x000000000000096c), mangled="_Block_release"
    So even if we pass the correct base_addr the disassembly will be all wrong
    ->  0x7fff9566c0d0: e8 73 f2 ff ff           call   0x7fff9566b348            ; tiny_free_no_lock
    Disassembly operand we get 0x19348
x libsystem_malloc.dylib[0x1a0d0]: call   0x19348
     Module: file = "/usr/lib/system/libsystem_malloc.dylib", arch = "x86_64"
     Symbol: id = {0x000000c7}, range = [0x0000000000019e36-0x000000000001a129), name="free_tiny"

LLDB design:
------------
lldb -> debugger -> target -> process -> thread -> frame(s)
                                      -> thread -> frame(s)
'''

if __name__ == "__main__":
    print("Run only as script from lldb... Not as standalone program")

try:
    import  lldb
except:
    pass
import  sys
import  re
import  os
import  thread
import  time
import  struct
import  argparse
import  subprocess
import  tempfile

try:
    from keystone import *
    CONFIG_KEYSTONE_AVAILABLE = 1
except:
    CONFIG_KEYSTONE_AVAILABLE = 0
    pass

#
# User configurable options
#
CONFIG_ENABLE_COLOR = 1
CONFIG_DISPLAY_DISASSEMBLY_BYTES = 1
CONFIG_DISASSEMBLY_LINE_COUNT = 8
CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT = 1
CONFIG_DISPLAY_STACK_WINDOW = 0
CONFIG_DISPLAY_FLOW_WINDOW = 1
CONFIG_ENABLE_REGISTER_SHORTCUTS = 1
CONFIG_DISPLAY_DATA_WINDOW = 0

# removes the offsets and modifies the module name position
# reference: https://lldb.llvm.org/formats.html
CUSTOM_DISASSEMBLY_FORMAT = "\"{${function.initial-function}{${function.name-without-args}} @ {${module.file.basename}}:\n}{${function.changed}\n{${function.name-without-args}} @ {${module.file.basename}}:\n}{${current-pc-arrow} }${addr-file-or-load}: \""

BLACK = 0
RED = 1
GREEN = 2
YELLOW = 3
BLUE = 4
MAGENTA = 5
CYAN = 6
WHITE = 7

COLOR_REGNAME = GREEN
COLOR_REGVAL = BLACK
COLOR_REGVAL_MODIFIED  = RED
COLOR_SEPARATOR = BLUE
COLOR_CPUFLAGS = RED
COLOR_HIGHLIGHT_LINE = RED

#
# Don't mess after here unless you know what you are doing!
#

DATA_WINDOW_ADDRESS = 0

old_eax = 0
old_ecx = 0
old_edx = 0
old_ebx = 0
old_esp = 0
old_ebp = 0
old_esi = 0
old_edi = 0
old_eip = 0
old_eflags = 0
old_cs  = 0
old_ds  = 0
old_fs  = 0
old_gs  = 0
old_ss  = 0
old_es  = 0

old_rax = 0
old_rcx = 0
old_rdx = 0
old_rbx = 0
old_rsp = 0
old_rbp = 0
old_rsi = 0
old_rdi = 0
old_r8  = 0
old_r9  = 0
old_r10 = 0
old_r11 = 0
old_r12 = 0
old_r13 = 0
old_r14 = 0
old_r15 = 0
old_rflags = 0
old_rip = 0

old_arm_r0  = 0
old_arm_r1  = 0
old_arm_r2  = 0
old_arm_r3  = 0
old_arm_r4  = 0
old_arm_r5  = 0
old_arm_r6  = 0
old_arm_r7  = 0
old_arm_r8  = 0
old_arm_r9  = 0
old_arm_r10 = 0
old_arm_r11 = 0
old_arm_r12 = 0
old_arm_sp  = 0
old_arm_lr  = 0
old_arm_pc  = 0
old_arm_cpsr = 0

arm_type = "thumbv7-apple-ios"

GlobalListOutput = []

Int3Dictionary = {}

crack_cmds = []
crack_cmds_noret = []

All_Registers = [ "rip", "rax", "rbx", "rbp", "rsp", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eip", "eax", "ebx", "ebp", "esp", "edi", "esi", "edx", "ecx" ]

def __lldb_init_module(debugger, internal_dict):
    ''' we can execute commands using debugger.HandleCommand which makes all output to default
    lldb console. With GetCommandinterpreter().HandleCommand() we can consume all output
    with SBCommandReturnObject and parse data before we send it to output (eg. modify it);
    '''

    '''
    If I'm running from $HOME where .lldbinit is located, seems like lldb will load 
    .lldbinit 2 times, thus this dirty hack is here to prevent doulbe loading...
    if somebody knows better way, would be great to know :)
    ''' 
    var = lldb.debugger.GetInternalVariableValue("stop-disassembly-count", lldb.debugger.GetInstanceName())
    if var.IsValid():
        var = var.GetStringAtIndex(0)
        if var == "0":
            return
    res = lldb.SBCommandReturnObject()
    
    # settings
    lldb.debugger.GetCommandInterpreter().HandleCommand("settings set target.x86-disassembly-flavor intel", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("settings set prompt \"(lldbinit) \"", res)
    #lldb.debugger.GetCommandInterpreter().HandleCommand("settings set prompt \"\033[01;31m(lldb) \033[0m\"", res);
    lldb.debugger.GetCommandInterpreter().HandleCommand("settings set stop-disassembly-count 0", res)

    if CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT == 1:
        lldb.debugger.GetCommandInterpreter().HandleCommand("settings set disassembly-format " + CUSTOM_DISASSEMBLY_FORMAT, res)

    # the hook that makes everything possible :-)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget ctx", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget context", res)
    # commands
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.lldbinitcmds lldbinitcmds", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.IphoneConnect iphone", res)
    #
    # dump memory commands
    #
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.db db", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dw dw", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dd dd", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.dq dq", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.DumpInstructions u", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.findmem findmem", res)
    #
    # Settings related commands
    #
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.enable enable", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.disable disable", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.contextcodesize contextcodesize", res)
    # a few settings aliases
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias enablesolib enable solib", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias disablesolib disable solib", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias enableaslr enable aslr", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias disableaslr disable aslr", res)
    #
    # Breakpoint related commands
    #
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bhb bhb", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bht bht", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpt bpt", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpn bpn", res)
    # disable a breakpoint or all
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpd bpd", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpda bpda", res)
    # clear a breakpoint or all
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpc bpc", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias bpca breakpoint delete", res)
    # enable a breakpoint or all
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpe bpe", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.bpea bpea", res)
    # commands to set temporary int3 patches and restore original bytes
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.int3 int3", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rint3 rint3", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.listint3 listint3", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.nop nop", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.null null", res)
    # change eflags commands
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfa cfa", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfc cfc", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfd cfd", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfi cfi", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfo cfo", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfp cfp", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfs cfs", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cft cft", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.cfz cfz", res)
    # skip/step current instruction commands
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.skip skip", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.stepo stepo", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.si si", res)
    # load breakpoints from file
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.LoadBreakPoints lb", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.LoadBreakPointsRva lbrva", res)
    # cracking friends
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.crack crack", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.crackcmd crackcmd", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.crackcmd_noret crackcmd_noret", res)
    # alias for existing breakpoint commands
    # list all breakpoints
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias bpl breakpoint list", res)
    # alias "bp" command that exists in gdbinit - lldb also has alias for "b"
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias bp _regexp-break", res)
    # to set breakpoint commands - I hate typing too much
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias bcmd breakpoint command add", res)
    # launch process and stop at entrypoint (not exactly as gdb command that just inserts breakpoint)
    # usually it will be inside dyld and not the target main()
    lldb.debugger.GetCommandInterpreter().HandleCommand("command alias break_entrypoint process launch --stop-at-entry", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.show_loadcmds show_loadcmds", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.show_header show_header", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.tester tester", res)
    lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.datawin datawin", res)
    # shortcut command to modify registers content
    if CONFIG_ENABLE_REGISTER_SHORTCUTS == 1:
        # x64
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rip rip", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rax rax", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rbx rbx", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rbp rbp", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rsp rsp", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rdi rdi", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rsi rsi", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rdx rdx", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.rcx rcx", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r8 r8", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r9 r9", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r10 r10", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r11 r11", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r12 r12", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r13 r13", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r14 r14", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.r15 r15", res)
        # x86
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.eip eip", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.eax eax", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.ebx ebx", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.ebp ebp", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.esp esp", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.edi edi", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.esi esi", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.edx edx", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.ecx ecx", res)

    if CONFIG_KEYSTONE_AVAILABLE == 1:
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.asm32 asm32", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.asm64 asm64", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.arm32 arm32", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.arm64 arm64", res)
        lldb.debugger.GetCommandInterpreter().HandleCommand("command script add -f lldbinit.armthumb armthumb", res)
    # add the hook - we don't need to wait for a target to be loaded
    lldb.debugger.GetCommandInterpreter().HandleCommand("target stop-hook add -o \"HandleHookStopOnTarget\"", res)
    
    return

def lldbinitcmds(debugger, command, result, dict):
    '''Display all available lldbinit commands.'''

    help_table = [
    [ "lldbinitcmds", "this command" ],
    [ "enable", "configure lldb and lldbinit options" ],
    [ "disable", "configure lldb and lldbinit options" ],
    [ "contextcodesize", "set number of instruction lines in code window" ],
    [ "b", "breakpoint address" ],
    [ "bpt", "set a temporary software breakpoint" ],
    [ "bpc", "clear breakpoint" ],
    [ "bpca", "clear all breakpoints" ],
    [ "bpd", "disable breakpoint" ],
    [ "bpda", "disable all breakpoints" ],
    [ "bpe", "enable a breakpoint" ],
    [ "bpea", "enable all breakpoints" ],
    [ "bcmd", "alias to breakpoint command add"],
    [ "bpl", "list all breakpoints"],
    [ "bpn", "temporarly breakpoint next instruction" ],
    [ "break_entrypoint", "launch target and stop at entrypoint" ],
    [ "skip", "skip current instruction" ],
    [ "int3", "patch memory address with INT3" ],
    [ "rint3", "restore original byte at address patched with INT3" ],
    [ "listint3", "list all INT3 patched addresses" ],
    [ "nop", "patch memory address with NOP" ],
    [ "null", "patch memory address with NULL" ],
    [ "stepo", "step over calls and loop instructions" ],
    [ "lb", "load breakpoints from file and apply them (currently only func names are applied)" ],
    [ "lbrva", "load breakpoints from file and apply to main executable, only RVA in this case" ],
    [ "db/dw/dd/dq", "memory hex dump in different formats" ],
    [ "findmem", "search memory" ],
    [ "cfa/cfc/cfd/cfi/cfo/cfp/cfs/cft/cfz", "change CPU flags" ],
    [ "u", "dump instructions" ],
    [ "iphone", "connect to debugserver running on iPhone" ],
    [ "ctx/context", "show current instruction pointer CPU context" ],
    [ "show_loadcmds", "show otool output of Mach-O load commands" ],
    [ "show_header", "show otool output of Mach-O header" ],
    [ "enablesolib/disablesolib", "enable/disable the stop on library load events" ],
    [ "enableaslr/disableaslr", "enable/disable process ASLR" ],
    [ "crack", "return from current function" ],
    [ "crackcmd", "set a breakpoint and return from that function" ],
    [ "crackcmd_noret", "set a breakpoint and set a register value. doesn't return from function" ],
    [ "datawin", "set start address to display on data window" ],
    [ "rip/rax/rbx/etc", "shortcuts to modify x64 registers" ],
    [ "eip/eax/ebx/etc", "shortcuts to modify x86 register" ],
    [ "asm32/asm64", "x86/x64 assembler using keystone" ],
    [ "arm32/arm64/armthumb", "ARM assembler using keystone" ]
    ]

    print "lldbinit available commands:"

    for row in help_table:
        print(" {: <20} - {: <30}".format(*row))

    print "\nUse \'cmdname help\' for extended command help."

# placeholder to make tests
def tester(debugger, command, result, dict):
    print "test"
    #frame = get_frame()
    # the SBValue to ReturnFromFrame must be eValueTypeRegister type
    # if we do a lldb.SBValue() we can't set to that type
    # so we need to make a copy
    # can we use FindRegister() from frame?
    #return_value = frame.reg["rax"]
    #return_value.value = "1"
    #thread.ReturnFromFrame(frame, return_value)


#
# Settings related commands
#

def enable(debugger, command, result, dict):
    '''Enable certain lldb and lldbinit options. Use \'enable help\' for more information.'''
    help = """
Enable certain lldb and lldbinit configuration options.

Syntax: enable <setting>

Available settings:
 color: enable color mode.
 solib: enable stop on library events trick.
 aslr: enable process aslr.
 stackwin: enable stack window in context display.
 datawin: enable data window in context display, configure address with datawin.
 flow: call targets and objective-c class/methods.
 """

    global CONFIG_ENABLE_COLOR
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: command requires arguments."
        print ""
        print help
        return

    if cmd[0] == "color":
        CONFIG_ENABLE_COLOR = 1
        print "[+] Enabled color mode."
    elif cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events true")
        print "[+] Enabled stop on library events trick."
    elif cmd[0] == "aslr:":
        debugger.HandleCommand("settings set target.disable-aslr false")
        print "[+] Enabled ASLR."
    elif cmd[0] == "stackwin":
        CONFIG_DISPLAY_STACK_WINDOW = 1
        print "[+] Enabled stack window in context display."
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 1
        print "[+] Enabled indirect control flow window in context display."
    elif cmd[0] == "datawin":
        CONFIG_DISPLAY_DATA_WINDOW = 1
        print "[+] Enabled data window in context display. Configure address with \'datawin\' cmd."
    elif cmd[0] == "help":
        print help
    else:
        print "[-] error: unrecognized command."
        print help

    return

def disable(debugger, command, result, dict):
    '''Disable certain lldb and lldbinit options. Use \'disable help\' for more information.'''
    help = """
Disable certain lldb and lldbinit configuration options.

Syntax: disable <setting>

Available settings:
 color: disable color mode.
 solib: disable stop on library events trick.
 aslr: disable process aslr.
 stackwin: disable stack window in context display.
 datawin: enable data window in context display.
 flow: call targets and objective-c class/methods.
 """

    global CONFIG_ENABLE_COLOR
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: command requires arguments."
        print ""
        print help
        return

    if cmd[0] == "color":
        CONFIG_ENABLE_COLOR = 0
        print "[+] Disabled color mode."
    elif cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events false")
        print "[+] Disabled stop on library events trick."
    elif cmd[0] == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr true")
        print "[+] Disabled ASLR."
    elif cmd[0] == "stackwin":
        CONFIG_DISPLAY_STACK_WINDOW = 0
        print "[+] Disabled stack window in context display."
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 0
        print "[+] Disabled indirect control flow window in context display."
    elif cmd[0] == "datawin":
        CONFIG_DISPLAY_DATA_WINDOW = 0
        print "[+] Disabled data window in context display."
    elif cmd[0] == "help":
        print help
    else:
        print "[-] error: unrecognized command."
        print help

    return

def contextcodesize(debugger, command, result, dict): 
    '''Set the number of disassembly lines in code window. Use \'contextcodesize help\' for more information.'''
    help = """
Configures the number of disassembly lines displayed in code window.

Syntax: contextcodesize <line_count>

Note: expressions supported, do not use spaces between operators.
"""

    global CONFIG_DISASSEMBLY_LINE_COUNT

    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert the number of disassembly lines to display."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        print "\nCurrent configuration value is: %d" % CONFIG_DISASSEMBLY_LINE_COUNT
        return
    
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid input value."
        print ""
        print help
        return

    CONFIG_DISASSEMBLY_LINE_COUNT = value

    return

#
# End Settings related commands
#

#
# Color and output related commands
#

def color_reset():
    output("\033[0m")

def color_bold():
    if CONFIG_ENABLE_COLOR == 0:
        output("")
        return

    output("\033[1m")

def color_underline():
    if CONFIG_ENABLE_COLOR == 0:
        output("")
        return

    output("\033[4m")

def color(x):
    out_col = ""
    if CONFIG_ENABLE_COLOR == 0:
        output(out_col)
        return
            
    if x == BLACK:
        out_col = "\033[30m"
    elif x == RED:
        out_col = "\033[31m"
    elif x == GREEN:
        out_col = "\033[32m"
    elif x == YELLOW:
        out_col = "\033[33m"
    elif x == BLUE:
        out_col = "\033[34m"
    elif x == MAGENTA:
        out_col = "\033[35m"
    elif x == CYAN:
        out_col = "\033[36m"
    elif x == WHITE:
        out_col = "\033[37m"
    output(out_col)

# append data to the output that we display at the end of the hook-stop
def output(x):
    global GlobalListOutput
    GlobalListOutput.append(x)

#
# End Color related commands
#

#
# Breakpoint related commands
#

# temporary software breakpoint
def bpt(debugger, command, result, dict):
    '''Set a temporary software breakpoint. Use \'bpt help\' for more information.'''
    help = """
Set a temporary software breakpoint.

Syntax: bpt <address>

Note: expressions supported, do not use spaces between operators.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert a breakpoint address."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        return
    
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid input value."
        print ""
        print help
        return
    
    target = get_target()
    breakpoint = target.BreakpointCreateByAddress(value)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print "[+] Set temporary breakpoint at 0x{:x}".format(value)
    
# hardware breakpoint
def bhb(debugger, command, result, dict):
    '''Set a hardware breakpoint'''
    print "[-] error: lldb has no x86/x64 hardware breakpoints implementation."
    return

# temporary hardware breakpoint
def bht(debugger, command, result, dict):
    '''Set a temporary hardware breakpoint'''
    print "[-] error: lldb has no x86/x64 hardware breakpoints implementation."
    return

# clear breakpoint number
def bpc(debugger, command, result, dict):
    '''Clear a breakpoint. Use \'bpc help\' for more information.'''
    help = """
Clear a breakpoint.

Syntax: bpc <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert a breakpoint number."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid input value - only a breakpoint number is valid."
        print ""
        print help
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value:
            if target.BreakpointDelete(bpt.id) == False:
                print "[-] error: failed to delete breakpoint #{:d}".format(value)
                return
            print "[+] Deleted breakpoint #{:d}".format(value)
            return

    print "[-] error: breakpoint #{:d} not found".format(value)
    return

# disable breakpoint number
# XXX: we could support addresses, not sure it's worth the trouble
def bpd(debugger, command, result, dict):
    '''Disable a breakpoint. Use \'bpd help\' for more information.'''
    help = """
Disable a breakpoint.

Syntax: bpd <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert a breakpoint number."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid input value - only a breakpoint number is valid."
        print ""
        print help
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and bpt.IsEnabled() == True:
            bpt.SetEnabled(False)
            print "[+] Disabled breakpoint #{:d}".format(value)

# disable all breakpoints
def bpda(debugger, command, result, dict):
    '''Disable all breakpoints. Use \'bpda help\' for more information.'''
    help = """
Disable all breakpoints.

Syntax: bpda
"""
        
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print help
           return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    target = get_target()

    if target.DisableAllBreakpoints() == False:
        print "[-] error: failed to disable all breakpoints."

    print "[+] Disabled all breakpoints."

# enable breakpoint number
def bpe(debugger, command, result, dict):
    '''Enable a breakpoint. Use \'bpe help\' for more information.'''
    help = """
Enable a breakpoint.

Syntax: bpe <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert a breakpoint number."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        return

    # breakpoint enable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid input value - only a breakpoint number is valid."
        print ""
        print help
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and bpt.IsEnabled() == False:
            bpt.SetEnabled(True)
            print "[+] Enabled breakpoint #{:d}".format(value)

# enable all breakpoints
def bpea(debugger, command, result, dict):
    '''Enable all breakpoints. Use \'bpea help\' for more information.'''
    help = """
Enable all breakpoints.

Syntax: bpea
"""
        
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print help
           return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    target = get_target()

    if target.EnableAllBreakpoints() == False:
        print "[-] error: failed to enable all breakpoints."

    print "[+] Enabled all breakpoints."

# skip current instruction - just advances PC to next instruction but doesn't execute it
def skip(debugger, command, result, dict):
    '''Advance PC to instruction at next address. Use \'skip help\' for more information.'''
    help = """
Advance current instruction pointer to next instruction.

Syntax: skip

Note: control flow is not respected, it advances to next instruction in memory.
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print help
           return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    start_addr = get_current_pc()
    next_addr = start_addr + get_inst_size(start_addr)
    
    if is_x64():
        get_frame().reg["rip"].value = format(next_addr, '#x')
    elif is_i386():
        get_frame().reg["eip"].value = format(next_addr, '#x')
    # show the updated context
    lldb.debugger.HandleCommand("context")

# XXX: ARM breakpoint
def int3(debugger, command, result, dict):
    '''Patch byte at address to an INT3 (0xCC) instruction. Use \'int3 help\' for more information.'''
    help = """
Patch process memory with an INT3 byte at given address.

Syntax: int3 [<address>]

Note: useful in cases where the debugger breakpoints aren't respected but an INT3 will always trigger the debugger.
Note: ARM not yet supported.
Note: expressions supported, do not use spaces between operators.
"""

    global Int3Dictionary

    error = lldb.SBError()
    target = get_target()

    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        
        int3_addr = evaluate(cmd[0])
        if int3_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a breakpoint address."
        print ""
        print help
        return

    bytes_string = target.GetProcess().ReadMemory(int3_addr, 1, error)
    if error.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % int3_addr
        return

    bytes_read = bytearray(bytes_string)
    
    patch_bytes = str('\xCC')
    result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
    if error.Success() == False:
        print "[-] error: Failed to write memory at 0x%x." % int3_addr
        return

    # save original bytes for later restore
    Int3Dictionary[str(int3_addr)] = bytes_read[0]

    print "[+] Patched INT3 at 0x%x" % int3_addr
    return

def rint3(debugger, command, result, dict):
    '''Restore byte at address from a previously patched INT3 (0xCC) instruction. Use \'rint3 help\' for more information.'''
    help = """
Restore the original byte at a previously patched address using \'int3\' command.

Syntax: rint3 [<address>]

Note: expressions supported, do not use spaces between operators.
"""

    global Int3Dictionary

    error = lldb.SBError()
    target = get_target()
    
    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        int3_addr = evaluate(cmd[0])
        if int3_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return        
    else:
        print "[-] error: please insert a INT3 patched address."
        print ""
        print help
        return

    if len(Int3Dictionary) == 0:
        print "[-] error: No INT3 patched addresses to restore available."
        return

    bytes_string = target.GetProcess().ReadMemory(int3_addr, 1, error)
    if error.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % int3_addr
        return
        
    bytes_read = bytearray(bytes_string)

    if bytes_read[0] == 0xCC:
        #print "Found byte patched byte at 0x%x" % int3_addr
        try:
            original_byte = Int3Dictionary[str(int3_addr)]
        except:
            print "[-] error: Original byte for address 0x%x not found." % int3_addr
            return
        patch_bytes = chr(original_byte)
        result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
        if error.Success() == False:
            print "[-] error: Failed to write memory at 0x%x." % int3_addr
            return
        # remove element from original bytes list
        del Int3Dictionary[str(int3_addr)]
    else:
        print "[-] error: No INT3 patch found at 0x%x." % int3_addr

    return

def listint3(debugger, command, result, dict):
    '''List all patched INT3 (0xCC) instructions. Use \'listint3 help\' for more information.'''
    help = """
List all addresses patched with \'int3\' command.

Syntax: listint3
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print help
           return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    if len(Int3Dictionary) == 0:
        print "[-] No INT3 patched addresses available."
        return

    print "Current INT3 patched addresses:"
    for address, byte in Int3Dictionary.items():
        print "[*] %s" % hex(int(address, 10))

    return

# XXX: ARM NOPs
def nop(debugger, command, result, dict):
    '''NOP byte(s) at address. Use \'nop help\' for more information.'''
    help = """
Patch process memory with NOP (0x90) byte(s) at given address.

Syntax: nop <address> [<size>]

Note: default size is one byte if size not specified.
Note: ARM not yet supported.
Note: expressions supported, do not use spaces between operators.
"""

    error = lldb.SBError()
    target = get_target()

    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        
        nop_addr = evaluate(cmd[0])
        patch_size = 1
        if nop_addr == None:
            print "[-] error: invalid address value."
            print ""
            print help
            return
    elif len(cmd) == 2:
        nop_addr = evaluate(cmd[0])
        if nop_addr == None:
            print "[-] error: invalid address value."
            print ""
            print help
            return
        
        patch_size = evaluate(cmd[1])
        if patch_size == None:
            print "[-] error: invalid size value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a breakpoint address."
        print ""
        print help
        return

    current_patch_addr = nop_addr
    # format for WriteMemory()
    patch_bytes = str('\x90')
    # can we do better here? WriteMemory takes an input string... weird
    for i in xrange(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if error.Success() == False:
            print "[-] error: Failed to write memory at 0x%x." % current_patch_addr
            return
        current_patch_addr = current_patch_addr + 1

    return

def null(debugger, command, result, dict):
    '''Patch byte(s) at address to NULL (0x00). Use \'null help\' for more information.'''
    help = """
Patch process memory with NULL (0x00) byte(s) at given address.

Syntax: null <address> [<size>]

Note: default size is one byte if size not specified.
Note: expressions supported, do not use spaces between operators.
"""

    error = lldb.SBError()
    target = get_target()

    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return        
        null_addr = evaluate(cmd[0])
        patch_size = 1
        if null_addr == None:
            print "[-] error: invalid address value."
            print ""
            print help
            return
    elif len(cmd) == 2:
        null_addr = evaluate(cmd[0])
        if null_addr == None:
            print "[-] error: invalid address value."
            print ""
            print help
            return
        patch_size = evaluate(cmd[1])
        if patch_size == None:
            print "[-] error: invalid size value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a breakpoint address."
        print ""
        print help
        return

    current_patch_addr = null_addr
    # format for WriteMemory()
    patch_bytes = str('\x00')
    # can we do better here? WriteMemory takes an input string... weird
    for i in xrange(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if error.Success() == False:
            print "[-] error: Failed to write memory at 0x%x." % current_patch_addr
            return
        current_patch_addr = current_patch_addr + 1

    return

'''
    Implements stepover instruction.    
'''
def stepo(debugger, command, result, dict):
    '''Step over calls and some other instructions so we don't need to step into them. Use \'stepo help\' for more information.'''
    help = """
Step over calls and loops that we want executed but not step into.
Affected instructions: call, movs, stos, cmps, loop.

Syntax: stepo
"""

    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    global arm_type
    debugger.SetAsync(True)
    arch = get_arch()
            
    target = get_target()
        
    if is_arm():
        cpsr = get_gp_register("cpsr")
        t = (cpsr >> 5) & 1
        if t:
            #it's thumb
            arm_type = "thumbv7-apple-ios"
        else:
            arm_type = "armv7-apple-ios"

    # compute the next address where to breakpoint
    pc_addr = get_current_pc()
    if pc_addr == 0:
        print "[-] error: invalid current address."
        return

    next_addr = pc_addr + get_inst_size(pc_addr)
    # much easier to use the mnemonic output instead of disassembling via cmd line and parse
    mnemonic = get_mnemonic(pc_addr)

    if is_arm():
        if "blx" == mnemonic or "bl" == mnemonic:
            breakpoint = target.BreakpointCreateByAddress(next_addr)
            breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
            breakpoint.SetOneShot(True)
            breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
            target.GetProcess().Continue()
            return
        else:
            get_process().selected_thread.StepInstruction(False)
            return
    # XXX: make the other instructions besides call user configurable?
    # calls can be call, callq, so use wider matching for those
    if mnemonic == "call" or mnemonic == "callq" or "movs" == mnemonic or "stos" == mnemonic or "loop" == mnemonic or "cmps" == mnemonic:
        breakpoint = target.BreakpointCreateByAddress(next_addr)
        breakpoint.SetOneShot(True)
        breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
        target.GetProcess().Continue()
    else:
        get_process().selected_thread.StepInstruction(False)

# XXX: help
def LoadBreakPointsRva(debugger, command, result, dict):
    global  GlobalOutputList
    GlobalOutputList = []
    '''
    frame = get_frame();
        target = lldb.debugger.GetSelectedTarget();

        nummods = target.GetNumModules();
        #for x in range (0, nummods):
        #       mod = target.GetModuleAtIndex(x);
        #       #print(dir(mod));
        #       print(target.GetModuleAtIndex(x));              
        #       for sec in mod.section_iter():
        #               addr = sec.GetLoadAddress(target);
        #               name = sec.GetName();
        #               print(hex(addr));

        #1st module is executable
        mod = target.GetModuleAtIndex(0);
        sec = mod.GetSectionAtIndex(0);
        loadaddr = sec.GetLoadAddress(target);
        if loadaddr == lldb.LLDB_INVALID_ADDRESS:
                sec = mod.GetSectionAtIndex(1);
                loadaddr = sec.GetLoadAddress(target);
        print(hex(loadaddr));
    '''

    target = get_target()
    mod = target.GetModuleAtIndex(0)
    sec = mod.GetSectionAtIndex(0)
    loadaddr = sec.GetLoadAddress(target)
    if loadaddr == lldb.LLDB_INVALID_ADDRESS:
        sec = mod.GetSectionAtIndex(1)
        loadaddr = sec.GetLoadAddress(target)
    try:
        f = open(command, "r")
    except:
        output("[-] Failed to load file : " + command)
        result.PutCString("".join(GlobalListOutput))
        return
    while True:
        line = f.readline()
        if not line: 
            break
        line = line.rstrip()
        if not line: 
            break
        debugger.HandleCommand("breakpoint set -a " + hex(loadaddr + long(line, 16)))
    f.close()


# XXX: help
def LoadBreakPoints(debugger, command, result, dict):
    global GlobalOutputList
    GlobalOutputList = []

    try:
        f = open(command, "r")
    except:
        output("[-] Failed to load file : " + command)
        result.PutCString("".join(GlobalListOutput))
        return
    while True:
        line = f.readline()
        if not line:
            break
        line = line.rstrip()
        if not line:
            break
        debugger.HandleCommand("breakpoint set --name " + line)
    f.close()

# Temporarily breakpoint next instruction - this is useful to skip loops (don't want to use stepo for this purpose)
def bpn(debugger, command, result, dict):
    '''Temporarily breakpoint instruction at next address. Use \'bpn help\' for more information.'''
    help = """
Temporarily breakpoint instruction at next address

Syntax: bpn

Note: control flow is not respected, it breakpoints next instruction in memory.
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print help
           return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    target = get_target()
    start_addr = get_current_pc()
    next_addr = start_addr + get_inst_size(start_addr)
    
    breakpoint = target.BreakpointCreateByAddress(next_addr)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print "[+] Set temporary breakpoint at 0x%x" % next_addr

# command that sets rax to 1 or 0 and returns right away from current function
# technically just a shortcut to "thread return"
def crack(debugger, command, result, dict):
    '''Return from current function and set return value. Use \'crack help\' for more information.'''
    help = """
Return from current function and set return value

Syntax: crack <return value>

Sets rax to return value and returns immediately from current function.
You probably want to use this at the top of the function you want to return from.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print "[-] error: please insert a return value."
        print ""
        print help
        return
    if cmd[0] == "help":
        print help
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value == None:
        print "[-] error: invalid return value."
        print ""
        print help
        return

    frame = get_frame()
    # if we copy the SBValue from any register and use that copy
    # for return value we will get that register and rax/eax set
    # on return
    # the SBValue to ReturnFromFrame must be eValueTypeRegister type
    # if we do a lldb.SBValue() we can't set to that type
    # so we need to make a copy
    # can we use FindRegister() from frame?
    return_value = frame.reg["rax"]
    return_value.value = str(value)
    get_thread().ReturnFromFrame(frame, return_value)

# set a breakpoint with return command associated when hit
def crackcmd(debugger, command, result, dict):
    '''Breakpoint an address, when breakpoint is hit return from function and set return value. Use \'crackcmd help\' for more information.'''
    help = """
Breakpoint an address, when breakpoint is hit return from function and set return value.

Syntax: crackcmd <address> <return value>

Sets rax/eax to return value and returns immediately from current function where breakpoint was set.
"""
    global crack_cmds

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: please check required arguments."
        print ""
        print help
        return
    elif len(cmd) > 0 and cmd[0] == "help":
        print help
        return
    elif len(cmd) < 2:
        print "[-] error: please check required arguments."
        print ""
        print help
        return        

    # XXX: is there a way to verify if address is valid? or just let lldb error when setting the breakpoint
    address = evaluate(cmd[0])
    if address == None:
        print "[-] error: invalid address value."
        print ""
        print help
        return
    
    return_value = evaluate(cmd[1])
    if return_value == None:
        print "[-] error: invalid return value."
        print ""
        print help
        return
    
    for tmp_entry in crack_cmds:
        if tmp_entry['address'] == address:
            print "[-] error: address already contains a crack command."
            return

    # set a new entry so we can deal with it in the callback
    new_crack_entry = {}
    new_crack_entry['address'] = address
    new_crack_entry['return_value'] = return_value
    crack_cmds.append(new_crack_entry)

    target = get_target()

    # we want a global breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    # when the breakpoint is hit we get this callback executed
    breakpoint.SetScriptCallbackFunction('lldbinit.crackcmd_callback')

def crackcmd_callback(frame, bp_loc, internal_dict):
    global crack_cmds
    # retrieve address we just hit
    current_bp = bp_loc.GetLoadAddress()
    print "[+] warning: hit crack command breakpoint at 0x{:x}".format(current_bp)

    crack_entry = None
    for tmp_entry in crack_cmds:
        if tmp_entry['address'] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry == None:
        print "[-] error: current breakpoint not found in list."
        return

    # we can just set the register in the frame and return empty SBValue
    if is_x64() == True:
        frame.reg["rax"].value = str(crack_entry['return_value']).rstrip('L')
    elif is_i386() == True:
        frame.reg["eax"].value = str(crack_entry['return_value']).rstrip('L')
    else:
        print "[-] error: unsupported architecture."
        return

    get_thread().ReturnFromFrame(frame, lldb.SBValue())
    get_process().Continue()

# set a breakpoint with a command that doesn't return, just sets the specified register to a value
def crackcmd_noret(debugger, command, result, dict):
    '''Set a breakpoint and a register to a value when hit. Use \'crackcmd_noret help\' for more information.'''
    help = """
Set a breakpoint and a register to a value when hit.

Syntax: crackcmd_noret <address> <register> <value>

Sets the specified register to a value when the breakpoint at specified address is hit, and resumes execution.
"""
    global crack_cmds_noret

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: please check required arguments."
        print ""
        print help
        return
    if len(cmd) > 0 and cmd[0] == "help":
        print help
        return
    if len(cmd) < 3:
        print "[-] error: please check required arguments."
        print ""
        print help
        return

    address = evaluate(cmd[0])
    if address == None:
        print "[-] error: invalid address."
        print ""
        print help
        return

    # check if register is set and valid
    if (cmd[1] in All_Registers) == False:
        print "[-] error: invalid register."
        print ""
        print help
        return
    
    value = evaluate(cmd[2])
    if value == None:
        print "[-] error: invalid value."
        print ""
        print help
        return

    register = cmd[1]
    
    for tmp_entry in crack_cmds_noret:
        if tmp_entry['address'] == address:
            print "[-] error: address already contains a crack command."
            return

    # set a new entry so we can deal with it in the callback
    new_crack_entry = {}
    new_crack_entry['address'] = address
    new_crack_entry['register'] = register
    new_crack_entry['value'] = value
    
    crack_cmds_noret.append(new_crack_entry)

    target = get_target()

    # we want a global breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    # when the breakpoint is hit we get this callback executed
    breakpoint.SetScriptCallbackFunction('lldbinit.crackcmd_noret_callback')

def crackcmd_noret_callback(frame, bp_loc, internal_dict):
    global crack_cmds_noret
    # retrieve address we just hit
    current_bp = bp_loc.GetLoadAddress()
    print "[+] warning: hit crack command no ret breakpoint at 0x{:x}".format(current_bp)
    crack_entry = None
    for tmp_entry in crack_cmds_noret:
        if tmp_entry['address'] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry == None:
        print "[-] error: current breakpoint not found in list."
        return

    # must be a string!
    frame.reg[crack_entry['register']].value = str(crack_entry['value']).rstrip('L')
    get_process().Continue()

#
# End Breakpoint related commands
#

#
# Memory related commands
#

'''
    Output nice memory hexdumps...
'''
# display byte values and ASCII characters
def db(debugger, command, result, dict):
    '''Display hex dump in byte values and ASCII characters. Use \'db help\' for more information.'''
    help = """
Display memory hex dump in byte length and ASCII representation.

Syntax: db [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

    global GlobalListOutput
    GlobalListOutput = []
        
    cmd = command.split()

    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return        
        dump_addr = evaluate(cmd[0])
        if dump_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a start address."
        print ""
        print help
        return

    err = lldb.SBError()
    size = 0x100
    while size != 0:
        membuff = get_process().ReadMemory(dump_addr, size, err)
        if err.Success() == False and size == 0:
            output(str(err))
            result.PutCString("".join(GlobalListOutput))
            return
        if err.Success() == True:
            break
        size = size - 1
    membuff = membuff + "\x00" * (0x100-size) 
    color(BLUE)
    if get_pointer_size() == 4:
        output("[0x0000:0x%.08X]" % dump_addr)
        output("------------------------------------------------------")
    else:
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("------------------------------------------------------")
    color_bold()
    output("[data]")
    color_reset()
    output("\n")        
    #output(hexdump(dump_addr, membuff, " ", 16));
    index = 0
    while index < 0x100:
        data = struct.unpack("B"*16, membuff[index:index+0x10])
        if get_pointer_size() == 4:
            szaddr = "0x%.08X" % dump_addr
        else:
            szaddr = "0x%.016lX" % dump_addr
        fmtnice = "%.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X"
        fmtnice = fmtnice + " - " + fmtnice
        output("\033[1m%s :\033[0m %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X - %.02X %.02X %.02X %.02X %.02X %.02X %.02X %.02X \033[1m%s\033[0m" % 
            (szaddr, 
            data[0], 
            data[1], 
            data[2], 
            data[3], 
            data[4], 
            data[5], 
            data[6], 
            data[7], 
            data[8], 
            data[9], 
            data[10], 
            data[11], 
            data[12], 
            data[13], 
            data[14], 
            data[15], 
            quotechars(membuff[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color_reset()
    #last element of the list has all data output...
    #so we remove last \n
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display word values and ASCII characters
def dw(debugger, command, result, dict):
    ''' Display hex dump in word values and ASCII characters. Use \'dw help\' for more information.'''
    help = """
Display memory hex dump in word length and ASCII representation.

Syntax: dw [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

    global GlobalListOutput
    GlobalListOutput = []

    cmd = command.split()

    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a start address."
        print ""
        print help
        return

    err = lldb.SBError()
    size = 0x100
    while size != 0:
        membuff = get_process().ReadMemory(dump_addr, size, err)
        if err.Success() == False and size == 0:
            output(str(err))
            result.PutCString("".join(GlobalListOutput))
            return
        if err.Success() == True:
            break
        size = size - 2
    membuff = membuff + "\x00" * (0x100-size)

    color(BLUE)
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("[0x0000:0x%.08X]" % dump_addr)
        output("--------------------------------------------")
    else: #is_x64():
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("--------------------------------------------")
    color_bold()
    output("[data]")
    color_reset()
    output("\n")
    index = 0
    while index < 0x100:
        data = struct.unpack("HHHHHHHH", membuff[index:index+0x10])
        if get_pointer_size() == 4:
            szaddr = "0x%.08X" % dump_addr
        else:
            szaddr = "0x%.016lX" % dump_addr
        output("\033[1m%s :\033[0m %.04X %.04X %.04X %.04X %.04X %.04X %.04X %.04X \033[1m%s\033[0m" % (szaddr, 
            data[0],
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            quotechars(membuff[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color_reset()
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display dword values and ASCII characters
def dd(debugger, command, result, dict):
    ''' Display hex dump in double word values and ASCII characters. Use \'dd help\' for more information.'''
    help = """
Display memory hex dump in double word length and ASCII representation.

Syntax: dd [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

    global GlobalListOutput
    GlobalListOutput = []

    cmd = command.split()

    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a start address."
        print ""
        print help
        return

    err = lldb.SBError()
    size = 0x100
    while size != 0:    
        membuff = get_process().ReadMemory(dump_addr, size, err)
        if err.Success() == False and size == 0:
            output(str(err))
            result.PutCString("".join(GlobalListOutput))
            return
        if err.Success() == True:
            break
        size = size - 4
    membuff = membuff + "\x00" * (0x100-size)
    color(BLUE)
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("[0x0000:0x%.08X]" % dump_addr)
        output("----------------------------------------")
    else: #is_x64():
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("----------------------------------------")
    color_bold()
    output("[data]")
    color_reset()
    output("\n")
    index = 0
    while index < 0x100:
        (mem0, mem1, mem2, mem3) = struct.unpack("IIII", membuff[index:index+0x10])
        if get_pointer_size() == 4: #is_i386() or is_arm():
            szaddr = "0x%.08X" % dump_addr
        else:  #is_x64():
            szaddr = "0x%.016lX" % dump_addr
        output("\033[1m%s :\033[0m %.08X %.08X %.08X %.08X \033[1m%s\033[0m" % (szaddr, 
                                            mem0, 
                                            mem1, 
                                            mem2, 
                                            mem3, 
                                            quotechars(membuff[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color_reset()
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display quad values
def dq(debugger, command, result, dict):
    ''' Display hex dump in quad values. Use \'dq help\' for more information.'''
    help = """
Display memory hex dump in quad word length.

Syntax: dq [<address>]

Note: if no address specified it will dump current instruction pointer address.
Note: expressions supported, do not use spaces between operators.
"""

    global GlobalListOutput
    GlobalListOutput = []

    cmd = command.split()

    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            print "[-] error: invalid current address."
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return        
        dump_addr = evaluate(cmd[0])
        if dump_addr == None:
            print "[-] error: invalid input address value."
            print ""
            print help
            return
    else:
        print "[-] error: please insert a start address."
        print ""
        print help
        return

    err = lldb.SBError()
    size = 0x100
    while size != 0:
        membuff = get_process().ReadMemory(dump_addr, size, err)
        if err.Success() == False and size == 0:
            output(str(err))
            result.PutCString("".join(GlobalListOutput))
            return
        if err.Success() == True:
            break
        size = size - 8
    membuff = membuff + "\x00" * (0x100-size)
    if err.Success() == False:
        output(str(err))
        result.PutCString("".join(GlobalListOutput))
        return

    color(BLUE)
    if get_pointer_size() == 4:
        output("[0x0000:0x%.08X]" % dump_addr)
        output("-------------------------------------------------------")
    else:
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("-------------------------------------------------------")
    color_bold()
    output("[data]")
    color_reset()
    output("\n")   
    index = 0
    while index < 0x100:
        (mem0, mem1, mem2, mem3) = struct.unpack("QQQQ", membuff[index:index+0x20])
        if get_pointer_size() == 4:
            szaddr = "0x%.08X" % dump_addr
        else:
            szaddr = "0x%.016lX" % dump_addr
        output("\033[1m%s :\033[0m %.016lX %.016lX %.016lX %.016lX" % (szaddr, mem0, mem1, mem2, mem3))
        if index + 0x20 != 0x100:
            output("\n")
        index += 0x20
        dump_addr += 0x20
    color_reset()
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

def hexdump(addr, chars, sep, width, lines=5):
    l = []
    line_count = 0
    while chars:
        if line_count >= lines:
            break
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        arch = get_arch()
        if get_pointer_size() == 4:
            szaddr = "0x%.08X" % addr
        else:
            szaddr = "0x%.016lX" % addr
        l.append("\033[1m%s :\033[0m %s%s \033[1m%s\033[0m" % (szaddr, sep.join( "%02X" % ord(c) for c in line ), sep, quotechars( line )))
        addr += 0x10
        line_count = line_count + 1
    return "\n".join(l)

def quotechars( chars ):
        #return ''.join( ['.', c][c.isalnum()] for c in chars )
    data = ""
    for x in chars:
        if ord(x) >= 0x20 and ord(x) <= 126:
            data += x
        else:       
            data += "."
    return data

# XXX: help
def findmem(debugger, command, result, dict):
    '''Search memory'''
    help == """
[options]
 -s searches for specified string
 -u searches for specified unicode string
 -b searches binary (eg. -b 4142434445 will find ABCDE anywhere in mem)
 -d searches dword  (eg. -d 0x41414141)
 -q searches qword  (eg. -d 0x4141414141414141)
 -f loads patern from file if it's tooooo big to fit into any of specified options
 -c specify if you want to find N occurances (default is all)
 """

    global GlobalListOutput
    GlobalListOutput = []

    arg = str(command)
    parser = argparse.ArgumentParser(prog="lldb")
    parser.add_argument("-s", "--string",  help="Search string")
    parser.add_argument("-u", "--unicode", help="Search unicode string")
    parser.add_argument("-b", "--binary",  help="Serach binary string")
    parser.add_argument("-d", "--dword",   help="Find dword (native packing)")
    parser.add_argument("-q", "--qword",   help="Find qword (native packing)")
    parser.add_argument("-f", "--file" ,   help="Load find pattern from file")
    parser.add_argument("-c", "--count",   help="How many occurances to find, default is all")

    parser = parser.parse_args(arg.split())
    
    if parser.string != None:
        search_string = parser.string
    elif parser.unicode != None:
        search_string  = unicode(parser.unicode)
    elif parser.binary != None:
        search_string = parser.binary.decode("hex")
    elif parser.dword != None:
        dword = evaluate(parser.dword)
        if dword == None:
            print("[-] Error evaluating : " + parser.dword)
            return
        search_string = struct.pack("I", dword & 0xffffffff)
    elif parser.qword != None:
        qword = evaluate(parser.qword)
        if qword == None:
            print("[-] Error evaluating : " + parser.qword)
            return
        search_string = struct.pack("Q", qword & 0xffffffffffffffff)
    elif parser.file != None:
        f = 0
        try:
            f = open(parser.file, "rb")
        except:
            print("[-] Failed to open file : " + parser.file)
            return
        search_string = f.read()
        f.close()
    else:
        print("[-] Wrong option... use findmem --help")
        return
    
    count = -1
    if parser.count != None:
        count = evaluate(parser.count)
        if count == None:
            print("[-] Error evaluating count : " + parser.count)
            return
    
    process = get_process()
    pid = process.GetProcessID()
    output_data = subprocess.check_output(["/usr/bin/vmmap", "%d" % pid])
    lines = output_data.split("\n")
    #print(lines);
    #this relies on output from /usr/bin/vmmap so code is dependant on that 
    #only reason why it's used is for better description of regions, which is
    #nice to have. If they change vmmap in the future, I'll use my version 
    #and that output is much easier to parse...
    newlines = []
    for x in lines:
        p = re.compile("([\S\s]+)\s([\da-fA-F]{16}-[\da-fA-F]{16}|[\da-fA-F]{8}-[\da-fA-F]{8})")
        m = p.search(x)
        if not m: continue
        tmp = []
        mem_name  = m.group(1)
        mem_range = m.group(2)
        #0x000000-0x000000
        mem_start = long(mem_range.split("-")[0], 16)
        mem_end   = long(mem_range.split("-")[1], 16)
        tmp.append(mem_name)
        tmp.append(mem_start)
        tmp.append(mem_end)
        newlines.append(tmp)
    
    lines = sorted(newlines, key=lambda sortnewlines: sortnewlines[1])
    #move line extraction a bit up, thus we can latter sort it, as vmmap gives
    #readable pages only, and then writable pages, so it looks ugly a bit :)
    newlines = []
    for x in lines:
        mem_name = x[0]
        mem_start= x[1]
        mem_end  = x[2]
        mem_size = mem_end - mem_start
    
        err = lldb.SBError()
                
        membuff = process.ReadMemory(mem_start, mem_size, err)
        if err.Success() == False:
            #output(str(err));
            #result.PutCString("".join(GlobalListOutput));
            continue
        off = 0
        base_displayed = 0

        while True:
            if count == 0: 
                return
            idx = membuff.find(search_string)
            if idx == -1: 
                break
            if count != -1:
                count = count - 1
            off += idx
    
            GlobalListOutput = []
            
            if get_pointer_size() == 4:
                ptrformat = "%.08X"
            else:
                ptrformat = "%.016lX"

            color_reset()
            output("Found at : ")
            color(GREEN)
            output(ptrformat % (mem_start + off))
            color_reset()
            if base_displayed == 0:
                output(" base : ")
                color(YELLOW)
                output(ptrformat % mem_start)
                color_reset()
                base_displayed = 1
            else:
                output("        ")
                if get_pointer_size() == 4:
                    output(" " * 8)
                else:
                    output(" " * 16)
            #well if somebody allocated 4GB of course offset will be to small to fit here
            #but who cares...
            output(" off : %.08X %s" % (off, mem_name))
            print("".join(GlobalListOutput))
            membuff = membuff[idx+len(search_string):]
            off += len(search_string)
    return

def datawin(debugger, command, result, dict):
    '''Configure address to display in data window. Use \'datawin help\' for more information.'''
    help = """
Configure address to display in data window.

Syntax: datawin <address>

The data window display will be fixed to the address you set. Useful to observe strings being decrypted, etc.
Note: expressions supported, do not use spaces between operators.
"""

    global DATA_WINDOW_ADDRESS

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: please insert an address."
        print ""
        print help
        return

    if cmd[0] == "help":
        print help
        return        

    dump_addr = evaluate(cmd[0])
    if dump_addr == None:
        print "[-] error: invalid address value."
        print ""
        print help
        DATA_WINDOW_ADDRESS = 0
        return
    DATA_WINDOW_ADDRESS = dump_addr

#
# End Memory related commands
#

#
# Functions to extract internal and process lldb information
#

def get_arch():
    return lldb.debugger.GetSelectedTarget().triple.split('-')[0]

#return frame for stopped thread... there should be one at least...
def get_frame():
    ret = None
    # SBProcess supports thread iteration -> SBThread
    for thread in get_process():
        if thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            ret = thread.GetFrameAtIndex(0)
            break
    # this will generate a false positive when we start the target the first time because there's no context yet.
    if ret == None:
        print "[-] warning: get_frame() failed. Is the target binary started?"

    return ret

def get_thread():
    ret = None
    # SBProcess supports thread iteration -> SBThread
    for thread in get_process():
        if thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            ret = thread
    
    if ret == None:
        print "[-] warning: get_thread() failed. Is the target binary started?"

    return ret

def get_target():
    target = lldb.debugger.GetSelectedTarget()
    if not target:
        print "[-] error: no target available. please add a target to lldb."
        return
    return target

def get_process():
    # process
    # A read only property that returns an lldb object that represents the process (lldb.SBProcess) that this target owns.
    return lldb.debugger.GetSelectedTarget().process

# evaluate an expression and return the value it represents
def evaluate(command):
    frame = get_frame()

    # use the target version - if no target exists we can't do anything about it
    if frame == None:
        return evaluate_target(command)
    
    value = frame.EvaluateExpression(command)
    if value.IsValid() == False:
        return None
    try:
        value = long(value.GetValue(), 10)
        return value
    except:
        return None

# evaluate expression under target context instead of frame, for cases where frame is not available (target not started for example)
def evaluate_target(command):
    target = get_target()
    if target == None:
        return None
    
    value = target.EvaluateExpression(command)
    if value.IsValid() == False:
        return None
    try:
        value = long(value.GetValue(), 10)
        return value
    except:
        return None

def is_i386():
    arch = get_arch()
    if arch[0:1] == "i":
        return True
    return False

def is_x64():
    arch = get_arch()
    if arch == "x86_64" or arch == "x86_64h":
        return True
    return False

def is_arm():
    arch = get_arch()
    if "arm" in arch:
        return True
    return False

def get_pointer_size():
    poisz = evaluate("sizeof(long)")
    return poisz

# from https://github.com/facebook/chisel/blob/master/fblldbobjcruntimehelpers.py
def get_instance_object():
    instanceObject = None
    if is_i386():
        instanceObject = '*(id*)($esp+4)'
    elif is_x64():
        instanceObject = '(id)$rdi'
    # not supported yet
    elif is_arm():
        instanceObject = None
  
    return instanceObject
#
# End Functions to extract internal and process lldb information
#

#
# Register related commands
#

# return the int value of a general purpose register
def get_gp_register(reg_name):
    regs = get_registers("general purpose")
    if regs == None:
        return 0
    for reg in regs:
        if reg_name == reg.GetName():
            return int(reg.GetValue(), 16)
    return 0
        
def get_register(reg_name):
    regs = get_registers("general purpose")
    if regs == None:
        return "0"
    for reg in regs:
        if reg_name == reg.GetName():
            return reg.GetValue()
    return "0"

def get_registers(kind):
    """Returns the registers given the frame and the kind of registers desired.

    Returns None if there's no such kind.
    """
    registerSet = get_frame().GetRegisters() # Return type of SBValueList.
    for value in registerSet:
        if kind.lower() in value.GetName().lower():
            return value

    return None

# retrieve current instruction pointer via registers information
# XXX: add ARM
def get_current_pc():
    if is_i386():
        pc_addr = get_gp_register("eip")
    elif is_x64():
        pc_addr = get_gp_register("rip")
    else:
        print "[-] error: wrong architecture."
        return 0
    return pc_addr

# retrieve current stack pointer via registers information
# XXX: add ARM
def get_current_sp():
    if is_i386():
        sp_addr = get_gp_register("esp")
    elif is_x64():
        sp_addr = get_gp_register("rsp")
    else:
        print "[-] error: wrong architecture."
        return 0
    return sp_addr

# helper function that updates given register
def update_register(register, command):
    help = """
Update given register with a new value.

Syntax: register_name <value>

Where value can be a single value or an expression.
"""

    cmd = command.split()
    if len(cmd) == 0:
        print "[-] error: command requires arguments."
        print ""
        print help
        return

    if cmd[0] == "help":
        print help
        return

    value = evaluate(command)
    if value == None:
        print "[-] error: invalid input value."
        print ""
        print help
        return

    # we need to format because hex() will return string with an L and that will fail to update register
    get_frame().reg[register].value = format(value, '#x')

# shortcut functions to modify each register
def rip(debugger, command, result, dict):
    update_register("rip", command)

def rax(debugger, command, result, dict):
    update_register("rax", command)

def rbx(debugger, command, result, dict):
    update_register("rbx", command)

def rbp(debugger, command, result, dict):
    update_register("rbp", command)

def rsp(debugger, command, result, dict):
    update_register("rsp", command)

def rdi(debugger, command, result, dict):
    update_register("rdi", command)

def rsi(debugger, command, result, dict):
    update_register("rsi", command)

def rdx(debugger, command, result, dict):
    update_register("rdx", command)

def rcx(debugger, command, result, dict):
    update_register("rcx", command)

def r8(debugger, command, result, dict):
    update_register("r8", command)

def r9(debugger, command, result, dict):
    update_register("r9", command)

def r10(debugger, command, result, dict):
    update_register("r10", command)

def r11(debugger, command, result, dict):
    update_register("r11", command)

def r12(debugger, command, result, dict):
    update_register("r12", command)

def r13(debugger, command, result, dict):
    update_register("r13", command)

def r14(debugger, command, result, dict):
    update_register("r14", command)

def r15(debugger, command, result, dict):
    update_register("r15", command)

def eip(debugger, command, result, dict):
    update_register("eip", command)

def eax(debugger, command, result, dict):
    update_register("eax", command)

def ebx(debugger, command, result, dict):
    update_register("ebx", command)

def ebp(debugger, command, result, dict):
    update_register("ebp", command)

def esp(debugger, command, result, dict):
    update_register("esp", command)

def edi(debugger, command, result, dict):
    update_register("edi", command)

def esi(debugger, command, result, dict):
    update_register("esi", command)

def edx(debugger, command, result, dict):
    update_register("edx", command)

def ecx(debugger, command, result, dict):
    update_register("ecx", command)

#
# modify eflags/rflags commands
#
def modify_eflags(register):
    # read the current value so we can modify it
    if is_x64():
        eflags = get_gp_register("rflags")
    elif is_i386():
        eflags = get_gp_register("eflags")
    else:
        print "[-] error: unsupported architecture."
        return

    if register == "a":
        if (eflags >> 4) & 1:
            eflags = eflags & ~0x10
        else:
            eflags = eflags | 0x10
    elif register == "c":
        if (eflags & 1):
            eflags = eflags & ~0x1
        else:
            eflags = eflags | 0x1
    elif register == "d":
        if (eflags >> 0xA) & 1:
            eflags = eflags & ~0x400
        else:
            eflags = eflags | 0x400
    elif register == "i":
        if (eflags >> 0x9) & 1:
            eflags = eflags & ~0x200
        else:
            eflags = eflags | 0x200
    elif register == "o":
        if (eflags >> 0xB) & 1:
            eflags = eflags & ~0x800
        else:
            eflags = eflags | 0x800
    elif register == "p":
        if (eflags >> 0x2) & 1:
            eflags = eflags & ~0x4
        else:
            eflags = eflags | 0x4
    elif register == "s":
        if (eflags >> 0x7) & 1:
            eflags = eflags & ~0x80
        else:
            eflags = eflags | 0x80
    elif register == "t":
        if (eflags >> 0x8) & 1:
            eflags = eflags & ~0x100
        else:
            eflags = eflags | 0x100
    elif register == "z":
        if (eflags >> 6) & 1:
            eflags = eflags & ~0x40
        else:
            eflags = eflags | 0x40

    # finally update the value
    if is_x64():
        get_frame().reg["rflags"].value = format(eflags, '#x')
    elif is_i386():
        get_frame().reg["eflags"].value = format(eflags, '#x')

def cfa(debugger, command, result, dict):
    '''Change adjust flag. Use \'cfa help\' for more information.'''
    help = """
Flip current adjust flag.

Syntax: cfa
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return
    
    modify_eflags("a")

def cfc(debugger, command, result, dict):
    '''Change carry flag. Use \'cfc help\' for more information.'''
    help = """
Flip current carry flag.

Syntax: cfc
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("c")

def cfd(debugger, command, result, dict):
    '''Change direction flag. Use \'cfd help\' for more information.'''
    help = """
Flip current direction flag.

Syntax: cfd
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return
    
    modify_eflags("d")

def cfi(debugger, command, result, dict):
    '''Change interrupt flag. Use \'cfi help\' for more information.'''
    help = """
Flip current interrupt flag.

Syntax: cfi
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("i")

def cfo(debugger, command, result, dict):
    '''Change overflow flag. Use \'cfo help\' for more information.'''
    help = """
Flip current overflow flag.

Syntax: cfo
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("o")

def cfp(debugger, command, result, dict):
    '''Change parity flag. Use \'cfp help\' for more information.'''
    help = """
Flip current parity flag.

Syntax: cfp
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("p")

def cfs(debugger, command, result, dict):
    '''Change sign flag. Use \'cfs help\' for more information.'''
    help = """
Flip current sign flag.

Syntax: cfs
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("s")

def cft(debugger, command, result, dict):
    '''Change trap flag. Use \'cft help\' for more information.'''
    help = """
Flip current trap flag.

Syntax: cft
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("t")

def cfz(debugger, command, result, dict):
    '''Change zero flag. Use \'cfz help\' for more information.'''
    help = """
Flip current zero flag.

Syntax: cfz
"""
    
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print help
            return
        print "[-] error: command doesn't take any arguments."
        print ""
        print help
        return

    modify_eflags("z")

#
# end modify eflags/rflags commands
#

def dump_eflags(eflags):
    if (eflags >> 0xB) & 1:
        output("O ")
    else:
        output("o ")
    
    if (eflags >> 0xA) & 1:
        output("D ")
    else:
        output("d ")

    if (eflags >> 9) & 1:
        output("I ")
    else:
        output("i ")

    if (eflags >> 8) & 1:
        output("T ")
    else:
        output("t ")
    
    if (eflags >> 7) & 1:
        output("S ")
    else:
        output("s ")
    
    if (eflags >> 6) & 1:
        output("Z ")
    else:
        output("z ")
    
    if (eflags >> 4) & 1:
        output("A ")
    else:
        output("a ")

    if (eflags >> 2) & 1:
        output("P ")
    else:
        output("p ")        

    if eflags & 1:
        output("C")
    else:
        output("c")

# function to dump the conditional jumps results
def dump_jumpx86(eflags):
    o_flag = 0
    d_flag = 0
    i_flag = 0
    t_flag = 0
    s_flag = 0
    z_flag = 0
    a_flag = 0
    p_flag = 0
    c_flag = 0

    if (eflags >> 0xB) & 1:
        o_flag = 1
    
    if (eflags >> 0xA) & 1:
        d_flag = 1

    if (eflags >> 9) & 1:
        i_flag = 1

    if (eflags >> 8) & 1:
        t_flag = 1
    
    if (eflags >> 7) & 1:
        s_flag = 1
    
    if (eflags >> 6) & 1:
        z_flag = 1
    
    if (eflags >> 4) & 1:
        a_flag = 1

    if (eflags >> 2) & 1:
        p_flag = 1

    if eflags & 1:
        c_flag = 1

    error = lldb.SBError()
    target = get_target()
    if is_i386():
        pc_addr = get_gp_register("eip")
    elif is_x64():
        pc_addr = get_gp_register("rip")
    else:
        print "[-] error: wrong architecture."
        return

    mnemonic = get_mnemonic(pc_addr)

    color(RED)
    output_string=""
    ## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
    ## opcode 0x0F87: JNBE, JA
    if "ja" == mnemonic or "jnbe" == mnemonic:
        if c_flag == 0 and z_flag == 0:
            output_string="Jump is taken (c = 0 and z = 0)"
        else:
            output_string="Jump is NOT taken (c = 0 and z = 0)"
    ## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
    ## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
    if "jae" == mnemonic or "jnb" == mnemonic or "jnc" == mnemonic:
        if c_flag == 0:
            output_string="Jump is taken (c = 0)"
        else:
            output_string="Jump is NOT taken (c != 0)"
    ## opcode 0x72: JB, JC, JNAE (jump if CF=1)
    ## opcode 0x0F82: JNAE, JB, JC
    if "jb" == mnemonic or "jc" == mnemonic or "jnae" == mnemonic:
        if c_flag == 1:
            output_string="Jump is taken (c = 1)"
        else:
            output_string="Jump is NOT taken (c != 1)"
    ## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
    ## opcode 0x0F86: JBE, JNA
    if "jbe" == mnemonic or "jna" == mnemonic:
        if c_flag == 1 or z_flag == 1:
            output_string="Jump is taken (c = 1 or z = 1)"
        else:
            output_string="Jump is NOT taken (c != 1 or z != 1)"
    ## opcode 0xE3: JCXZ, JECXZ, JRCXZ (jump if CX=0 or ECX=0 or RCX=0)
    # XXX: we just need cx output...
    if "jcxz" == mnemonic or "jecxz" == mnemonic or "jrcxz" == mnemonic:
        rcx = get_gp_register("rcx")
        ecx = get_gp_register("ecx")
        cx = get_gp_register("cx")
        if ecx == 0 or cx == 0 or rcx == 0:
            output_string="Jump is taken (cx = 0 or ecx = 0 or rcx = 0)"
        else:
            output_string="Jump is NOT taken (cx != 0 or ecx != 0 or rcx != 0)"
    ## opcode 0x74: JE, JZ (jump if ZF=1)
    ## opcode 0x0F84: JZ, JE, JZ (jump if ZF=1)
    if "je" == mnemonic or "jz" == mnemonic:
        if z_flag == 1:
            output_string="Jump is taken (z = 1)"
        else:
            output_string="Jump is NOT taken (z != 1)"
    ## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
    ## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
    if "jg" == mnemonic or "jnle" == mnemonic:
        if z_flag == 0 and s_flag == o_flag:
            output_string="Jump is taken (z = 0 and s = o)"
        else:
            output_string="Jump is NOT taken (z != 0 or s != o)"
    ## opcode 0x7D: JGE, JNL (jump if SF=OF)
    ## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
    if "jge" == mnemonic or "jnl" == mnemonic:
        if s_flag == o_flag:
            output_string="Jump is taken (s = o)"
        else:
            output_string="Jump is NOT taken (s != o)"
    ## opcode: 0x7C: JL, JNGE (jump if SF != OF)
    ## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
    if "jl" == mnemonic or "jnge" == mnemonic:
        if s_flag != o_flag:
            output_string="Jump is taken (s != o)"
        else:
            output_string="Jump is NOT taken (s = o)"
    ## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
    ## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
    if "jle" == mnemonic or "jng" == mnemonic:
        if z_flag == 1 or s_flag != o_flag:
            output_string="Jump is taken (z = 1 or s != o)"
        else:
            output_string="Jump is NOT taken (z != 1 or s = o)"
    ## opcode 0x75: JNE, JNZ (jump if ZF = 0)
    ## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
    if "jne" == mnemonic or "jnz" == mnemonic:
        if z_flag == 0:
            output_string="Jump is taken (z = 0)"
        else:
            output_string="Jump is NOT taken (z != 0)"
    ## opcode 0x71: JNO (OF = 0)
    ## opcode 0x0F81: JNO (OF = 0)
    if "jno" == mnemonic:
        if o_flag == 0:
            output_string="Jump is taken (o = 0)"
        else:
            output_string="Jump is NOT taken (o != 0)"
    ## opcode 0x7B: JNP, JPO (jump if PF = 0)
    ## opcode 0x0F8B: JPO (jump if PF = 0)
    if "jnp" == mnemonic or "jpo" == mnemonic:
        if p_flag == 0:
            output_string="Jump is NOT taken (p = 0)"
        else:
            output_string="Jump is taken (p != 0)"
    ## opcode 0x79: JNS (jump if SF = 0)
    ## opcode 0x0F89: JNS (jump if SF = 0)
    if "jns" == mnemonic:
        if s_flag == 0:
            output_string="Jump is taken (s = 0)"
        else:
            output_string="Jump is NOT taken (s != 0)"
    ## opcode 0x70: JO (jump if OF=1)
    ## opcode 0x0F80: JO (jump if OF=1)
    if "jo" == mnemonic:
        if o_flag == 1:
            output_string="Jump is taken (o = 1)"
        else:
            output_string="Jump is NOT taken (o != 1)"
    ## opcode 0x7A: JP, JPE (jump if PF=1)
    ## opcode 0x0F8A: JP, JPE (jump if PF=1)
    if "jp" == mnemonic or "jpe" == mnemonic:
        if p_flag == 1:
            output_string="Jump is taken (p = 1)"
        else:
            output_string="Jump is NOT taken (p != 1)"
    ## opcode 0x78: JS (jump if SF=1)
    ## opcode 0x0F88: JS (jump if SF=1)
    if "js" == mnemonic:
        if s_flag == 1:
            output_string="Jump is taken (s = 1)"
        else:
            output_string="Jump is NOT taken (s != 1)"

    if is_i386():
        output(" " + output_string)
    elif is_x64():
        output("                                              " + output_string)
    else:
        output(output_string)

    color_reset()

def reg64():
    global old_cs
    global old_ds
    global old_fs
    global old_gs
    global old_ss
    global old_es
    global old_rax
    global old_rcx
    global old_rdx
    global old_rbx
    global old_rsp
    global old_rbp
    global old_rsi
    global old_rdi
    global old_r8 
    global old_r9 
    global old_r10
    global old_r11
    global old_r12
    global old_r13
    global old_r14
    global old_r15
    global old_rflags
    global old_rip

    rax = get_gp_register("rax")
    rcx = get_gp_register("rcx")
    rdx = get_gp_register("rdx")
    rbx = get_gp_register("rbx")
    rsp = get_gp_register("rsp")
    rbp = get_gp_register("rbp")
    rsi = get_gp_register("rsi")
    rdi = get_gp_register("rdi")
    r8  = get_gp_register("r8")
    r9  = get_gp_register("r9")
    r10 = get_gp_register("r10")
    r11 = get_gp_register("r11")
    r12 = get_gp_register("r12")
    r13 = get_gp_register("r13")
    r14 = get_gp_register("r14")
    r15 = get_gp_register("r15")
    rip = get_gp_register("rip")
    rflags = get_gp_register("rflags")
    cs = get_gp_register("cs")
    gs = get_gp_register("gs")
    fs = get_gp_register("fs")

    color(COLOR_REGNAME)
    output("  RAX: ")
    if rax == old_rax:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rax))
    old_rax = rax
    
    color(COLOR_REGNAME)
    output("  RBX: ")
    if rbx == old_rbx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rbx))
    old_rbx = rbx
    
    color(COLOR_REGNAME)
    output("  RBP: ")
    if rbp == old_rbp:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rbp))
    old_rbp = rbp
    
    color(COLOR_REGNAME)
    output("  RSP: ")
    if rsp == old_rsp:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rsp))
    old_rsp = rsp
    
    output("  ")
    color_bold()
    color_underline()
    color(COLOR_CPUFLAGS)
    dump_eflags(rflags)
    color_reset()
    
    output("\n")
            
    color(COLOR_REGNAME)
    output("  RDI: ")
    if rdi == old_rdi:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rdi))
    old_rdi = rdi
    
    color(COLOR_REGNAME)
    output("  RSI: ")
    if rsi == old_rsi:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rsi))
    old_rsi = rsi
    
    color(COLOR_REGNAME)
    output("  RDX: ")
    if rdx == old_rdx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rdx))
    old_rdx = rdx
    
    color(COLOR_REGNAME)
    output("  RCX: ")
    if rcx == old_rcx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rcx))
    old_rcx = rcx
    
    color(COLOR_REGNAME)
    output("  RIP: ")
    if rip == old_rip:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rip))
    old_rip = rip
    output("\n")
        
    color(COLOR_REGNAME)
    output("  R8:  ")
    if r8 == old_r8:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r8))
    old_r8 = r8
    
    color(COLOR_REGNAME)
    output("  R9:  ")
    if r9 == old_r9:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r9))
    old_r9 = r9
    
    color(COLOR_REGNAME)
    output("  R10: ")
    if r10 == old_r10:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r10))
    old_r10 = r10
    
    color(COLOR_REGNAME)
    output("  R11: ")
    if r11 == old_r11:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r11))
    old_r11 = r11
    
    color(COLOR_REGNAME)
    output("  R12: ")
    if r12 == old_r12:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r12))
    old_r12 = r12
    
    output("\n")
        
    color(COLOR_REGNAME)
    output("  R13: ")
    if r13 == old_r13:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r13))
    old_r13 = r13
    
    color(COLOR_REGNAME)
    output("  R14: ")
    if r14 == old_r14:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r14))
    old_r14 = r14
    
    color(COLOR_REGNAME)
    output("  R15: ")
    if r15 == old_r15:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r15))
    old_r15 = r15
    output("\n")
        
    color(COLOR_REGNAME)
    output("  CS:  ")
    if cs == old_cs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (cs))
    old_cs = cs
        
    color(COLOR_REGNAME)
    output("  FS: ")
    if fs == old_fs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (fs))
    old_fs = fs
    
    color(COLOR_REGNAME)
    output("  GS: ")
    if gs == old_gs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (gs))
    old_gs = gs
    
    dump_jumpx86(rflags)
    output("\n")

def reg32():
    global old_eax
    global old_ecx
    global old_edx
    global old_ebx
    global old_esp
    global old_ebp
    global old_esi
    global old_edi
    global old_eflags
    global old_cs
    global old_ds
    global old_fs
    global old_gs
    global old_ss
    global old_es
    global old_eip
        
    color(COLOR_REGNAME)
    output("  EAX: ")
    eax = get_gp_register("eax")
    if eax == old_eax:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (eax))
    old_eax = eax
    
    color(COLOR_REGNAME)
    output("  EBX: ")
    ebx = get_gp_register("ebx")
    if ebx == old_ebx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ebx))
    old_ebx = ebx
    
    color(COLOR_REGNAME)
    output("  ECX: ")
    ecx = get_gp_register("ecx")
    if ecx == old_ecx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ecx))
    old_ecx = ecx

    color(COLOR_REGNAME)
    output("  EDX: ")
    edx = get_gp_register("edx")
    if edx == old_edx:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (edx))
    old_edx = edx
    
    output("  ")
    eflags = get_gp_register("eflags")
    color_bold()
    color_underline()
    color(COLOR_CPUFLAGS)
    dump_eflags(eflags)
    color_reset()
    
    output("\n")
    
    color(COLOR_REGNAME)
    output("  ESI: ")
    esi = get_gp_register("esi")
    if esi == old_esi:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (esi))
    old_esi = esi
    
    color(COLOR_REGNAME)
    output("  EDI: ")
    edi = get_gp_register("edi")
    if edi == old_edi:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (edi))
    old_edi = edi
    
    color(COLOR_REGNAME)
    output("  EBP: ")
    ebp = get_gp_register("ebp")
    if ebp == old_ebp:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ebp))
    old_ebp = ebp
    
    color(COLOR_REGNAME)
    output("  ESP: ")
    esp = get_gp_register("esp")
    if esp == old_esp:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (esp))
    old_esp = esp
    
    color(COLOR_REGNAME)
    output("  EIP: ")
    eip = get_gp_register("eip")
    if eip == old_eip:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (eip))
    old_eip = eip
    output("\n")
    
    color(COLOR_REGNAME)
    output("  CS:  ")
    cs = get_gp_register("cs")
    if cs == old_cs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (cs))
    old_cs = cs
    
    color(COLOR_REGNAME)
    output("  DS: ")
    ds = get_gp_register("ds")
    if ds == old_ds:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (ds))
    old_ds = ds
    
    color(COLOR_REGNAME)
    output("  ES: ")
    es = get_gp_register("es")
    if es == old_es:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (es))
    old_es = es
    
    color(COLOR_REGNAME)
    output("  FS: ")
    fs = get_gp_register("fs")
    if fs == old_fs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (fs))
    old_fs = fs
    
    color(COLOR_REGNAME)
    output("  GS: ")
    gs = get_gp_register("gs")
    if gs == old_gs:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (gs))
    old_gs = gs
    
    color(COLOR_REGNAME)
    output("  SS: ")
    ss = get_gp_register("ss")
    if ss == old_ss:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (ss))
    old_ss = ss

    dump_jumpx86(eflags)
    output("\n")
    
def dump_cpsr(cpsr):
    if (cpsr >> 31) & 1:
        output("N ")
    else:
        output("n ")

    if (cpsr >> 30) & 1:
        output("Z ")
    else:
        output("z ")

    if (cpsr >> 29) & 1:
        output("C ")
    else:
        output("c ")
    
    if (cpsr >> 28) & 1:
        output("V ")
    else:
        output("v ")
    
    if (cpsr >> 27) & 1:
        output("Q ")
    else:
        output("q ")
    
    if (cpsr >> 24) & 1:
        output("J ")
    else:
        output("j ")
    
    if (cpsr >> 9) & 1:
        output("E ")
    else:
        output("e ")
    if (cpsr >> 8) & 1:
        output("A ")
    else:
        output("a ")
    if (cpsr >> 7) & 1:
        output("I ")
    else:
        output("i ")
    if (cpsr >> 6) & 1:
        output("F ")
    else:
        output("f ")
    if (cpsr >> 5) & 1:
        output("T")
    else:
        output("t")
        
def regarm():
    global  old_arm_r0
    global  old_arm_r1
    global  old_arm_r2
    global  old_arm_r3
    global  old_arm_r4
    global  old_arm_r5
    global  old_arm_r6
    global  old_arm_r7
    global  old_arm_r8
    global  old_arm_r9
    global  old_arm_r10
    global  old_arm_r11
    global  old_arm_r12
    global  old_arm_sp
    global  old_arm_lr
    global  old_arm_pc
    global  old_arm_cpsr

    color(COLOR_REGNAME)
    output("  R0:  ")
    r0 = get_gp_register("r0")
    if r0 == old_arm_r0:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r0))
    old_arm_r0 = r0

    color(COLOR_REGNAME)
    output("  R1:  ")
    r1 = get_gp_register("r1")
    if r1 == old_arm_r1:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r1))
    old_arm_r1 = r1

    color(COLOR_REGNAME)
    output("  R2:  ")
    r2 = get_gp_register("r2")
    if r2 == old_arm_r2:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r2))
    old_arm_r2 = r2

    color(COLOR_REGNAME)
    output("  R3:  ")
    r3 = get_gp_register("r3")
    if r3 == old_arm_r3:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r3))
    old_arm_r3 = r3
    
    output(" ")
    color_bold()
    color_underline()
    color(COLOR_CPUFLAGS)
    cpsr = get_gp_register("cpsr")
    dump_cpsr(cpsr)
    color_reset()

    output("\n")
    
    color(COLOR_REGNAME)
    output("  R4:  ")
    r4 = get_gp_register("r4")
    if r4 == old_arm_r4:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r4))
    old_arm_r4 = r4

    color(COLOR_REGNAME)
    output("  R5:  ")
    r5 = get_gp_register("r5")
    if r5 == old_arm_r5:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r5))
    old_arm_r5 = r5

    color(COLOR_REGNAME)
    output("  R6:  ")
    r6 = get_gp_register("r6")
    if r6 == old_arm_r6:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r6))
    old_arm_r6 = r6

    color(COLOR_REGNAME)
    output("  R7:  ")
    r7 = get_gp_register("r7")
    if r7 == old_arm_r7:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r7))
    old_arm_r7 = r7

    output("\n")

    color(COLOR_REGNAME)
    output("  R8:  ")
    r8 = get_gp_register("r8")
    if r8 == old_arm_r8:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r8))
    old_arm_r8 = r8

    color(COLOR_REGNAME)
    output("  R9:  ")
    r9 = get_gp_register("r9")
    if r9 == old_arm_r9:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r9))
    old_arm_r9 = r9

    color(COLOR_REGNAME)
    output("  R10: ")
    r10 = get_gp_register("r10")
    if r10 == old_arm_r10:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r10))
    old_arm_r10 = r10

    color(COLOR_REGNAME)
    output("  R11: ")
    r11 = get_gp_register("r11")
    if r11 == old_arm_r11:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r11))
    old_arm_r11 = r11
    
    output("\n")

    color(COLOR_REGNAME)
    output("  R12: ")
    r12 = get_gp_register("r12")
    if r12 == old_arm_r12:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r12))
    old_arm_r12 = r12

    color(COLOR_REGNAME)
    output("  SP:  ")
    sp = get_gp_register("sp")
    if sp == old_arm_sp:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (sp))
    old_arm_sp = sp

    color(COLOR_REGNAME)
    output("  LR:  ")
    lr = get_gp_register("lr")
    if lr == old_arm_lr:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (lr))
    old_arm_lr = lr

    color(COLOR_REGNAME)
    output("  PC:  ")
    pc = get_gp_register("pc")
    if pc == old_arm_pc:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (pc))
    old_arm_pc = pc
    output("\n")

def print_registers():
    arch = get_arch()
    if is_i386(): 
        reg32()
    elif is_x64():
        reg64()
    elif is_arm():
        regarm()

#
# End Register related commands
#

'''
    si, c, r instruction override deault ones to consume their output.
    For example:
        si is thread step-in which by default dumps thread and frame info
        after every step. Consuming output of this instruction allows us
        to nicely display informations in our hook-stop
    Same goes for c and r (continue and run)
'''
def si(debugger, command, result, dict):
    debugger.SetAsync(True)
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False)
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

def c(debugger, command, result, dict):
    debugger.SetAsync(True)
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetSelectedTarget().GetProcess().Continue()
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

#
# Disassembler related functions
#

'''
    Handles 'u' command which displays instructions. Also handles output of
    'disassemble' command ...
'''
# XXX: help
def DumpInstructions(debugger, command, result, dict):
    '''Dump instructions at certain address (SoftICE like u command style)'''
    help = """ """

    global GlobalListOutput
    global arm_type
    GlobalListOutput = []
    
    if is_arm():
        cpsr = get_gp_register("cpsr")
        t = (cpsr >> 5) & 1
        if t:
            #it's thumb
            arm_type = "thumbv7-apple-ios"
        else:
            arm_type = "armv7-apple-ios"
    res = lldb.SBCommandReturnObject()
    cmd = command.split()
    if len(cmd) == 0 or len(cmd) > 2:
        if is_arm():
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A " +arm_type + " --start-address=$pc --count=8", res)
        else:
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=$pc --count=8", res)
    elif len(cmd) == 1:
        if is_arm():
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A "+arm_type+" --start-address=" + cmd[0] + " --count=8", res)
        else:
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + cmd[0] + " --count=8", res)
    else:
        if is_arm():
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A "+arm_type+" --start-address=" + cmd[0] + " --count="+cmd[1], res)
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + cmd[0] + " --count="+cmd[1], res)
        
    if res.Succeeded() == True:
        output(res.GetOutput())
    else:
        output("[-] Error getting instructions for : " + command)
    
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# return the instruction mnemonic at input address
def get_mnemonic(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print "[-] error: not enough instructions disassembled."
        return ""

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    # much easier to use the mnemonic output instead of disassembling via cmd line and parse
    mnemonic = cur_instruction.GetMnemonic(target)

    return mnemonic

# returns the instruction operands
def get_operands(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print "[-] error: not enough instructions disassembled."
        return ""
    
    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    operands = cur_instruction.operands

    return operands

# find out the size of an instruction using internal disassembler
def get_inst_size(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print "[-] error: not enough instructions disassembled."
        return 0

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    return cur_instruction.size

#
# End Disassembler related functions
#

#
# Commands that use external utilities
#

def show_loadcmds(debugger, command, result, dict): 
    '''Show otool output of Mach-O load commands. Use \'show_loadcmds\' for more information.'''
    help = """
Show otool output of Mach-O load commands.

Syntax: show_loadcmds <address>

Where address is start of Mach-O header in memory.
Note: expressions supported, do not use spaces between operators.
"""
    
    error = lldb.SBError()

    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        header_addr = evaluate(cmd[0])
        if header_addr == None:
            print "[-] error: invalid header address value."
            print ""
            print help
            return        
    else:
        print "[-] error: please insert a valid Mach-O header address."
        print ""
        print help
        return

    if os.path.isfile("/usr/bin/otool") == False:
            print "/usr/bin/otool not found. Please install Xcode or Xcode command line tools."
            return
    
    bytes_string = get_process().ReadMemory(header_addr, 4096*10, error)
    if error.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % header_addr
        return

    # open a temporary filename and set it to delete on close
    f = tempfile.NamedTemporaryFile(delete=True)
    f.write(bytes_string)
    # pass output to otool
    output_data = subprocess.check_output(["/usr/bin/otool", "-l", f.name])
    # show the data
    print output_data
    # close file - it will be automatically deleted
    f.close()

    return

def show_header(debugger, command, result, dict): 
    '''Show otool output of Mach-O header. Use \'show_header\' for more information.'''
    help = """
Show otool output of Mach-O header.

Syntax: show_header <address>

Where address is start of Mach-O header in memory.
Note: expressions supported, do not use spaces between operators.
"""

    error = lldb.SBError()

    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           print help
           return
        header_addr = evaluate(cmd[0])
        if header_addr == None:
            print "[-] error: invalid header address value."
            print ""
            print help
            return        
    else:
        print "[-] error: please insert a valid Mach-O header address."
        print ""
        print help
        return

    if os.path.isfile("/usr/bin/otool") == False:
            print "/usr/bin/otool not found. Please install Xcode or Xcode command line tools."
            return
    
    # recent otool versions will fail so we need to read a reasonable amount of memory
    # even just for the mach-o header
    bytes_string = get_process().ReadMemory(header_addr, 4096*10, error)
    if error.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % header_addr
        return

    # open a temporary filename and set it to delete on close
    f = tempfile.NamedTemporaryFile(delete=True)
    f.write(bytes_string)
    # pass output to otool
    output_data = subprocess.check_output(["/usr/bin/otool", "-hv", f.name])
    # show the data
    print output_data
    # close file - it will be automatically deleted
    f.close()

    return

# use keystone-engine.org to assemble
def assemble_keystone(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    print "\nKeystone output:\n----------"
    for inst in code:
        try:
            encoding, count = ks.asm(inst)
        except KsError as e:
            print "[-] error: keystone failed to assemble: {:s}".format(e)
            return
        output = []
        output.append(inst)
        output.append('->')
        for i in encoding:
            output.append("{:02x}".format(i))
        print " ".join(output)

def asm32(debugger, command, result, dict):
    '''32 bit x86 interactive Keystone based assembler. Use \'asm32 help\' for more information.'''
    help = """
32 bit x86 interactive Keystone based assembler.

Syntax: asm32

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_32.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print "[-] error: keystone python bindings not available. please install from www.keystone-engine.org."
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_X86, KS_MODE_32, inst_list)

def asm64(debugger, command, result, dict):
    '''64 bit x86 interactive Keystone based assembler. Use \'asm64 help\' for more information.'''
    help = """
64 bit x86 interactive Keystone based assembler

Syntax: asm64

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_64.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print "[-] error: keystone python bindings not available. please install from www.keystone-engine.org."
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_X86, KS_MODE_64, inst_list)

def arm32(debugger, command, result, dict):
    '''32 bit ARM interactive Keystone based assembler. Use \'arm32 help\' for more information.'''
    help = """
32 bit ARM interactive Keystone based assembler

Syntax: arm32

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_ARM.
    
Requires Keystone and Python bindings from www.keystone-engine.org.
"""
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print "[-] error: keystone python bindings not available. please install from www.keystone-engine.org."
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM, KS_MODE_ARM, inst_list)

def armthumb(debugger, command, result, dict):
    '''32 bit ARM Thumb interactive Keystone based assembler. Use \'armthumb help\' for more information.'''
    help = """
32 bit ARM Thumb interactive Keystone based assembler

Syntax: armthumb

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_THUMB.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print "[-] error: keystone python bindings not available. please install from www.keystone-engine.org."
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM, KS_MODE_THUMB, inst_list)

def arm64(debugger, command, result, dict):
    '''64 bit ARM interactive Keystone based assembler. Use \'arm64 help\' for more information.'''
    help = """
64 bit ARM interactive Keystone based assembler

Syntax: arm64

Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM64 and KS_MODE_ARM.

Requires Keystone and Python bindings from www.keystone-engine.org.
"""
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print help
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print "[-] error: keystone python bindings not available. please install from www.keystone-engine.org."
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM64, KS_MODE_ARM, inst_list)

#
# End Commands that use external utilities
#

# XXX: help
def IphoneConnect(debugger, command, result, dict): 
    '''Connect to debugserver running on iPhone'''
    help = """ """
    global GlobalListOutput
    GlobalListOutput = []
        
    if len(command) == 0 or ":" not in command:
        output("Connect to remote iPhone debug server")
        output("\n")
        output("iphone <ipaddress:port>")
        output("\n")
        output("iphone 192.168.0.2:5555")
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand("platform select remote-ios", res)
    if res.Succeeded() == True:
        output(res.GetOutput())
    else:
        output("[-] Error running platform select remote-ios")
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return
    lldb.debugger.GetCommandInterpreter().HandleCommand("process connect connect://" + command, res)
    if res.Succeeded() == True:
        output("[+] Connected to iphone at : " + command)
    else:
        output(res.GetOutput())
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

def display_stack():
    '''Hex dump current stack pointer'''
    stack_addr = get_current_sp()
    if stack_addr == 0:
        return
    err = lldb.SBError()
    target = get_target()
    membuff = get_process().ReadMemory(stack_addr, 0x100, err)
    if err.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % stack_addr
        return
    if len(membuff) == 0:
        print "[-] error: not enough bytes read."
        return

    output(hexdump(stack_addr, membuff, " ", 16, 4))

def display_data():
    '''Hex dump current data window pointer'''
    data_addr = DATA_WINDOW_ADDRESS
    print data_addr
    if data_addr == 0:
        return
    err = lldb.SBError()
    target = get_target()
    membuff = get_process().ReadMemory(data_addr, 0x100, err)
    if err.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % stack_addr
        return
    if len(membuff) == 0:
        print "[-] error: not enough bytes read."
        return

    output(hexdump(data_addr, membuff, " ", 16, 4))

# workaround for lldb bug regarding RIP addressing outside main executable
def get_rip_relative_addr(source_address):
    err = lldb.SBError()
    target = get_target()
    inst_size = get_inst_size(source_address)
    if inst_size <= 1:
        print "[-] error: instruction size too small."
        return 0
    offset_bytes = get_process().ReadMemory(source_address+1, inst_size-1, err)
    if err.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % source_address
        return 0
    if inst_size == 2:
        data = struct.unpack("b", offset_bytes)
    elif inst_size == 5:
        data = struct.unpack("i", offset_bytes)
    rip_call_addr = source_address + inst_size + data[0]
    #output("source {:x} rip call offset {:x} {:x}\n".format(source_address, data[0], rip_call_addr))
    return rip_call_addr

# XXX: instead of reading memory we can dereference right away in the evaluation
def get_indirect_flow_target(source_address):
    err = lldb.SBError()
    target = get_target()

    operand = get_operands(source_address)
    #output("Operand: {}\n".format(operand))
    # calls into a deferenced memory address
    if "qword" in operand:
        #output("dereferenced call\n")
        deref_addr = 0
        # first we need to find the address to dereference
        if '+' in operand:
            x = re.search('\[([a-z0-9]{2,3} \+ 0x[0-9a-z]+)\]', operand)
            if x == None:
                return 0
            value = get_frame().EvaluateExpression("$" + x.group(1))
            if value.IsValid() == False:                
                return 0
            deref_addr = int(value.GetValue(), 10)
            if "rip" in operand:
                deref_addr = deref_addr + get_inst_size(source_address)
        else:
            x = re.search('\[([a-z0-9]{2,3})\]', operand)
            if x == None:
                return 0
            value = get_frame().EvaluateExpression("$" + x.group(1))
            if value.IsValid() == False:                
                return 0
            deref_addr = int(value.GetValue(), 10)
        
        # now we can dereference and find the call target
        if get_pointer_size() == 4:
            call_target_addr = get_process().ReadUnsignedFromMemory(deref_addr, 4, err)
            return call_target_addr
        elif get_pointer_size() == 8:
            call_target_addr = get_process().ReadUnsignedFromMemory(deref_addr, 8, err)
            return call_target_addr
        if err.Success() == False:
            return 0
        return 0        
    # calls into a register
    elif operand.startswith('r') or operand.startswith('e'):
        #output("register call\n")
        x = re.search('([a-z0-9]{2,3})', operand)
        if x == None:
            return 0
        #output("Result {}\n".format(x.group(1)))
        value = get_frame().EvaluateExpression("$" + x.group(1))
        if value.IsValid() == False:                
            return 0
        return int(value.GetValue(), 10)
    # RIP relative calls
    elif operand.startswith('0x'):
        #output("direct call\n")
        # there's a lldb bug with calls inside modules that are not the main executable
        # the operand output we get is wrong because the internal section address is wrong
        # so we need to manually compute the RIP address
        main_module = target.GetModuleAtIndex(0)
        current_module = lldb.SBAddress(source_address, target).module
        if current_module != main_module:
            #output("address outside main module\n")
            return get_rip_relative_addr(source_address)
        x = re.search('(0x[0-9a-z]+)', operand)
        if x != None:
            #output("Result {}\n".format(x.group(0)))
            return int(x.group(1), 16)

def get_ret_address(source_address):
    err = lldb.SBError()
    target = get_target()
    stack_addr = get_current_sp()
    if stack_addr == 0:
        return 0
    ret_addr = get_process().ReadPointerFromMemory(stack_addr, err)
    if err.Success() == False:
        print "[-] error: Failed to read memory at 0x%x." % stack_addr
        return 0
    return ret_addr

def is_sending_objc_msg():
    err = lldb.SBError()
    target = get_target()

    call_addr = get_indirect_flow_target(get_current_pc())
    sym_addr = lldb.SBAddress(call_addr, target)
    symbol = sym_addr.GetSymbol()
    # XXX: add others?
    if symbol.name != "objc_msgSend":
        return False
    
    return True

# XXX: x64 only
def display_objc():
    pc_addr = get_current_pc()

    err = lldb.SBError()
    target = get_target()

    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC)
    options.SetTrapExceptions(False)

#    command = '(void*)object_getClass({})'.format(get_instance_object())
#    value = get_frame().EvaluateExpression(command, options).GetObjectDescription()
    classname_command = '(const char *)object_getClassName((id){})'.format(get_instance_object())
    classname_value = get_frame().EvaluateExpression(classname_command)
    if classname_value.IsValid() == False:
        return
    
    className = classname_value.GetSummary().strip('"')

    selector_addr = get_gp_register("rsi")

    membuff = get_process().ReadMemory(selector_addr, 0x100, err)
    strings = membuff.split('\00')
    if len(strings) != 0:
        color(RED)
        output('Class: ')
        color_reset()
        output(className)
        color(RED)
        output(' Selector: ')
        color_reset()
        output(strings[0])

def display_indirect_flow():
    target = get_target()
    pc_addr = get_current_pc()
    mnemonic = get_mnemonic(pc_addr)

    if ("ret" in mnemonic) == True:
        indirect_addr = get_ret_address(pc_addr)
        output("0x%x -> %s" % (indirect_addr, lldb.SBAddress(indirect_addr, target).GetSymbol().name))
        output("\n")
        return
    
    if "call" == mnemonic or "callq" == mnemonic or ("jmp" in mnemonic) == True:
        # we need to identify the indirect target address
        indirect_addr = get_indirect_flow_target(pc_addr)
        output("0x%x -> %s" % (indirect_addr, lldb.SBAddress(indirect_addr, target).GetSymbol().name))

        if is_sending_objc_msg() == True:
            output("\n")
            display_objc()
        output("\n")

    return
#
# The heart of lldbinit - when lldb stop this is where we land 
#
def HandleHookStopOnTarget(debugger, command, result, dict):
    '''Display current code context.'''
    # Don't display anything if we're inside Xcode
    if os.getenv('PATH').startswith('/Applications/Xcode.app'):
        return
    
    global GlobalListOutput
    global arm_type
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW

    debugger.SetAsync(True)

    # when we start the thread is still not valid and get_frame() will always generate a warning
    # this way we avoid displaying it in this particular case
    if get_process().GetNumThreads() == 1:
        thread = get_process().GetThreadAtIndex(0)
        if thread.IsValid() == False:
            return

    frame = get_frame()
    if not frame: 
        return
            
    thread= frame.GetThread()
    while True:
        frame = get_frame()
        thread = frame.GetThread()
        
        if thread.GetStopReason() == lldb.eStopReasonNone or thread.GetStopReason() == lldb.eStopReasonInvalid:
            time.sleep(0.001)
        else:
            break
    
    GlobalListOutput = []
    
    arch = get_arch()
    if not is_i386() and not is_x64() and not is_arm():
        #this is for ARM probably in the future... when I will need it...
        print("[-] error: Unknown architecture : " + arch)
        return
    
    color(COLOR_SEPARATOR)
    if is_i386() or is_arm():
        output("---------------------------------------------------------------------------------")
    elif is_x64():
        output("-----------------------------------------------------------------------------------------------------------------------")
            
    color_bold()
    output("[regs]\n")
    color_reset()
    print_registers()

    if CONFIG_DISPLAY_STACK_WINDOW == 1:
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("--------------------------------------------------------------------------------")
        elif is_x64():
            output("----------------------------------------------------------------------------------------------------------------------")
        color_bold()
        output("[stack]\n")
        color_reset()
    
        display_stack()
        output("\n")
    if CONFIG_DISPLAY_DATA_WINDOW == 1:
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("---------------------------------------------------------------------------------")
        elif is_x64():
            output("-----------------------------------------------------------------------------------------------------------------------")
        color_bold()
        output("[data]\n")
        color_reset()
    
        display_data()
        output("\n")

    if CONFIG_DISPLAY_FLOW_WINDOW == 1 and is_x64():
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("---------------------------------------------------------------------------------")
        elif is_x64():
            output("-----------------------------------------------------------------------------------------------------------------------")
        color_bold()
        output("[flow]\n")
        color_reset()

        display_indirect_flow()


    color(COLOR_SEPARATOR)
    if is_i386() or is_arm():
        output("---------------------------------------------------------------------------------")
    elif is_x64():
        output("-----------------------------------------------------------------------------------------------------------------------")
    color_bold()
    output("[code]\n")
    color_reset()
    
    if is_i386():
        pc = get_register("eip")
    elif is_x64():
        pc = get_register("rip")
    elif is_arm():
        pc = get_register("pc")        
    
    res = lldb.SBCommandReturnObject()
    if is_arm():
        cpsr = get_gp_register("cpsr")
        t = (cpsr >> 5) & 1
        if t:
            #it's thumb
            arm_type = "thumbv7-apple-ios"
        else:
            arm_type = "armv7-apple-ios"
        lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -A " + arm_type + " --start-address=" + pc + " --count=8", res)
    else:
        if CONFIG_DISPLAY_DISASSEMBLY_BYTES == 1:
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -b --start-address=" + pc + " --count=" + str(CONFIG_DISASSEMBLY_LINE_COUNT), res)
        else:
            lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble --start-address=" + pc + " --count=" + str(CONFIG_DISASSEMBLY_LINE_COUNT), res)
    
    data = res.GetOutput()
    #split lines... and mark currently executed code...
    data = data.split("\n")
    #detemine what to hl, as sometimes lldb won't put => into stoped thread... well...
    #need to check if first sym is => or '  ' which means this is name without symol
    #symbols are stored 1st so here we go...
    
    line_to_hl = 0
    #if data[0][0:2] == "->":
    #   line_to_hl = 0;
    #if data[0][0:2] != '  ':
    #   line_to_hl = 1;
    
    #now we look when pc is held in disassembly and we color only that line 
    pc_text = int(str(pc).strip().split()[0], 16)
    pc_text = hex(pc_text)
    #print(pc_text);
    for idx,x in enumerate(data):
        if pc_text in x:
            line_to_hl = idx
            break
    for idx,x in enumerate(data):
        if line_to_hl == idx: #x[0:2] == "->" and idx < 3:
            color(COLOR_HIGHLIGHT_LINE)
            color_bold()
            output(x)
            color_reset()
            output("\n")
        # don't add newline to last line to avoid empty line
        elif len(data) > 0 and idx == len(data)-1:
            output(x)
        else:
            output(x)
            output("\n")
        
    #output(res.GetOutput());
    color(COLOR_SEPARATOR)
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("---------------------------------------------------------------------------------------")
    elif get_pointer_size() == 8: #is_x64():
        output("-----------------------------------------------------------------------------------------------------------------------------")
    color_reset()
    #output("\n");
    
    data = "".join(GlobalListOutput)
    
    result.PutCString(data)
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    return 0
