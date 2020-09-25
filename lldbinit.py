'''
.____    .____     ________ __________.__ _______  ._____________
|    |   |    |    \______ \\______   \__|\      \ |__\__    ___/
|    |   |    |     |    |  \|    |  _/  |/   |   \|  | |    |   
|    |___|    |___  |    `   \    |   \  /    |    \  | |    |   
|_______ \_______ \/_______  /______  /__\____|__  /__| |____|   
        \/       \/        \/       \/           \/

LLDBINIT v2.0
A gdbinit clone for LLDB aka how to make LLDB a bit more useful and less crappy

(c) Deroko 2014, 2015, 2016
(c) fG! 2017-2020 - reverser@put.as - https://reverse.put.as

Available at https://github.com/gdbinit/lldbinit

No original license by Deroko so I guess this is do whatever you want with this
as long you keep original credits and sources references.

Original lldbinit code by Deroko @ https://github.com/deroko/lldbinit
gdbinit available @ https://github.com/gdbinit/Gdbinit

Huge thanks to Deroko for his original effort!

To list all implemented commands use 'lldbinitcmds' command.

How to install it:
------------------

$ cp lldbinit.py ~
$ echo "command script import  ~/lldbinit.py" >>$HOME/.lldbinit

or

$ cp lldbinit.py /Library/Python/2.7/site-packages
$ echo "command script import lldbinit" >> $HOME/.lldbinit

or

just copy it somewhere and use "command script import path_to_script" when you want to load it.

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

- command to search for symbol and display image address (image lookup -s symbol -v) (address is the range)
- command to update breakpoints with new ASLR
- fix get_indirect_flow_target (we can get real load address of the modules - check the new disassembler code)
- solve addresses like lea    rsi, [rip + 0x38cf] (lldb does solve some stuff that it has symbols for and adds the info as comment)
- some sort of colors theme support

BUGS:
-----

LLDB design:
------------
lldb -> debugger -> target -> process -> thread -> frame(s)
                                      -> thread -> frame(s)
'''

if __name__ == "__main__":
    print("Run only as script from LLDB... Not as standalone program!")

try:
    import  lldb
except:
    pass
import  sys
import  re
import  os
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

VERSION = "2.0"
BUILD = "204"

#
# User configurable options
#
CONFIG_ENABLE_COLOR = 1
# display the instruction bytes in disassembler output
CONFIG_DISPLAY_DISASSEMBLY_BYTES = 1
# the maximum number of lines to display in disassembler output
CONFIG_DISASSEMBLY_LINE_COUNT = 8
# x/i and disas output customization - doesn't affect context disassembler output
CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT = 1
# enable all the register command shortcuts
CONFIG_ENABLE_REGISTER_SHORTCUTS = 1
# display stack contents on context stop
CONFIG_DISPLAY_STACK_WINDOW = 0
CONFIG_DISPLAY_FLOW_WINDOW = 0
# display data contents on context stop - an address for the data must be set with "datawin" command
CONFIG_DISPLAY_DATA_WINDOW = 0

# setup the logging level, which is a bitmask of any of the following possible values (don't use spaces, doesn't seem to work)
#
# LOG_VERBOSE LOG_PROCESS LOG_THREAD LOG_EXCEPTIONS LOG_SHLIB LOG_MEMORY LOG_MEMORY_DATA_SHORT LOG_MEMORY_DATA_LONG LOG_MEMORY_PROTECTIONS LOG_BREAKPOINTS LOG_EVENTS LOG_WATCHPOINTS
# LOG_STEP LOG_TASK LOG_ALL LOG_DEFAULT LOG_NONE LOG_RNB_MINIMAL LOG_RNB_MEDIUM LOG_RNB_MAX LOG_RNB_COMM  LOG_RNB_REMOTE LOG_RNB_EVENTS LOG_RNB_PROC LOG_RNB_PACKETS LOG_RNB_ALL LOG_RNB_DEFAULT
# LOG_DARWIN_LOG LOG_RNB_NONE
#
# to see log (at least in macOS)
# $ log stream --process debugserver --style compact
# (or whatever style you like)
CONFIG_LOG_LEVEL = "LOG_NONE"

# removes the offsets and modifies the module name position
# reference: https://lldb.llvm.org/formats.html
CUSTOM_DISASSEMBLY_FORMAT = "\"{${function.initial-function}{${function.name-without-args}} @ {${module.file.basename}}:\n}{${function.changed}\n{${function.name-without-args}} @ {${module.file.basename}}:\n}{${current-pc-arrow} }${addr-file-or-load}: \""

# default colors - modify as you wish
COLOR_REGVAL           = "BLACK"
COLOR_REGNAME          = "GREEN"
COLOR_CPUFLAGS         = "RED"
COLOR_SEPARATOR        = "BLUE"
COLOR_HIGHLIGHT_LINE   = "RED"
COLOR_REGVAL_MODIFIED  = "RED"
COLOR_SYMBOL_NAME      = "BLUE"
COLOR_CURRENT_PC       = "RED"

#
# Don't mess after here unless you know what you are doing!
#

COLORS = {  
            "BLACK":     "\033[30m",
            "RED":       "\033[31m",
            "GREEN":     "\033[32m",
            "YELLOW":    "\033[33m",
            "BLUE":      "\033[34m",
            "MAGENTA":   "\033[35m",
            "CYAN":      "\033[36m",
            "WHITE":     "\033[37m",
            "RESET":     "\033[0m",
            "BOLD":      "\033[1m",
            "UNDERLINE": "\033[4m"
         }

DATA_WINDOW_ADDRESS = 0

old_x86 = { "eax": 0, "ecx": 0, "edx": 0, "ebx": 0, "esp": 0, "ebp": 0, "esi": 0, "edi": 0, "eip": 0,
            "eflags": 0, "cs": 0, "ds": 0, "fs": 0, "gs": 0, "ss": 0, "es": 0 }

old_x64 = { "rax": 0, "rcx": 0, "rdx": 0, "rbx": 0, "rsp": 0, "rbp": 0, "rsi": 0, "rdi": 0, "rip": 0,
            "r8": 0, "r9": 0, "r10": 0, "r11": 0, "r12": 0, "r13": 0, "r14": 0, "r15": 0,
            "rflags": 0, "cs": 0, "fs": 0, "gs": 0 }

old_arm = { "r0": 0, "r1": 0, "r2": 0, "r3": 0, "r4": 0, "r5": 0, "r6": 0, "r7": 0, "r8": 0, "r9": 0, "r10": 0, 
            "r11": 0, "r12": 0, "sp": 0, "lr": 0, "pc": 0, "cpsr": 0 }

arm_type = "thumbv7-apple-ios"

GlobalListOutput = []

int3patches = {}

crack_cmds = []
crack_cmds_noret = []
modules_list = []

def __lldb_init_module(debugger, internal_dict):
    ''' we can execute commands using debugger.HandleCommand which makes all output to default
    lldb console. With GetCommandinterpreter().HandleCommand() we can consume all output
    with SBCommandReturnObject and parse data before we send it to output (eg. modify it);
    '''

    # don't load if we are in Xcode since it is not compatible and will block Xcode
    if os.getenv('PATH').startswith('/Applications/Xcode'):
        return

    '''
    If I'm running from $HOME where .lldbinit is located, seems like lldb will load 
    .lldbinit 2 times, thus this dirty hack is here to prevent doulbe loading...
    if somebody knows better way, would be great to know :)
    ''' 
    var = debugger.GetInternalVariableValue("stop-disassembly-count", debugger.GetInstanceName())
    if var.IsValid():
        var = var.GetStringAtIndex(0)
        if var == "0":
            return
    
    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    # settings
    ci.HandleCommand("settings set target.x86-disassembly-flavor intel", res)
    ci.HandleCommand("settings set prompt \"(lldbinit) \"", res)
    #lldb.debugger.GetCommandInterpreter().HandleCommand("settings set prompt \"\033[01;31m(lldb) \033[0m\"", res);
    ci.HandleCommand("settings set stop-disassembly-count 0", res)
    # set the log level - must be done on startup?
    ci.HandleCommand("settings set target.process.extra-startup-command QSetLogging:bitmask=" + CONFIG_LOG_LEVEL + ";", res)
    if CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT == 1:
        ci.HandleCommand("settings set disassembly-format " + CUSTOM_DISASSEMBLY_FORMAT, res)

    # the hook that makes everything possible :-)
    ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget", res)
    ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget ctx", res)
    ci.HandleCommand("command script add -f lldbinit.HandleHookStopOnTarget context", res)
    # commands
    ci.HandleCommand("command script add -f lldbinit.cmd_lldbinitcmds lldbinitcmds", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_IphoneConnect iphone", res)
    #
    # dump memory commands
    #
    ci.HandleCommand("command script add -f lldbinit.cmd_db db", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_dw dw", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_dd dd", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_dq dq", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_DumpInstructions u", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_findmem findmem", res)
    #
    # Settings related commands
    #
    ci.HandleCommand("command script add -f lldbinit.cmd_enable enable", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_disable disable", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_contextcodesize contextcodesize", res)
    # a few settings aliases
    ci.HandleCommand("command alias enablesolib enable solib", res)
    ci.HandleCommand("command alias disablesolib disable solib", res)
    ci.HandleCommand("command alias enableaslr enable aslr", res)
    ci.HandleCommand("command alias disableaslr disable aslr", res)
    #
    # Breakpoint related commands
    #
    ci.HandleCommand("command script add -f lldbinit.cmd_bhb bhb", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_bht bht", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_bpt bpt", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_bpn bpn", res)
    # disable a breakpoint or all
    ci.HandleCommand("command script add -f lldbinit.cmd_bpd bpd", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_bpda bpda", res)
    # clear a breakpoint or all
    ci.HandleCommand("command script add -f lldbinit.cmd_bpc bpc", res)
    ci.HandleCommand("command alias bpca breakpoint delete", res)
    # enable a breakpoint or all
    ci.HandleCommand("command script add -f lldbinit.cmd_bpe bpe", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_bpea bpea", res)
    # commands to set temporary int3 patches and restore original bytes
    ci.HandleCommand("command script add -f lldbinit.cmd_int3 int3", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_rint3 rint3", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_listint3 listint3", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_nop nop", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_null null", res)
    # change eflags commands
    ci.HandleCommand("command script add -f lldbinit.cmd_cfa cfa", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfc cfc", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfd cfd", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfi cfi", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfo cfo", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfp cfp", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfs cfs", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cft cft", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_cfz cfz", res)
    # skip/step current instruction commands
    ci.HandleCommand("command script add -f lldbinit.cmd_skip skip", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_stepo stepo", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_si si", res)
    # load breakpoints from file
    ci.HandleCommand("command script add -f lldbinit.cmd_LoadBreakPoints lb", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_LoadBreakPointsRva lbrva", res)
    # cracking friends
    ci.HandleCommand("command script add -f lldbinit.cmd_crack crack", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_crackcmd crackcmd", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_crackcmd_noret crackcmd_noret", res)
    # alias for existing breakpoint commands
    # list all breakpoints
    ci.HandleCommand("command alias bpl breakpoint list", res)
    # alias "bp" command that exists in gdbinit - lldb also has alias for "b"
    ci.HandleCommand("command alias bp _regexp-break", res)
    # to set breakpoint commands - I hate typing too much
    ci.HandleCommand("command alias bcmd breakpoint command add", res)
    # launch process and stop at entrypoint (not exactly as gdb command that just inserts breakpoint)
    # usually it will be inside dyld and not the target main()
    ci.HandleCommand("command alias break_entrypoint process launch --stop-at-entry", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_show_loadcmds show_loadcmds", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_show_header show_header", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_tester tester", res)
    ci.HandleCommand("command script add -f lldbinit.cmd_datawin datawin", res)
    # shortcut command to modify registers content
    if CONFIG_ENABLE_REGISTER_SHORTCUTS == 1:
        # x64
        ci.HandleCommand("command script add -f lldbinit.cmd_rip rip", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rax rax", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rbx rbx", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rbp rbp", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rsp rsp", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rdi rdi", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rsi rsi", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rdx rdx", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_rcx rcx", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r8 r8", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r9 r9", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r10 r10", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r11 r11", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r12 r12", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r13 r13", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r14 r14", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_r15 r15", res)
        # x86
        ci.HandleCommand("command script add -f lldbinit.cmd_eip eip", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_eax eax", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_ebx ebx", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_ebp ebp", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_esp esp", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_edi edi", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_esi esi", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_edx edx", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_ecx ecx", res)
    if CONFIG_KEYSTONE_AVAILABLE == 1:
        ci.HandleCommand("command script add -f lldbinit.cmd_asm32 asm32", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_asm64 asm64", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_arm32 arm32", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_arm64 arm64", res)
        ci.HandleCommand("command script add -f lldbinit.cmd_armthumb armthumb", res)
    # add the hook - we don't need to wait for a target to be loaded
    ci.HandleCommand("target stop-hook add -o \"HandleHookStopOnTarget\"", res)
    ci.HandleCommand("command script add --function lldbinit.cmd_banner banner", res)
    debugger.HandleCommand("banner")
    return

def cmd_banner(debugger,command,result,dict):    
    print(COLORS["RED"] + "[+] Loaded lldbinit version: " + VERSION + "." + BUILD + COLORS["RESET"])

def cmd_lldbinitcmds(debugger, command, result, dict):
    '''Display all available lldbinit commands.'''

    help_table = [
    [ "lldbinitcmds", "this command" ],
    [ "enable", "configure lldb and lldbinit options" ],
    [ "disable", "configure lldb and lldbinit options" ],
    [ "contextcodesize", "set number of instruction lines in code window" ],
    [ "b", "breakpoint address" ],
    [ "bpt", "set a temporary software breakpoint" ],
    [ "bhb", "set an hardware breakpoint" ],
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

    print("lldbinit available commands:")

    for row in help_table:
        print(" {: <20} - {: <30}".format(*row))

    print("\nUse \'cmdname help\' for extended command help.")

# placeholder to make tests
def cmd_tester(debugger, command, result, dict):
    print("test")
    #frame = get_frame()
    # the SBValue to ReturnFromFrame must be eValueTypeRegister type
    # if we do a lldb.SBValue() we can't set to that type
    # so we need to make a copy
    # can we use FindRegister() from frame?
    #return_value = frame.reg["rax"]
    #return_value.value = "1"
    #thread.ReturnFromFrame(frame, return_value)


# -------------------------
# Settings related commands
# -------------------------

def cmd_enable(debugger, command, result, dict):
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
        print("[-] error: command requires arguments.")
        print("")
        print(help)
        return

    if cmd[0] == "color":
        CONFIG_ENABLE_COLOR = 1
        print("[+] Enabled color mode.")
    elif cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events true")
        print("[+] Enabled stop on library events trick.")
    elif cmd[0] == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr false")
        print("[+] Enabled ASLR.")
    elif cmd[0] == "stackwin":
        CONFIG_DISPLAY_STACK_WINDOW = 1
        print("[+] Enabled stack window in context display.")
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 1
        print("[+] Enabled indirect control flow window in context display.")
    elif cmd[0] == "datawin":
        CONFIG_DISPLAY_DATA_WINDOW = 1
        print("[+] Enabled data window in context display. Configure address with \'datawin\' cmd.")
    elif cmd[0] == "help":
        print(help)
    else:
        print("[-] error: unrecognized command.")
        print(help)

    return

def cmd_disable(debugger, command, result, dict):
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
        print("[-] error: command requires arguments.")
        print("")
        print(help)
        return

    if cmd[0] == "color":
        CONFIG_ENABLE_COLOR = 0
        print("[+] Disabled color mode.")
    elif cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events false")
        print("[+] Disabled stop on library events trick.")
    elif cmd[0] == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr true")
        print("[+] Disabled ASLR.")
    elif cmd[0] == "stackwin":
        CONFIG_DISPLAY_STACK_WINDOW = 0
        print("[+] Disabled stack window in context display.")
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 0
        print("[+] Disabled indirect control flow window in context display.")
    elif cmd[0] == "datawin":
        CONFIG_DISPLAY_DATA_WINDOW = 0
        print("[+] Disabled data window in context display.")
    elif cmd[0] == "help":
        print(help)
    else:
        print("[-] error: unrecognized command.")
        print(help)

    return

def cmd_contextcodesize(debugger, command, result, dict): 
    '''Set the number of disassembly lines in code window. Use \'contextcodesize help\' for more information.'''
    help = """
Configures the number of disassembly lines displayed in code window.

Syntax: contextcodesize <line_count>

Note: expressions supported, do not use spaces between operators.
"""

    global CONFIG_DISASSEMBLY_LINE_COUNT

    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert the number of disassembly lines to display.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        print("\nCurrent configuration value is: {:d}".format(CONFIG_DISASSEMBLY_LINE_COUNT))
        return
    
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return

    CONFIG_DISASSEMBLY_LINE_COUNT = value

    return

# ---------------------------------
# Color and output related commands
# ---------------------------------

def color(x):
    out_col = ""
    if CONFIG_ENABLE_COLOR == 0:
        output(out_col)
        return    
    output(COLORS[x])

# append data to the output that we display at the end of the hook-stop
def output(x):
    global GlobalListOutput
    GlobalListOutput.append(x)

# ---------------------------
# Breakpoint related commands
# ---------------------------

# temporary software breakpoint
def cmd_bpt(debugger, command, result, dict):
    '''Set a temporary software breakpoint. Use \'bpt help\' for more information.'''
    help = """
Set a temporary software breakpoint.

Syntax: bpt <address>

Note: expressions supported, do not use spaces between operators.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return
    
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return
    
    target = get_target()
    breakpoint = target.BreakpointCreateByAddress(value)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print("[+] Set temporary breakpoint at 0x{:x}".format(value))
    
# hardware breakpoint
def cmd_bhb(debugger, command, result, dict):
    '''Set an hardware breakpoint'''
    help = """
Set an hardware breakpoint.

Syntax: bhb <address>

Note: expressions supported, do not use spaces between operators.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return
    
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return

    # the python API doesn't seem to support hardware breakpoints
    # so we set it via command line interpreter
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H -a " + hex(value), res)

    print("[+] Set hardware breakpoint at 0x{:x}".format(value))
    return

# temporary hardware breakpoint
def cmd_bht(debugger, command, result, dict):
    '''Set a temporary hardware breakpoint'''
    print("[-] error: lldb has no x86/x64 temporary hardware breakpoints implementation.")
    return

# clear breakpoint number
def cmd_bpc(debugger, command, result, dict):
    '''Clear a breakpoint. Use \'bpc help\' for more information.'''
    help = """
Clear a breakpoint.

Syntax: bpc <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint number.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value - only a breakpoint number is valid.")
        print("")
        print(help)
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value:
            if target.BreakpointDelete(bpt.id) == False:
                print("[-] error: failed to delete breakpoint #{:d}".format(value))
                return
            print("[+] Deleted breakpoint #{:d}".format(value))
            return

    print("[-] error: breakpoint #{:d} not found".format(value))
    return

# disable breakpoint number
# XXX: we could support addresses, not sure it's worth the trouble
def cmd_bpd(debugger, command, result, dict):
    '''Disable a breakpoint. Use \'bpd help\' for more information.'''
    help = """
Disable a breakpoint.

Syntax: bpd <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint number.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value - only a breakpoint number is valid.")
        print("")
        print(help)
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and bpt.IsEnabled() == True:
            bpt.SetEnabled(False)
            print("[+] Disabled breakpoint #{:d}".format(value))

# disable all breakpoints
def cmd_bpda(debugger, command, result, dict):
    '''Disable all breakpoints. Use \'bpda help\' for more information.'''
    help = """
Disable all breakpoints.

Syntax: bpda
"""
        
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print(help)
           return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return

    target = get_target()

    if target.DisableAllBreakpoints() == False:
        print("[-] error: failed to disable all breakpoints.")

    print("[+] Disabled all breakpoints.")

# enable breakpoint number
def cmd_bpe(debugger, command, result, dict):
    '''Enable a breakpoint. Use \'bpe help\' for more information.'''
    help = """
Enable a breakpoint.

Syntax: bpe <breakpoint_number>

Note: only breakpoint numbers are valid, not addresses. Use \'bpl\' to list breakpoints.
Note: expressions supported, do not use spaces between operators.
"""
        
    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a breakpoint number.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return

    # breakpoint enable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid input value - only a breakpoint number is valid.")
        print("")
        print(help)
        return
    
    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and bpt.IsEnabled() == False:
            bpt.SetEnabled(True)
            print("[+] Enabled breakpoint #{:d}".format(value))

# enable all breakpoints
def cmd_bpea(debugger, command, result, dict):
    '''Enable all breakpoints. Use \'bpea help\' for more information.'''
    help = """
Enable all breakpoints.

Syntax: bpea
"""
        
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print(help)
           return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return

    target = get_target()

    if target.EnableAllBreakpoints() == False:
        print("[-] error: failed to enable all breakpoints.")

    print("[+] Enabled all breakpoints.")

# skip current instruction - just advances PC to next instruction but doesn't execute it
def cmd_skip(debugger, command, result, dict):
    '''Advance PC to instruction at next address. Use \'skip help\' for more information.'''
    help = """
Advance current instruction pointer to next instruction.

Syntax: skip

Note: control flow is not respected, it advances to next instruction in memory.
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print(help)
           return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
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
def cmd_int3(debugger, command, result, dict):
    '''Patch byte at address to an INT3 (0xCC) instruction. Use \'int3 help\' for more information.'''
    help = """
Patch process memory with an INT3 byte at given address.

Syntax: int3 [<address>]

Note: useful in cases where the debugger breakpoints aren't respected but an INT3 will always trigger the debugger.
Note: ARM not yet supported.
Note: expressions supported, do not use spaces between operators.
"""

    global int3patches

    error = lldb.SBError()
    target = get_target()

    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return
        
        int3_addr = evaluate(cmd[0])
        if int3_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return

    bytes_string = target.GetProcess().ReadMemory(int3_addr, 1, error)
    if error.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(int3_addr))
        return

    bytes_read = bytearray(bytes_string)
    
    patch_bytes = str('\xCC')
    result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
    if error.Success() == False:
        print("[-] error: Failed to write memory at 0x{:x}.".format(int3_addr))
        return

    # save original bytes for later restore
    int3patches[str(int3_addr)] = bytes_read[0]

    print("[+] Patched INT3 at 0x{:x}".format(int3_addr))
    return

def cmd_rint3(debugger, command, result, dict):
    '''Restore byte at address from a previously patched INT3 (0xCC) instruction. Use \'rint3 help\' for more information.'''
    help = """
Restore the original byte at a previously patched address using \'int3\' command.

Syntax: rint3 [<address>]

Note: expressions supported, do not use spaces between operators.
"""

    global int3patches

    error = lldb.SBError()
    target = get_target()
    
    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return
        int3_addr = evaluate(cmd[0])
        if int3_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return        
    else:
        print("[-] error: please insert a INT3 patched address.")
        print("")
        print(help)
        return

    if len(int3patches) == 0:
        print("[-] error: No INT3 patched addresses to restore available.")
        return

    bytes_string = target.GetProcess().ReadMemory(int3_addr, 1, error)
    if error.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(int3_addr))
        return
        
    bytes_read = bytearray(bytes_string)

    if bytes_read[0] == 0xCC:
        #print("Found byte patched byte at 0x{:x}".format(int3_addr))
        try:
            original_byte = int3patches[str(int3_addr)]
        except:
            print("[-] error: Original byte for address 0x{:x} not found.".format(int3_addr))
            return
        patch_bytes = chr(original_byte)
        result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
        if error.Success() == False:
            print("[-] error: Failed to write memory at 0x{:x}.".format(int3_addr))
            return
        # remove element from original bytes list
        del int3patches[str(int3_addr)]
    else:
        print("[-] error: No INT3 patch found at 0x{:x}.".format(int3_addr))

    return

def cmd_listint3(debugger, command, result, dict):
    '''List all patched INT3 (0xCC) instructions. Use \'listint3 help\' for more information.'''
    help = """
List all addresses patched with \'int3\' command.

Syntax: listint3
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print(help)
           return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return

    if len(int3patches) == 0:
        print("[-] No INT3 patched addresses available.")
        return

    print("Current INT3 patched addresses:")
    for address, byte in int3patches.items():
        print("[*] {:s}".format(hex(int(address, 10))))

    return

# XXX: ARM NOPs
def cmd_nop(debugger, command, result, dict):
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
           print(help)
           return
        
        nop_addr = evaluate(cmd[0])
        patch_size = 1
        if nop_addr is None:
            print("[-] error: invalid address value.")
            print("")
            print(help)
            return
    elif len(cmd) == 2:
        nop_addr = evaluate(cmd[0])
        if nop_addr is None:
            print("[-] error: invalid address value.")
            print("")
            print(help)
            return
        
        patch_size = evaluate(cmd[1])
        if patch_size is None:
            print("[-] error: invalid size value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return

    current_patch_addr = nop_addr
    # format for WriteMemory()
    patch_bytes = str('\x90')
    # can we do better here? WriteMemory takes an input string... weird
    for i in xrange(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if error.Success() == False:
            print("[-] error: Failed to write memory at 0x{:x}.".format(current_patch_addr))
            return
        current_patch_addr = current_patch_addr + 1

    return

def cmd_null(debugger, command, result, dict):
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
           print(help)
           return        
        null_addr = evaluate(cmd[0])
        patch_size = 1
        if null_addr is None:
            print("[-] error: invalid address value.")
            print("")
            print(help)
            return
    elif len(cmd) == 2:
        null_addr = evaluate(cmd[0])
        if null_addr is None:
            print("[-] error: invalid address value.")
            print("")
            print(help)
            return
        patch_size = evaluate(cmd[1])
        if patch_size is None:
            print("[-] error: invalid size value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a breakpoint address.")
        print("")
        print(help)
        return

    current_patch_addr = null_addr
    # format for WriteMemory()
    patch_bytes = str('\x00')
    # can we do better here? WriteMemory takes an input string... weird
    for i in xrange(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if error.Success() == False:
            print("[-] error: Failed to write memory at 0x{:x}.".format(current_patch_addr))
            return
        current_patch_addr = current_patch_addr + 1

    return

'''
    Implements stepover instruction.    
'''
def cmd_stepo(debugger, command, result, dict):
    '''Step over calls and some other instructions so we don't need to step into them. Use \'stepo help\' for more information.'''
    help = """
Step over calls and loops that we want executed but not step into.
Affected instructions: call, movs, stos, cmps, loop.

Syntax: stepo
"""

    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        print(help)
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
        print("[-] error: invalid current address.")
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
def cmd_LoadBreakPointsRva(debugger, command, result, dict):
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
def cmd_LoadBreakPoints(debugger, command, result, dict):
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
def cmd_bpn(debugger, command, result, dict):
    '''Temporarily breakpoint instruction at next address. Use \'bpn help\' for more information.'''
    help = """
Temporarily breakpoint instruction at next address

Syntax: bpn

Note: control flow is not respected, it breakpoints next instruction in memory.
"""

    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           print(help)
           return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return

    target = get_target()
    start_addr = get_current_pc()
    next_addr = start_addr + get_inst_size(start_addr)
    
    breakpoint = target.BreakpointCreateByAddress(next_addr)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print("[+] Set temporary breakpoint at 0x{:x}".format(next_addr))

# command that sets rax to 1 or 0 and returns right away from current function
# technically just a shortcut to "thread return"
def cmd_crack(debugger, command, result, dict):
    '''Return from current function and set return value. Use \'crack help\' for more information.'''
    help = """
Return from current function and set return value

Syntax: crack <return value>

Sets rax to return value and returns immediately from current function.
You probably want to use this at the top of the function you want to return from.
"""

    cmd = command.split()
    if len(cmd) != 1:
        print("[-] error: please insert a return value.")
        print("")
        print(help)
        return
    if cmd[0] == "help":
        print(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        print("[-] error: invalid return value.")
        print("")
        print(help)
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
def cmd_crackcmd(debugger, command, result, dict):
    '''Breakpoint an address, when breakpoint is hit return from function and set return value. Use \'crackcmd help\' for more information.'''
    help = """
Breakpoint an address, when breakpoint is hit return from function and set return value.

Syntax: crackcmd <address> <return value>

Sets rax/eax to return value and returns immediately from current function where breakpoint was set.
"""
    global crack_cmds

    cmd = command.split()
    if len(cmd) == 0:
        print("[-] error: please check required arguments.")
        print("")
        print(help)
        return
    elif len(cmd) > 0 and cmd[0] == "help":
        print(help)
        return
    elif len(cmd) < 2:
        print("[-] error: please check required arguments.")
        print("")
        print(help)
        return        

    # XXX: is there a way to verify if address is valid? or just let lldb error when setting the breakpoint
    address = evaluate(cmd[0])
    if address is None:
        print("[-] error: invalid address value.")
        print("")
        print(help)
        return
    
    return_value = evaluate(cmd[1])
    if return_value is None:
        print("[-] error: invalid return value.")
        print("")
        print(help)
        return
    
    for tmp_entry in crack_cmds:
        if tmp_entry['address'] == address:
            print("[-] error: address already contains a crack command.")
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
    print("[+] warning: hit crack command breakpoint at 0x{:x}".format(current_bp))

    crack_entry = None
    for tmp_entry in crack_cmds:
        if tmp_entry['address'] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        print("[-] error: current breakpoint not found in list.")
        return

    # we can just set the register in the frame and return empty SBValue
    if is_x64() == True:
        frame.reg["rax"].value = str(crack_entry['return_value']).rstrip('L')
    elif is_i386() == True:
        frame.reg["eax"].value = str(crack_entry['return_value']).rstrip('L')
    else:
        print("[-] error: unsupported architecture.")
        return

    get_thread().ReturnFromFrame(frame, lldb.SBValue())
    get_process().Continue()

# set a breakpoint with a command that doesn't return, just sets the specified register to a value
def cmd_crackcmd_noret(debugger, command, result, dict):
    '''Set a breakpoint and a register to a value when hit. Use \'crackcmd_noret help\' for more information.'''
    help = """
Set a breakpoint and a register to a value when hit.

Syntax: crackcmd_noret <address> <register> <value>

Sets the specified register to a value when the breakpoint at specified address is hit, and resumes execution.
"""
    global crack_cmds_noret

    cmd = command.split()
    if len(cmd) == 0:
        print("[-] error: please check required arguments.")
        print("")
        print(help)
        return
    if len(cmd) > 0 and cmd[0] == "help":
        print(help)
        return
    if len(cmd) < 3:
        print("[-] error: please check required arguments.")
        print("")
        print(help)
        return

    address = evaluate(cmd[0])
    register = cmd[1]
    value = evaluate(cmd[2])

    if address is None:
        print("[-] error: invalid address.")
        print("")
        print(help)
        return

    # check if register is set and valid
    valid = [ "rip", "rax", "rbx", "rbp", "rsp", "rdi", "rsi", "rdx", "rcx", "r8", "r9", 
              "r10", "r11", "r12", "r13", "r14", "r15", "eip", "eax", "ebx", "ebp", "esp",
               "edi", "esi", "edx", "ecx" ]
    if register not in valid:
        print("[-] error: invalid register.")
        print("")
        print(help)
        return
    
    if value is None:
        print("[-] error: invalid value.")
        print("")
        print(help)
        return
    
    for tmp_entry in crack_cmds_noret:
        if tmp_entry['address'] == address:
            print("[-] error: address already contains a crack command.")
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
    print("[+] warning: hit crack command no ret breakpoint at 0x{:x}".format(current_bp))
    crack_entry = None
    for tmp_entry in crack_cmds_noret:
        if tmp_entry['address'] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        print("[-] error: current breakpoint not found in list.")
        return

    # must be a string!
    frame.reg[crack_entry['register']].value = str(crack_entry['value']).rstrip('L')
    get_process().Continue()

# -----------------------
# Memory related commands
# -----------------------

'''
    Output nice memory hexdumps...
'''
# display byte values and ASCII characters
def cmd_db(debugger, command, result, dict):
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
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return        
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a start address.")
        print("")
        print(help)
        return

    err = lldb.SBError()
    size = 0x100
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if err.Success() == False:
        print("[-] error: failed to read memory from address 0x{:x}".format(dump_addr))
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    color("BLUE")
    if get_pointer_size() == 4:
        output("[0x0000:0x%.08X]" % dump_addr)
        output("------------------------------------------------------")
    else:
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("------------------------------------------------------")
    color("BOLD")
    output("[data]")
    color("RESET")
    output("\n")        
    #output(hexdump(dump_addr, membuff, " ", 16));
    index = 0
    while index < 0x100:
        data = struct.unpack("B"*16, membuf[index:index+0x10])
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
            quotechars(membuf[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color("RESET")
    #last element of the list has all data output...
    #so we remove last \n
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display word values and ASCII characters
def cmd_dw(debugger, command, result, dict):
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
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a start address.")
        print("")
        print(help)
        return

    err = lldb.SBError()
    size = 0x100
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if err.Success() == False:
        print("[-] error: failed to read memory from address 0x{:x}".format(dump_addr))
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    color("BLUE")
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("[0x0000:0x%.08X]" % dump_addr)
        output("--------------------------------------------")
    else: #is_x64():
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("--------------------------------------------")
    color("BOLD")
    output("[data]")
    color("RESET")
    output("\n")
    index = 0
    while index < 0x100:
        data = struct.unpack("HHHHHHHH", membuf[index:index+0x10])
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
            quotechars(membuf[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color("RESET")
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display dword values and ASCII characters
def cmd_dd(debugger, command, result, dict):
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
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a start address.")
        print("")
        print(help)
        return

    err = lldb.SBError()
    size = 0x100
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if err.Success() == False:
        print("[-] error: failed to read memory from address 0x{:x}".format(dump_addr))
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return
    color("BLUE")
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("[0x0000:0x%.08X]" % dump_addr)
        output("----------------------------------------")
    else: #is_x64():
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("----------------------------------------")
    color("BOLD")
    output("[data]")
    color("RESET")
    output("\n")
    index = 0
    while index < 0x100:
        (mem0, mem1, mem2, mem3) = struct.unpack("IIII", membuf[index:index+0x10])
        if get_pointer_size() == 4: #is_i386() or is_arm():
            szaddr = "0x%.08X" % dump_addr
        else:  #is_x64():
            szaddr = "0x%.016lX" % dump_addr
        output("\033[1m%s :\033[0m %.08X %.08X %.08X %.08X \033[1m%s\033[0m" % (szaddr, 
                                            mem0, 
                                            mem1, 
                                            mem2, 
                                            mem3, 
                                            quotechars(membuf[index:index+0x10])));
        if index + 0x10 != 0x100:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    color("RESET")
    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display quad values
def cmd_dq(debugger, command, result, dict):
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
            print("[-] error: invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           print(help)
           return        
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            print("[-] error: invalid input address value.")
            print("")
            print(help)
            return
    else:
        print("[-] error: please insert a start address.")
        print("")
        print(help)
        return

    err = lldb.SBError()
    size = 0x100
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if err.Success() == False:
        print("[-] error: failed to read memory from address 0x{:x}".format(dump_addr))
        result.PutCString("".join(GlobalListOutput))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    color("BLUE")
    if get_pointer_size() == 4:
        output("[0x0000:0x%.08X]" % dump_addr)
        output("-------------------------------------------------------")
    else:
        output("[0x0000:0x%.016lX]" % dump_addr)
        output("-------------------------------------------------------")
    color("BOLD")
    output("[data]")
    color("RESET")
    output("\n")   
    index = 0
    while index < 0x100:
        (mem0, mem1, mem2, mem3) = struct.unpack("QQQQ", membuf[index:index+0x20])
        if get_pointer_size() == 4:
            szaddr = "0x%.08X" % dump_addr
        else:
            szaddr = "0x%.016lX" % dump_addr
        output("\033[1m%s :\033[0m %.016lX %.016lX %.016lX %.016lX" % (szaddr, mem0, mem1, mem2, mem3))
        if index + 0x20 != 0x100:
            output("\n")
        index += 0x20
        dump_addr += 0x20
    color("RESET")
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
        line = line.ljust( width, b'\000' )
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
    data = ""
    for x in bytearray(chars):
        if x >= 0x20 and x <= 126:
            data += chr(x)
        else:       
            data += "."
    return data

# XXX: help
def cmd_findmem(debugger, command, result, dict):
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
    
    if parser.string is not None:
        search_string = parser.string
    elif parser.unicode is not None:
        search_string  = unicode(parser.unicode)
    elif parser.binary is not None:
        search_string = parser.binary.decode("hex")
    elif parser.dword is not None:
        dword = evaluate(parser.dword)
        if dword is None:
            print("[-] Error evaluating : " + parser.dword)
            return
        search_string = struct.pack("I", dword & 0xffffffff)
    elif parser.qword is not None:
        qword = evaluate(parser.qword)
        if qword is None:
            print("[-] Error evaluating : " + parser.qword)
            return
        search_string = struct.pack("Q", qword & 0xffffffffffffffff)
    elif parser.file is not None:
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
    if parser.count is not None:
        count = evaluate(parser.count)
        if count is None:
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

            color("RESET")
            output("Found at : ")
            color("GREEN")
            output(ptrformat % (mem_start + off))
            color("RESET")
            if base_displayed == 0:
                output(" base : ")
                color("YELLOW")
                output(ptrformat % mem_start)
                color("RESET")
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

def cmd_datawin(debugger, command, result, dict):
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
        print("[-] error: please insert an address.")
        print("")
        print(help)
        return

    if cmd[0] == "help":
        print(help)
        return        

    dump_addr = evaluate(cmd[0])
    if dump_addr is None:
        print("[-] error: invalid address value.")
        print("")
        print(help)
        DATA_WINDOW_ADDRESS = 0
        return
    DATA_WINDOW_ADDRESS = dump_addr

# ----------------------------------------------------------
# Functions to extract internal and process lldb information
# ----------------------------------------------------------

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
    if ret is None:
        print("[-] warning: get_frame() failed. Is the target binary started?")

    return ret

def get_thread():
    ret = None
    # SBProcess supports thread iteration -> SBThread
    for thread in get_process():
        if thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            ret = thread
    
    if ret is None:
        print("[-] warning: get_thread() failed. Is the target binary started?")

    return ret

def get_target():
    target = lldb.debugger.GetSelectedTarget()
    if not target:
        print("[-] error: no target available. please add a target to lldb.")
        return
    return target

def get_process():
    # process
    # A read only property that returns an lldb object that represents the process (lldb.SBProcess) that this target owns.
    return lldb.debugger.GetSelectedTarget().process

# evaluate an expression and return the value it represents
def evaluate(command):
    frame = get_frame()
    if frame is not None:
        value = frame.EvaluateExpression(command)
        if value.IsValid() == False:
            return None
        try:
            value = int(value.GetValue(), base=10)
            return value
        except Exception as e:
            print("Exception on evaluate: " + str(e))
            return None
    # use the target version - if no target exists we can't do anything about it
    else:
        target = get_target()    
        if target is None:
            return None
        value = target.EvaluateExpression(command)
        if value.IsValid() == False:
            return None
        try:
            value = int(value.GetValue(), base=10)
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

# -------------------------
# Register related commands
# -------------------------

# return the int value of a general purpose register
def get_gp_register(reg_name):
    regs = get_registers("general purpose")
    if regs is None:
        return 0
    for reg in regs:
        if reg_name == reg.GetName():
            #return int(reg.GetValue(), 16)
            return reg.unsigned
    return 0

def get_gp_registers():
    regs = get_registers("general purpose")
    if regs is None:
        return 0
    
    registers = {}
    for reg in regs:
        reg_name = reg.GetName()
        registers[reg_name] = reg.unsigned
    return registers
        
def get_register(reg_name):
    regs = get_registers("general purpose")
    if regs is None:
        return "0"
    for reg in regs:
        if reg_name == reg.GetName():
            return reg.GetValue()
    return "0"

def get_registers(kind):
    """Returns the registers given the frame and the kind of registers desired.

    Returns None if there's no such kind.
    """
    frame = get_frame()
    if frame is None:
        return None
    registerSet = frame.GetRegisters() # Return type of SBValueList.
    for value in registerSet:
        if kind.lower() in value.GetName().lower():
            return value
    return None

# retrieve current instruction pointer via platform independent $pc register
def get_current_pc():
    frame = get_frame()
    if frame is None:
        return 0
    pc = frame.FindRegister("pc")
    return int(pc.GetValue(), 16)

# retrieve current stack pointer via registers information
# XXX: add ARM
def get_current_sp():
    if is_i386():
        sp_addr = get_gp_register("esp")
    elif is_x64():
        sp_addr = get_gp_register("rsp")
    else:
        print("[-] error: wrong architecture.")
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
        print("[-] error: command requires arguments.")
        print("")
        print(help)
        return

    if cmd[0] == "help":
        print(help)
        return

    value = evaluate(command)
    if value is None:
        print("[-] error: invalid input value.")
        print("")
        print(help)
        return

    # we need to format because hex() will return string with an L and that will fail to update register
    get_frame().reg[register].value = format(value, '#x')

# shortcut functions to modify each register
def cmd_rip(debugger, command, result, dict):
    update_register("rip", command)

def cmd_rax(debugger, command, result, dict):
    update_register("rax", command)

def cmd_rbx(debugger, command, result, dict):
    update_register("rbx", command)

def cmd_rbp(debugger, command, result, dict):
    update_register("rbp", command)

def cmd_rsp(debugger, command, result, dict):
    update_register("rsp", command)

def cmd_rdi(debugger, command, result, dict):
    update_register("rdi", command)

def cmd_rsi(debugger, command, result, dict):
    update_register("rsi", command)

def cmd_rdx(debugger, command, result, dict):
    update_register("rdx", command)

def cmd_rcx(debugger, command, result, dict):
    update_register("rcx", command)

def cmd_r8(debugger, command, result, dict):
    update_register("r8", command)

def cmd_r9(debugger, command, result, dict):
    update_register("r9", command)

def cmd_r10(debugger, command, result, dict):
    update_register("r10", command)

def cmd_r11(debugger, command, result, dict):
    update_register("r11", command)

def cmd_r12(debugger, command, result, dict):
    update_register("r12", command)

def cmd_r13(debugger, command, result, dict):
    update_register("r13", command)

def cmd_r14(debugger, command, result, dict):
    update_register("r14", command)

def cmd_r15(debugger, command, result, dict):
    update_register("r15", command)

def cmd_eip(debugger, command, result, dict):
    update_register("eip", command)

def cmd_eax(debugger, command, result, dict):
    update_register("eax", command)

def cmd_ebx(debugger, command, result, dict):
    update_register("ebx", command)

def cmd_ebp(debugger, command, result, dict):
    update_register("ebp", command)

def cmd_esp(debugger, command, result, dict):
    update_register("esp", command)

def cmd_edi(debugger, command, result, dict):
    update_register("edi", command)

def cmd_esi(debugger, command, result, dict):
    update_register("esi", command)

def cmd_edx(debugger, command, result, dict):
    update_register("edx", command)

def cmd_ecx(debugger, command, result, dict):
    update_register("ecx", command)

# -----------------------------
# modify eflags/rflags commands
# -----------------------------

def modify_eflags(flag):
    # read the current value so we can modify it
    if is_x64():
        eflags = get_gp_register("rflags")
    elif is_i386():
        eflags = get_gp_register("eflags")
    else:
        print("[-] error: unsupported architecture.")
        return

    masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
    if flag not in masks.keys():
        print("[-] error: requested flag not available")
        return
    # we invert whatever value is set
    if bool(eflags & (1 << masks[flag])) == True:
        eflags = eflags & ~(1 << masks[flag])
    else:
        eflags = eflags | (1 << masks[flag])

    # finally update the value
    if is_x64():
        get_frame().reg["rflags"].value = format(eflags, '#x')
    elif is_i386():
        get_frame().reg["eflags"].value = format(eflags, '#x')

def cmd_cfa(debugger, command, result, dict):
    '''Change adjust flag. Use \'cfa help\' for more information.'''
    help = """
Flip current adjust flag.

Syntax: cfa
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("AF")

def cmd_cfc(debugger, command, result, dict):
    '''Change carry flag. Use \'cfc help\' for more information.'''
    help = """
Flip current carry flag.

Syntax: cfc
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("CF")

def cmd_cfd(debugger, command, result, dict):
    '''Change direction flag. Use \'cfd help\' for more information.'''
    help = """
Flip current direction flag.

Syntax: cfd
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("DF")

def cmd_cfi(debugger, command, result, dict):
    '''Change interrupt flag. Use \'cfi help\' for more information.'''
    help = """
Flip current interrupt flag.

Syntax: cfi
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("IF")

def cmd_cfo(debugger, command, result, dict):
    '''Change overflow flag. Use \'cfo help\' for more information.'''
    help = """
Flip current overflow flag.

Syntax: cfo
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("OF")

def cmd_cfp(debugger, command, result, dict):
    '''Change parity flag. Use \'cfp help\' for more information.'''
    help = """
Flip current parity flag.

Syntax: cfp
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("PF")

def cmd_cfs(debugger, command, result, dict):
    '''Change sign flag. Use \'cfs help\' for more information.'''
    help = """
Flip current sign flag.

Syntax: cfs
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("SF")

def cmd_cft(debugger, command, result, dict):
    '''Change trap flag. Use \'cft help\' for more information.'''
    help = """
Flip current trap flag.

Syntax: cft
"""
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("TF")

def cmd_cfz(debugger, command, result, dict):
    '''Change zero flag. Use \'cfz help\' for more information.'''
    help = """
Flip current zero flag.

Syntax: cfz
""" 
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            print(help)
            return
        print("[-] error: command doesn't take any arguments.")
        print("")
        print(help)
        return
    modify_eflags("ZF")

def dump_eflags(eflags):
    # the registers are printed by inverse order of bit field
    # no idea where this comes from :-]
    # masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
    # printTuples = sorted(masks.items() , reverse=True, key=lambda x: x[1])
    eflagsTuples = [('OF', 11), ('DF', 10), ('IF', 9), ('TF', 8), ('SF', 7), ('ZF', 6), ('AF', 4), ('PF', 2), ('CF', 0)]
    # use the first character of each register key to output, lowercase if bit not set
    for flag, bitfield in eflagsTuples :
        if bool(eflags & (1 << bitfield)) == True:
            output(flag[0] + " ")
        else:
            output(flag[0].lower() + " ")

# function to dump the conditional jumps results
def dump_jumpx86(eflags):
    # masks and flags from https://github.com/ant4g0nist/lisa.py
    masks = { "CF":0, "PF":2, "AF":4, "ZF":6, "SF":7, "TF":8, "IF":9, "DF":10, "OF":11 }
    flags = { key: bool(eflags & (1 << value)) for key, value in masks.items() }

    error = lldb.SBError()
    target = get_target()
    if is_i386():
        pc_addr = get_gp_register("eip")
    elif is_x64():
        pc_addr = get_gp_register("rip")
    else:
        print("[-] error: wrong architecture.")
        return

    mnemonic = get_mnemonic(pc_addr)
    color("RED")
    output_string=""
    ## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
    ## opcode 0x0F87: JNBE, JA
    if "ja" == mnemonic or "jnbe" == mnemonic:
        if flags["CF"] == False and flags["ZF"] == False:
            output_string="Jump is taken (c = 0 and z = 0)"
        else:
            output_string="Jump is NOT taken (c = 0 and z = 0)"
    ## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
    ## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
    if "jae" == mnemonic or "jnb" == mnemonic or "jnc" == mnemonic:
        if flags["CF"] == False:
            output_string="Jump is taken (c = 0)"
        else:
            output_string="Jump is NOT taken (c != 0)"
    ## opcode 0x72: JB, JC, JNAE (jump if CF=1)
    ## opcode 0x0F82: JNAE, JB, JC
    if "jb" == mnemonic or "jc" == mnemonic or "jnae" == mnemonic:
        if flags["CF"] == True:
            output_string="Jump is taken (c = 1)"
        else:
            output_string="Jump is NOT taken (c != 1)"
    ## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
    ## opcode 0x0F86: JBE, JNA
    if "jbe" == mnemonic or "jna" == mnemonic:
        if flags["CF"] == True or flags["ZF"] == 1:
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
        if flags["ZF"] == 1:
            output_string="Jump is taken (z = 1)"
        else:
            output_string="Jump is NOT taken (z != 1)"
    ## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
    ## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
    if "jg" == mnemonic or "jnle" == mnemonic:
        if flags["ZF"] == 0 and flags["SF"] == flags["OF"]:
            output_string="Jump is taken (z = 0 and s = o)"
        else:
            output_string="Jump is NOT taken (z != 0 or s != o)"
    ## opcode 0x7D: JGE, JNL (jump if SF=OF)
    ## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
    if "jge" == mnemonic or "jnl" == mnemonic:
        if flags["SF"] == flags["OF"]:
            output_string="Jump is taken (s = o)"
        else:
            output_string="Jump is NOT taken (s != o)"
    ## opcode: 0x7C: JL, JNGE (jump if SF != OF)
    ## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
    if "jl" == mnemonic or "jnge" == mnemonic:
        if flags["SF"] != flags["OF"]:
            output_string="Jump is taken (s != o)"
        else:
            output_string="Jump is NOT taken (s = o)"
    ## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
    ## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
    if "jle" == mnemonic or "jng" == mnemonic:
        if flags["ZF"] == 1 or flags["SF"] != flags["OF"]:
            output_string="Jump is taken (z = 1 or s != o)"
        else:
            output_string="Jump is NOT taken (z != 1 or s = o)"
    ## opcode 0x75: JNE, JNZ (jump if ZF = 0)
    ## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
    if "jne" == mnemonic or "jnz" == mnemonic:
        if flags["ZF"] == 0:
            output_string="Jump is taken (z = 0)"
        else:
            output_string="Jump is NOT taken (z != 0)"
    ## opcode 0x71: JNO (OF = 0)
    ## opcode 0x0F81: JNO (OF = 0)
    if "jno" == mnemonic:
        if flags["OF"] == 0:
            output_string="Jump is taken (o = 0)"
        else:
            output_string="Jump is NOT taken (o != 0)"
    ## opcode 0x7B: JNP, JPO (jump if PF = 0)
    ## opcode 0x0F8B: JPO (jump if PF = 0)
    if "jnp" == mnemonic or "jpo" == mnemonic:
        if flags["PF"] == 0:
            output_string="Jump is NOT taken (p = 0)"
        else:
            output_string="Jump is taken (p != 0)"
    ## opcode 0x79: JNS (jump if SF = 0)
    ## opcode 0x0F89: JNS (jump if SF = 0)
    if "jns" == mnemonic:
        if flags["SF"] == 0:
            output_string="Jump is taken (s = 0)"
        else:
            output_string="Jump is NOT taken (s != 0)"
    ## opcode 0x70: JO (jump if OF=1)
    ## opcode 0x0F80: JO (jump if OF=1)
    if "jo" == mnemonic:
        if flags["OF"] == 1:
            output_string="Jump is taken (o = 1)"
        else:
            output_string="Jump is NOT taken (o != 1)"
    ## opcode 0x7A: JP, JPE (jump if PF=1)
    ## opcode 0x0F8A: JP, JPE (jump if PF=1)
    if "jp" == mnemonic or "jpe" == mnemonic:
        if flags["PF"] == 1:
            output_string="Jump is taken (p = 1)"
        else:
            output_string="Jump is NOT taken (p != 1)"
    ## opcode 0x78: JS (jump if SF=1)
    ## opcode 0x0F88: JS (jump if SF=1)
    if "js" == mnemonic:
        if flags["SF"] == 1:
            output_string="Jump is taken (s = 1)"
        else:
            output_string="Jump is NOT taken (s != 1)"

    if is_i386():
        output(" " + output_string)
    elif is_x64():
        output("                                              " + output_string)
    else:
        output(output_string)

    color("RESET")

def reg64():
    registers = get_gp_registers()
    rax = registers["rax"]
    rcx = registers["rcx"]
    rdx = registers["rdx"]
    rbx = registers["rbx"]
    rsp = registers["rsp"]
    rbp = registers["rbp"]
    rsi = registers["rsi"]
    rdi = registers["rdi"]
    r8  = registers["r8"]
    r9  = registers["r9"]
    r10 = registers["r10"]
    r11 = registers["r11"]
    r12 = registers["r12"]
    r13 = registers["r13"]
    r14 = registers["r14"]
    r15 = registers["r15"]
    rip = registers["rip"]
    rflags = registers["rflags"]
    cs = registers["cs"]
    gs = registers["gs"]
    fs = registers["fs"]

    color(COLOR_REGNAME)
    output("  RAX: ")
    if rax == old_x64["rax"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rax))
    old_x64["rax"] = rax
    
    color(COLOR_REGNAME)
    output("  RBX: ")
    if rbx == old_x64["rbx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rbx))
    old_x64["rbx"] = rbx
    
    color(COLOR_REGNAME)
    output("  RBP: ")
    if rbp == old_x64["rbp"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rbp))
    old_x64["rbp"] = rbp
    
    color(COLOR_REGNAME)
    output("  RSP: ")
    if rsp == old_x64["rsp"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rsp))
    old_x64["rsp"] = rsp
    
    output("  ")
    color("BOLD")
    color("UNDERLINE")
    color(COLOR_CPUFLAGS)
    dump_eflags(rflags)
    color("RESET")
    
    output("\n")
            
    color(COLOR_REGNAME)
    output("  RDI: ")
    if rdi == old_x64["rdi"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rdi))
    old_x64["rdi"] = rdi
    
    color(COLOR_REGNAME)
    output("  RSI: ")
    if rsi == old_x64["rsi"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rsi))
    old_x64["rsi"] = rsi
    
    color(COLOR_REGNAME)
    output("  RDX: ")
    if rdx == old_x64["rdx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rdx))
    old_x64["rdx"] = rdx
    
    color(COLOR_REGNAME)
    output("  RCX: ")
    if rcx == old_x64["rcx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rcx))
    old_x64["rcx"] = rcx
    
    color(COLOR_REGNAME)
    output("  RIP: ")
    if rip == old_x64["rip"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (rip))
    old_x64["rip"] = rip
    output("\n")
        
    color(COLOR_REGNAME)
    output("  R8:  ")
    if r8 == old_x64["r8"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r8))
    old_x64["r8"] = r8
    
    color(COLOR_REGNAME)
    output("  R9:  ")
    if r9 == old_x64["r9"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r9))
    old_x64["r9"] = r9
    
    color(COLOR_REGNAME)
    output("  R10: ")
    if r10 == old_x64["r10"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r10))
    old_x64["r10"] = r10
    
    color(COLOR_REGNAME)
    output("  R11: ")
    if r11 == old_x64["r11"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r11))
    old_x64["r11"] = r11
    
    color(COLOR_REGNAME)
    output("  R12: ")
    if r12 == old_x64["r12"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r12))
    old_x64["r12"] = r12
    
    output("\n")
        
    color(COLOR_REGNAME)
    output("  R13: ")
    if r13 == old_x64["r13"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r13))
    old_x64["r13"] = r13
    
    color(COLOR_REGNAME)
    output("  R14: ")
    if r14 == old_x64["r14"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r14))
    old_x64["r14"] = r14
    
    color(COLOR_REGNAME)
    output("  R15: ")
    if r15 == old_x64["r15"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.016lX" % (r15))
    old_x64["r15"] = r15
    output("\n")
        
    color(COLOR_REGNAME)
    output("  CS:  ")
    if cs == old_x64["cs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (cs))
    old_x64["cs"] = cs
        
    color(COLOR_REGNAME)
    output("  FS: ")
    if fs == old_x64["fs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (fs))
    old_x64["fs"] = fs
    
    color(COLOR_REGNAME)
    output("  GS: ")
    if gs == old_x64["gs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (gs))
    old_x64["gs"] = gs
    
    dump_jumpx86(rflags)
    output("\n")

def reg32():
    registers = get_gp_registers()
    eax = registers["eax"]
    ecx = registers["ecx"]
    edx = registers["edx"]
    ebx = registers["ebx"]
    esp = registers["esp"]
    ebp = registers["ebp"]
    esi = registers["esi"]
    edi = registers["edi"]
    eflags = registers["eflags"]
    cs = registers["cs"]
    ds = registers["ds"]
    es = registers["es"]
    gs = registers["gs"]
    fs = registers["fs"]
    ss = registers["ss"]
        
    color(COLOR_REGNAME)
    output("  EAX: ")
    if eax == old_x86["eax"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (eax))
    old_x86["eax"] = eax
    
    color(COLOR_REGNAME)
    output("  EBX: ")
    if ebx == old_x86["ebx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ebx))
    old_x86["ebx"] = ebx
    
    color(COLOR_REGNAME)
    output("  ECX: ")
    if ecx == old_x86["ecx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ecx))
    old_x86["ecx"] = ecx

    color(COLOR_REGNAME)
    output("  EDX: ")
    if edx == old_x86["edx"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (edx))
    old_x86["edx"] = edx
    
    output("  ")
    color("BOLD")
    color("UNDERLINE")
    color(COLOR_CPUFLAGS)
    dump_eflags(eflags)
    color("RESET")
    
    output("\n")
    
    color(COLOR_REGNAME)
    output("  ESI: ")
    if esi == old_x86["esi"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (esi))
    old_x86["esi"] = esi
    
    color(COLOR_REGNAME)
    output("  EDI: ")
    if edi == old_x86["edi"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (edi))
    old_x86["edi"] = edi
    
    color(COLOR_REGNAME)
    output("  EBP: ")
    if ebp == old_x86["ebp"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (ebp))
    old_x86["ebp"] = ebp
    
    color(COLOR_REGNAME)
    output("  ESP: ")
    if esp == old_x86["esp"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (esp))
    old_x86["esp"] = esp
    
    color(COLOR_REGNAME)
    output("  EIP: ")
    if eip == old_x86["eip"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (eip))
    old_x86["eip"] = eip
    output("\n")
    
    color(COLOR_REGNAME)
    output("  CS:  ")
    if cs == old_x86["cs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (cs))
    old_x86["cs"] = cs
    
    color(COLOR_REGNAME)
    output("  DS: ")
    if ds == old_x86["ds"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (ds))
    old_x86["ds"] = ds
    
    color(COLOR_REGNAME)
    output("  ES: ")
    if es == old_x86["es"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (es))
    old_x86["es"] = es
    
    color(COLOR_REGNAME)
    output("  FS: ")
    if fs == old_x86["fs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (fs))
    old_x86["fs"] = fs
    
    color(COLOR_REGNAME)
    output("  GS: ")
    if gs == old_x86["gs"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (gs))
    old_x86["gs"] = gs
    
    color(COLOR_REGNAME)
    output("  SS: ")
    if ss == old_x86["ss"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("%.04X" % (ss))
    old_x86["ss"] = ss

    dump_jumpx86(eflags)
    output("\n")
    
def dump_cpsr(cpsr):
    # XXX: some fields reserved in recent ARM specs so we should revise and set to latest?
    cpsrTuples = [ ('N', 31), ('Z', 30), ('C', 29), ('V', 28), ('Q', 27), ('J', 24), 
                   ('E', 9), ('A', 8), ('I', 7), ('F', 6), ('T', 5) ]
    # use the first character of each register key to output, lowercase if bit not set
    for flag, bitfield in cpsrTuples :
        if bool(cpsr & (1 << bitfield)) == True:
            output(flag + " ")
        else:
            output(flag.lower() + " ")
        
def regarm():
    color(COLOR_REGNAME)
    output("  R0:  ")
    r0 = get_gp_register("r0")
    if r0 == old_arm["r0"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r0))
    old_arm["r0"] = r0

    color(COLOR_REGNAME)
    output("  R1:  ")
    r1 = get_gp_register("r1")
    if r1 == old_arm["r1"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r1))
    old_arm["r1"] = r1

    color(COLOR_REGNAME)
    output("  R2:  ")
    r2 = get_gp_register("r2")
    if r2 == old_arm["r2"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r2))
    old_arm["r2"] = r2

    color(COLOR_REGNAME)
    output("  R3:  ")
    r3 = get_gp_register("r3")
    if r3 == old_arm["r3"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r3))
    old_arm["r3"] = r3
    
    output(" ")
    color("BOLD")
    color("UNDERLINE")
    color(COLOR_CPUFLAGS)
    cpsr = get_gp_register("cpsr")
    dump_cpsr(cpsr)
    color("RESET")

    output("\n")
    
    color(COLOR_REGNAME)
    output("  R4:  ")
    r4 = get_gp_register("r4")
    if r4 == old_arm["r4"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r4))
    old_arm["r4"] = r4

    color(COLOR_REGNAME)
    output("  R5:  ")
    r5 = get_gp_register("r5")
    if r5 == old_arm["r5"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r5))
    old_arm["r5"] = r5

    color(COLOR_REGNAME)
    output("  R6:  ")
    r6 = get_gp_register("r6")
    if r6 == old_arm["r6"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r6))
    old_arm["r6"] = r6

    color(COLOR_REGNAME)
    output("  R7:  ")
    r7 = get_gp_register("r7")
    if r7 == old_arm["r7"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r7))
    old_arm["r7"] = r7

    output("\n")

    color(COLOR_REGNAME)
    output("  R8:  ")
    r8 = get_gp_register("r8")
    if r8 == old_arm["r8"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r8))
    old_arm["r8"] = r8

    color(COLOR_REGNAME)
    output("  R9:  ")
    r9 = get_gp_register("r9")
    if r9 == old_arm["r9"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r9))
    old_arm["r9"] = r9

    color(COLOR_REGNAME)
    output("  R10: ")
    r10 = get_gp_register("r10")
    if r10 == old_arm["r10"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r10))
    old_arm["r10"] = r10

    color(COLOR_REGNAME)
    output("  R11: ")
    r11 = get_gp_register("r11")
    if r11 == old_arm["r11"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r11))
    old_arm["r11"] = r11
    
    output("\n")

    color(COLOR_REGNAME)
    output("  R12: ")
    r12 = get_gp_register("r12")
    if r12 == old_arm["r12"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (r12))
    old_arm["r12"] = r12

    color(COLOR_REGNAME)
    output("  SP:  ")
    sp = get_gp_register("sp")
    if sp == old_arm["sp"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (sp))
    old_arm["sp"] = sp

    color(COLOR_REGNAME)
    output("  LR:  ")
    lr = get_gp_register("lr")
    if lr == old_arm["lr"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (lr))
    old_arm["lr"] = lr

    color(COLOR_REGNAME)
    output("  PC:  ")
    pc = get_gp_register("pc")
    if pc == old_arm["pc"]:
        color(COLOR_REGVAL)
    else:
        color(COLOR_REGVAL_MODIFIED)
    output("0x%.08X" % (pc))
    old_arm["pc"] = pc
    output("\n")

def print_registers():
    arch = get_arch()
    if is_i386(): 
        reg32()
    elif is_x64():
        reg64()
    elif is_arm():
        regarm()

'''
    si, c, r instruction override deault ones to consume their output.
    For example:
        si is thread step-in which by default dumps thread and frame info
        after every step. Consuming output of this instruction allows us
        to nicely display informations in our hook-stop
    Same goes for c and r (continue and run)
'''
def cmd_si(debugger, command, result, dict):
    debugger.SetAsync(True)
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False)
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

def c(debugger, command, result, dict):
    debugger.SetAsync(True)
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetSelectedTarget().GetProcess().Continue()
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

# ------------------------------
# Disassembler related functions
# ------------------------------

'''
    Handles 'u' command which displays instructions. Also handles output of
    'disassemble' command ...
'''
# XXX: help
def cmd_DumpInstructions(debugger, command, result, dict):
    '''Dump instructions at certain address (SoftICE like u command style)'''
    help = """ """

    global GlobalListOutput
    GlobalListOutput = []
    
    target = get_target()
    cmd = command.split()
    if len(cmd) == 0 or len(cmd) > 2:
        disassemble(get_current_pc(), CONFIG_DISASSEMBLY_LINE_COUNT)
    elif len(cmd) == 1:
        address = evaluate(cmd[0])
        if address is None:
            return
        disassemble(address, CONFIG_DISASSEMBLY_LINE_COUNT)
    else:
        address = evaluate(cmd[0])
        if address is None:
            return
        count = evaluate(cmd[1])
        if count is None:
            return
        disassemble(address, count)

    result.PutCString("".join(GlobalListOutput))
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# return the instruction mnemonic at input address
def get_mnemonic(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print("[-] error: not enough instructions disassembled.")
        return ""

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    # much easier to use the mnemonic output instead of disassembling via cmd line and parse
    mnemonic = cur_instruction.GetMnemonic(target)

    return mnemonic

# returns the instruction operands
def get_operands(src_address):
    err = lldb.SBError()
    target = get_target()
    # use current memory address
    # needs to be this way to workaround SBAddress init bug
    src_sbaddr = lldb.SBAddress()
    src_sbaddr.SetLoadAddress(src_address, target)
    instruction_list = target.ReadInstructions(src_sbaddr, 1, 'intel')
    if instruction_list.GetSize() == 0:
        print("[-] error: not enough instructions disassembled.")
        return ""    
    cur_instruction = instruction_list[0]
    return cur_instruction.GetOperands(target)

# find out the size of an instruction using internal disassembler
def get_inst_size(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print("[-] error: not enough instructions disassembled.")
        return 0

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    return cur_instruction.size

# the disassembler we use on stop context
# we can customize output here instead of using the cmdline as before and grabbing its output
def disassemble(start_address, count):
    target = get_target()
    if target is None:
        return
    # this init will set a file_addr instead of expected load_addr
    # and so the disassembler output will be referenced to the file address
    # instead of the current loaded memory address
    # this is annoying because all RIP references will be related to file addresses
    file_sbaddr = lldb.SBAddress(start_address, target)
    # create a SBAddress object with the load_addr set so we can disassemble with
    # current memory addresses and what is happening right now
    # we use the empty init and then set the property which is read/write for load_addr
    # this whole thing seems like a bug?
    mem_sbaddr = lldb.SBAddress()
    mem_sbaddr.SetLoadAddress(start_address, target)
    # disassemble to get the file and memory version
    # we could compute this by finding sections etc but this way it seems
    # much simpler and faster
    # this seems to be a bug or missing feature because there is no way
    # to distinguish between the load and file addresses in the disassembler
    # the reason might be because we can't create a SBAddress that has
    # load_addr and file_addr set so that the disassembler can distinguish them
    # somehow when we use file_sbaddr object the SBAddress GetLoadAddress()
    # retrieves the correct memory address for the instruction while the
    # SBAddress GetFileAddress() retrives the correct file address
    # but the branch instructions addresses are the file addresses
    # bug on SBAddress init implementation???
    # this also has problems with symbols - the memory version doesn't have them
    instructions_mem = target.ReadInstructions(mem_sbaddr, count, "intel")
    instructions_file = target.ReadInstructions(file_sbaddr, count, "intel")
    if instructions_mem.GetSize() != instructions_file.GetSize():
        print("[-] error: instructions arrays sizes are different.")
        return
    # find out the biggest instruction length and mnemonic length
    # so we can have a uniform output
    max_size = 0
    max_mnem_size = 0
    for i in instructions_mem:
        if i.size > max_size:
            max_size = i.size        
        mnem_len = len(i.GetMnemonic(target))
        if mnem_len > max_mnem_size:
            max_mnem_size = mnem_len
    
    current_pc = get_current_pc()
    # get info about module if there is a symbol
    module = file_sbaddr.module
    #module_name = module.file.GetFilename()
    module_name = module.file.fullpath

    count = 0
    blockstart_symaddr = None
    blockend_symaddr = None
    for mem_inst in instructions_mem:
        # get the same instruction but from the file version because we need some info from it
        file_inst = instructions_file[count]
        # try to extract the symbol name from this location if it exists
        # needs to be referenced to file because memory it doesn't work
        symbol_name = instructions_file[count].addr.GetSymbol().GetName()
        # if there is no symbol just display module where current instruction is
        # also get rid of unnamed symbols since they are useless
        if symbol_name is None or "___lldb_unnamed_symbol" in symbol_name:
            if count == 0:
                if CONFIG_ENABLE_COLOR == 1:
                    color(COLOR_SYMBOL_NAME)
                    output("@ {}:".format(module_name) + "\n")
                    color("RESET")
                else:
                    output("@ {}:".format(module_name) + "\n")            
        elif symbol_name is not None:
            # print the first time there is a symbol name and save its interval
            # so we don't print again until there is a different symbol
            file_symaddr = file_inst.GetAddress().GetFileAddress()
            if blockstart_symaddr is None or (file_symaddr < blockstart_symaddr) or (file_symaddr >= blockend_symaddr):
                if CONFIG_ENABLE_COLOR == 1:
                    color(COLOR_SYMBOL_NAME)
                    output("{} @ {}:".format(symbol_name, module_name) + "\n")
                    color("RESET")
                else:
                    output("{} @ {}:".format(symbol_name, module_name) + "\n")
                blockstart_symaddr = file_inst.GetAddress().GetSymbol().GetStartAddress().GetFileAddress()
                blockend_symaddr = file_inst.GetAddress().GetSymbol().GetEndAddress().GetFileAddress()

        
        # get the instruction bytes formatted as uint8
        inst_data = mem_inst.GetData(target).uint8
        mnem = mem_inst.GetMnemonic(target)
        operands = mem_inst.GetOperands(target)
        bytes_string = ""
        if CONFIG_DISPLAY_DISASSEMBLY_BYTES == 1:
            total_fill = max_size - mem_inst.size
            total_spaces = mem_inst.size - 1
            for x in inst_data:
                bytes_string += "{:02x}".format(x)
                if total_spaces > 0:
                    bytes_string += " "
                    total_spaces -= 1
            if total_fill > 0:
                # we need one more space because the last byte doesn't have space
                # and if we are smaller than max size we are one space short
                bytes_string += "  " * total_fill
                bytes_string += " " * total_fill
        
        mnem_len = len(mem_inst.GetMnemonic(target))
        if mnem_len < max_mnem_size:
            missing_spaces = max_mnem_size - mnem_len
            mnem += " " * missing_spaces

        # the address the current instruction is loaded at
        # we need to extract the address of the instruction and then find its loaded address
        memory_addr = mem_inst.addr.GetLoadAddress(target)
        # the address of the instruction in the current module
        # for main exe it will be the address before ASLR if enabled, otherwise the same as current
        # for modules it will be the address in the module code, not the address it's loaded at
        # so we can use this address to quickly get to current instruction in module loaded at a disassembler
        # without having to rebase everything etc
        #file_addr = mem_inst.addr.GetFileAddress()
        file_addr = file_inst.addr.GetFileAddress()
        
        comment = ""
        if file_inst.GetComment(target) != "":
            comment = " ; " + file_inst.GetComment(target)

        if current_pc == memory_addr:
            # try to retrieve extra information if it's a branch instruction
            # used to resolve indirect branches and try to extract Objective-C selectors
            if mem_inst.DoesBranch():
                flow_addr = get_indirect_flow_address(mem_inst.GetAddress().GetLoadAddress(target))
                if flow_addr > 0:
                    flow_module_name = get_module_name(flow_addr)
                    symbol_info = ""
                    # try to solve the symbol for the target address
                    target_symbol_name = lldb.SBAddress(flow_addr,target).GetSymbol().GetName()
                    # if there is a symbol append to the string otherwise
                    # it will be empty and have no impact in output
                    if target_symbol_name is not None:
                        symbol_info = target_symbol_name + " @ "
                    
                    if comment == "":
                        # remove space for instructions without operands
                        if mem_inst.GetOperands(target) == "":
                            comment = "; " + symbol_info + hex(flow_addr) + " @ " + flow_module_name
                        else:
                            comment = " ; " + symbol_info + hex(flow_addr) + " @ " + flow_module_name
                    else:
                        comment = comment + " " + hex(flow_addr) + " @ " + flow_module_name
                else:
                    comment = ""

                objc = get_objectivec_selector(current_pc)
                if objc != "":
                    comment = comment + " -> " + objc

            if CONFIG_ENABLE_COLOR == 1:
                color("BOLD")
                color(COLOR_CURRENT_PC)
                output("->  0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")
                color("RESET")
            else:
                output("->  0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")
        else:
            output("    0x{:x} (0x{:x}): {}  {}   {}{}".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + "\n")

        count += 1
    
    return

# ------------------------------------
# Commands that use external utilities
# ------------------------------------

def cmd_show_loadcmds(debugger, command, result, dict): 
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
           print(help)
           return
        header_addr = evaluate(cmd[0])
        if header_addr is None:
            print("[-] error: invalid header address value.")
            print("")
            print(help)
            return        
    else:
        print("[-] error: please insert a valid Mach-O header address.")
        print("")
        print(help)
        return

    if os.path.isfile("/usr/bin/otool") == False:
            print("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
            return
    
    bytes_string = get_process().ReadMemory(header_addr, 4096*10, error)
    if error.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(header_addr))
        return

    # open a temporary filename and set it to delete on close
    f = tempfile.NamedTemporaryFile(delete=True)
    f.write(bytes_string)
    # pass output to otool
    output_data = subprocess.check_output(["/usr/bin/otool", "-l", f.name])
    # show the data
    print(output_data)
    # close file - it will be automatically deleted
    f.close()

    return

def cmd_show_header(debugger, command, result, dict): 
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
           print(help)
           return
        header_addr = evaluate(cmd[0])
        if header_addr is None:
            print("[-] error: invalid header address value.")
            print("")
            print(help)
            return        
    else:
        print("[-] error: please insert a valid Mach-O header address.")
        print("")
        print(help)
        return

    if os.path.isfile("/usr/bin/otool") == False:
            print("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
            return
    
    # recent otool versions will fail so we need to read a reasonable amount of memory
    # even just for the mach-o header
    bytes_string = get_process().ReadMemory(header_addr, 4096*10, error)
    if error.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(header_addr))
        return

    # open a temporary filename and set it to delete on close
    f = tempfile.NamedTemporaryFile(delete=True)
    f.write(bytes_string)
    # pass output to otool
    output_data = subprocess.check_output(["/usr/bin/otool", "-hv", f.name])
    # show the data
    print(output_data)
    # close file - it will be automatically deleted
    f.close()

    return

# use keystone-engine.org to assemble
def assemble_keystone(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    print("\nKeystone output:\n----------")
    for inst in code:
        try:
            encoding, count = ks.asm(inst)
        except KsError as e:
            print("[-] error: keystone failed to assemble: {:s}".format(e))
            return
        output = []
        output.append(inst)
        output.append('->')
        for i in encoding:
            output.append("{:02x}".format(i))
        print(" ".join(output))

def cmd_asm32(debugger, command, result, dict):
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
        print(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_X86, KS_MODE_32, inst_list)

def cmd_asm64(debugger, command, result, dict):
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
        print(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_X86, KS_MODE_64, inst_list)

def cmd_arm32(debugger, command, result, dict):
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
        print(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM, KS_MODE_ARM, inst_list)

def cmd_armthumb(debugger, command, result, dict):
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
        print(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM, KS_MODE_THUMB, inst_list)

def cmd_arm64(debugger, command, result, dict):
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
        print(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        print("[-] error: keystone python bindings not available. please install from www.keystone-engine.org.")
        return
    
    inst_list = []
    while True:
        line = raw_input('Assemble ("stop" or "end" to finish): ')
        if line == 'stop' or line == 'end':
            break
        inst_list.append(line)
    
    assemble_keystone(KS_ARCH_ARM64, KS_MODE_ARM, inst_list)

# XXX: help
def cmd_IphoneConnect(debugger, command, result, dict): 
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
        print("[-] error: Failed to read memory at 0x{:x}.".format(stack_addr))
        return
    if len(membuff) == 0:
        print("[-] error: not enough bytes read.")
        return

    output(hexdump(stack_addr, membuff, " ", 16, 4))

def display_data():
    '''Hex dump current data window pointer'''
    data_addr = DATA_WINDOW_ADDRESS
    print(data_addr)
    if data_addr == 0:
        return
    err = lldb.SBError()
    target = get_target()
    membuff = get_process().ReadMemory(data_addr, 0x100, err)
    if err.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(stack_addr))
        return
    if len(membuff) == 0:
        print("[-] error: not enough bytes read.")
        return

    output(hexdump(data_addr, membuff, " ", 16, 4))

# workaround for lldb bug regarding RIP addressing outside main executable
def get_rip_relative_addr(src_address):
    err = lldb.SBError()
    target = get_target()
    inst_size = get_inst_size(src_address)
    if inst_size <= 1:
        print("[-] error: instruction size too small.")
        return 0
    # XXX: problem because it's not just 2 and 5 bytes
    # 0x7fff53fa2180 (0x1180): 0f 85 84 01 00 00     jne    0x7fff53fa230a ; stack_not_16_byte_aligned_error

    offset_bytes = get_process().ReadMemory(src_address+1, inst_size-1, err)
    if err.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(src_address))
        return 0
    if inst_size == 2:
        data = struct.unpack("b", offset_bytes)
    elif inst_size == 5:
        data = struct.unpack("i", offset_bytes)
    rip_call_addr = src_address + inst_size + data[0]
    #output("source {:x} rip call offset {:x} {:x}\n".format(src_address, data[0], rip_call_addr))
    return rip_call_addr

# XXX: instead of reading memory we can dereference right away in the evaluation
def get_indirect_flow_target(src_address):
    err = lldb.SBError()
    operand = get_operands(src_address)
    #output("Operand: {}\n".format(operand))
    # calls into a deferenced memory address
    if "qword" in operand:
        #output("dereferenced call\n")
        deref_addr = 0
        # first we need to find the address to dereference
        if '+' in operand:
            x = re.search('\[([a-z0-9]{2,3} \+ 0x[0-9a-z]+)\]', operand)
            if x is None:
                return 0
            value = get_frame().EvaluateExpression("$" + x.group(1))
            if value.IsValid() == False:                
                return 0
            deref_addr = int(value.GetValue(), 10)
            if "rip" in operand:
                deref_addr = deref_addr + get_inst_size(src_address)
        elif '-' in operand:
            x = re.search('\[([a-z0-9]{2,3} \- 0x[0-9a-z]+)\]', operand)
            if x is None:
                return 0
            value = get_frame().EvaluateExpression("$" + x.group(1))
            if value.IsValid() == False:                
                return 0
            deref_addr = int(value.GetValue(), 10)
            if "rip" in operand:
                deref_addr = deref_addr + get_inst_size(src_address)
        else:
            x = re.search('\[([a-z0-9]{2,3})\]', operand)
            if x is None:
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
        if x is None:
            return 0
        #output("Result {}\n".format(x.group(1)))
        value = get_frame().EvaluateExpression("$" + x.group(1))
        if value.IsValid() == False:                
            return 0
        return int(value.GetValue(), 10)
    # RIP relative calls
    elif operand.startswith('0x'):
        #output("direct call\n")
        # the disassembler already did the dirty work for us
        # so we just extract the address
        x = re.search('(0x[0-9a-z]+)', operand)
        if x is not None:
            #output("Result {}\n".format(x.group(0)))
            return int(x.group(1), 16)
    return 0

def get_ret_address():
    err = lldb.SBError()
    stack_addr = get_current_sp()
    if stack_addr == 0:
        return -1
    ret_addr = get_process().ReadPointerFromMemory(stack_addr, err)
    if err.Success() == False:
        print("[-] error: Failed to read memory at 0x{:x}.".format(stack_addr))
        return -1
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
    strings = membuff.split(b'\00')
    if len(strings) != 0:
        color("RED")
        output('Class: ')
        color("RESET")
        output(className)
        color("RED")
        output(' Selector: ')
        color("RESET")
        output(strings[0])

def display_indirect_flow():
    target = get_target()
    pc_addr = get_current_pc()
    mnemonic = get_mnemonic(pc_addr)

    if ("ret" in mnemonic) == True:
        indirect_addr = get_ret_address()
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

# find out the target address of ret, and indirect call and jmp
def get_indirect_flow_address(src_addr):
    target = get_target()
    instruction_list = target.ReadInstructions(lldb.SBAddress(src_addr, target), 1, 'intel')
    if instruction_list.GetSize() == 0:
        print("[-] error: not enough instructions disassembled.")
        return -1

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    if cur_instruction.DoesBranch() == False:
        return -1

    if "ret" in cur_instruction.GetMnemonic(target):
        ret_addr = get_ret_address()
        return ret_addr
    if ("call" in cur_instruction.GetMnemonic(target)) or ("jmp" in cur_instruction.GetMnemonic(target)):
        # don't care about RIP relative jumps
        if cur_instruction.GetOperands(target).startswith('0x'):
            return -1
        indirect_addr = get_indirect_flow_target(src_addr)
        return indirect_addr
    # all other branches just return -1
    return -1

# retrieve the module full path name an address belongs to
def get_module_name(src_addr):
    target = get_target()
    src_module = lldb.SBAddress(src_addr, target).module
    module_name = src_module.file.fullpath
    if module_name is None:
        return ""
    else:
        return module_name

def get_objectivec_selector(src_addr):
    err = lldb.SBError()
    target = get_target()

    call_addr = get_indirect_flow_target(src_addr)
    if call_addr == 0:
        return ""
    sym_addr = lldb.SBAddress(call_addr, target)
    symbol = sym_addr.GetSymbol()
    # XXX: add others?
    if symbol.name != "objc_msgSend":
        return ""

    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC)
    options.SetTrapExceptions(False)

    classname_command = '(const char *)object_getClassName((id){})'.format(get_instance_object())
    classname_value = get_frame().EvaluateExpression(classname_command)
    if classname_value.IsValid() == False:
        return ""
    
    className = classname_value.GetSummary().strip('"')
    selector_addr = get_gp_register("rsi")
    membuf = get_process().ReadMemory(selector_addr, 0x100, err)
    strings = membuf.split(b'\00')
    if len(strings) != 0:
        methodName = strings[0].decode() if isinstance(strings[0], bytes) else strings[0]
        return "[" + className + " " + methodName + "]"
    else:
        return "[" + className + "]"
    
    return ""

# ------------------------------------------------------------
# The heart of lldbinit - when lldb stop this is where we land 
# ------------------------------------------------------------

def HandleHookStopOnTarget(debugger, command, result, dict):
    '''Display current code context.'''
    # Don't display anything if we're inside Xcode
    if os.getenv('PATH').startswith('/Applications/Xcode.app'):
        return
    
    global GlobalListOutput
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
            
    color("BOLD")
    output("[regs]\n")
    color("RESET")
    print_registers()

    if CONFIG_DISPLAY_STACK_WINDOW == 1:
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("--------------------------------------------------------------------------------")
        elif is_x64():
            output("----------------------------------------------------------------------------------------------------------------------")
        color("BOLD")
        output("[stack]\n")
        color("RESET")
        display_stack()
        output("\n")

    if CONFIG_DISPLAY_DATA_WINDOW == 1:
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("---------------------------------------------------------------------------------")
        elif is_x64():
            output("-----------------------------------------------------------------------------------------------------------------------")
        color("BOLD")
        output("[data]\n")
        color("RESET")
        display_data()
        output("\n")

    if CONFIG_DISPLAY_FLOW_WINDOW == 1 and is_x64():
        color(COLOR_SEPARATOR)
        if is_i386() or is_arm():
            output("---------------------------------------------------------------------------------")
        elif is_x64():
            output("-----------------------------------------------------------------------------------------------------------------------")
        color("BOLD")
        output("[flow]\n")
        color("RESET")
        display_indirect_flow()

    color(COLOR_SEPARATOR)
    if is_i386() or is_arm():
        output("---------------------------------------------------------------------------------")
    elif is_x64():
        output("-----------------------------------------------------------------------------------------------------------------------")
    color("BOLD")
    output("[code]\n")
    color("RESET")
            
    # disassemble and add its contents to output inside
    disassemble(get_current_pc(), CONFIG_DISASSEMBLY_LINE_COUNT)
        
    color(COLOR_SEPARATOR)
    if get_pointer_size() == 4: #is_i386() or is_arm():
        output("---------------------------------------------------------------------------------------")
    elif get_pointer_size() == 8: #is_x64():
        output("-----------------------------------------------------------------------------------------------------------------------------")
    color("RESET")
    
    # XXX: do we really need to output all data into the array and then print it in a single go? faster to just print directly?
    # was it done this way because previously disassembly was capturing the output and modifying it?
    data = "".join(GlobalListOutput)
    result.PutCString(data)
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    return 0
