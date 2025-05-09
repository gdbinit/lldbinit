"""
 _ _   _ _   _     _ _
| | |_| | |_|_|___|_| |_
| | | . | . | |   | |  _|
|_|_|___|___|_|_|_|_|_|

lldbinit v3.2
A gdbinit clone for LLDB aka how to make LLDB a bit more useful and less crappy

Available at https://github.com/gdbinit/lldbinit
Original lldbinit code by Deroko @ https://github.com/deroko/lldbinit
gdbinit available @ https://github.com/gdbinit/Gdbinit

(c) Deroko 2014, 2015, 2016
(c) fG! 2017-2025 - reverser@put.as - https://reverse.put.as

No original license by Deroko.

All my modifications are under MIT license:

Copyright 2017-2025 Pedro Vilaca

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Huge thanks to Deroko for his original effort!

To list all implemented commands use 'lldbinitcmds' command.

How to install it:
------------------

$ cp lldbinit.py ~
$ echo "command script import  ~/lldbinit.py" >>$HOME/.lldbinit

or

just copy it somewhere and use "command script import path_to_script" when you want to load it.

Notes:
------
Version 3.0+ drops support for ARM32 and assumes ARM64 instead

KNOWN BUGS:
-----------

"""
# python 2.x doesn't have the end option so we need this
from __future__ import print_function

if __name__ == "__main__":
    print("Run only as script from LLDB... Not as standalone program!")

import lldb
import sys
import re
import os
import struct
import argparse
import subprocess
import tempfile
import termios
import fcntl
import json
import hashlib
import datetime

try:
    import keystone
    CONFIG_KEYSTONE_AVAILABLE = 1
except ImportError:
    CONFIG_KEYSTONE_AVAILABLE = 0
    pass

VERSION = "3.2"
BUILD = "441"

#
# User configurable options
#
CONFIG_ENABLE_COLOR = 1
# light or dark mode
CONFIG_APPEARANCE = "light"
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
# disassembly flavor 'intel' or 'att' - default is Intel unless AT&T syntax is your cup of tea
CONFIG_FLAVOR = "intel"

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
CUSTOM_DISASSEMBLY_FORMAT = '"{${function.initial-function}{${function.name-without-args}} @ {${module.file.basename}}:\n}{${function.changed}\n{${function.name-without-args}} @ {${module.file.basename}}:\n}{${current-pc-arrow} }${addr-file-or-load}: "'

# the colors definitions - don't mess with this
if CONFIG_ENABLE_COLOR:
    RESET =     "\033[0m"
    BOLD =      "\033[1m"
    UNDERLINE = "\033[4m"
    REVERSE =   "\033[7m"
    BLACK =     "\033[30m"
    RED =       "\033[31m"
    GREEN =     "\033[32m"
    YELLOW =    "\033[33m"
    BLUE =      "\033[34m"
    MAGENTA =   "\033[35m"
    CYAN =      "\033[36m"
    WHITE =     "\033[37m"
else:
    RESET =     ""
    BOLD =      ""
    UNDERLINE = ""
    REVERSE =   ""
    BLACK =     ""
    RED =       ""
    GREEN =     ""
    YELLOW =    ""
    BLUE =      ""
    MAGENTA =   ""
    CYAN =      ""
    WHITE =     ""

# default colors - modify as you wish
# since these are just strings modes can be combined
if CONFIG_APPEARANCE == "light":
    COLOR_REGVAL           = BLACK
    COLOR_REGNAME          = GREEN
    COLOR_CPUFLAGS         = BOLD + UNDERLINE + MAGENTA
    COLOR_SEPARATOR        = BOLD + BLUE
    COLOR_HIGHLIGHT_LINE   = RED
    COLOR_REGVAL_MODIFIED  = RED
    COLOR_SYMBOL_NAME      = BLUE
    COLOR_CURRENT_PC       = RED
    COLOR_CONDITIONAL_YES  = REVERSE + GREEN
    COLOR_CONDITIONAL_NO   = REVERSE + RED
    COLOR_HEXDUMP_HEADER   = BLUE
    COLOR_HEXDUMP_ADDR     = BLACK
    COLOR_HEXDUMP_DATA     = BLACK
    COLOR_HEXDUMP_ASCII    = BLACK
    COLOR_COMMENT          = GREEN
    COLOR_ERROR            = RED
elif CONFIG_APPEARANCE == "dark":
    COLOR_REGVAL           = WHITE
    COLOR_REGNAME          = GREEN
    COLOR_CPUFLAGS         = BOLD + UNDERLINE + MAGENTA
    COLOR_SEPARATOR        = CYAN
    COLOR_HIGHLIGHT_LINE   = RED
    COLOR_REGVAL_MODIFIED  = RED
    COLOR_SYMBOL_NAME      = BLUE
    COLOR_CURRENT_PC       = RED
    COLOR_CONDITIONAL_YES  = REVERSE + GREEN
    COLOR_CONDITIONAL_NO   = REVERSE + RED
    COLOR_HEXDUMP_HEADER   = BLUE
    COLOR_HEXDUMP_ADDR     = WHITE
    COLOR_HEXDUMP_DATA     = WHITE
    COLOR_HEXDUMP_ASCII    = WHITE
    COLOR_COMMENT          = GREEN # XXX: test and change
    COLOR_ERROR            = RED
else:
    print("[-] Invalid CONFIG_APPEARANCE value.")

# configure the separator character between the "windows" and their size
SEPARATOR = "-"
# minimum terminal width 120 chars
I386_TOP_SIZE = 81
I386_HEADER_SIZE = I386_TOP_SIZE - 11
I386_STACK_SIZE = I386_TOP_SIZE - 1
I386_BOTTOM_SIZE = 87
# minimum terminal width 125 chars
X64_TOP_SIZE = 119
X64_HEADER_SIZE = X64_TOP_SIZE - 11
X64_STACK_SIZE = X64_TOP_SIZE - 1
X64_BOTTOM_SIZE = 125
# minimum terminal width 108 chars
ARM_TOP_SIZE = 102
ARM_HEADER_SIZE = ARM_TOP_SIZE - 11
ARM_STACK_SIZE = ARM_TOP_SIZE - 1
ARM_BOTTOM_SIZE = 108

# turn on debugging output - you most probably don't need this
DEBUG = 0

#
# Don't mess after here unless you know what you are doing!
#

DATA_WINDOW_ADDRESS = 0
POINTER_SIZE = 8

old_x86 = {"eax":0,"ecx":0,"edx":0,"ebx":0,"esp":0,"ebp":0,"esi":0,"edi":0,"eip":0,
            "eflags":0,"cs":0,"ds":0,"fs":0,"gs":0,"ss":0,"es":0}

old_x64 = {"rax":0,"rcx":0,"rdx":0,"rbx":0,"rsp":0,"rbp":0,"rsi":0,"rdi":0,"rip":0,
            "r8":0,"r9":0,"r10":0,"r11":0,"r12":0,"r13":0,"r14":0,"r15":0,
            "rflags":0,"cs":0,"fs":0,"gs":0}

old_arm64 = {"x0":0,"x1":0,"x2":0,"x3":0,"x4":0,"x5":0,"x6":0,"x7":0,"x8":0,"x9":0,"x10":0,
              "x11":0,"x12":0,"x13":0,"x14":0,"x15":0,"x16":0,"x17":0,"x18":0,"x19":0,"x20":0,
              "x21":0,"x22":0,"x23":0,"x24":0,"x25":0,"x26":0,"x27":0,"x28":0,"fp":0,"lr":0,
              "sp":0,"pc":0,"cpsr":0}

int3patches = {}

crack_cmds = []
crack_cmds_noret = []
modules_list = []

g_current_target = ""
g_target_hash = ""
g_home = ""
g_sessionfile = ""
g_sessiondata = {}

# dyld modes
dyld_mode_dict = {
    0: "dyld_image_adding",
    1: "dyld_image_removing",
    2: "dyld_image_info_change",
    3: "dyld_image_dyld_moved"
}

MIN_COLUMNS = 125
MIN_ROWS = 25
LLDB_MAJOR = 0
LLDB_MINOR = 0
LLDB_VARIANT = None

# current sessions storage version
SESSION_VERSION = 2

def __lldb_init_module(debugger, internal_dict):
    """ we can execute lldb commands using debugger.HandleCommand() which makes all output to default
    lldb console. With SBDebugger.GetCommandinterpreter().HandleCommand() we can consume all output
    with SBCommandReturnObject and parse data before we send it to output (eg. modify it);

    in practice there is nothing here in initialization or anywhere else that we want to modify
    """

    # don't load if we are in Xcode since it is not compatible and will block Xcode
    if os.getenv("PATH").startswith("/Applications/Xcode"):
        return

    # test terminal - idea from https://github.com/ant4g0nist/lisa.py/
    try:
        tty_rows, tty_columns = struct.unpack("hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234"))
        # i386 is fine with 87x21
        # x64 is fine with 125x23
        # aarch64 is fine with 108x26
        if tty_columns < MIN_COLUMNS or tty_rows < MIN_ROWS:
            print("\033[1m\033[31m[!] current terminal size is {:d}x{:d}".format(tty_columns, tty_rows))
            print("[!] lldbinit is best experienced with a terminal size at least {}x{}\033[0m".format(MIN_COLUMNS, MIN_ROWS))
    except Exception as e:
        print("\033[1m\033[31m[-] failed to find out terminal size.")
        print("[!] lldbinit is best experienced with a terminal size at least {}x{}\033[0m".format(MIN_COLUMNS, MIN_ROWS))

    global g_home, LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR

    if g_home == "":
        g_home = os.getenv("HOME")

    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    # settings
    ci.HandleCommand("settings set target.x86-disassembly-flavor " + CONFIG_FLAVOR, res)
    ci.HandleCommand('settings set prompt "(lldbinit) "', res)
    ci.HandleCommand("settings set stop-disassembly-count 0", res)
    # set the log level - must be done on startup?
    ci.HandleCommand("settings set target.process.extra-startup-command QSetLogging:bitmask=" + CONFIG_LOG_LEVEL + ";", res)
    if CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT == 1:
        ci.HandleCommand("settings set disassembly-format " + CUSTOM_DISASSEMBLY_FORMAT, res)

    # the hook that makes everything possible :-)
    ci.HandleCommand("command script add -h '(lldbinit)' -f lldbinit.HandleProcessLaunchHook HandleProcessLaunchHook", res)
    ci.HandleCommand("command script add -h '(lldbinit) The main lldbinit hook.' -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget", res)
    ci.HandleCommand("command script add -h '(lldbinit) Display the current disassembly/CPU context.' -f lldbinit.HandleHookStopOnTarget context", res)
    ci.HandleCommand("command alias -h '(lldbinit) Alias to context command.' -- ctx HandleHookStopOnTarget", res)
    # commands
    ci.HandleCommand("command script add -h '(lldbinit) Print list of available commands.' -f lldbinit.cmd_lldbinitcmds lldbinitcmds", res)
    # thread commands
    ci.HandleCommand("command script add -h '(lldbinit) List threads.' -f lldbinit.cmd_listthreads tl", res)
    ci.HandleCommand("command script add -h '(lldbinit) Suspend a thread.' -f lldbinit.cmd_suspendthread ts", res)
    #
    # comments commands
    #
    ci.HandleCommand("command script add -h '(lldbinit) Add disassembly comment.' -f lldbinit.cmd_addcomment acm", res)
    ci.HandleCommand("command script add -h '(lldbinit) Remove disassembly comment.' -f lldbinit.cmd_delcomment dcm", res)
    ci.HandleCommand("command script add -h '(lldbinit) List disassembly comments.' -f lldbinit.cmd_listcomments lcm", res)
    # fuck the nazis :-)
    # save session, restore session, list session commands
    ci.HandleCommand("command script add -h '(lldbinit) Save breakpoint session.' -f lldbinit.cmd_save_session ss", res)
    ci.HandleCommand("command script add -h '(lldbinit) Restore breakpoint session.' -f lldbinit.cmd_restore_session rs", res)
    ci.HandleCommand("command script add -h '(lldbinit) List breakpoint sessions.' -f lldbinit.cmd_list_sessions ls", res)
    #
    # dump memory commands
    #
    ci.HandleCommand("command script add -h '(lldbinit) Memory hex dump in byte format.' -f lldbinit.cmd_db db", res)
    ci.HandleCommand("command script add -h '(lldbinit) Memory hex dump in word format.' -f lldbinit.cmd_dw dw", res)
    ci.HandleCommand("command script add -h '(lldbinit) Memory hex dump in double word format.' -f lldbinit.cmd_dd dd", res)
    ci.HandleCommand("command script add -h '(lldbinit) Memory hex dump in quad word format.' -f lldbinit.cmd_dq dq", res)
    # XXX: fix help
    ci.HandleCommand("command script add -h '(lldbinit) Disassemble instructions at address.' -f lldbinit.cmd_DumpInstructions u", res)
    ci.HandleCommand("command script add -h '(lldbinit) Memory search.' -f lldbinit.cmd_findmem findmem", res)
    ci.HandleCommand("command script add -h '(lldbinit) Display process memory regions.' -f lldbinit.cmd_showregions showregions", res)
    #
    # Settings related commands
    #
    ci.HandleCommand("command script add -h '(lldbinit) Configure lldb and lldbinit options.' -f lldbinit.cmd_enable enable", res)
    ci.HandleCommand("command script add -h '(lldbinit) Configure lldb and lldbinit options.' -f lldbinit.cmd_disable disable", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set number of instruction lines in code window.' -f lldbinit.cmd_contextcodesize contextcodesize", res)
    # a few settings aliases
    ci.HandleCommand("command alias -h '(lldbinit) Enable the stop on library load events.' -- enablesolib enable solib", res)
    ci.HandleCommand("command alias -h '(lldbinit) Disable the stop on library load events.' -- disablesolib disable solib", res)
    ci.HandleCommand("command alias -h '(lldbinit) Enable target ASLR.' -- enableaslr enable aslr", res)
    ci.HandleCommand("command alias -h '(lldbinit) Disable target ASLR.' -- disableaslr disable aslr", res)
    #
    # Breakpoint related commands
    #
    # replace the default alias with our own version
    ci.HandleCommand("command unalias b", res)
    # software breakpoints
    ci.HandleCommand("command script add -h '(lldbinit) Set a software breakpoint.' -f lldbinit.cmd_bp b", res)
    # alias "bp" command that exists in gdbinit
    ci.HandleCommand("command alias -h '(lldbinit) Alias to b.' -- bp b", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set a temporary software breakpoint.' -f lldbinit.cmd_bpt bpt", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set a temporary breakpoint on next instruction.' -f lldbinit.cmd_bpn bpn", res)
    # hardware breakpoints
    ci.HandleCommand("command script add -h '(lldbinit) Set an hardware breakpoint.' -f lldbinit.cmd_bh bh", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set a temporary hardware breakpoint.' -f lldbinit.cmd_bht bht", res)
    # module breakpoints
    ci.HandleCommand("command script add -h '(lldbinit) Breakpoint on module load.' -f lldbinit.cmd_bm bm", res)
    ci.HandleCommand("command script add -h '(lldbinit) Clear all module load breakpoints.' -f lldbinit.cmd_bmc bmc", res)
    ci.HandleCommand("command script add -h '(lldbinit) List all on module load breakpoints.' -f lldbinit.cmd_bml bml", res)
    ci.HandleCommand("command script add -h '(lldbinit) Enable anti-anti-debugging measures.' -f lldbinit.cmd_antidebug antidebug", res)
    ci.HandleCommand("command script add -h '(lldbinit) Print all images available at gdb_image_notifier() breakpoint.' -f lldbinit.cmd_print_notifier_images print_images", res)
    # disable a breakpoint or all
    ci.HandleCommand("command script add -h '(lldbinit) Disable a breakpoint.' -f lldbinit.cmd_bpd bpd", res)
    ci.HandleCommand("command script add -h '(lldbinit) Disable all breakpoints.' -f lldbinit.cmd_bpda bpda", res)
    # clear a breakpoint or all
    ci.HandleCommand("command script add -h '(lldbinit) Clear a breakpoint.' -f lldbinit.cmd_bpc bpc", res)
    ci.HandleCommand("command alias -h '(lldbinit) Clear all breakpoints' -- bpca breakpoint delete", res)
    # enable a breakpoint or all
    ci.HandleCommand("command script add -h '(lldbinit) Enable a breakpoint.' -f lldbinit.cmd_bpe bpe", res)
    ci.HandleCommand("command script add -h '(lldbinit) Enable all breakpoints.' -f lldbinit.cmd_bpea bpea", res)
    # commands to set temporary int3 patches and restore original bytes
    ci.HandleCommand("command script add -h '(lldbinit) Patch memory address with INT3.' -f lldbinit.cmd_int3 int3", res)
    ci.HandleCommand("command script add -h '(lldbinit) Restore original byte at address patched with INT3.' -f lldbinit.cmd_rint3 rint3", res)
    ci.HandleCommand("command script add -h '(lldbinit) List all INT3 patched addresses.' -f lldbinit.cmd_listint3 listint3", res)
    ci.HandleCommand("command script add -h '(lldbinit) Patch memory address with NOP.' -f lldbinit.cmd_nop nop", res)
    ci.HandleCommand("command script add -h '(lldbinit) Patch memory address with NULL.' -f lldbinit.cmd_null null", res)
    # change eflags commands
    ci.HandleCommand("command script add -h '(lldbinit) Change adjust CPU flag.' -f lldbinit.cmd_cfa cfa", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change carry CPU flag.' -f lldbinit.cmd_cfc cfc", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change direction CPU flag.' -f lldbinit.cmd_cfd cfd", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change interrupt CPU flag.' -f lldbinit.cmd_cfi cfi", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change overflow CPU flag.' -f lldbinit.cmd_cfo cfo", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change parity CPU flag.' -f lldbinit.cmd_cfp cfp", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change sign CPU flag.' -f lldbinit.cmd_cfs cfs", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change trap CPU flag.' -f lldbinit.cmd_cft cft", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change zero CPU flag.' -f lldbinit.cmd_cfz cfz", res)
    # change NZCV flags - exclusive commands to AArch64 (Z, C are common)
    ci.HandleCommand("command script add -h '(lldbinit) Change negative CPU flag.' -f lldbinit.cmd_cfn cfn", res)
    ci.HandleCommand("command script add -h '(lldbinit) Change overflow CPU flag.' -f lldbinit.cmd_cfv cfv", res)
    # skip/step current instruction commands
    ci.HandleCommand("command script add -h '(lldbinit) Skip current instruction.' -f lldbinit.cmd_skip skip", res)
    ci.HandleCommand("command script add -h '(lldbinit) Step over calls and loop instructions.' -f lldbinit.cmd_stepo stepo", res)
    ci.HandleCommand("command script add -h '(lldbinit) Step over calls and loop instructions, using hardware breakpoints.' -f lldbinit.cmd_stepoh stepoh", res)
    # cracking friends
    ci.HandleCommand("command script add -h '(lldbinit) Return from current function.' -f lldbinit.cmd_crack crack", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set a breakpoint and return from that function.' -f lldbinit.cmd_crackcmd crackcmd", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set a breakpoint and set a register value. does not return from function.' -f lldbinit.cmd_crackcmd_noret crackcmd_noret", res)
    # alias for existing breakpoint commands
    # list all breakpoints
    ci.HandleCommand("command script add -h '(lldbinit) List breakpoints.' -f lldbinit.cmd_bpl bpl", res)
    # to set breakpoint commands - I hate typing too much
    ci.HandleCommand("command alias -h '(lldbinit) breakpoint command add alias.' -- bcmd breakpoint command add", res)
    # launch process and stop at entrypoint (not exactly as gdb command that just inserts breakpoint)
    # replace the default run alias with our version
    ci.HandleCommand("command unalias r", res)
    ci.HandleCommand("command unalias run", res)
    ci.HandleCommand("command script add -h '(lldbinit) Start the target and stop at entrypoint.' -f lldbinit.cmd_run r", res)
    ci.HandleCommand("command alias -h '(lldbinit) Start the target and stop at entrypoint.' -- run r", res)

    # usually it will be inside dyld and not the target main()
    ci.HandleCommand("command alias -h '(lldbinit) Start target and stop at entrypoint.' -- break_entrypoint process launch --stop-at-entry", res)
    ci.HandleCommand("command script add -h '(lldbinit) Show otool output of Mach-O load commands.' -f lldbinit.cmd_show_loadcmds show_loadcmds", res)
    ci.HandleCommand("command script add -h '(lldbinit) Show otool output of Mach-O header.' -f lldbinit.cmd_show_header show_header", res)
    ci.HandleCommand("command script add -h '(lldbinit) Test function - do not use :-).' -f lldbinit.cmd_tester tester", res)
    ci.HandleCommand("command script add -h '(lldbinit) Set start address to display on data window.' -f lldbinit.cmd_datawin datawin", res)
    # used mostly for aliases below but can be called as other commands
    ci.HandleCommand("command script add -h '(lldbinit) Update register function to be used by all the register alias.' -f lldbinit.cmd_update_register update_register", res)
    # shortcut command to modify registers content
    if CONFIG_ENABLE_REGISTER_SHORTCUTS == 1:
        # x64
        ci.HandleCommand("command alias -h '(lldbinit) Update RIP register.' -- rip update_register rip", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RAX register.' -- rax update_register rax", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RBX register.' -- rbx update_register rbx", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RBP register.' -- rbp update_register rbp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RSP register.' -- rsp update_register rsp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RDI register.' -- rdi update_register rdi", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RSI register.' -- rsi update_register rsi", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RDX register.' -- rdx update_register rdx", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update RCX register.' -- rcx update_register rcx", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R8 register.' -- r8 update_register r8", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R9 register.' -- r9 update_register r9", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R10 register.' -- r10 update_register r10", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R11 register.' -- r11 update_register r11", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R12 register.' -- r12 update_register r12", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R13 register.' -- r13 update_register r13", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R14 register.' -- r14 update_register r14", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update R15 register.' -- r15 update_register r15", res)
        # x86
        ci.HandleCommand("command alias -h '(lldbinit) Update EIP register.' -- eip update_register eip", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update EAX register.' -- eax update_register eax", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update EBX register.' -- ebx update_register ebx", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update EBP register.' -- ebp update_register ebp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update ESP register.' -- esp update_register esp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update EDI register.' -- edi update_register edi", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update ESI register.' -- esi update_register esi", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update EDX register.' -- edx update_register edx", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update ECX register.' -- ecx update_register ecx", res)
        # ARM64
        ci.HandleCommand("command alias -h '(lldbinit) Update X0 register.' -- x0 update_register x0", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X1 register.' -- x1 update_register x1", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X2 register.' -- x2 update_register x2", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X3 register.' -- x3 update_register x3", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X4 register.' -- x4 update_register x4", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X5 register.' -- x5 update_register x5", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X6 register.' -- x6 update_register x6", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X7 register.' -- x7 update_register x7", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X8 register.' -- x8 update_register x8", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X9 register.' -- x9 update_register x9", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X10 register.' -- x10 update_register x10", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X11 register.' -- x11 update_register x11", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X12 register.' -- x12 update_register x12", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X13 register.' -- x13 update_register x13", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X14 register.' -- x14 update_register x14", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X15 register.' -- x15 update_register x15", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X16 register.' -- x16 update_register x16", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X17 register.' -- x17 update_register x17", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X18 register.' -- x18 update_register x18", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X19 register.' -- x19 update_register x19", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X20 register.' -- x20 update_register x20", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X21 register.' -- x21 update_register x21", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X22 register.' -- x22 update_register x22", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X23 register.' -- x23 update_register x23", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X24 register.' -- x24 update_register x24", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X25 register.' -- x25 update_register x25", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X26 register.' -- x26 update_register x26", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X27 register.' -- x27 update_register x27", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update X28 register.' -- x28 update_register x28", res)
        # register write recognizes x29 and x30 but they don't exist in SBFrame
        ci.HandleCommand("command alias -h '(lldbinit) Update FP register.' -- fp update_register fp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update LR register.' -- lr update_register lr", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update SP register.' -- sp update_register sp", res)
        ci.HandleCommand("command alias -h '(lldbinit) Update PC register.' -- pc update_register pc", res)
    if CONFIG_KEYSTONE_AVAILABLE == 1:
        ci.HandleCommand("command script add -h '(lldbinit) 32 bit x86 interactive Keystone based assembler.' -f lldbinit.cmd_asm32 asm32", res)
        ci.HandleCommand("command script add -h '(lldbinit) 64 bit x86 interactive Keystone based assembler.' -f lldbinit.cmd_asm64 asm64", res)
        ci.HandleCommand("command script add -h '(lldbinit) 32 bit ARM interactive Keystone based assembler.' -f lldbinit.cmd_arm32 arm32", res)
        ci.HandleCommand("command script add -h '(lldbinit) 64 bit ARM interactive Keystone based assembler.' -f lldbinit.cmd_arm64 arm64", res)
        ci.HandleCommand("command script add -h '(lldbinit) 32 bit ARM Thumb interactive Keystone based assembler.' -f lldbinit.cmd_armthumb armthumb", res)
    # add the hook - we don't need to wait for a target to be loaded
    # Note: since I removed the original stop-disassembly-count trick to allegedly avoid
    # double loading it had a side effect to keep adding multiple copies of the hook
    # when doing multiple imports of the script (for testing mostly)
    # a check is now implemented where the hook is only added if no previous hook exist
    ci.HandleCommand("target stop-hook list", res)
    if res.Succeeded():
        # XXX: older lldb crashes if we set the -s option...
        # if "HandleProcessLaunchHook" not in res.GetOutput():
        #     ci.HandleCommand("target stop-hook add -n _dyld_start -s /usr/lib/dyld -o 'HandleProcessLaunchHook'", res)
        if "HandleHookStopOnTarget" not in res.GetOutput():
            ci.HandleCommand("target stop-hook add -o 'HandleHookStopOnTarget'", res)
    else:
        err_msg("Failed to list stop hooks and our hook isn't loaded.")

    ci.HandleCommand("command script add -h '(lldbinit) Display lldbinit banner.' --function lldbinit.cmd_banner banner", res)
    ci.HandleCommand("command script add -h '(lldbinit) Display command man page.' -f lldbinit.cmd_man man", res)
    # custom commands
    ci.HandleCommand("command script add -h '(lldbinit) Fix return breakpoint.' -f lldbinit.cmd_fixret fixret", res)
    # displays the version banner when lldb is loaded
    LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR = get_lldb_version(debugger)
    debugger.HandleCommand("banner")
    return

def get_lldb_version(debugger):
    version_string = debugger.GetVersionString()
    # print("[+] lldb version: " + version_string)
    apple_pattern = r"lldb-(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    clang_pattern = r"lldb version (\d+)(?:\.(\d+))?(?:\.(\d+))?"
    # match apple lldb pattern (e.g: lldb-1500.0.404.7)
    apple_match = re.search(apple_pattern, version_string, re.IGNORECASE)
    if apple_match:
        variant = "apple"
        major = int(apple_match.group(1))
        minor = int(apple_match.group(2) or 0)
        return variant, major, minor
    # match clang lldb pattern (e.g: lldb version 18.1.8)
    clang_match = re.search(clang_pattern, version_string, re.IGNORECASE)
    if clang_match:
        variant = "clang"
        major = int(clang_match.group(1))
        minor = int(clang_match.group(2) or 0)
        return variant, major, minor
    # If no match is found, raise an exception
    raise ValueError("Unable to determine LLDB variant and version from string: " + version_string)

# helper function to print standardized and colored error messages
def err_msg(msg):
    print(COLOR_ERROR + "[-] ERROR: " + RESET + "{}".format(msg))

# XXX: kinda hacky and ugly since not adapting to terminal width etc
def help_msg(help):
    print(BOLD + "NAME")
    print(BOLD + "\t{}".format(help["cmd"]) + RESET + " -- {}".format(help["short"]) + "\n")
    print(BOLD + "SYNOPSIS")
    print(BOLD + "\t{}".format(help["cmd"]) + RESET + " " + "{}".format(help["args"]) + "\n")
    print(BOLD + "DESCRIPTION" + RESET)
    print("\t{}".format(help["desc"].replace("\n", "\n\t")))
    print("")
    if "options" in help:
        print(BOLD + "OPTIONS" + RESET)
        for opt in help["options"]:
            print(BOLD + "\t{}".format(opt["name"]) + RESET + "\n\t\t{}".format(opt["desc"]))
            if "values" in opt:
                print("")
                for v in opt["values"]:
                    print("\t\t{}\t{}".format(v["n"], v["d"]))
        print("")

    if "example" in help:
        print(BOLD + "EXAMPLES" + RESET)
        print("\t{}".format(help["example"]))
        print("")

    if "notes" in help and len(help["notes"]) > 0:
        print(BOLD + "NOTES" + RESET)
        for note in help["notes"]:
            print("\t{}".format(note))
        print("")

# just a silly shortcut - requires the command to have the help option
def cmd_man(debugger, command, result, dict):
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The man command requires an argument.")
        return

    res = lldb.SBCommandReturnObject()
    # just call the target command with the help option
    debugger.GetCommandInterpreter().HandleCommand(command + " " + "help", res)
    if res.GetErrorSize() > 0:
        err_msg("Requested man page for unknown command '{}'.".format(command))

def cmd_banner(debugger, command, result, dict):
    global LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR
    print("{}[+] Loaded lldbinit version {}.{} @ lldb-{}.{} ({} version){}".format(GREEN, VERSION, BUILD, LLDB_MAJOR, LLDB_MINOR, LLDB_VARIANT, RESET))

def cmd_lldbinitcmds(debugger, command, result, dict):
    """Display all available lldbinit commands."""

    help_table = [
        ["", ""],
        ["lldbinitcmds", "this command"],
        ["", ""],
        ["----[ Settings ]----", ""],
        ["enable", "configure lldb and lldbinit options"],
        ["disable", "configure lldb and lldbinit options"],
        ["contextcodesize", "set number of instruction lines in code window"],
        ["enablesolib/disablesolib", "enable/disable the stop on library load events"],
        ["enableaslr/disableaslr", "enable/disable process ASLR"],
        ["datawin", "set start address to display on data window"],
        ["", ""],
        ["----[ Sessions ]----", ""],
        ["ls", "display available sessions"],
        ["ss", "save current session"],
        ["rs", "restore session"],
        ["", ""],
        ["----[ Breakpoints ]----", ""],
        ["b", "breakpoint address"],
        ["bpt", "set a temporary software breakpoint"],
        ["bh", "set an hardware breakpoint"],
        ["bht", "set a temporary hardware breakpoint"],
        ["bpc", "clear breakpoint"],
        ["bpca", "clear all breakpoints"],
        ["bpd", "disable breakpoint"],
        ["bpda", "disable all breakpoints"],
        ["bpe", "enable a breakpoint"],
        ["bpea", "enable all breakpoints"],
        ["bcmd", "alias to breakpoint command add"],
        ["bpl", "list all breakpoints"],
        ["bpn", "temporarly breakpoint next instruction"],
        ["bm", "breakpoint on module load"],
        ["bmc", "clear all module load breakpoints"],
        ["bml", "list all on module load breakpoints"],
        ["break_entrypoint", "launch target and stop at entrypoint"],
        ["skip", "skip current instruction"],
        ["int3", "patch memory address with INT3"],
        ["rint3", "restore original byte at address patched with INT3"],
        ["listint3", "list all INT3 patched addresses"],
        ["lb", "load breakpoints from file and apply them (currently only func names are applied)"],
        ["lbrva", "load breakpoints from file and apply to main executable, only RVA in this case"],
        ["print_images", "print all images available at gdb_image_notifier() breakpoint"],
        ["", ""],
        ["----[ Memory ]----", ""],
        ["nop", "patch memory address with NOP"],
        ["null", "patch memory address with NULL"],
        ["db/dw/dd/dq", "memory hex dump in different formats"],
        ["findmem", "search memory"],
        ["showregions", "display process memory regions"],
        ["", ""],
        ["----[ Disassembly ]----", ""],
        ["u", "dump instructions"],
        ["ctx/context", "show current instruction pointer CPU context"],
        ["stepo", "step over calls and loop instructions"],
        ["acm", "add disassembly comment"],
        ["dcm", "remove disassembly comment"],
        ["lcm", "list disassembly comments"],
        ["", ""],
        ["----[ Registers and CPU Flags ]----", ""],
        ["rip/rax/rbx/etc", "shortcuts to modify x64 registers"],
        ["eip/eax/ebx/etc", "shortcuts to modify x86 registers"],
        ["x{0..28}", "shortcuts to modify ARM64 registers"],
        ["cfa/cfc/cfd/cfi/cfo/cfp/cfs/cft/cfz", "change x86/x64 CPU flags"],
        ["cfn/cfz/cfc/cfv", "change AArch64 CPU flags (NZCV register)"],
        ["", ""],
        ["----[ File headers ]----", ""],
        ["show_loadcmds", "show otool output of Mach-O load commands"],
        ["show_header", "show otool output of Mach-O header"],
        ["", ""],
        ["----[ Cracking ]----", ""],
        ["crack", "return from current function"],
        ["crackcmd", "set a breakpoint and return from that function"],
        ["crackcmd_noret", "set a breakpoint and set a register value. doesn't return from function"],
        ["", ""],
        ["----[ Misc ]----", ""],
        ["", ""],
        ["----[ Assembler ]----", ""],
        ["asm32/asm64", "x86/x64 assembler using keystone"],
        ["arm32/arm64/armthumb", "ARM assembler using keystone"],
    ]

    print(" ---------------------------")
    print(" lldbinit available commands")
    print(" ---------------------------")

    for row in help_table:
        if not row[1]:
            print(" {: <20} {: <30}".format(*row))
        else:
            print(" {: <20} - {: <30}".format(*row))

    print("\nUse 'cmdname help' for extended command help.")

# placeholder to make tests
def cmd_tester(debugger, command, result, dict):
    print("test")
    help = {
    "cmd": "tester",
    "short": "test command",
    "desc": """Testing the help command.\nThis is a multiline test.""",
    "args": "<settings> [<size>]",
    "options": [
        {
            "name": "settings",
            "desc": "The available settings are:",
            "values": [
                {
                    "n": "solib",
                    "d": "Enable stop on library events trick."
                },
                {
                    "n": "aslr",
                    "d": "Enable process ASLR."
                }
            ],
        },
        {   
            "name": "size",
            "desc": "The number of bytes to patch. Default is 1."
        }
    ],
    "example": "tester",
    "notes": [
        "This is note1.",
        "This is note2."
        ]
    }
    help_msg(help)
    return

# -------------------------
# Settings related commands
# -------------------------

def cmd_enable(debugger, command, result, dict):
    """Enable certain lldb and lldbinit options. Use \'enable help\' for more information."""
    help = {
        "cmd": "enable",
        "short": "enable configuration options",
        "desc": "Enable certain lldb and lldbinit configuration options.",
        "args": "<setting>",
        "options": [
            {
                "name": "settings",
                "desc": "The available settings are:",
                "values": [
                    {"n": "solib", "d": "Enable stop on library events trick."},
                    {"n": "aslr", "d": "Enable process ASLR."},
                    {"n": "stack", "d": "Enable stack window in context display."},
                    {"n": "data", "d": "Enable data window in context display, configure address with datawin."},
                    {"n": "flow", "d": "Enable call targets and objective-c class/methods window in context display."},
                ],
            },
        ],
    }
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The command requires an argument.")
        help_msg(help)
        return

    if cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events true")
        print("[+] Enabled stop on library events trick.")
    elif cmd[0] == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr false")
        print("[+] Enabled ASLR.")
    elif cmd[0] == "stack":
        CONFIG_DISPLAY_STACK_WINDOW = 1
        print("[+] Enabled stack window in context display.")
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 1
        print("[+] Enabled indirect control flow window in context display.")
    elif cmd[0] == "data":
        CONFIG_DISPLAY_DATA_WINDOW = 1
        print("[+] Enabled data window in context display. Configure address with 'datawin' cmd.")
    elif cmd[0] == "help":
        help_msg(help)
    else:
        err_msg("Unrecognized command.")
        help_msg(help)

    return

def cmd_disable(debugger, command, result, dict):
    """Disable certain lldb and lldbinit options. Use \'disable help\' for more information."""
    help = {
        "cmd": "disable",
        "short": "disable configuration options",
        "desc": "Disable certain lldb and lldbinit configuration options.",
        "args": "<setting>",
        "options": [
            {
                "name": "settings",
                "desc": "The available settings are:",
                "values": [
                    {"n": "solib", "d": "Disable stop on library events trick."},
                    {"n": "aslr", "d": "Disable process ASLR."},
                    {"n": "stack", "d": "Disable stack window in context display."},
                    {"n": "data", "d": "Disable data window in context display, configure address with datawin."},
                    {"n": "flow", "d": "Disable call targets and objective-c class/methods window in context display."},
                ],
            },
        ],
    }
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The command requires an argument.")
        help_msg(help)
        return

    if cmd[0] == "solib":
        debugger.HandleCommand("settings set target.process.stop-on-sharedlibrary-events false")
        print("[+] Disabled stop on library events trick.")
    elif cmd[0] == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr true")
        print("[+] Disabled ASLR.")
    elif cmd[0] == "stack":
        CONFIG_DISPLAY_STACK_WINDOW = 0
        print("[+] Disabled stack window in context display.")
    elif cmd[0] == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 0
        print("[+] Disabled indirect control flow window in context display.")
    elif cmd[0] == "data":
        CONFIG_DISPLAY_DATA_WINDOW = 0
        print("[+] Disabled data window in context display.")
    elif cmd[0] == "help":
        help_msg(help)
    else:
        err_msg("Unrecognized command.")
        help_msg(help)
    return

def cmd_contextcodesize(debugger, command, result, dict):
    """Set the number of disassembly lines in code window. Use \'contextcodesize help\' for more information."""
    help = {
        "cmd": "contextcodesize",
        "short": "set disassembly lines",
        "desc": "Configures the number of disassembly lines displayed in code window.",
        "args": "<line count>",
        "options": [{"name": "line count", "desc": "Number of disassembly lines to display. Default is 8."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    global CONFIG_DISASSEMBLY_LINE_COUNT
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert the number of disassembly lines to display.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        print("Current configuration value is: {:d}".format(CONFIG_DISASSEMBLY_LINE_COUNT))
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    CONFIG_DISASSEMBLY_LINE_COUNT = value

    return

# ---------------------------------
# Color and output related commands
# ---------------------------------

# this was used to append data to a global string and then output at the end of hook-stop
# replace it with direct print since I don't see any more usage to it
def output(x):
    print(x, end='')

# ---------------------------------
# Threads related commands
# ---------------------------------
def cmd_listthreads(debugger, command, result, dict):
    """List current threads. Use \'tl help\' for more information."""
    help = {
        "cmd": "tl",
        "short": "list threads",
        "desc": "List current running threads.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    proc = get_target().GetProcess()

    if proc.num_threads == 0:
        err_msg("No threads available. Is the target started?")
        return
    print("Available threads")
    for thread in proc:
        ID = thread.GetThreadID()
        index = thread.GetIndexID()
        print("ID: {} Number: {}".format(ID, index))

def cmd_suspendthread(debugger, command, result, dict):
    """Suspend a thread. Use \'ts help\' for more information."""
    help = {
        "cmd": "ts",
        "short": "suspend thread",
        "desc": "Suspend a thread.",
        "args": "<thread number>",
        "options": [{"name": "thread number", "desc": "The thread number to suspend. List available threads with 'thread list' or 'tl' command."}],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a thread index.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value - only a thread index is valid.")
        help_msg(help)
        return

    proc = get_target().GetProcess()
    thread = proc.GetThreadByIndexID(value)
    result = thread.Suspend()
    if result is False:
        err_msg("Failed to suspend thread.")
    return

# ---------------------------
# Breakpoint related commands
# ---------------------------

ANTIDEBUG_SYSCTL_OBJS = []

# the second step breakpoint callback of the sysctl antidebug bypass
# we are at the return address of sysctl symbol
# and we simply remove the P_TRACED flag if it exists
def antidebug_callback_step2(frame, bp_loc, dict):
    P_TRACED = 0x800
    global ANTIDEBUG_SYSCTL_OBJS
    # print("[+] Hit antidebug_callback_step2")
    for i in ANTIDEBUG_SYSCTL_OBJS:
        ANTIDEBUG_SYSCTL_OBJS.remove(i)
        # offset to kp_proc.p_flag - this should be stable
        offset = 0x20
        target = get_target()
        error = lldb.SBError()
        # read the current value so we can modify and write again
        value = get_process().ReadUnsignedFromMemory(i + offset, 4, error)
        # remove P_TRACED flag if it exists
        if value & P_TRACED:
            print("[+] Hit sysctl antidebug request")
            value = value ^ P_TRACED
            # WriteMemory accepts a string so we need to pack this
            patch = struct.pack("I", value)
            result = target.GetProcess().WriteMemory(i + offset, patch, error)
            if not error.Success():
                err_msg("Failed to write memory at 0x{:x}.".format(i + offset))
                return
        get_process().Continue()

# the first step breakpoint callback of the sysctl antidebug bypass
# this deals with the breakpoint at sysctl symbol
# the purpose is to verify the request and set a second stage on return address
# where the debug flag is removed
def antidebug_callback_step1(frame, bp_loc, dict):
    global ANTIDEBUG_SYSCTL_OBJS
    error = lldb.SBError()

    if frame is None:
        return 0

    target = get_target()
    if is_x64():
        src_reg = "rdi"
        dst_reg = "rdx"
    elif is_arm():
        src_reg = "x0"
        dst_reg = "x2"
    else:
        err_msg("Unsupported architecture.")
        return 0

    mib_addr = int(frame.FindRegister(src_reg).GetValue(), 16)

    mib0 = get_process().ReadUnsignedFromMemory(mib_addr, 4, error)
    if not error.Success():
        err_msg("Failed to read mib0.")
        return
    mib1 = get_process().ReadUnsignedFromMemory(mib_addr + 4, 4, error)
    if not error.Success():
        err_msg("Failed to read mib1.")
        return
    mib2 = get_process().ReadUnsignedFromMemory(mib_addr + 8, 4, error)
    if not error.Success():
        err_msg("Failed to read mib2.")
        return
    # check if it's a potential AmIBeingDebugged request
    # it's a common request from some apps
    # so we need to verify on the return and remove the flag
    # CTL_KERN (1) - KERN_PROC (14) - KERN_PROC_PID (1)
    if mib0 == 1 and mib1 == 14 and mib2 == 1:
        # print("[+] Hit sysctl antidebug request")
        # the pointer to the sysctl output oldp
        oldp = int(frame.FindRegister(dst_reg).GetValue(), 16)
        if oldp == 0:
            print("[!] Warning: oldp == 0")
            get_process().Continue()
        ANTIDEBUG_SYSCTL_OBJS.append(oldp)
        # set a temporary breakpoint on the ret
        # temporary because we can't sync this with other sysctl calls
        # and we don't want to tamper with the rest of the results - just with the P_TRACED flag
        mem_sbaddr = lldb.SBAddress(int(frame.FindRegister("pc").GetValue(), 16), target)
        # flavor only relevant for x86, ignored when aarch64
        inst = target.ReadInstructions(mem_sbaddr, 64)
        for i in inst:
            # print(hex(i.GetAddress().GetLoadAddress(target)), i.GetMnemonic(target))
            # the properties seem broken in newer lldb versions because this will fail
            # if we use i.mnemonic - the SBTarget will be NULL
            # what's going on with lldb regressions?
            # x64 - ret ; aarch64 - retab
            if i.GetMnemonic(target).startswith("ret"):
                # print(hex(i.addr.GetLoadAddress(target)), i.GetMnemonic(target))
                nextbp = target.BreakpointCreateByAddress(i.GetAddress().GetLoadAddress(target))
                nextbp.SetOneShot(True)
                nextbp.SetThreadID(get_frame().GetThread().GetThreadID())
                # this will generate a traceback on newer lldb versions
                # it seems we can't set another callback while inside a callback
                # lldb regressions ftw...
                nextbp.SetScriptCallbackFunction("lldbinit.antidebug_callback_step2")
    # everything automatic here so continue in any case
    get_process().Continue()

# bypass PT_DENY_ATTACH via ptrace() call
def antidebug_ptrace_callback(frame, bp_loc, dict):
    PT_DENY_ATTACH = 31
    error = lldb.SBError()
    if is_x64():
        src_reg = "rdi"
    elif is_arm():
        src_reg = "x0"
    request = int(frame.FindRegister(src_reg).GetValue(), 16)
    if request == PT_DENY_ATTACH:
        print("[+] Hit ptrace anti-debug request")
        if is_x64():
            src_reg = "rax"
        elif is_arm():
            src_reg = "x0"
        # we are essentially bypassing the whole call to return a value of 0
        result = frame.registers[0].GetChildMemberWithName(src_reg).SetValueFromCString("0x0", error)
        if not result:
            err_msg("Failed to write to {} register.".format(src_reg))
            return 0
        # and return immediately to the caller without executing any ptrace() code
        get_thread().ReturnFromFrame(frame, frame.registers[0].GetChildMemberWithName(src_reg))
    get_process().Continue()

# debugger detection via the mach exception ports
def antidebug_task_exception_ports_callback(frame, bp_loc, dict):
    if frame is None:
        return 0
    if is_x64():
        src_reg = "rsi"
    elif is_arm():
        src_reg = "x1"
    exception_mask = int(frame.FindRegister(src_reg).GetValue(), 16)
    if exception_mask != 0x0:
        print("[+] Hit {} antidebug request".format(get_frame().symbol.name))
        error = lldb.SBError()
        result = frame.registers[0].GetChildMemberWithName(src_reg).SetValueFromCString("0x0", error)
        if not result:
            err_msg("Failed to write to {} register.".format(src_reg))
            return 0
    get_process().Continue()

def cmd_antidebug(debugger, command, result, dict):
    """Enable anti-anti-debugging. Use \'antidebug help\' for more information."""
    help = {
        "cmd": "antidebug",
        "short": "enable anti-anti-debugging",
        "desc": "Enable anti-anti-debugging measures.\nBypasses debugger detection via sysctl, ptrace PT_DENY_ATTACH, and task exception ports.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    target = get_target()
    for m in target.module_iter():
        if m.file.fullpath == "/usr/lib/dyld":
            # sysctl
            bp = target.BreakpointCreateByName("sysctl", "/usr/lib/system/libsystem_c.dylib")
            bp.SetScriptCallbackFunction("lldbinit.antidebug_callback_step1")
            # PT_DENY_ATTACH
            bp2 = target.BreakpointCreateByName("ptrace", "/usr/lib/system/libsystem_kernel.dylib")
            bp2.SetScriptCallbackFunction("lldbinit.antidebug_ptrace_callback")
            # mach exception ports
            bp3 = target.BreakpointCreateByName("task_get_exception_ports", "/usr/lib/system/libsystem_kernel.dylib")
            bp3.SetScriptCallbackFunction("lldbinit.antidebug_task_exception_ports_callback")
            bp4 = target.BreakpointCreateByName("task_set_exception_ports", "/usr/lib/system/libsystem_kernel.dylib")
            bp4.SetScriptCallbackFunction("lldbinit.antidebug_task_exception_ports_callback")
            print("[+] Enabled anti-anti-debugging measures")
            break

# the callback for the specific module loaded breakpoint
# supports x64, i386, arm64
def module_breakpoint_callback(frame, bp_loc, dict):
    global modules_list
    # rdx contains the module address
    # rdx+8 contains pointer to the module name string
    if frame is None:
        return 0

    error = lldb.SBError()

    i386 = is_i386()
    x64 = is_x64()
    arm = is_arm()
    if not i386 and not x64 and not arm:
        err_msg("Unsupported architecture.")

    # for i386 we need the stack pointer to retrieve arguments
    if i386:
        sp = frame.FindRegister("esp")
        sp = int(sp.GetValue(), 16)

    # static void gdb_image_notifier(enum dyld_image_mode mode, uint32_t infoCount, const dyld_image_info info[])
    # static void lldb_image_notifier(enum dyld_image_mode mode, uint32_t infoCount, const dyld_image_info info[])
    if x64:
        pc = frame.FindRegister("rdi")
        mode = int(pc.GetValue(), 16)
    elif arm:
        # argument registers from x0 to x7
        pc = frame.FindRegister("x0")
        mode = int(pc.GetValue(), 16)
    elif i386:
        mode = get_process().ReadUnsignedFromMemory(sp + 4, 4, error)
        if not error.Success():
            err_msg("Failed to read mode from stack.")
            return

    # only interested in new images
    # enum dyld_image_mode { dyld_image_adding=0, dyld_image_removing=1, dyld_image_info_change=2, dyld_image_dyld_moved=3 };
    if mode != 0:
        get_process().Continue()
        return

    # infoCount argument
    if x64:
        pc = frame.FindRegister("rsi")
        infoCount = int(pc.GetValue(), 16)
    elif arm:
        pc = frame.FindRegister("x1")
        infoCount = int(pc.GetValue(), 16)
    elif i386:
        infoCount = get_process().ReadUnsignedFromMemory(sp + 8, 4, error)
        if not error.Success():
            err_msg("Failed to read infoCount from stack.")
            return

    # info argument
    if x64:
        pc = frame.FindRegister("rdx")
        info = int(pc.GetValue(), 16)
    elif arm:
        pc = frame.FindRegister("x2")
        info = int(pc.GetValue(), 16)
    elif i386:
        info = get_process().ReadUnsignedFromMemory(sp + 12, 4, error)
        if not error.Success():
            err_msg("Failed to read address from rdx.")
            return

    # set values according to target platform
    if i386:
        readSize = 4
        # sizeof(struct dyld_image_info) - this should be constant?
        dyld_image_info_size = 4 * 3
    else:
        readSize = 8
        dyld_image_info_size = 8 * 3

    hit = 0
    # go over all the images being added and try to found the ones we are interested in
    for x in range(infoCount):
        address = get_process().ReadUnsignedFromMemory(info, readSize, error)
        if not error.Success():
            err_msg("Failed to read address from info structure:" + error)
            return
        string_ptr = get_process().ReadUnsignedFromMemory(info + readSize, readSize, error)
        if not error.Success():
            err_msg("Failed to read string pointer from info structure.")
            return
        string = get_process().ReadCStringFromMemory(string_ptr, 1024, error)
        if not error.Success():
            err_msg("Failed to read module name string.")
            return
        # XXX: convert this to dictionary? we expect this to be always quite small (one or just a few entries)
        for i in modules_list:
            if i == string:
                hit = 1
                print("[+] Hit module loading: {0} @ {1}".format(string, hex(address)))
                break
        # we found the module so no point continuing
        # lldb stays at the gdb_image_notifier() breakpoint
        # so that user can do something
        if hit == 1:
            return
        # advance to next one
        info += dyld_image_info_size

    # nothing found so we resume execution
    if hit == 0:
        get_process().Continue()

# breakpoint on specific module
def cmd_bm(debugger, command, result, dict):
    """Set breakpoint on specific module load. Use \'bm help\' for more information."""
    help = {
        "cmd": "bm",
        "short": "set breakpoint on module load",
        "desc": """Set gdb_image_notifier() or lldb_image_notifier() breakpoint on module load.
Similar to stop on shared library events feature but stops only on configured modules.
Issue the command multiple times to add different modules.
If no module path specified it will just be a shortcut to set breakpoint
at beginning of image notifier. Use \'print_images\' to show all images there.""",
        "args": "[<full path to module>]",
        "notes": ["The gdb_image_notifier() was removed in Monterey."],
        "example": "bm /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    }
    global modules_list
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    # convert everything to a single string
    # spaces should be fine on the path without escaping since we expect them like that in memory
    # when matching the modules at the callback
    modpath = " ".join([str(item) for item in cmd[0:]])

    found = 0
    target = get_target()
    for m in target.module_iter():
        # print(m.file.fullpath)
        if m.file.fullpath == "/usr/lib/dyld":
            for symbol in m:
                # mangled is easier because the other symbol commands will retrieve with prototype info in the name
                name = symbol.GetMangledName()
                # XXX: improve this because we are doubling the amount of work?
                # the lldb symbol isn't mangled
                name2 = symbol.GetName()
                if name == "_ZL18gdb_image_notifier15dyld_image_modejPK15dyld_image_info" or name2 == "lldb_image_notifier":
                    saddr = symbol.GetStartAddress()
                    # process needs to be loaded before we can execute this command...
                    if saddr.GetLoadAddress(target) == 0xFFFFFFFFFFFFFFFF:
                        err_msg("Failed to retrieve address of gdb_image_notifier. use 'break_entrypoint' or 'process launch -s' command first and then this one.")
                        return
                    bpt_addr = saddr.GetLoadAddress(target)
                    # check if it's a duplicate breakpoint
                    # just add to the module list if the callback is already set
                    for bpt in target.breakpoint_iter():
                        # we need to iterate all locations of each breakpoint... geezzzzzz
                        for bl in bpt:
                            if bl.GetLoadAddress() ==  bpt_addr:
                                print("[+] Added '{}' to breakpoint on module load.".format(modpath))
                                modules_list.append(modpath)
                                return
                    print("[+] Setting breakpoint on gdb_image_notifier located at address {0}".format(hex(saddr.GetLoadAddress(target))))
                    breakpoint = target.BreakpointCreateByAddress(bpt_addr)
                    # append the module name to the list if set
                    if len(cmd) > 0:
                        breakpoint.SetScriptCallbackFunction("lldbinit.module_breakpoint_callback")
                        print("[+] Added '{}' to breakpoint on module load.".format(modpath))
                        modules_list.append(modpath)
                    found = 1
                    break
        if found:
            break

def cmd_bmc(debugger, command, result, dict):
    """Clear all breakpoints on specific module load. Use \'bmc help\' for more information."""
    help = {
        "cmd": "bmc",
        "short": "clear breakpoints",
        "desc": "Clear all breakpoints set on module load. Check the 'bm' command for further information.",
        "args": "",
    }
    global modules_list
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    modules_list = []

def cmd_bml(debugger, command, result, dict):
    """List all breakpoints on module load."""
    help = {
        "cmd": "bml",
        "short": "list breakpoints",
        "desc": "List all breakpoints set on module load. Check the 'bm' command for further information.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if len(modules_list) == 0:
        print("No breakpoints on modules currently set.")
        return
    print("Breakpoints on modules:")
    for i in modules_list:
        print("- " + i)

def cmd_print_notifier_images(debugger, command, result, dict):
    """Print all images available at gdb_image_notifier/lldb_image_notifier breakpoint."""
    help = {
        "cmd": "print_images",
        "short": "print target modules",
        "desc": """Print all modules available at gdb_image_notifier() or lldb_image_notifier() breakpoint.\nOnly valid when breakpoint set at beginning of the image notifier.""",
        "args": "",
        "notes": ["The gdb_image_notifier() was removed in Monterey."],
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    frame = get_frame()
    if frame is None:
        return 0

    error = lldb.SBError()
    # XXX: check that we are effectively at gdb_image_notifier address

    i386 = is_i386()
    x64 = is_x64()
    arm = is_arm()
    if not i386 and not x64 and not arm:
        err_msg("Unsupported architecture.")

    # for i386 we need the stack pointer to retrieve arguments
    if i386:
        sp = frame.FindRegister("esp")
        sp = int(sp.GetValue(), 16)

    # static void gdb_image_notifier(enum dyld_image_mode mode, uint32_t infoCount, const dyld_image_info info[])
    # static void lldb_image_notifier(enum dyld_image_mode mode, uint32_t infoCount, const dyld_image_info info[])

    # mode argument
    if x64:
        pc = frame.FindRegister("rdi")
        mode = int(pc.GetValue(), 16)
    elif arm:
        # argument registers from x0 to x7
        pc = frame.FindRegister("x0")
        mode = int(pc.GetValue(), 16)
    elif i386:
        mode = get_process().ReadUnsignedFromMemory(sp + 4, 4, error)
        if not error.Success():
            err_msg("Failed to read mode from stack.")
            return

    # infoCount argument
    if x64:
        pc = frame.FindRegister("rsi")
        infoCount = int(pc.GetValue(), 16)
    elif arm:
        pc = frame.FindRegister("x1")
        infoCount = int(pc.GetValue(), 16)
    elif i386:
        infoCount = get_process().ReadUnsignedFromMemory(sp + 8, 4, error)
        if not error.Success():
            err_msg("Failed to read infoCount from stack.")
            return

    # info argument
    if x64:
        pc = frame.FindRegister("rdx")
        info = int(pc.GetValue(), 16)
    elif arm:
        pc = frame.FindRegister("x2")
        info = int(pc.GetValue(), 16)
    elif i386:
        info = get_process().ReadUnsignedFromMemory(sp + 12, 4, error)
        if not error.Success():
            err_msg("Failed to read address from rdx.")
            return

    # set values according to target platform
    if i386:
        readSize = 4
        dyld_image_info_size = 4 * 3
    else:
        readSize = 8
        dyld_image_info_size = 8 * 3

    print("gdb_image_notifier available dyld_image_info images: {0}".format(infoCount))
    if infoCount == 0:
        return
    print("Mode: {0} ({1})".format(mode, dyld_mode_dict[mode]))
    print("Loaded modules:")
    print("----------------------------------------------------------")
    for x in range(infoCount):
        address = get_process().ReadUnsignedFromMemory(info, readSize, error)
        if not error.Success():
            err_msg("Failed to read address from info structure.")
            return
        string_ptr = get_process().ReadUnsignedFromMemory(info + readSize, readSize, error)
        if not error.Success():
            err_msg("Failed to read string pointer from info structure.")
            return
        string = get_process().ReadCStringFromMemory(string_ptr, 1024, error)
        if not error.Success():
            err_msg("Failed to read module name string.")
            return
        print("0x{:>014x} | {:s}".format(address, string))
        # advance to next one sizeof(struct dyld_image_info)
        info += dyld_image_info_size

# software breakpoint
# overwrites the default alias
# XXX: should we verify duplicate breakpoints?
# they should exist, for example one with condition another without
# and user can enable/disable the one he wants to work with
#
# NOTE: this is straighforward breakpoint without conditions etc
# user can always set conditions via regular commands
def cmd_bp(debugger, command, result, dict):
    """Set a software breakpoint."""
    help = {
        "cmd": "bp",
        "short": "set software breakpoint",
        "desc": """Set a software breakpoint.""",
        "args": "<address> [<breakpoint name>]",
        "options": [
                {"name": "address", "desc": "The breakpoint address."},
                {"name": "breakpoint name", "desc": "The breakpoint name."},
            ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    # accept spaces and replace them with underscores
    # the breakpoint names don't allow spaces?
    name = ""
    if len(cmd) > 1:
        name = "_".join([str(item) for item in cmd[1:]])

    target = get_target()
    breakpoint = target.BreakpointCreateByAddress(value)
    if name != "":
        breakpoint.AddName(name)

    print("[+] Software #{:d} breakpoint set at 0x{:x}".format(target.num_breakpoints, value))
    return

# temporary software breakpoint
def cmd_bpt(debugger, command, result, dict):
    """Set a temporary software breakpoint. Use \'bpt help\' for more information."""
    help = {
        "cmd": "bpt",
        "short": "set temporary software breakpoint",
        "desc": "Set a temporary software breakpoint. Breakpoint is deleted on first hit.",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The breakpoint address."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    target = get_target()
    breakpoint = target.BreakpointCreateByAddress(value)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print("[+] Temporary software breakpoint #{:d} set at 0x{:x}".format(target.num_breakpoints, value))

# hardware breakpoint
def cmd_bh(debugger, command, result, dict):
    """Set an hardware breakpoint."""
    help = {
        "cmd": "bh",
        "short": "set hardware breakpoint",
        "desc": """Set an hardware breakpoint.""",
        "args": "<address> [<breakpoint name>]",
        "options": [
                {"name": "address", "desc": "The breakpoint address."},
                {"name": "breakpoint name", "desc": "The breakpoint name."}
        ],
        "notes": [
                "Expressions are supported, do not use spaces between operators.",
                "Breakpoint name must *not* use spaces."
        ],
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    # accept spaces and replace them with underscores
    # the breakpoint names don't allow spaces?
    name = ""
    if len(cmd) > 1:
        name = "_".join([str(item) for item in cmd[1:]])

    res = lldb.SBCommandReturnObject()
    # the python API doesn't seem to support hardware breakpoints
    # so we set it via command line interpreter
    if name != "":
        debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H -a {} -N {}".format(hex(value), name), res)
    else:
        debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H -a {}".format(hex(value)), res)

    # if hardware breakpoints are not supported, the command only generates a warning
    # and no error is available in res, so we can't distinguish those cases
    # unless we parse output... meh, too much work to support old versions!
    print("[+] Hardware breakpoint #{:d} set at 0x{:x}".format(get_target().num_breakpoints, value))
    return

# temporary hardware breakpoint
def cmd_bht(debugger, command, result, dict):
    """Set a temporary hardware breakpoint."""
    help = {
        "cmd": "bht",
        "short": "set temporary hardware breakpoint",
        "desc": """Set a temporary hardware breakpoint. Breakpoint is deleted on first hit.""",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The breakpoint address."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return
    res = lldb.SBCommandReturnObject()
    # the python API doesn't seem to support hardware breakpoints
    # so we set it via command line interpreter
    lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H --one-shot true -a {}".format(hex(value)), res)
    print("[+] Temporary hardware breakpoint #{:d} set at 0x{:x}".format(get_target().num_breakpoints, value))
    return

# clear breakpoint number
def cmd_bpc(debugger, command, result, dict):
    """Clear a breakpoint. Use \'bpc help\' for more information."""
    help = {
        "cmd": "bpc",
        "short": "clear breakpoint",
        "desc": "Clear a breakpoint by number.",
        "args": "<breakpoint number>",
        "options": [
                {"name": "breakpoint number", "desc": "The breakpoint number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint numbers are valid, not addresses.",
                "Expressions are supported, do not use spaces between operators."
        ],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint number.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value - only a breakpoint number is valid.")
        help_msg(help)
        return

    target = get_target()
    for bpt in target.breakpoint_iter():
        if bpt.id == value:
            if target.BreakpointDelete(bpt.id) is False:
                err_msg("Failed to delete breakpoint #{:d}.".format(value))
                return
            print("[+] Deleted breakpoint #{:d}".format(value))
            return

    err_msg("Breakpoint #{:d} not found.".format(value))
    return

# disable breakpoint number
# XXX: we could support addresses, not sure it's worth the trouble
def cmd_bpd(debugger, command, result, dict):
    """Disable a breakpoint. Use \'bpd help\' for more information."""
    help = {
        "cmd": "bpd",
        "short": "disable breakpoint",
        "desc": "Disable a breakpoint by number.",
        "args": "<breakpoint number>",
        "options": [
                {"name": "breakpoint number", "desc": "The breakpoint number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint numbers are valid, not addresses.",
                "Expressions are supported, do not use spaces between operators."
        ],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint number.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value - only a breakpoint number is valid.")
        help_msg(help)
        return

    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and bpt.IsEnabled():
            bpt.SetEnabled(False)
            print("[+] Disabled breakpoint #{:d}".format(value))

# disable all breakpoints
def cmd_bpda(debugger, command, result, dict):
    """Disable all breakpoints. Use \'bpda help\' for more information."""
    help = {
        "cmd": "bpda",
        "short": "disable all breakpoints",
        "desc": "Disable all breakpoints.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return

    target = get_target()

    if target.DisableAllBreakpoints() is False:
        err_msg("Failed to disable all breakpoints.")

    print("[+] Disabled all breakpoints.")

# enable breakpoint number
def cmd_bpe(debugger, command, result, dict):
    """Enable a breakpoint. Use \'bpe help\' for more information."""
    help = {
        "cmd": "bpe",
        "short": "enable breakpoint",
        "desc": "Enable a breakpoint by number.",
        "args": "<breakpoint number>",
        "options": [
                {"name": "breakpoint number", "desc": "The breakpoint number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint numbers are valid, not addresses.",
                "Expressions are supported, do not use spaces between operators."
        ],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint number.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    # breakpoint enable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value - only a breakpoint number is valid.")
        help_msg(help)
        return

    target = get_target()

    for bpt in target.breakpoint_iter():
        if bpt.id == value and not bpt.IsEnabled():
            bpt.SetEnabled(True)
            print("[+] Enabled breakpoint #{:d}".format(value))

# enable all breakpoints
def cmd_bpea(debugger, command, result, dict):
    """Enable all breakpoints. Use \'bpea help\' for more information."""
    help = {
        "cmd": "bpea",
        "short": "enable all breakpoints",
        "desc": "Enable all breakpoints.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return

    target = get_target()

    if not target.EnableAllBreakpoints():
        err_msg("Failed to enable all breakpoints.")

    print("[+] Enabled all breakpoints.")

# list all breakpoints
# XXX: add option to display only the active breakpoints
def cmd_bpl(debugger, command, result, dict):
    """List all breakpoints. Use \'bpl help\' for more information."""
    help = {
        "cmd": "bpl",
        "short": "list breakpoints",
        "desc": "List all breakpoints.",
        "args": "[-e]",
        "options": [{"name": "-e", "desc": "Display only enabled breakpoints."}],
    }
    enabled_only = False
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        elif cmd[0] == "-e":
            enabled_only = True
        else:
            # err_msg("The command doesn't take any arguments.")
            help_msg(help)
            return

    target = get_target()
    # nothing to present
    if target.num_breakpoints == 0:
        print("No breakpoints currently set.")
        return

    total = 0
    hw = 0
    disabledsoft = 0
    disabledhw = 0

    print("{:<4} {: <19} {:<3} {:s} {:<5} {:s} {: <24} {:s}".format("#", "Address", "Type", "Enabled", "Count", "Commands", "Module", "Name"))
    print("-----------------------------------------------------------------------------------------------")
    # the live version should be equal to the disk version since we write to database after every op
    for bpt in target.breakpoint_iter():
        # XXX: we assume always the first location
        item = bpt.location[0]
        # XXX: display bad addresses? more checks, more problems to deal with
        if item is None:
            continue
        bp_addr = item.GetLoadAddress()
        # set module binary if resolved
        binary = "Unresolved breakpoint"
        iaddr = item.GetAddress()
        fullpath = iaddr.module.file.fullpath
        path = fullpath
        if fullpath is not None:
            path = os.path.abspath(fullpath)
        if path is not None:
            binary = os.path.basename(path)
        # set the enabled flag
        total += 1
        enabled = "Y"
        # set temporary breakpoint flag
        btype = "S"
        # this function not available in older lldb versions
        # XXX: because of no hw breakpoints or this function? otherwise we have logic issue if hw breakpoints exist but not function
        try:
            if bpt.IsHardware():
                btype = "H"
                hw += 1
                if bpt.IsEnabled() is False:
                    enabled = "N"
                    disabledhw += 1
            else:
                if bpt.IsEnabled() is False:
                    enabled = "N"
                    disabledsoft += 1
        except:
            if bpt.IsEnabled() is False:
                enabled = "N"
                disabledsoft += 1
            pass
        if bpt.IsOneShot():
            btype += "*"
        # retrieve the first breakpoint name if set
        # only the first name supported
        name = ""
        names = lldb.SBStringList()
        bpt.GetNames(names)
        if names.IsValid():
            name = names.GetStringAtIndex(0)
        commands = lldb.SBStringList()
        if enabled_only is True and enabled == "N":
            continue
        print("{:<4} {: <19} {:^4s} {:^7s} {:^5d} {:^8s} {: <24} {}".format(bpt.id,hex(bp_addr), btype, enabled, bpt.GetHitCount(), str(bpt.GetCommandLineCommands(commands)), binary, name))

    print("-----------------------------------------------------------------------------------------------")
    print("Total: {:^d} - Software: {:^d}/{:^d} - Hardware: {:^d}/{:^d}".format(total, total-hw-disabledsoft, total-hw, hw-disabledhw, hw))

# skip current instruction - just advances PC to next instruction but doesn't execute it
def cmd_skip(debugger, command, result, dict):
    """Advance PC to instruction at next address. Use \'skip help\' for more information."""
    help = {
        "cmd": "skip",
        "short": "skip current instruction",
        "desc": "Advance current instruction pointer to next instruction.",
        "args": "",
        "notes": ["The control flow is not respected, it advances to the next instruction in memory."],
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return

    start_addr = get_current_pc()
    next_addr = start_addr + get_inst_size(start_addr)

    if is_x64():
        get_frame().reg["rip"].value = format(next_addr, "#x")
    elif is_i386():
        get_frame().reg["eip"].value = format(next_addr, "#x")
    elif is_arm():
        get_frame().reg["pc"].value = format(next_addr, "#x")

    # show the updated context
    lldb.debugger.HandleCommand("context")

def cmd_int3(debugger, command, result, dict):
    """Patch at address to a breakpoint instruction (INT3 for x86, BRK #0 for AArch64) . Use \'int3 help\' for more information."""
    help = {
        "cmd": "int3",
        "short": "patch memory with int3/brk",
        "desc": """Patch process memory with a breakpoint instruction at given address.\nUseful in cases where the debugger breakpoints aren't respected but an INT3/BRK will always trigger the debugger.""",
        "args": "[<address>]",
        "options": [
                {"name": "address", "desc": "The address to patch. Current address if not specified."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators. Example: int3 $pc+0x10"],
    }
    global int3patches
    error = lldb.SBError()
    target = get_target()

    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return

        int3_addr = evaluate(cmd[0])
        if int3_addr is None:
            err_msg("Invalid input address value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return

    bpt_size = 1
    if is_arm():
        bpt_size = 4

    bytes_string = target.GetProcess().ReadMemory(int3_addr, bpt_size, error)
    if not error.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(int3_addr))
        return

    bytes_read = bytearray(bytes_string)
    if is_python2():
        patch_bytes = str("\xCC")
        if is_arm():
            # brk #0
            patch_bytes = str("\x00\x00\x20\xd4")
    else:
        patch_bytes = bytearray(b"\xCC")
        if is_arm():
            patch_bytes = bytearray(b"\x00\x00\x20\xd4")

    # insert the patch
    result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
    # XXX: compare len(patch) with result
    if not error.Success():
        err_msg("Failed to write memory at 0x{:x}.".format(int3_addr))
        return
    # save original bytes for later restore
    int3patches[str(int3_addr)] = bytes_read
    print("[+] Patched breakpoint at 0x{:x}".format(int3_addr))
    return

def cmd_rint3(debugger, command, result, dict):
    """Restore byte at address from a previously patched breakpoint instruction. Use \'rint3 help\' for more information."""
    help = {
        "cmd": "rint3",
        "short": "restore original byte(s)",
        "desc": "Restore the original byte(s) at a 'int3' patched address.",
        "args": "[<address>]",
        "options": [{"name": "address", "desc": "The address to restore. Current address if not specified."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    global int3patches
    error = lldb.SBError()
    target = get_target()
    cmd = command.split()
    # if empty insert a int3 at current PC
    if len(cmd) == 0:
        int3_addr = get_current_pc()
        if int3_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        int3_addr = evaluate(cmd[0])
        if int3_addr is None:
            err_msg("Invalid input address value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a breakpoint patched address.")
        help_msg(help)
        return

    if len(int3patches) == 0:
        err_msg("No breakpoint patched addresses to restore available.")
        return

    if str(int3_addr) not in int3patches:
        err_msg("No breakpoint patch found at address 0x{:x}.".format(int3_addr))
        return

    original_bytes = int3patches[str(int3_addr)]

    bpt_size = 1
    if is_arm():
        bpt_size = 4

    bytes_string = target.GetProcess().ReadMemory(int3_addr, bpt_size, error)
    if not error.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(int3_addr))
        return

    bytes_read = bytearray(bytes_string)
    # validate what's in memory
    if len(bytes_read) == 1 and bytes_read[0] != 0xCC:
        err_msg("No INT3 patch found in memory at address 0x{:x}.".format(int3_addr))
        return
    elif len(bytes_read) == 4 and bytes_read[3] != 0xD4:
        err_msg("No BRK patch found in memory at address 0x{:x}.".format(int3_addr))
        return
    if is_python2():
        patch_bytes = str(original_bytes)
    else:
        patch_bytes = original_bytes
    # restore original bytes
    result = target.GetProcess().WriteMemory(int3_addr, patch_bytes, error)
    if not error.Success():
        err_msg("Failed to write memory at 0x{:x}.".format(int3_addr))
        return
    # remove element from original bytes list
    del int3patches[str(int3_addr)]
    return

def cmd_listint3(debugger, command, result, dict):
    """List all patched addresses with breakpoint instructions. Use \'listint3 help\' for more information."""
    help = {
        "cmd": "listint3",
        "short": "list int3 addresses",
        "desc": "List all addresses patched with 'int3' command.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return

    if len(int3patches) == 0:
        print("No breakpoint patched addresses available.")
        return

    print("Current breakpoint patched addresses:")
    for address, byte in int3patches.items():
        print("[*] {:s}".format(hex(int(address, 10))))

    return

def cmd_nop(debugger, command, result, dict):
    """NOP byte(s) at address. Use \'nop help\' for more information."""
    help = {
        "cmd": "nop",
        "short": "NOP patch address",
        "desc": "Patch process memory with NOP instruction(s) at given address.",
        "args": "<address> [<amount>]",
        "options": [
                {"name": "address", "desc": "The address to patch."},
                {"name": "amount", "desc": "The number of bytes/instructions to patch."}
        ],
        "notes": [
                "Default is one byte for x86 targets and one instruction for ARM64 targets, if amount not specified.",
                "Expressions are supported, do not use spaces between operators. Example: nop $pc+10"
        ],
    }
    error = lldb.SBError()
    target = get_target()
    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return

        nop_addr = evaluate(cmd[0])
        patch_size = 1
        if nop_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        nop_addr = evaluate(cmd[0])
        if nop_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return

        patch_size = evaluate(cmd[1])
        if patch_size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a target address.")
        help_msg(help)
        return

    current_patch_addr = nop_addr
    # format for WriteMemory()
    # Python 2
    if is_python2():
        patch_len = 1
        patch_bytes = str("\x90")
        if is_arm():
            patch_bytes = str("\x1f\x20\x03\xd5")
            patch_len = 4
    else:
        patch_len = 1
        patch_bytes = bytearray(b"\x90")
        if is_arm():
            patch_bytes = bytearray(b"\x1f\x20\x03\xd5")
            patch_len = 4

    for i in range(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if not error.Success():
            err_msg("Failed to write memory at 0x{:x}.".format(current_patch_addr))
            return
        current_patch_addr = current_patch_addr + patch_len

    return

def cmd_null(debugger, command, result, dict):
    """Patch byte(s) at address to NULL (0x00). Use \'null help\' for more information."""
    help = {
        "cmd": "null",
        "short": "write NULL bytes to memory",
        "desc": "Patch process memory with NULL (0x00) byte(s) at given address.",
        "args": "<address> [<amount>]",
        "options": [
            {"name": "address", "desc": "The address to patch."},
            {"name": "amount", "desc": "The number of bytes to patch. Default is 1 byte."}
        ],
        "example": "null 0x100000 0x10",
        "notes": ["Expressions are supported, do not use spaces between operators. Example: null $pc+0x10"],
    }
    error = lldb.SBError()
    target = get_target()
    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        null_addr = evaluate(cmd[0])
        patch_size = 1
        if null_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        null_addr = evaluate(cmd[0])
        if null_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
        patch_size = evaluate(cmd[1])
        if patch_size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a breakpoint address.")
        help_msg(help)
        return

    current_patch_addr = null_addr
    # format for WriteMemory()
    patch_bytes = str("\x00")
    # can we do better here? WriteMemory takes an input string... weird
    for i in range(patch_size):
        result = target.GetProcess().WriteMemory(current_patch_addr, patch_bytes, error)
        if not error.Success():
            err_msg("Failed to write memory at 0x{:x}.".format(current_patch_addr))
            return
        current_patch_addr = current_patch_addr + 1
    return

# Implements the stepover command.
def cmd_stepo(debugger, command, result, dict):
    """Step over calls and some other instructions so we don't need to step into them. Use \'stepo help\' for more information."""
    help = {
        "cmd": "stepo",
        "short": "step over calls and loops",
        "desc": """Step over calls and loops that we want executed but not step into.
Affected instructions:
- x86: call, movs, stos, cmps, loop.
- ARM64: bl, blr, blraa, blraaz, blrab, blrabz.""",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    debugger.SetAsync(True)

    target = get_target()

    # compute the next address where to breakpoint
    pc_addr = get_current_pc()
    if pc_addr == 0:
        err_msg("Invalid current address.")
        return

    next_addr = pc_addr + get_inst_size(pc_addr)
    # much easier to use the mnemonic output instead of disassembling via cmd line and parse
    mnemonic = get_mnemonic(pc_addr)

    if is_arm():
        # the a versions are with pointer authentication
        branch_mnemo = ["bl", "blr", "blraa", "blraaz", "blrab", "blrabz"]
        if mnemonic in branch_mnemo:
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
    step_list = ["call", "callq", "movs", "stos", "loop", "cmps"]
    if mnemonic in step_list:
        breakpoint = target.BreakpointCreateByAddress(next_addr)
        breakpoint.SetOneShot(True)
        breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
        target.GetProcess().Continue()
    else:
        get_process().selected_thread.StepInstruction(False)

"""
    Implements stepover instruction with hardware breakpoints.
"""
def cmd_stepoh(debugger, command, result, dict):
    """Step over calls and some other instructions so we don't need to step into them, using hardware breakpoints. Use \'stepohhelp\' for more information."""
    help = {
        "cmd": "stepoh",
        "short": "step over calls and loops",
        "desc": """Uses hardware breakpoint to step over calls and loops that we want executed but not step into.
Affected instructions:
- x86: call, movs, stos, cmps, loop.
- ARM64: bl, blr, blraa, blraaz, blrab, blrabz.""",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    debugger.SetAsync(True)

    target = get_target()
    res = lldb.SBCommandReturnObject()

    # compute the next address where to breakpoint
    pc_addr = get_current_pc()
    if pc_addr == 0:
        err_msg("Invalid current address.")
        return

    next_addr = pc_addr + get_inst_size(pc_addr)
    # much easier to use the mnemonic output instead of disassembling via cmd line and parse
    mnemonic = get_mnemonic(pc_addr)

    if is_arm():
        # the a versions are with pointer authentication
        branch_mnemo = ["bl", "blr", "blraa", "blraaz", "blrab", "blrabz"]
        if mnemonic in branch_mnemo:
            # setup temporary hardware breakpoint for current thread only
            lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H --one-shot true -t current -a {}".format(hex(next_addr)), res)
            target.GetProcess().Continue()
            return
        else:
            get_process().selected_thread.StepInstruction(False)
            return
    # XXX: make the other instructions besides call user configurable?
    # calls can be call, callq, so use wider matching for those
    step_list = ["call", "callq", "movs", "stos", "loop", "cmps"]
    if mnemonic in step_list:
        # setup temporary hardware breakpoint for current thread only
        lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set -H --one-shot true -t current -a {}".format(hex(next_addr)), res)
        target.GetProcess().Continue()
    else:
        get_process().selected_thread.StepInstruction(False)
        return

# Temporarily breakpoint next instruction - this is useful to skip loops (don't want to use stepo for this purpose)
def cmd_bpn(debugger, command, result, dict):
    """Temporarily breakpoint instruction at next address. Use \'bpn help\' for more information."""
    help = {
        "cmd": "bpn",
        "short": "breakpoint next instruction",
        "desc": "Temporarily breakpoint the next instruction.",
        "args": "",
        "notes": ["The control flow is not respected, it breakpoints the next instruction in memory."],
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return

    target = get_target()
    start_addr = get_current_pc()
    next_addr = start_addr + get_inst_size(start_addr)

    breakpoint = target.BreakpointCreateByAddress(next_addr)
    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())

    print("[+] Set temporary breakpoint at 0x{:x}".format(next_addr))

# command that sets rax/eax/x0 to 1 or 0 and returns right away from current function
# technically just a shortcut to "thread return"
def cmd_crack(debugger, command, result, dict):
    """Return from current function and set return value. Use \'crack help\' for more information."""
    help = {
        "cmd": "crack",
        "short": "return from current function",
        "desc": """Return from current function and set the return value.
Sets RAX/EAX/X0 to return value and returns immediately from current function.
Most useful to use at the beginning of the function to return from.""",
        "args": "<return value>",
        "options": [{"name": "return value", "desc": "The return value to set."}],
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a return value.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return

    # breakpoint disable only accepts breakpoint numbers not addresses
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid return value.")
        help_msg(help)
        return

    frame = get_frame()
    # if we copy the SBValue from any register and use that copy
    # for return value we will get that register and rax/eax set
    # on return
    # the SBValue to ReturnFromFrame must be eValueTypeRegister type
    # if we do a lldb.SBValue() we can't set to that type
    # so we need to make a copy
    # can we use FindRegister() from frame?
    if is_x64():
        return_value = frame.reg["rax"]
    elif is_arm():
        return_value = frame.reg["x0"]
    elif is_i386():
        return_value = frame.reg["eax"]
    else:
        err_msg("Unsupported architecture.")
        return
    return_value.value = str(value)
    # XXX: should check the frame count and validate if there is something to return to
    get_thread().ReturnFromFrame(frame, return_value)

# set a breakpoint with return command associated when hit
def cmd_crackcmd(debugger, command, result, dict):
    """Breakpoint an address, when breakpoint is hit return from function and set return value. Use \'crackcmd help\' for more information."""
    help = {
        "cmd": "crackcmd",
        "short": "breakpoint and return",
        "desc": """Breakpoint an address, and when the breakpoint is hit returns from function and sets the return value.
    Sets RAX/EAX/X0 to return value and returns immediately from current function where breakpoint was set.""",
        "args": "<address> <return value>",
        "options": [
            {"name": "address", "desc": "The breakpoint address"},
            {"name": "return value", "desc": "The return value to set."}
        ],
    }
    global crack_cmds
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("Please check required arguments.")
        help_msg(help)
        return
    elif len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    elif len(cmd) < 2:
        err_msg("Please check the required arguments.")
        help_msg(help)
        return

    # XXX: is there a way to verify if address is valid? or just let lldb error when setting the breakpoint
    address = evaluate(cmd[0])
    if address is None:
        err_msg("Invalid address value.")
        help_msg(help)
        return

    return_value = evaluate(cmd[1])
    if return_value is None:
        err_msg("Invalid return value.")
        help_msg(help)
        return

    for tmp_entry in crack_cmds:
        if tmp_entry["address"] == address:
            err_msg("Address already contains a crack command.")
            return

    # set a new entry so we can deal with it in the callback
    new_crack_entry = {}
    new_crack_entry["address"] = address
    new_crack_entry["return_value"] = return_value
    crack_cmds.append(new_crack_entry)

    target = get_target()

    # we want a global breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    # when the breakpoint is hit we get this callback executed
    breakpoint.SetScriptCallbackFunction("lldbinit.crackcmd_callback")

def crackcmd_callback(frame, bp_loc, internal_dict):
    global crack_cmds
    # retrieve address we just hit
    current_bp = bp_loc.GetLoadAddress()
    print("[!] Warning: hit crack command breakpoint at 0x{:x}".format(current_bp))

    crack_entry = None
    for tmp_entry in crack_cmds:
        if tmp_entry["address"] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        err_msg("The current breakpoint was not found in the list.")
        return

    # we can just set the register in the frame and return empty SBValue
    if is_x64():
        frame.reg["rax"].value = str(crack_entry["return_value"]).rstrip("L")
    elif is_arm():
        frame.reg["x0"].value = str(crack_entry["return_value"]).rstrip("L")
    elif is_i386():
        frame.reg["eax"].value = str(crack_entry["return_value"]).rstrip("L")
    else:
        err_msg("Unsupported architecture.")
        return

    get_thread().ReturnFromFrame(frame, lldb.SBValue())
    get_process().Continue()

# set a breakpoint with a command that doesn't return, just sets the specified register to a value
def cmd_crackcmd_noret(debugger, command, result, dict):
    """Set a breakpoint and a register to a value when hit. Use \'crackcmd_noret help\' for more information."""
    help = {
        "cmd": "crackcmd_noret",
        "short": "breakpoint and set register value",
        "desc": "Sets the specified register to a value when the breakpoint at specified address is hit, and resumes execution.",
        "args": "<address> <register> <value>",
        "options": [
            {"name": "address", "desc": "The breakpoint address"},
            {"name": "register", "desc": "The register to modify."},        
            {"name": "value", "desc": "The value to set."}
        ],
    }
    global crack_cmds_noret
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("Please check the required arguments.")
        help_msg(help)
        return
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    if len(cmd) < 3:
        err_msg("Please check the required arguments.")
        help_msg(help)
        return

    address = evaluate(cmd[0])
    register = cmd[1]
    value = evaluate(cmd[2])

    if address is None:
        err_msg("Invalid address.")
        help_msg(help)
        return

    # check if register is set and valid
    if is_x64():
        valid = ["rip","rax","rbx","rbp","rsp","rdi","rsi","rdx","rcx","r8","r9","r10","r11","r12","r13","r14","r15"]
        if register not in valid:
            err_msg("Invalid register for x64 architecture.")
            help_msg(help)
            return
    elif is_arm():
        valid = ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","fp","lr","sp","pc","cpsr"]
        if register not in valid:
            err_msg("Invalid register for arm64 architecture.")
            help_msg(help)
            return
    elif is_i386():
        valid = ["eip","eax","ebx","ebp","esp","edi","esi","edx","ecx"]
        if register not in valid:
            err_msg("Invalid register for i386 architecture.")
            help_msg(help)
            return

    if value is None:
        err_msg("Invalid value.")
        help_msg(help)
        return

    for tmp_entry in crack_cmds_noret:
        if tmp_entry["address"] == address:
            err_msg("The address already contains a crack command.")
            return

    # set a new entry so we can deal with it in the callback
    new_crack_entry = {}
    new_crack_entry["address"] = address
    new_crack_entry["register"] = register
    new_crack_entry["value"] = value

    crack_cmds_noret.append(new_crack_entry)

    target = get_target()

    # we want a global breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    # when the breakpoint is hit we get this callback executed
    breakpoint.SetScriptCallbackFunction("lldbinit.crackcmd_noret_callback")

def crackcmd_noret_callback(frame, bp_loc, internal_dict):
    global crack_cmds_noret
    # retrieve address we just hit
    current_bp = bp_loc.GetLoadAddress()
    print("[!] Warning: hit crack command no ret breakpoint at 0x{:x}".format(current_bp))
    crack_entry = None
    for tmp_entry in crack_cmds_noret:
        if tmp_entry["address"] == current_bp:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        err_msg("The current breakpoint was not found in the list.")
        return

    # must be a string!
    frame.reg[crack_entry["register"]].value = str(crack_entry["value"]).rstrip("L")
    get_process().Continue()

# -----------------------
# Memory related commands
# -----------------------

"""
    Output nice memory hexdumps...
"""
# display byte values and ASCII characters
def cmd_db(debugger, command, result, dict):
    """Display hex dump in byte values and ASCII characters. Use \'db help\' for more information."""
    help = {
        "cmd": "db",
        "short": "display memory",
        "desc": "Display memory hex dump in byte length and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display. Current address if not specified."},
            {"name": "size", "desc": "The amount of memory to display. Default is 256 bytes."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    size = 0x100
    cmd = command.split()
    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
        size = evaluate(cmd[1])
        if size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a start address.")
        help_msg(help)
        return

    err = lldb.SBError()

    membuf = get_process().ReadMemory(dump_addr, size, err)
    if not err.Success():
        err_msg("Failed to read memory from address 0x{:x}.".format(dump_addr))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    if POINTER_SIZE == 4:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.08X]" % dump_addr + RESET)
    else:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.016lX]" % dump_addr + RESET)
    output(COLOR_HEXDUMP_HEADER + "------------------------------------------------------" + RESET)
    output(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET + "\n")

    offset = 0
    hex_str = ""
    ascii_str = ""
    while offset < len(membuf):
        hex_str += BOLD + COLOR_HEXDUMP_ADDR
        hex_str += "0x{0:08x}  ".format(offset + dump_addr) if POINTER_SIZE == 4 else "0x{0:016x}  ".format(offset + dump_addr)
        hex_str += RESET

        for i in range(16):
            if offset + i < len(membuf):
                byte = membuf[offset + i]
                # python 2
                if is_python2():
                    hex_str += "{0:02x} ".format(ord(byte))
                    ascii_str += byte if 32 <= ord(byte) <= 126 else "."
                else:
                    hex_str += "{0:02x} ".format(byte)
                    ascii_str += chr(byte) if 32 <= byte <= 126 else "."
            else:
                # no data so just print empty space
                hex_str += "   "
                ascii_str += " "
            # split hexdump at 8 bytes
            if i % 8 == 7:
                hex_str += " "
        hex_str += " " + BOLD + COLOR_HEXDUMP_ASCII + ascii_str + RESET + "\n"
        ascii_str = ""
        offset += 16
    # put output into the print buffer
    output(hex_str)

    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display word values and ASCII characters
def cmd_dw(debugger, command, result, dict):
    """ Display hex dump in word values and ASCII characters. Use \'dw help\' for more information."""
    help = {
        "cmd": "dw",
        "short": "display memory",
        "desc": "Display memory hex dump in word length and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display. Current address if not specified."},
            {"name": "size", "desc": "The amount of memory to display. Default is 256 bytes. Must be a multiple of 16 bytes."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    size = 0x100
    cmd = command.split()
    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
        size = evaluate(cmd[1])
        if size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a start address.")
        help_msg(help)
        return

    if size % 16:
        err_msg("The size must be multiple of 16 bytes.")
        return

    err = lldb.SBError()
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if not err.Success():
        err_msg("Failed to read memory from address 0x{:x}.".format(dump_addr))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    if POINTER_SIZE == 4:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.08X]" % dump_addr + RESET)
    else:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.016lX]" % dump_addr + RESET)
    output(COLOR_HEXDUMP_HEADER + "--------------------------------------------" + RESET)
    output(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET + "\n")
    index = 0
    while index < size:
        data = struct.unpack("HHHHHHHH", membuf[index:index+0x10])
        szaddr = "0x%.016lX" % dump_addr
        if POINTER_SIZE == 4:
            szaddr = "0x%.08X" % dump_addr
        data_str = COLOR_HEXDUMP_DATA + " {:04x} {:04x} {:04x} {:04x} {:04x} {:04x} {:04x} {:04x} ".format(
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]) + RESET
        output(BOLD + COLOR_HEXDUMP_ADDR + "{:s} :".format(szaddr) + RESET + data_str + BOLD + COLOR_HEXDUMP_ASCII + "{:s}".format(quotechars(membuf[index:index+0x10])) + RESET)
        if index + 0x10 != size:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display dword values and ASCII characters
def cmd_dd(debugger, command, result, dict):
    """ Display hex dump in double word values and ASCII characters. Use \'dd help\' for more information."""
    help = {
        "cmd": "dd",
        "short": "display memory",
        "desc": "Display memory hex dump in doubleword length and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display. Current address if not specified."},
            {"name": "size", "desc": "The amount of memory to display. Default is 256 bytes. Must be a multiple of 16 bytes."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    size = 0x100
    cmd = command.split()
    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
        size = evaluate(cmd[1])
        if size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a start address.")
        help_msg(help)
        return

    if size % 16:
        err_msg("The size must be multiple of 16 bytes.")
        return

    err = lldb.SBError()
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if not err.Success():
        err_msg("Failed to read memory from address 0x{:x}.".format(dump_addr))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return
    if POINTER_SIZE == 4:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.08X]" % dump_addr + RESET)
    else:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.016lX]" % dump_addr + RESET)
    output(COLOR_HEXDUMP_HEADER + "----------------------------------------" + RESET)
    output(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET + "\n")
    index = 0
    while index < size:
        (mem0, mem1, mem2, mem3) = struct.unpack("IIII", membuf[index : index + 0x10])
        szaddr = "0x%.016lX" % dump_addr
        if POINTER_SIZE == 4:
            szaddr = "0x%.08X" % dump_addr
        data_str = COLOR_HEXDUMP_DATA + " {:08x} {:08x} {:08x} {:08x} ".format(mem0, mem1, mem2, mem3) + RESET
        output(BOLD + COLOR_HEXDUMP_ADDR + "{:s} :".format(szaddr) + RESET + data_str + BOLD + COLOR_HEXDUMP_ASCII + "{:s}".format(quotechars(membuf[index : index + 0x10])) + RESET)
        if index + 0x10 != size:
            output("\n")
        index += 0x10
        dump_addr += 0x10
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# display quad values
def cmd_dq(debugger, command, result, dict):
    """ Display hex dump in quad values. Use \'dq help\' for more information."""
    help = {
        "cmd": "dq",
        "short": "display memory",
        "desc": "Display memory hex dump in quadword length and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display. Current address if not specified."},
            {"name": "size", "desc": "The amount of memory to display. Default is 256 bytes. Must be a multiple of 16 bytes."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    size = 0x100
    cmd = command.split()
    if len(cmd) == 0:
        dump_addr = get_current_pc()
        if dump_addr == 0:
            err_msg("Invalid current address.")
            return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
    elif len(cmd) == 2:
        if cmd[0] == "help":
           help_msg(help)
           return
        dump_addr = evaluate(cmd[0])
        if dump_addr is None:
            err_msg("Invalid address value.")
            help_msg(help)
            return
        size = evaluate(cmd[1])
        if size is None:
            err_msg("Invalid size value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a start address.")
        help_msg(help)
        return

    if size % 16:
        err_msg("The size must be multiple of 16 bytes.")
        return

    err = lldb.SBError()
    membuf = get_process().ReadMemory(dump_addr, size, err)
    if not err.Success():
        err_msg("Failed to read memory from address 0x{:x}.".format(dump_addr))
        result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        return

    if POINTER_SIZE == 4:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.08X]" % dump_addr + RESET)
    else:
        output(COLOR_HEXDUMP_HEADER + "[0x0000:0x%.016lX]" % dump_addr + RESET)
    output(COLOR_HEXDUMP_HEADER + "----------------------------------------------------------------------------------------" + RESET)
    output(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET + "\n")
    index = 0
    while index < size:
        (mem0, mem1, mem2, mem3) = struct.unpack("QQQQ", membuf[index : index + 0x20])
        szaddr = "0x%.016lX" % dump_addr
        if POINTER_SIZE == 4:
            szaddr = "0x%.08X" % dump_addr
        data_str = COLOR_HEXDUMP_DATA + " {:016x} {:016x} {:016x} {:016x} ".format(mem0, mem1, mem2, mem3) + RESET
        output(BOLD + COLOR_HEXDUMP_ADDR + "{:s} :".format(szaddr) + RESET + data_str + BOLD + COLOR_HEXDUMP_ASCII + "{:s}".format(quotechars(membuf[index : index + 0x20])) + RESET)
        if index + 0x20 != size:
            output("\n")
        index += 0x20
        dump_addr += 0x20
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# thx poupas :-)
def byte_to_int(b):
    if isinstance(b, int):
        return b
    return ord(b)

def hexdump(addr, chars, sep, width, lines=5):
    out = []
    line_count = 0
    while chars:
        if line_count >= lines:
            break
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, b"\000")

        szaddr = "0x%.016lX" % addr
        if POINTER_SIZE == 4:
            szaddr = "0x%.08X" % addr

        lineout = (
            BOLD + COLOR_HEXDUMP_ADDR 
            + "{:s} :".format(szaddr) 
            + RESET 
            + COLOR_HEXDUMP_DATA 
            + " {:s}{:s} ".format(sep.join( "%02X" % byte_to_int(c) for c in line ), sep) 
            + RESET 
            + BOLD + COLOR_HEXDUMP_ASCII 
            + "{:s}".format(quotechars(line)) 
            + RESET
        )
        out.append(lineout)
        addr += 0x10
        line_count = line_count + 1
    return "\n".join(out)

def quotechars( chars ):
    data = ""
    for x in bytearray(chars):
        if x >= 0x20 and x <= 0x7E:
            data += chr(x)
        else:
            data += "."
    return data

# XXX: help
# find memory command - lldb has 'memory find' but requires a start and end address where to search
# this version will seek in all available process memory regions
def cmd_findmem(debugger, command, result, dict):
    """Search memory."""
    help = """
[options]
 -s searches for specified string
 -b searches binary (eg. -b 4142434445 will find ABCDE anywhere in mem)
 -d searches dword  (eg. -d 0x41414141)
 -q searches qword  (eg. -d 0x4141414141414141)
 -f loads patern from file if it's tooooo big to fit into any of specified options
 -c specify if you want to find N occurances (default is all)
 -v verbose output
 """

    arg = str(command)
    parser = argparse.ArgumentParser(prog="findmem")
    parser.add_argument("-s", "--string",  help="Search unicode string")
    parser.add_argument("-b", "--binary",  help="Search binary string")
    parser.add_argument("-d", "--dword",   help="Find dword (native packing)")
    parser.add_argument("-q", "--qword",   help="Find qword (native packing)")
    parser.add_argument("-f", "--file",   help="Load find pattern from file")
    parser.add_argument("-c", "--count",   help="How many occurances to find, default is all")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output such as current memory region being searched")
    # XXX: problem with strings with spaces
    parser = parser.parse_args(arg.split())

    if parser.string is not None:
        search_string = parser.string.encode("utf-8")
    elif parser.binary is not None:
        if parser.binary[0:2] == "0x":
            parser.binary = parser.binary[2:]
        if is_python2():
            search_string = parser.binary.decode("hex")
        else:
            search_string = bytes.fromhex(parser.binary)

    elif parser.dword is not None:
        dword = evaluate(parser.dword)
        if dword is None:
            err_msg("Evaluating : " + parser.dword)
            return
        search_string = struct.pack("I", dword & 0xFFFFFFFF)
    elif parser.qword is not None:
        qword = evaluate(parser.qword)
        if qword is None:
            err_msg("Evaluating : " + parser.qword)
            return
        search_string = struct.pack("Q", qword & 0xFFFFFFFFFFFFFF)
    elif parser.file is not None:
        f = 0
        try:
            f = open(parser.file, "rb")
        except OSError:
            return
        search_string = f.read()
        f.close()
    else:
        err_msg("Wrong option... use findmem --help")
        return

    count = -1
    if parser.count is not None:
        count = evaluate(parser.count)
        if count is None:
            err_msg("Evaluating count : " + parser.count)
            return

    process = get_process()
    target = get_target()
    # retrieve SBMemoryRegionInfoList list
    regions = process.GetMemoryRegions()
    # iterate list of SBMemoryRegionInfo
    scan_list = []
    for i in range(0, regions.GetSize()):
        reg = lldb.SBMemoryRegionInfo()
        t = regions.GetMemoryRegionAtIndex(i, reg)
        isexec = reg.IsExecutable()
        isread = reg.IsReadable()
        iswrite = reg.IsWritable()
        tmp = []
        tmp.append(reg.GetRegionBase())
        tmp.append(reg.GetRegionEnd())
        scan_list.append(tmp)

    for x in scan_list:
        mem_name = ""
        mem_start = x[0]
        mem_end = x[1]
        mem_size = mem_end - mem_start
        if parser.verbose:
            print("[+] Searching 0x{:x} to 0x{:x} size:0x{:x}".format(mem_start, mem_end, mem_size))
        err = lldb.SBError()
        # XXX: this is going to use a lot of memory for large zones
        #      we should split reading?
        membuf = process.ReadMemory(mem_start, mem_size, err)
        if not err.Success():
            # output(str(err));
            continue
        off = 0
        base_displayed = 0
        # slice indexing starts at 0
        start_search = 0
        while True:
            if count == 0:
                return
            # we can pass slice notation here
            # the original would slice the buffer - that seems to create a new copy in Python?
            idx = membuf.find(search_string, start_search)
            if idx == -1:
                break
            if count != -1:
                count = count - 1
            # the offset is relative to the slice start
            off = idx

            if POINTER_SIZE == 4:
                ptrformat = "0x%.08X"
            else:
                ptrformat = "0x%.016lX"

            output(RESET + "Found at : ")
            output(GREEN + ptrformat % (mem_start + off) + RESET)
            if base_displayed == 0:
                output(" base : ")
                output(YELLOW + ptrformat % mem_start + RESET)
                base_displayed = 1
            else:
                output("        ")
                if POINTER_SIZE == 4:
                    output(" " * 8)
                else:
                    output(" " * 16)
            # try to find where this match address belongs to
            # this has a problem when searching the dyld cache memory area
            # the libraries that are mapped in the process do have a file path available
            # but the others that are part of it can trigger match but no file path is available
            # since they aren't linked to the target
            file_sbaddr = lldb.SBAddress(mem_start + off, target)
            module = file_sbaddr.module
            module_name = module.file.fullpath
            output(" off : 0x%.08X %s (%s)" % (off, mem_name, module_name))
            # set the slice pointer for next search
            start_search = idx + len(search_string)
    return

# display information about process memory regions similar to vmmap
# contains less information in particular the type of memory region
def cmd_showregions(debugger, command, result, dict):
    """Display memory regions information."""
    help = {
        "cmd": "showregions",
        "short": "display memory regions",
        "desc": """Display memory regions similar to vmmap (but with less information).""",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    process = get_process()
    target = get_target()
    regions = process.GetMemoryRegions()
    if POINTER_SIZE == 4:
        ptrformat = "0x{:08x} 0x{:08x} 0x{:08x} {:s}{:s}{:s} {:^16s} {:<s}"
        hdrformat = "{:^10s} {:^10s} {:^10s} {:^4s} {:^16s} {:^12s}\n-------------------------------------------------------------------------"
    else:
        ptrformat = "0x{:016x} 0x{:016x} 0x{:016x} {:s}{:s}{:s} {:^16s} {:<s}"
        hdrformat = "{:^18s} {:^18s} {:^18s} {:^4s} {:^16s} {:>12s}\n--------------------------------------------------------------------------------------------------"

    print(hdrformat.format("START", "END", "SIZE", "PROT", "TYPE", "PATH"))

    for i in range(0, regions.GetSize()):
        reg = lldb.SBMemoryRegionInfo()
        t = regions.GetMemoryRegionAtIndex(i, reg)
        r = "-"
        w = "-"
        x = "-"
        if reg.IsReadable():
            r = "r"
        if reg.IsWritable():
            w = "w"
        if reg.IsExecutable():
            x = "x"
        start = reg.GetRegionBase()
        end = reg.GetRegionEnd()
        size = end - start
        err = lldb.SBError()
        # try to find the type of region by reading some bytes
        # and matching magic values
        # XXX: we should read more bytes here?
        membuf = process.ReadMemory(start, 4, err)
        if not err.Success():
            continue
        data = struct.unpack("I", membuf)
        hdr_name = ""
        # XXX: add more magic
        if data[0] == 0xFEEDFACF:
            hdr_name = "mach-o"
        elif data[0] == 0x646C7964:
            hdr_name = "dyld cache"
        elif data[0] == 0xFEEDFACE:
            hdr_name = "mach-o"
        # try to find if addresses belong to files
        file_sbaddr = lldb.SBAddress(start, target)
        module = file_sbaddr.module
        module_name = module.file.fullpath
        if module_name is None:
            module_name = ""

        try:
            # older LLDB versions don't have this API available
            # this doesn't seem to work anyway, returning None for all regions
            name = reg.GetName()
            if name is None:
                print(ptrformat.format(start, end, size, r, w, x, hdr_name, module_name))
            else:
                print(ptrformat.format(start, end, size, r, w, x, name, module_name))
        except Exception as e:
            print(ptrformat.format(start, end, size, r, w, x, hdr_name, module_name))
    return

def cmd_datawin(debugger, command, result, dict):
    """Configure address to display in data window. Use \'datawin help\' for more information."""
    help = {
        "cmd": "datawin",
        "short": "configure data window",
        "desc": """Configure address to display in data window.
The data window display will be fixed to the address you set. Useful to observe strings being decrypted, etc.""",
        "args": "<address>",
        "options": [
            {"name": "address", "desc": "The address to display."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    global DATA_WINDOW_ADDRESS
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("Please insert an address.")
        help_msg(help)
        return

    if cmd[0] == "help":
        help_msg(help)
        return

    dump_addr = evaluate(cmd[0])
    if dump_addr is None:
        err_msg("Invalid address value.")
        help_msg(help)
        DATA_WINDOW_ADDRESS = 0
        return
    DATA_WINDOW_ADDRESS = dump_addr

# ----------------------------------------------------------
# Functions to extract internal and process lldb information
# ----------------------------------------------------------

def is_python2():
    if sys.version_info[0] < 3:
        return True
    return False

def get_arch():
    target = get_target()
    return target.triple.split("-")[0]

# return frame for stopped thread... there should be one at least...
def get_frame():
    frame = None
    # SBProcess supports thread iteration -> SBThread
    for thread in get_process():
        if thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            frame = thread.GetFrameAtIndex(0)
            break
    # this will generate a false positive when we start the target the first time because there's no context yet.
    if frame is None:
        raise Exception("[!] Warning: get_frame() failed. Is the target binary started?")
    return frame

def get_thread():
    ret = None
    # SBProcess supports thread iteration -> SBThread
    for thread in get_process():
        if thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            ret = thread
            # XXX: bug? should break?

    if ret is None:
        print("[!] Warning: get_thread() failed. Is the target binary started?")
    return ret

def get_target():
    target = lldb.debugger.GetSelectedTarget()
    if not target:
        raise Exception("[-] ERROR: No target available. Please add a target to lldb.")
    return target

def get_process():
    return get_target().GetProcess()

# evaluate an expression and return the value it represents
def evaluate(command):
    frame = get_frame()
    if frame is not None:
        value = frame.EvaluateExpression(command)
        if not value.IsValid():
            return None
        try:
            value = int(value.GetValue(), base=10)
            return value
        except Exception as e:
            err_msg("Exception on evaluate: " + str(e))
            return None
    # use the target version - if no target exists we can't do anything about it
    else:
        target = get_target()
        if target is None:
            return None
        value = target.EvaluateExpression(command)
        if not value.IsValid():
            return None
        try:
            value = int(value.GetValue(), base=10)
            return value
        except Exception as e:
            err_msg("Exception on evaluate: " + str(e))
            return None

def is_i386():
    arch = get_arch()
    return arch == "i386"

def is_x64():
    arch = get_arch()
    return arch.startswith("x86_64")

def is_arm():
    arch = get_arch()
    # Linux returns aarch64 instead of arm64* for macOS/iOS
    return arch.startswith("arm64") or arch == "aarch64"

def get_pointer_size():
    poisz = evaluate("sizeof(long)")
    return poisz

# from https://github.com/facebook/chisel/blob/main/fbchisellldbobjcruntimehelpers.py
# returns a string with an expression to evaluate to retrieve the target object
def get_instance_object():
    instanceObject = None
    if is_i386():
        # at the call to objc_msgSend esp contains object, esp+4 the selector
        instanceObject = "*(id*)($esp)"
    elif is_x64():
        instanceObject = "(id)$rdi"
    elif is_arm():
        instanceObject = "(id)$x0"
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
def get_current_sp():
    if is_i386():
        sp_addr = get_gp_register("esp")
    elif is_x64():
        sp_addr = get_gp_register("rsp")
    elif is_arm():
        sp_addr = get_gp_register("sp")
    else:
        err_msg("Wrong architecture.")
        return 0
    return sp_addr

# function that updates given register
# used for register aliases to replace individual commands per register
def cmd_update_register(debugger, command, result, dict):
    help = {
        "cmd": "update_register",
        "short": "update register value",
        "desc": """Update register with a new value.""",
        "args": "<register name> <value>",
        "options": [
            {"name": "register name", "desc": "The register name to update."},
            {"name": "value", "desc": "The new register value. Can be a single or an expression."}
        ],
        "notes": ["If using the register aliases commands, only the value is required."],
    }
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The command requires an argument.")
        help_msg(help)
        return
    if cmd[0] == "help":
        help_msg(help)
        return
    if len(cmd) != 2:
        err_msg("Missing arguments.")
        help_msg(help)
        return

    register = cmd[0]
    value = evaluate(cmd[1])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return
    # test if register exists for current arch being debugged
    valid_reg = get_frame().reg[register]
    if valid_reg is None:
        arch = get_arch()
        err_msg("Invalid register. Trying to set a register for the wrong arch? Current arch: {:s}".format(arch))
        return
    # we need to format because hex() will return string with an L and that will fail to update register
    get_frame().reg[register].value = format(value, "#x")

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
        err_msg("Unsupported architecture for this command.")
        return

    masks = {"CF":0,"PF":2,"AF":4,"ZF":6,"SF":7,"TF":8,"IF":9,"DF":10,"OF":11}
    if flag not in masks.keys():
        err_msg("Requested flag not available.")
        return
    # we invert whatever value is set
    if bool(eflags & (1 << masks[flag])):
        eflags = eflags & ~(1 << masks[flag])
    else:
        eflags = eflags | (1 << masks[flag])

    # finally update the value
    if is_x64():
        get_frame().reg["rflags"].value = format(eflags, "#x")
    elif is_i386():
        get_frame().reg["eflags"].value = format(eflags, "#x")

def modify_cpsr(flag):
    if is_x64() or is_i386():
        err_msg("Unsupported architecture for this command.")
        return

    masks = {"N":31,"Z":30,"C":29,"V":28}
    if flag not in masks.keys():
        err_msg("Requested flag not available.")
        return

    cpsr = get_gp_register("cpsr")
    # we invert whatever value is set
    if bool(cpsr & (1 << masks[flag])):
        cpsr = cpsr & ~(1 << masks[flag])
    else:
        cpsr = cpsr | (1 << masks[flag])
    get_frame().reg["cpsr"].value = format(cpsr, "#x")

# AArch64 NZCV register negative bit
def cmd_cfn(debugger, command, result, dict):
    """Change negative flag. Use \'cfn help\' for more information."""
    help = {
        "cmd": "cfn",
        "short": "flip negative flag",
        "desc": "Flip ARM64 CPSR register negative flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_cpsr("N")

# AArch NZCV register overflow bit
def cmd_cfv(debugger, command, result, dict):
    """Change overflow flag. Use \'cfv help\' for more information."""
    help = {
        "cmd": "cfv",
        "short": "flip overflow flag",
        "desc": "Flip ARM64 CPSR register overflow flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_cpsr("V")

def cmd_cfa(debugger, command, result, dict):
    """Change adjust flag. Use \'cfa help\' for more information."""
    help = {
        "cmd": "cfa",
        "short": "flip auxiliary carry flag",
        "desc": "Flip x86 EFLAGS register auxiliary carry flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("AF")

def cmd_cfc(debugger, command, result, dict):
    """Change carry flag. Use \'cfc help\' for more information."""
    help = {
        "cmd": "cfc",
        "short": "flip carry flag",
        "desc": """Flip x86/ARM64 carry flag.""",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    if is_arm():
        modify_cpsr("C")
    else:
        modify_eflags("CF")

def cmd_cfd(debugger, command, result, dict):
    """Change direction flag. Use \'cfd help\' for more information."""
    help = {
        "cmd": "cfd",
        "short": "flip direction flag",
        "desc": "Flip x86 EFLAGS register direction flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("DF")

def cmd_cfi(debugger, command, result, dict):
    """Change interrupt flag. Use \'cfi help\' for more information."""
    help = {
        "cmd": "cfi",
        "short": "flip interrupt flag",
        "desc": "Flip x86 EFLAGS register interrupt flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("IF")

def cmd_cfo(debugger, command, result, dict):
    """Change overflow flag. Use \'cfo help\' for more information."""
    help = {
        "cmd": "cfo",
        "short": "flip overflow flag",
        "desc": "Flip x86 EFLAGS register overflow flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("OF")

def cmd_cfp(debugger, command, result, dict):
    """Change parity flag. Use \'cfp help\' for more information."""
    help = {
        "cmd": "cfp",
        "short": "flip parity flag",
        "desc": "Flip x86 EFLAGS register parity flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("PF")

def cmd_cfs(debugger, command, result, dict):
    """Change sign flag. Use \'cfs help\' for more information."""
    help = {
        "cmd": "cfs",
        "short": "flip sign flag",
        "desc": "Flip x86 EFLAGS register sign flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("SF")

def cmd_cft(debugger, command, result, dict):
    """Change trap flag. Use \'cft help\' for more information."""
    help = {
        "cmd": "cft",
        "short": "flip trap flag",
        "desc": "Flip x86 EFLAGS register trap flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    modify_eflags("TF")

def cmd_cfz(debugger, command, result, dict):
    """Change zero flag. Use \'cfz help\' for more information."""
    help = {
        "cmd": "cfz",
        "short": "flip zero flag",
        "desc": "Flip x86/ARM64 zero flag.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
            help_msg(help)
            return
        err_msg("The command doesn't take any arguments.")
        help_msg(help)
        return
    if is_arm():
        modify_cpsr("Z")
    else:
        modify_eflags("ZF")

def dump_eflags(eflags):
    eflagsTuples = [("OF", 11), ("DF", 10), ("IF", 9), ("TF", 8), ("SF", 7), ("ZF", 6), ("AF", 4), ("PF", 2), ("CF", 0)]
    # use the first character of each register key to output, lowercase if bit not set
    out = ""
    for flag, bitfield in eflagsTuples:
        last = " "
        # don't print a space on last bit
        if bitfield == 0:
            last = ""
        if bool(eflags & (1 << bitfield)):
            out += flag[0] + last
        else:
            out += flag[0].lower() + last
    return out

# returns the result of a conditional AArch64 instruction and the flags condition text
# adapted from https://github.com/ant4g0nist/lisa.py/blob/dev/lisa.py
def dump_conditionalaarch64(cpsr):
    # In AArch64 state, the NZCV register holds copies of the N, Z, C, and V condition flags.
    # The processor uses them to determine whether or not to execute conditional instructions.
    # The NZCV register contains the flags in bits[31:28].
    # N: Set to 1 when the result of the operation is negative, cleared to 0 otherwise.
    # Z: Set to 1 when the result of the operation is zero, cleared to 0 otherwise.
    # C: Set to 1 when the operation results in a carry, cleared to 0 otherwise.
    # V: Set to 1 when the operation causes overflow, cleared to 0 otherwise.
    # LLDB contains this information in the CPSR register (which doesn't really exist in AArch64)

    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast"
    }

    reason_dict = {
        "eq": {True: "Z == 1", False: "Z == 0"},
        "ne": {True: "Z == 0", False: "Z == 1"},
        "hs": {True: "C == 1", False: "C == 0"},
        "lo": {True: "C == 0", False: "C == 1"},
        "lt": {True: "N != V", False: "N == V"},
        "le": {True: "Z == 1 || N != V", False: "Z == 0 && N == V"},
        "gt": {True: "Z == 0 && N == V", False: "Z == 1 || N != V"},
        "ge": {True: "N == V", False: "N != V"},
        "vs": {True: "V == 1", False: "V == 0"},
        "vc": {True: "V == 0", False: "V == 1"},
        "mi": {True: "N == 1", False: "N == 0"},
        "pl": {True: "N == 0", False: "N == 1"},
        "hi": {True: "C == 1 && Z == 0", False: "C == 0 || Z == 1"},
        "ls": {True: "C == 0 || Z == 1", False: "C == 1 && Z == 0"},
    }

    branch_mnemos = {"cbnz", "cbz", "tbnz", "tbz"}

    pc_addr = get_gp_register("pc")
    mnemo = get_mnemonic(pc_addr)
    operands = get_operands(pc_addr)
    insn = get_instruction(pc_addr)
    # failed to retrieve instruction
    if insn.size == 0:
        return False, ""
    # we can test insn.is_branch property to check if it's a branch instruction

    taken, reason = False, ""
    # skip all processing if not a branch
    if not mnemo.startswith("b.") and mnemo not in branch_mnemos is True:
        return taken, reason

    flags = dict((flags_table[k], k) for k in flags_table)

    # compare/test and branch versions
    if mnemo in branch_mnemos:
        # x are 64 bit registers, w are 32 bit
        if operands.startswith("x") or operands.startswith("w"):
            # x = re.search('([a-z0-9]{2,3})', operands)
            # extract each operand - they are comma separated
            # cb have two, tb three operands
            x = re.findall("[^,\s]+", operands)
            # if we can't read the operands it's an error
            if x is None:
                return taken, reason
        # retrieve the first operand register name
        reg = x[0]
        # and its value
        op = get_gp_register(reg)
        # now we can deal with the instructions and their conditional results
        if mnemo == "cbnz":
            if op != 0:
                taken, reason = True, "{} != 0".format(reg)
            else:
                taken, reason = False, "{} == 0".format(reg)
        elif mnemo == "cbz":
            if op == 0:
                taken, reason = True, "{} == 0".format(reg)
            else:
                taken, reason = False, "{} != 0".format(reg)
        elif mnemo == "tbnz":
            # retrieve the immediate value - 2nd operand from tb* instruction
            # the imm is preceded by a # so we remove it
            i = int(x[1][1:], 16)
            if (op & 1 << i) != 0:
                taken, reason = True, "{} & 1 << {} != 0".format(reg, i)
            else:
                taken, reason = False, "{} & 1 << {} == 0".format(reg, i)
        elif mnemo == "tbz":
            i = int(x[1][1:], 16)
            if (op & 1 << i) == 0:
                taken, reason = True, "{} & 1 << {} == 0".format(reg, i)
            else:
                taken, reason = False, "{} & 1 << {} != 0".format(reg, i)
        return taken, reason

    # process conditional branches
    if mnemo.endswith("eq"):
        taken  = bool(cpsr & (1 << flags["zero"]))
        reason = reason_dict["eq"][taken]
    elif mnemo.endswith("ne"):
        taken  = not cpsr & (1 << flags["zero"])
        reason = reason_dict["ne"][taken]
    elif mnemo.endswith("hs"):
        taken  = bool(cpsr & (1 << flags["carry"]))
    elif mnemo.endswith("lo"):
        taken  = not cpsr & (1 << flags["carry"])
        reason = reason_dict["lo"][taken]
    elif mnemo.endswith("lt"):
        taken  = bool(cpsr & (1 << flags["negative"])) != bool(cpsr & (1 << flags["overflow"]))
        reason = reason_dict["lt"][taken]
    elif mnemo.endswith("le"):
        taken  = bool(cpsr & (1 << flags["zero"])) or bool(cpsr & (1 << flags["negative"])) != bool(cpsr & (1 << flags["overflow"]))
        reason = reason_dict["le"][taken]
    elif mnemo.endswith("gt"):
        taken  = bool(cpsr & (1 << flags["zero"])) == 0 and bool(cpsr & (1 << flags["negative"])) == bool(cpsr & (1 << flags["overflow"]))
        reason = reason_dict["gt"][taken]
    elif mnemo.endswith("ge"):
        taken = bool(cpsr & (1 << flags["negative"])) == bool(cpsr & (1 << flags["overflow"]))
        reason = reason_dict["ge"][taken]
    elif mnemo.endswith("vs"):
        taken  = bool(cpsr & (1 << flags["overflow"]))
        reason = reason_dict["vs"][taken]
    elif mnemo.endswith("vc"):
        taken  = not cpsr & (1 << flags["overflow"])
        reason = reason_dict["vc"][taken]
    elif mnemo.endswith("mi"):
        taken  = bool(cpsr & (1 << flags["negative"]))
        reason = reason_dict["mi"][taken]
    elif mnemo.endswith("pl"):
        taken  = not cpsr & (1 << flags["negative"])
        reason = reason_dict["pl"][taken]
    elif mnemo.endswith("hi"):
        taken  = bool(cpsr & (1 << flags["carry"])) and not cpsr & (1 << flags["zero"])
        reason = reason_dict["hi"][taken]
    elif mnemo.endswith("ls"):
        taken  = not cpsr & (1 << flags["carry"]) or bool(cpsr & (1 << flags["zero"]))
        reason = reason_dict["ls"][taken]
    return taken, reason

# function to dump the conditional jumps results
def dump_jumpx86(eflags):
    # masks and flags from https://github.com/ant4g0nist/lisa.py
    masks = {"CF":0,"PF":2,"AF":4,"ZF":6,"SF":7,"TF":8,"IF":9,"DF":10,"OF":11}
    flags = {key: bool(eflags & (1 << value)) for key, value in masks.items()}

    error = lldb.SBError()
    target = get_target()
    if is_i386():
        pc_addr = get_gp_register("eip")
    elif is_x64():
        pc_addr = get_gp_register("rip")
    else:
        err_msg("Wrong architecture.")
        return

    mnemonic = get_mnemonic(pc_addr)
    output_string = ""
    ## opcode 0x77: JA, JNBE (jump if CF=0 and ZF=0)
    ## opcode 0x0F87: JNBE, JA
    if "ja" == mnemonic or "jnbe" == mnemonic:
        if not flags["CF"] and not flags["ZF"]:
            output_string = "Jump is taken (c = 0 and z = 0)"
        else:
            output_string = "Jump is NOT taken (c = 0 and z = 0)"
    ## opcode 0x73: JAE, JNB, JNC (jump if CF=0)
    ## opcode 0x0F83: JNC, JNB, JAE (jump if CF=0)
    elif "jae" == mnemonic or "jnb" == mnemonic or "jnc" == mnemonic:
        if not flags["CF"]:
            output_string = "Jump is taken (c = 0)"
        else:
            output_string = "Jump is NOT taken (c != 0)"
    ## opcode 0x72: JB, JC, JNAE (jump if CF=1)
    ## opcode 0x0F82: JNAE, JB, JC
    elif "jb" == mnemonic or "jc" == mnemonic or "jnae" == mnemonic:
        if flags["CF"]:
            output_string = "Jump is taken (c = 1)"
        else:
            output_string = "Jump is NOT taken (c != 1)"
    ## opcode 0x76: JBE, JNA (jump if CF=1 or ZF=1)
    ## opcode 0x0F86: JBE, JNA
    elif "jbe" == mnemonic or "jna" == mnemonic:
        if flags["CF"] or flags["ZF"] == 1:
            output_string = "Jump is taken (c = 1 or z = 1)"
        else:
            output_string = "Jump is NOT taken (c != 1 or z != 1)"
    ## opcode 0xE3: JCXZ, JECXZ, JRCXZ (jump if CX=0 or ECX=0 or RCX=0)
    # XXX: we just need cx output...
    elif "jcxz" == mnemonic or "jecxz" == mnemonic or "jrcxz" == mnemonic:
        rcx = get_gp_register("rcx")
        ecx = get_gp_register("ecx")
        cx = get_gp_register("cx")
        if ecx == 0 or cx == 0 or rcx == 0:
            output_string = "Jump is taken (cx = 0 or ecx = 0 or rcx = 0)"
        else:
            output_string = "Jump is NOT taken (cx != 0 or ecx != 0 or rcx != 0)"
    ## opcode 0x74: JE, JZ (jump if ZF=1)
    ## opcode 0x0F84: JZ, JE, JZ (jump if ZF=1)
    elif "je" == mnemonic or "jz" == mnemonic:
        if flags["ZF"] == 1:
            output_string = "Jump is taken (z = 1)"
        else:
            output_string = "Jump is NOT taken (z != 1)"
    ## opcode 0x7F: JG, JNLE (jump if ZF=0 and SF=OF)
    ## opcode 0x0F8F: JNLE, JG (jump if ZF=0 and SF=OF)
    elif "jg" == mnemonic or "jnle" == mnemonic:
        if flags["ZF"] == 0 and flags["SF"] == flags["OF"]:
            output_string = "Jump is taken (z = 0 and s = o)"
        else:
            output_string = "Jump is NOT taken (z != 0 or s != o)"
    ## opcode 0x7D: JGE, JNL (jump if SF=OF)
    ## opcode 0x0F8D: JNL, JGE (jump if SF=OF)
    elif "jge" == mnemonic or "jnl" == mnemonic:
        if flags["SF"] == flags["OF"]:
            output_string = "Jump is taken (s = o)"
        else:
            output_string = "Jump is NOT taken (s != o)"
    ## opcode: 0x7C: JL, JNGE (jump if SF != OF)
    ## opcode: 0x0F8C: JNGE, JL (jump if SF != OF)
    elif "jl" == mnemonic or "jnge" == mnemonic:
        if flags["SF"] != flags["OF"]:
            output_string = "Jump is taken (s != o)"
        else:
            output_string = "Jump is NOT taken (s = o)"
    ## opcode 0x7E: JLE, JNG (jump if ZF = 1 or SF != OF)
    ## opcode 0x0F8E: JNG, JLE (jump if ZF = 1 or SF != OF)
    elif "jle" == mnemonic or "jng" == mnemonic:
        if flags["ZF"] == 1 or flags["SF"] != flags["OF"]:
            output_string = "Jump is taken (z = 1 or s != o)"
        else:
            output_string = "Jump is NOT taken (z != 1 or s = o)"
    ## opcode 0x75: JNE, JNZ (jump if ZF = 0)
    ## opcode 0x0F85: JNE, JNZ (jump if ZF = 0)
    elif "jne" == mnemonic or "jnz" == mnemonic:
        if flags["ZF"] == 0:
            output_string = "Jump is taken (z = 0)"
        else:
            output_string = "Jump is NOT taken (z != 0)"
    ## opcode 0x71: JNO (OF = 0)
    ## opcode 0x0F81: JNO (OF = 0)
    elif "jno" == mnemonic:
        if flags["OF"] == 0:
            output_string = "Jump is taken (o = 0)"
        else:
            output_string = "Jump is NOT taken (o != 0)"
    ## opcode 0x7B: JNP, JPO (jump if PF = 0)
    ## opcode 0x0F8B: JPO (jump if PF = 0)
    elif "jnp" == mnemonic or "jpo" == mnemonic:
        if flags["PF"] == 0:
            output_string = "Jump is NOT taken (p = 0)"
        else:
            output_string = "Jump is taken (p != 0)"
    ## opcode 0x79: JNS (jump if SF = 0)
    ## opcode 0x0F89: JNS (jump if SF = 0)
    elif "jns" == mnemonic:
        if flags["SF"] == 0:
            output_string = "Jump is taken (s = 0)"
        else:
            output_string = "Jump is NOT taken (s != 0)"
    ## opcode 0x70: JO (jump if OF=1)
    ## opcode 0x0F80: JO (jump if OF=1)
    elif "jo" == mnemonic:
        if flags["OF"] == 1:
            output_string = "Jump is taken (o = 1)"
        else:
            output_string = "Jump is NOT taken (o != 1)"
    ## opcode 0x7A: JP, JPE (jump if PF=1)
    ## opcode 0x0F8A: JP, JPE (jump if PF=1)
    elif "jp" == mnemonic or "jpe" == mnemonic:
        if flags["PF"] == 1:
            output_string = "Jump is taken (p = 1)"
        else:
            output_string = "Jump is NOT taken (p != 1)"
    ## opcode 0x78: JS (jump if SF=1)
    ## opcode 0x0F88: JS (jump if SF=1)
    elif "js" == mnemonic:
        if flags["SF"] == 1:
            output_string = "Jump is taken (s = 1)"
        else:
            output_string = "Jump is NOT taken (s != 1)"

    # XXX: we should just return a string and the caller should do this work instead
    if output_string:
        if is_i386():
            if "NOT" in output_string:
                output(" " + COLOR_CONDITIONAL_NO + "=> {:s}".format(output_string) + RESET)
            else:
                output(" " + COLOR_CONDITIONAL_YES + "=> {:s}".format(output_string) + RESET)
        elif is_x64():
            if "NOT" in output_string:
                output("  " + COLOR_CONDITIONAL_NO + "=> {:s}".format(output_string) + RESET)
            else:
                output("  " + COLOR_CONDITIONAL_YES + "=> {:s}".format(output_string) + RESET)

def showreg64(reg, val):
    output(COLOR_REGNAME + "  {:>3s}: ".format(reg.upper()) + RESET)
    c = COLOR_REGVAL_MODIFIED
    if val == old_x64[reg]:
        c = COLOR_REGVAL
    output(c + "0x%.016lX" % (val) + RESET)
    old_x64[reg] = val

def reg64():
    current = get_gp_registers()
    # first register line + rflags
    line = [ "rax", "rbx", "rbp", "rsp" ]
    for reg in line:
        r = current[reg]
        showreg64(reg, r)

    output("  ")
    # align flags right side
    output("      ")
    rflags = current["rflags"]
    f = dump_eflags(rflags)
    output(COLOR_CPUFLAGS + f + RESET)
    output("\n")

    # second register line
    line = ["rdi", "rsi", "rdx", "rcx", "rip"]
    for reg in line:
        r = current[reg]
        showreg64(reg, r)
    output("\n")

    # third register line
    line = ["r8", "r9", "r10", "r11", "r12"]
    for reg in line:
        r = current[reg]
        showreg64(reg, r)
    output("\n")

    # fourth register line + jump decision if exists
    line = ["r13", "r14", "r15"]
    for reg in line:
        r = current[reg]
        showreg64(reg, r)
    rflags = current["rflags"]
    dump_jumpx86(rflags)
    output("\n")

    # last register line
    line = ["cs", "fs", "gs"]
    for reg in line:
        r = current[reg]
        output(COLOR_REGNAME + "  {:>3s}: ".format(reg.upper()))
        c = COLOR_REGVAL_MODIFIED
        if r == old_x64[reg]:
            c = COLOR_REGVAL
        output(c + "%.04X" % (r) + RESET)
        old_x64[reg] = r
    output("\n")

def showreg32(reg, val):
    output(COLOR_REGNAME + "  {:>3s}: ".format(reg.upper()) + RESET)
    c = COLOR_REGVAL_MODIFIED
    if val == old_x86[reg]:
        c = COLOR_REGVAL
    output(c + "0x%.08X" % (val) + RESET)
    old_x86[reg] = val

def reg32():
    current = get_gp_registers()
    # first register line + eflags
    line = ["eax", "ebx", "ecx", "edx"]
    for reg in line:
        r = current[reg]
        showreg32(reg, r)
    output("  ")
    eflags = current["eflags"]
    f = dump_eflags(eflags)
    output(COLOR_CPUFLAGS + f + RESET)
    output("\n")
    # second register line
    line = ["esi", "edi", "ebp", "esp", "eip"]
    for reg in line:
        r = current[reg]
        showreg32(reg, r)
    output("\n")
    # last register line + jump decision if exists
    line = ["cs", "ds", "es", "fs", "gs", "ss"]
    for reg in line:
        r = current[reg]
        output(COLOR_REGNAME + "  {:>3s}: ".format(reg.upper()))
        c = COLOR_REGVAL_MODIFIED
        if r == old_x86[reg]:
            c = COLOR_REGVAL
        output(c + "%.04X" % (r) + RESET)
        old_x86[reg] = r

    eflags = current["eflags"]
    dump_jumpx86(eflags)
    output("\n")

def dump_cpsr(cpsr):
    # XXX: some fields reserved in recent ARM specs so we should revise and set to latest?
    # AArch32 - unused
    cpsrTuples32 = [("N", 31), ("Z", 30), ("C", 29), ("V", 28), ("Q", 27), ("SSBS", 23),
                   ("PAN", 22), ("DIT", 21), ("E", 9), ("A", 8), ("I", 7), ("F", 6)]
    # AArch64 - CPSR doesn't exist here
    # https://developer.arm.com/documentation/den0024/a/Fundamentals-of-ARMv8
    # https://medium.com/@deryugin.denis/poring-os-to-aarch64-a0a5dfa38c5d
    # DAIF register holds A (SError interrupt mask), I (IRQ mask), F (FIQ mask) bits of old CPSR
    # NZCV register holds N Z C V bits
    # LLDB keeps the same information in the "emulated" cpsr register
    cpsrTuples64 = [("N", 31), ("Z", 30), ("C", 29), ("V", 28), ("A", 8), ("I", 7), ("F", 6)]

    # use the first character of each register key to output, lowercase if bit not set
    allFlags = ""
    for flag, bitfield in cpsrTuples64 :
        last = " "
        # don't print space on last bit
        if bitfield == 6:
            last = ""
        if bool(cpsr & (1 << bitfield)):
            allFlags += flag + last
        else:
            allFlags += flag.lower() + last
    return allFlags

def regarm64():
    current = get_gp_registers()
    # register display order (4 columns)
    display = [
        ["x0", "x8",  "x16", "x24"],
        ["x1", "x9",  "x17", "x25"],
        ["x2", "x10", "x18", "x26"],
        ["x3", "x11", "x19", "x27"],
        ["x4", "x12", "x20", "x28"],
        ["x5", "x13", "x21", "fp"],
        ["x6", "x14", "x22", "lr"],
        ["x7", "x15", "x23", "sp"],
    ]
    for row in display:
        for col in row:
            reg_name = col
            output(COLOR_REGNAME + "  {:>3s}:  ".format(reg_name.upper()) + RESET)
            reg_value = current[reg_name]
            if reg_value == old_arm64[reg_name]:
                c = COLOR_REGVAL
            else:
                c = COLOR_REGVAL_MODIFIED
            output(c + "0x%.016X" % (reg_value) + RESET)
            old_arm64[reg_name] = reg_value
        output("\n")

    output(COLOR_REGNAME + "   PC:  ")
    pc = current["pc"]
    if pc == old_arm64["pc"]:
        c = COLOR_REGVAL
    else:
        c = COLOR_REGVAL_MODIFIED
    output(c + "0x%.016X" % (pc) + RESET)
    old_arm64["pc"] = pc
    output(" ")
    cpsr = current["cpsr"]
    taken, reason = dump_conditionalaarch64(cpsr)
    # add the () between the reason message
    if reason != "":
        reason = "({:s})".format(reason)
    # format the rest of the line according to conditional or lack of
    if taken:
        linefmt = " " + COLOR_CPUFLAGS + "{:s}" + RESET + "             " + COLOR_CONDITIONAL_YES + "=> Taken " + "{:s}" + RESET
    elif reason != "":
        linefmt = " " + COLOR_CPUFLAGS + "{:s}" + RESET + "             " + COLOR_CONDITIONAL_NO + "=> Not taken " + "{:s}" + RESET
    else:
        linefmt = " " + COLOR_CPUFLAGS + "{:s}" + RESET + "{:s}"
    flags = dump_cpsr(cpsr)
    # XXX: should flags be always red? red in registers means they changed
    output(linefmt.format(flags, reason) + "\n")

def print_registers():
    if is_i386():
        reg32()
    elif is_x64():
        reg64()
    elif is_arm():
        regarm64()

# ------------------------------
# Disassembler related functions
# ------------------------------

"""
    Handles 'u' command which displays instructions. Also handles output of
    'disassemble' command ...
"""
# XXX: help
def cmd_DumpInstructions(debugger, command, result, dict):
    """Dump instructions at certain address (SoftICE like u command style)."""
    help = """ """

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

    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)

# return the SBInstruction at input address
def get_instruction(target_addr):
    err = lldb.SBError()
    target = get_target()
    # flavor argument only relevant to x86 targets - seems to work with ARM anyway
    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1)
    if instruction_list.GetSize() == 0:
        err_msg("Not enough instructions disassembled.")
        return lldb.SBInstruction()
    return instruction_list.GetInstructionAtIndex(0)

# return the instruction mnemonic at input address
def get_mnemonic(target_addr):
    err = lldb.SBError()
    target = get_target()
    # flavor argument only relevant to x86 targets - seems to work with ARM anyway
    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1)
    if instruction_list.GetSize() == 0:
        err_msg("Not enough instructions disassembled.")
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
    instruction_list = target.ReadInstructions(src_sbaddr, 1)
    if instruction_list.GetSize() == 0:
        err_msg("Not enough instructions disassembled.")
        return ""
    cur_instruction = instruction_list[0]
    return cur_instruction.GetOperands(target)

# find out the size of an instruction using internal disassembler
def get_inst_size(target_addr):
    err = lldb.SBError()
    target = get_target()

    instruction_list = target.ReadInstructions(lldb.SBAddress(target_addr, target), 1)
    if instruction_list.GetSize() == 0:
        err_msg("Not enough instructions disassembled.")
        return 0

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    return cur_instruction.size

# the disassembler we use on stop context
# we can customize output here instead of using the cmdline as before and grabbing its output
def disassemble(start_address, nrlines):
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
    # flavor argument only relevant to x86 targets - works fine with ARM like this
    instructions_mem = target.ReadInstructions(mem_sbaddr, nrlines)
    instructions_file = target.ReadInstructions(file_sbaddr, nrlines)
    if instructions_mem.GetSize() != instructions_file.GetSize():
        err_msg("Instructions arrays sizes are different.")
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
    # module_name = module.file.GetFilename()
    module_name = module.file.fullpath
    if module_name is not None:
        module_name = os.path.abspath(module_name)

    count = 0
    blockstart_symaddr = None
    blockend_symaddr = None
    for mem_inst in instructions_mem:
        # get the same instruction but from the file version because we need some info from it
        file_inst = instructions_file[count]
        # try to extract the symbol (function) name from this location if it exists
        # needs to be referenced to file because memory it doesn't work
        symbol_name = instructions_file[count].addr.GetSymbol().GetName()
        # if there is no symbol just display module where current instruction is
        # also get rid of unnamed symbols since they are useless
        if symbol_name is None or "___lldb_unnamed_symbol" in symbol_name:
            if count == 0:
                if CONFIG_ENABLE_COLOR == 1:
                    output(COLOR_SYMBOL_NAME + "@ {}:".format(module_name) + "\n" + RESET)
                else:
                    output("@ {}:".format(module_name) + "\n")
        elif symbol_name is not None:
            # print the first time there is a symbol name and save its interval
            # so we don't print again until there is a different symbol
            file_symaddr = file_inst.GetAddress().GetFileAddress()
            if blockstart_symaddr is None or (file_symaddr < blockstart_symaddr) or (file_symaddr >= blockend_symaddr):
                if CONFIG_ENABLE_COLOR == 1:
                    output(COLOR_SYMBOL_NAME + "{} @ {}:".format(symbol_name, module_name) + "\n" + RESET)
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
        # file_addr = mem_inst.addr.GetFileAddress()
        file_addr = file_inst.addr.GetFileAddress()

        comment = ""
        # start at lldb automatic comments, if available
        # XXX: this might return bad characters and breaks the output when using the old PutCString() method
        #      only valid for older lldb versions?
        # XXX: might want to set a warning if this happens?
        if file_inst.GetComment(target) != "":
            comment = " ; " + file_inst.GetComment(target)

        # retrieve the base address of the module where the address belongs to
        # the comments offsets are relative to this
        # it's ok to use the module variable we got from file_sbaddr
        inst_base = get_module_base(module)
        user_comment = ""
        if inst_base > 0 and g_sessiondata != {}:
            # not the most efficient way to do this but converting to hash table is going to increase complexity
            # for almost no benefit speed wise (unless the number of comments is huge)
            mod_uuid = mem_inst.addr.module.GetUUIDString().lower()
            for k in g_sessiondata["comments"]:
                i = int(k["offset"], 16)
                if (k["uuid"] == mod_uuid) and (i + inst_base == memory_addr):
                    user_comment = COLOR_COMMENT + k["text"] + RESET
                    break

        header = 0
        if current_pc == memory_addr:
            header = 1
            # try to retrieve extra information if it's a branch instruction
            # used to resolve indirect branches and try to extract Objective-C selectors
            if mem_inst.DoesBranch():
                flow_addr = get_indirect_flow_address(mem_inst.GetAddress().GetLoadAddress(target))
                if flow_addr > 0:
                    flow_module_name = get_module_name(flow_addr)
                    symbol_info = ""
                    # try to solve the symbol for the target address
                    target_symbol_name = lldb.SBAddress(flow_addr, target).GetSymbol().GetName()
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
                        comment += " " + hex(flow_addr) + " @ " + flow_module_name
                # for arm64 targets there is a branch to a subroutine that does the real call to the objc_msgSend
                # and the selector string is there - the symbol name does contain the name
                # so we can either extract it from here or read the information from the subroutine
                # or not worth the trouble since the symbol name always has lots of info
                className, selectorName = get_objectivec_selector(current_pc)
                if className != "":
                    if selectorName != "":
                        comment += " -> " + "[" + className + " " + selectorName + "]"
                    else:
                        comment += " -> " + "[" + className + "]"

        # append or set user comment
        if user_comment != "":
            if comment != "":
                comment += " " + user_comment
            else:
                comment = " ; " + user_comment
        # first line is different from the rest
        if header:
            output(COLOR_CURRENT_PC + "->  0x{:x} (0x{:x}): {}  {}   {}{:s}\n".format(memory_addr, file_addr, bytes_string, mnem, operands, comment) + RESET)
        else:
            output("    0x{:x} (0x{:x}): {}  {}   {}{:s}\n".format(memory_addr, file_addr, bytes_string, mnem, operands, comment))

        count += 1

    return

# ------------------------------------
# Commands that use external utilities
# ------------------------------------

def cmd_show_loadcmds(debugger, command, result, dict):
    """Show otool output of Mach-O load commands. Use \'show_loadcmds\' for more information."""
    help = {
        "cmd": "show_loadcmds",
        "short": "display Mach-O load commands",
        "desc": "Display the 'otool' output of Mach-O load commands.",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The address of the Mach-O header in memory."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    error = lldb.SBError()
    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        header_addr = evaluate(cmd[0])
        if header_addr is None:
            err_msg("Invalid header address value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a valid Mach-O header address.")
        help_msg(help)
        return

    if not os.path.isfile("/usr/bin/otool"):
        err_msg("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
        return

    bytes_string = get_process().ReadMemory(header_addr, 4096 * 10, error)
    if not error.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(header_addr))
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
    """Show otool output of Mach-O header. Use \'show_header\' for more information."""
    help = {
        "cmd": "show_header",
        "short": "display Mach-O header",
        "desc": "Display the 'otool' output of Mach-O header.",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The address of the Mach-O header in memory."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
    }
    error = lldb.SBError()
    cmd = command.split()
    if len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help)
           return
        header_addr = evaluate(cmd[0])
        if header_addr is None:
            err_msg("Invalid header address value.")
            help_msg(help)
            return
    else:
        err_msg("Please insert a valid Mach-O header address.")
        help_msg(help)
        return

    if not os.path.isfile("/usr/bin/otool"):
        err_msg("/usr/bin/otool not found. Please install Xcode or Xcode command line tools.")
        return

    # recent otool versions will fail so we need to read a reasonable amount of memory
    # even just for the mach-o header
    bytes_string = get_process().ReadMemory(header_addr, 4096 * 10, error)
    if not error.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(header_addr))
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
    ks = keystone.Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    print("\nKeystone output:\n----------")
    for inst in code:
        try:
            encoding, count = ks.asm(inst)
        except keystone.KsError as e:
            err_msg("Keystone failed to assemble: {:s}".format(e))
            return
        output = []
        output.append(inst)
        output.append("->")
        for i in encoding:
            output.append("{:02x}".format(i))
        print(" ".join(output))

def cmd_asm32(debugger, command, result, dict):
    """32 bit x86 interactive Keystone based assembler. Use \'asm32 help\' for more information."""
    help = {
        "cmd": "asm32",
        "short": "interactive 32 bit x86 assembler",
        "desc": """Interactive 32 bit x86 assembler based on Keystone.
Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_32.""",
        "args": "",
        "notes": ["Requires Keystone and Python bindings from www.keystone-engine.org."],
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    inst_list = []
    while True:
        try:
            line = raw_input('Assemble ("stop" or "end" to finish): ')
        except NameError:
            line = input('Assemble ("stop" or "end" to finish): ')
        if line == "stop" or line == "end":
            break
        inst_list.append(line)

    assemble_keystone(keystone.KS_ARCH_X86, keystone.KS_MODE_32, inst_list)

def cmd_asm64(debugger, command, result, dict):
    """64 bit x86 interactive Keystone based assembler. Use \'asm64 help\' for more information."""
    help = {
        "cmd": "asm64",
        "short": "interactive 64 bit x86 assembler",
        "desc": """Interactive 64 bit x86 assembler based on Keystone.
Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_X86 and KS_MODE_64.""",
        "args": "",
        "notes": ["Requires Keystone and Python bindings from www.keystone-engine.org."],
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    inst_list = []
    while True:
        try:
            line = raw_input('Assemble ("stop" or "end" to finish): ')
        except NameError:
            line = input('Assemble ("stop" or "end" to finish): ')
        if line == "stop" or line == "end":
            break
        inst_list.append(line)

    assemble_keystone(keystone.KS_ARCH_X86, keystone.KS_MODE_64, inst_list)

def cmd_arm32(debugger, command, result, dict):
    """32 bit ARM interactive Keystone based assembler. Use \'arm32 help\' for more information."""
    help = {
        "cmd": "arm32",
        "short": "interactive 32 bit ARM assembler",
        "desc": """Interactive 32 bit ARM assembler based on Keystone.
Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_ARM.""",
        "args": "",
        "notes": ["Requires Keystone and Python bindings from www.keystone-engine.org."],
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    inst_list = []
    while True:
        try:
            line = raw_input('Assemble ("stop" or "end" to finish): ')
        except NameError:
            line = input('Assemble ("stop" or "end" to finish): ')
        if line == "stop" or line == "end":
            break
        inst_list.append(line)

    assemble_keystone(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM, inst_list)

def cmd_armthumb(debugger, command, result, dict):
    """32 bit ARM Thumb interactive Keystone based assembler. Use \'armthumb help\' for more information."""
    help = {
        "cmd": "armthumb",
        "short": "interactive 32 bit ARM Thumb assembler",
        "desc": """Interactive 32 bit ARM Thumb assembler based on Keystone.
Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM and KS_MODE_THUMB.""",
        "args": "",
        "notes": ["Requires Keystone and Python bindings from www.keystone-engine.org."],
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    inst_list = []
    while True:
        try:
            line = raw_input('Assemble ("stop" or "end" to finish): ')
        except NameError:
            line = input('Assemble ("stop" or "end" to finish): ')
        if line == "stop" or line == "end":
            break
        inst_list.append(line)

    assemble_keystone(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB, inst_list)

def cmd_arm64(debugger, command, result, dict):
    """64 bit ARM interactive Keystone based assembler. Use \'arm64 help\' for more information."""
    help = {
        "cmd": "arm64",
        "short": "interactive 64 bit ARM assembler",
        "desc": """Interactive 64 bit ARM assembler based on Keystone.
Type one instruction per line. Finish with \'end\' or \'stop\'.
Keystone set to KS_ARCH_ARM64 and KS_MODE_ARM.""",
        "args": "",
        "notes": ["Requires Keystone and Python bindings from www.keystone-engine.org."],
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help)
        return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    inst_list = []
    while True:
        try:
            line = raw_input('Assemble ("stop" or "end" to finish): ')
        except NameError:
            line = input('Assemble ("stop" or "end" to finish): ')
        if line == "stop" or line == "end":
            break
        inst_list.append(line)

    assemble_keystone(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN, inst_list)

def display_stack():
    """Hex dump current stack pointer."""
    stack_addr = get_current_sp()
    if stack_addr == 0:
        return
    err = lldb.SBError()
    target = get_target()
    membuf = get_process().ReadMemory(stack_addr, 0x100, err)
    if not err.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(stack_addr))
        return
    if len(membuf) == 0:
        err_msg("Not enough bytes read.")
        return
    output(hexdump(stack_addr, membuf, " ", 16, 4))

def display_data():
    """Hex dump current data window pointer."""
    data_addr = DATA_WINDOW_ADDRESS
    print(data_addr)
    if data_addr == 0:
        return
    err = lldb.SBError()
    target = get_target()
    membuf = get_process().ReadMemory(data_addr, 0x100, err)
    if not err.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(data_addr))
        return
    if len(membuf) == 0:
        err_msg("Not enough bytes read.")
        return
    output(hexdump(data_addr, membuf, " ", 16, 4))

# workaround for lldb bug regarding RIP addressing outside main executable
def get_rip_relative_addr(src_address):
    err = lldb.SBError()
    target = get_target()
    inst_size = get_inst_size(src_address)
    if inst_size <= 1:
        err_msg("The instruction size is too small.")
        return 0
    # XXX: problem because it's not just 2 and 5 bytes
    # 0x7fff53fa2180 (0x1180): 0f 85 84 01 00 00     jne    0x7fff53fa230a ; stack_not_16_byte_aligned_error

    offset_bytes = get_process().ReadMemory(src_address + 1, inst_size - 1, err)
    if not err.Success():
        err_msg("Failed to read memory at 0x{:x}.".format(src_address))
        return 0
    if inst_size == 2:
        data = struct.unpack("b", offset_bytes)
    elif inst_size == 5:
        data = struct.unpack("i", offset_bytes)
    rip_call_addr = src_address + inst_size + data[0]
    # output("source {:x} rip call offset {:x} {:x}\n".format(src_address, data[0], rip_call_addr))
    return rip_call_addr

# find out the target address of an indirect instruction
# such as memory references and registers but also RIP relative calls
def get_indirect_flow_target(src_address):
    err = lldb.SBError()
    operand = get_operands(src_address).lower()
    mnemonic = get_mnemonic(src_address)
    # XXX: check allowed instructions here ?

    # calls into a deferenced memory address (intel only)
    if "word" in operand:
        # output("dereferenced call\n")
        deref_addr = 0
        # first we need to find the address to dereference
        # we can simplify by extracting just the contents and sending for evaluation
        # we can have three cases
        # reg + offset
        # reg - offset
        # reg
        z = re.search(r"\[(.*?)\]", operand)
        # we need to transform the register into a variable
        # register + offset cases
        if z.group(1).startswith("r") or z.group(1).startswith("e"):
            value = get_frame().EvaluateExpression("$" + z.group(1))
        # only offset
        else:
            value = get_frame().EvaluateExpression(z.group(1))

        if not value.IsValid():
            return 0
        deref_addr = int(value.GetValue(), 10)
        if "rip" in operand:
            deref_addr = deref_addr + get_inst_size(src_address)
        # simpler than using ReadUnsignedFromMemory()
        call_target_addr = get_process().ReadPointerFromMemory(deref_addr, err)
        if err.Success():
            return call_target_addr
        else:
            return 0
    # calls into a register - x86_64, i386, aarch64 (register or blr/br*)
    # aarch64:
    # BRAA Xn, Xm/SP    : 30 08 1F D7 BRAA X1, X16
    # BRAAZ Xn          : 3F 08 1F D6 BRAAZ X1
    # BRAB Xn, Xm/SP
    # BRABZ Xn
    # BLRAA Xn, Xm/SP   : 28 09 3F D7 BLRAA X9, X8
    # BLRAAZ Xn         : 1F 0A 3F D6 BLRAAZ X16
    # BLRAB Xn, Xm/SP
    # BLRABZ Xn
    elif operand.startswith("r") or operand.startswith("e") or operand.startswith("x"):
        # these are PAC instructions that contain a modifier in a second register
        # the modifier is zero for Z terminated functions so we only see one operand
        if mnemonic in ("braa", "brab", "blraa", "blrab"):
            operand = operand.split(",")[0].strip(" ")
            # remove the PAC
            # XXX: what is really the number of bits? can't find good documentation on this :(
            # https://github.com/lelegard/arm-cpusysregs/blob/main/docs/arm64e-on-macos.md
            # says it's 47 bits for macOS
            # https://googleprojectzero.blogspot.com/2019/02/examining-pointer-authentication-on.html
            # talks about higher number of bits for iOS
        # XXX: why use the evaluate expression if we can extract the register directly?
        value = get_frame().EvaluateExpression("$" + operand)
        if not value.IsValid():
            return 0
        ret = int(value.GetValue(), 10)
        if mnemonic in ("braa", "braaz", "brab", "brabz", "blraa", "blraaz", "blrab", "blrabz"):
            # let's go with 47 bits for now...
            ret &= 0xFFFFFFFFFFFF
        return ret
    # RIP relative calls
    # the disassembly output already contains the target address so we just need to extract it
    # and don't need to compute anything ourselves
    elif operand.startswith("0x"):
        # the disassembler already did the dirty work for us
        # so we just extract the address
        x = re.search("(0x[0-9a-z]+)", operand)
        if x is not None:
            return int(x.group(1), 16)
    return 0

def get_ret_address(pc_addr):
    if is_arm():
        target = get_target()
        instruction = get_instruction(pc_addr)
        mnemonic = instruction.GetMnemonic(target)
        operands = instruction.GetOperands(target)
        lr = get_gp_register("lr")
        if lr == 0:
            err_msg("Failed to retrieve LR register.")
            return -1

        if mnemonic == "ret":
            # ret - x30 (LR) is default, register can be specified
            if len(operands) == 0:
                return lr
            # 20 00 5f d6 - ret x1
            elif operands.startswith("x") and len(operands) <= 3:
                ret = get_gp_register(operands)
                return ret
            else:
                err_msg("More than one operand in ret instruction.")
                return -1
        elif mnemonic in ("retaa", "retab"):
            # PAC versions: retaa and retab - use LR
            # https://developer.arm.com/documentation/dui0801/h/A64-General-Instructions/RETAA--RETAB
            return lr
    else:
        err = lldb.SBError()
        stack_addr = get_current_sp()
        if stack_addr == 0:
            return -1
        ret_addr = get_process().ReadPointerFromMemory(stack_addr, err)
        if not err.Success():
            err_msg("Failed to read memory at 0x{:x}.".format(stack_addr))
            return -1
        return ret_addr

def is_sending_objc_msg():
    err = lldb.SBError()
    target = get_target()
    call_addr = get_indirect_flow_target(get_current_pc())
    sym_addr = lldb.SBAddress(call_addr, target)
    symbol = sym_addr.GetSymbol()
    # XXX: add others?
    return symbol.name in ("objc_msgSend")

# displays the contents of the flow window (disabled by default)
# pretty much information about indirect references and objective-c where available
def display_indirect_flow():
    target = get_target()
    pc_addr = get_current_pc()
    mnemonic = get_mnemonic(pc_addr)

    # x86 and arm64 (including pac versions)
    if mnemonic.startswith("ret"):
        indirect_addr = get_ret_address(pc_addr)
        output("0x%x -> %s" % (indirect_addr, lldb.SBAddress(indirect_addr, target).GetSymbol().name))
        output("\n")
        return

    if mnemonic in ("call", "callq", "jmp", "br", "bl", "b", "braa", "braaz", "brab", "brabz", "blraa", "blraaz", "blrab", "blrabz"):
        # we need to identify the indirect target address
        indirect_addr = get_indirect_flow_target(pc_addr)
        output("0x%x -> %s" % (indirect_addr, lldb.SBAddress(indirect_addr, target).GetSymbol().name))

        if is_sending_objc_msg():
            output("\n")
            className, selectorName = get_objectivec_selector(pc_addr)
            if className != "":
                output(RED + "Class: " + RESET)
                output(className)
                if selectorName != "":
                    output(RED + " Selector: " + RESET)
                    output(selectorName)
        output("\n")
    return

# find out the target address of ret, and indirect call and jmp
def get_indirect_flow_address(src_addr):
    target = get_target()
    instruction_list = target.ReadInstructions(lldb.SBAddress(src_addr, target), 1)
    if instruction_list.GetSize() == 0:
        err_msg("Not enough instructions disassembled.")
        return -1

    cur_instruction = instruction_list.GetInstructionAtIndex(0)
    if not cur_instruction.DoesBranch():
        return -1

    if cur_instruction.GetMnemonic(target).startswith("ret"):
        ret_addr = get_ret_address(src_addr)
        return ret_addr
    elif cur_instruction.GetMnemonic(target) in ("call", "jmp"):
        # don't care about RIP relative jumps
        if cur_instruction.GetOperands(target).startswith("0x"):
            return -1
        indirect_addr = get_indirect_flow_target(src_addr)
        return indirect_addr
    elif cur_instruction.GetMnemonic(target) in ("br", "blr", "braa", "braaz", "brab", "brabz", "blraa", "blraaz", "blrab", "blrabz"):
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

# tries to retrieve the class name of object being sent a message and the selector
def get_objectivec_selector(src_addr):
    options = lldb.SBExpressionOptions()
    options.SetLanguage(lldb.eLanguageTypeObjC)
    options.SetTrapExceptions(False)

    err = lldb.SBError()
    target = get_target()
    process = get_process()

    call_addr = get_indirect_flow_target(src_addr)
    if call_addr == 0:
        return "", ""

    # first verify if it's the right symbol
    sym_addr = lldb.SBAddress(call_addr, target)
    symbol = sym_addr.GetSymbol()
    if not symbol.IsValid():
        return "", ""
    # XXX: add others?
    if not symbol.name.startswith("objc_msgSend"):
        return "", ""

    # expr -- (void)printf("[%s, %s]\n",(char *) object_getClassName(*(long*)($rdi)), (char *) *(long *)($rsi) )
    # if the target isn't compiled with obj-c information we get this error and crash (-ObjC option to the compiler)
    # warning: could not execute support code to read Objective-C class data in the process. This may reduce the quality of type information available.
    classname_command = "(const char *)object_getClassName((id){})".format(get_instance_object())
    classname_value = get_frame().EvaluateExpression(classname_command)
    # IsValid() doesn't seem that useful because if there is an error it still returns true
    # we can check the error property or the size of the data for example
    # https://lldb.llvm.org/python_api/lldb.SBValue.html?highlight=sbvalue
    if not classname_value.IsValid() or classname_value.size == 0:
        return "", ""
    className = classname_value.GetSummary().strip('"')
    # get pointer to selector string
    if is_x64():
        selector_addr = get_gp_register("rsi")
    elif is_arm():
        selector_addr = get_gp_register("x1")
    elif is_i386:
        # selector pointer is at esp+4
        src = get_gp_register("esp")
        src += 4
        selector_addr = process.ReadPointerFromMemory(src, err)
        if not err.Success():
            err_msg("Failed to read selector address from 0x{:x}.".format(src))
            return className, ""
    # XXX: verify that address makes some sense?
    # read selector string
    methodName = process.ReadCStringFromMemory(selector_addr, 0x100, err)
    if not err.Success():
        err_msg("Failed to read selector string from 0x{:x}.".format(selector_addr))
        # XXX: do we need to return here or methodName is empty?

    if len(methodName) != 0:
        return className, methodName
    else:
        return className, ""

# -----------------
#  CUSTOM COMMANDS
# -----------------

def cmd_fixret(debugger, command, result, dict):
    """Fix return breakpoint. Use \'fixret help\' for more information."""
    help = {
    "cmd": "fixret",
    "short": "fix return breakpoint anti-debugging",
    "desc": "Fix return breakpoint anti-debugging.",
    "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    target = get_target()
    frame = get_frame()
    if frame is None:
        return
    thread = frame.GetThread()
    rsp = int(frame.FindRegister("rsp").GetValue(), 16)
    # print(hex(rsp))
    error = lldb.SBError()
    ret_addr = get_process().ReadUnsignedFromMemory(rsp, 8, error)
    if not error.Success():
        err_msg("Failed to read RSP.")
        return
    # print("[DEBUG] return address is {0}".format(hex(ret_addr)))
    get_frame().reg["rip"].value = format(ret_addr, "#x")
    rsp = rsp + 0x8
    get_frame().reg["rsp"].value = format(rsp, "#x")
    if len(cmd) == 0:
        get_process().Continue()

# return the module to which an address belongs to
# XXX: duplicate of get_module_name()
def aux_find_module(address):
    target = get_target()
    addr = lldb.SBAddress(address, target)
    module = addr.module
    if DEBUG:
        print(module.file.basename, module.file.fullpath)
    return module

def get_module_base(module):
    if module is None:
        return -1
    if module.num_sections == 0:
        return -1
    target = get_target()
    # if __PAGEZERO exists it returns -1 for the value
    if module.sections[0].GetLoadAddress(target) != 0xFFFFFFFFFFFFFFFF:
        return module.sections[0].GetLoadAddress(target)
    # so we assume it's the next segment that is valid (which is the regular case)
    else:
        return module.sections[1].GetLoadAddress(target)

def get_module_offset(address, module):
    target = get_target()
    addr = lldb.SBAddress(address, target)
    segment_nr = 0
    base = get_module_base(module)
    return addr.GetLoadAddress(target) - base

def cmd_addcomment(debugger, command, result, dict):
    """Add comment to address. Use \'acm help\' for more information."""
    help = {
        "cmd": "acm",
        "short": "add disassembly comment",
        "desc": "Add comment to target address.",
        "args": "<address> <comment>",
        "options": [
            {"name": "address", "desc": "The address to comment."},
            {"name": "comment", "desc": "The comment content. Spaces are allowed."}
        ],
        "notes": ["Comments are saved automatically to session storage."],
    }
    global g_sessiondata
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if len(cmd) < 2:
        err_msg("Please insert an address and comment.")
        help_msg(help)
        return
    # the json is only loaded/created on first hook stop
    if "comments" not in g_sessiondata:
        err_msg("Please start the target before using this command.")
        return

    # XXX: the value can be anything but if it doesn't match a disassembly address it will not be displayed
    #      kind of not our problem - we could solve to nearest address but maybe waste of time anyway
    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    # check if it's a dupe - we just update comment in that case
    module = aux_find_module(value)
    offset = get_module_offset(value, module)
    mod_uuid = module.GetUUIDString().lower()
    found = None
    if len(g_sessiondata["comments"]) > 0:
        for item in g_sessiondata["comments"]:
            if (item["uuid"] == mod_uuid) and (item["offset"] == hex(offset)):
                found = item
                break

    # since we split the command string we should join everything else past the address as comment
    # XXX: is there a better solution here?
    comment = " ".join([str(item) for item in cmd[1:]])

    if found is None:
        g_sessiondata["comments"].append({
            "offset": hex(offset),  # always from the base address of the module
            "text": comment,
            "uuid": module.GetUUIDString().lower(),
            "module": os.path.abspath(module.file.fullpath)
            })
    # for dupes we just update the comment
    else:
        found["text"] = comment

    save_json_session(g_sessionfile)
    print("[+] Added comment at address {}".format(hex(value)))
    if DEBUG:
        print(g_sessiondata)

def cmd_delcomment(debugger, command, result, dict):
    """Delete comment to address. Use \'dcm help\' for more information."""
    help = {
        "cmd": "dcm",
        "short": "delete disassembly comment",
        "desc": "Delete comment from target address.",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The address to comment."}],
    }
    global g_sessiondata
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if len(cmd) < 1:
        err_msg("Please insert an address to remove comment from.")
        help_msg(help)
        return
    # the json is only loaded/created on first hook stop
    if "comments" not in g_sessiondata:
        err_msg("[-] Please start the target before using this command.")
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid input value.")
        help_msg(help)
        return

    # we don't verify if the address exists - kind of waste of time
    # we also assume there are no dupes since add shouldn't let it happen
    module = aux_find_module(value)
    offset = get_module_offset(value, module)
    mod_uuid = module.GetUUIDString().lower()
    for i in g_sessiondata["comments"]:
        if (i["uuid"] == mod_uuid) and (i["offset"] == hex(offset)):
            g_sessiondata["comments"].remove(i)
            save_json_session(g_sessionfile)
            return

# XXX: to get an address we would need to resolve each module, find the base and add the offset
def cmd_listcomments(debugger, command, result, dict):
    """List comments. Use \'lcm help\' for more information."""
    help = {
        "cmd": "lcm",
        "short": "list disassembly comments",
        "desc": "List all disassembly comments.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    # nothing to present
    if g_sessiondata == {} or len(g_sessiondata["comments"]) == 0:
        return
    print("{: <8} {:<32} {}".format("Offset", "Module", " Comment"))
    print("--------------------------------------------------------------------------------")
    # the live version should be equal to the disk version since we write to database after every op
    for comment in g_sessiondata["comments"]:
        print("{: <8} {: <32}  {:s}".format(comment["offset"], comment["module"], comment["text"]))

# hash the r-x region of the target process - this should be enough for the database purposes
# x64dbg hashes the memory with murmurhash
def hash_target():
    process = get_process()
    regions = process.GetMemoryRegions()
    if regions.GetSize() < 1:
        err_msg("Invalid memory region.")
        return ""
    error = lldb.SBError()
    reg = lldb.SBMemoryRegionInfo()
    t = regions.GetMemoryRegionAtIndex(0, reg)
    start = reg.GetRegionBase()
    end = reg.GetRegionEnd()
    # software breakpoints don't show up here so it's safe to hash the process memory
    membuf = process.ReadMemory(start, end - start, error)
    hash_obj = hashlib.sha256(membuf)
    if DEBUG:
        print(hash_obj.hexdigest())
    return hash_obj.hexdigest()

# XXX: refactor this mess
def save_json_session(target):
    # make backup copy first
    if DEBUG:
        print("Backup target:", target)
    # we can only make a backup if there is something there
    if os.path.isfile(target):
        try:
            buffer = open(target, "r").read()
            backup_name = target + ".bak"
            with open(backup_name, "w") as output:
                output.write(buffer)
        except Exception as e:
            err_msg("Failed to make database backup:", e)
            return
    # create/overwrite with the new data
    try:
        with open(target, "w") as json_file:
            json.dump(g_sessiondata, json_file, sort_keys=True, indent=4)
    except Exception as e:
        # XXX: if it failed restore the backup when it exists
        err_msg("Failed to write new database:", e)
        return

# save the breakpoint session
# the BreakpointsWriteToFile() from API doesn't work since it doesn't save all information
# the restore from the file doesn't work because of missing addresses
def cmd_save_session(debugger, command, result, dict):
    """Save breakpoint session. Use \'ss help\' for more information."""
    help = {
        "cmd": "ss",
        "short": "save session",
        "desc": "Save debugging session.",
        "args": "[<session name>]",
        "options": [{"name": "session name", "desc": "The session name. Spaces are not allowed. If no session name is specified then 'default' will be used."}],
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if isinstance(g_sessiondata["sessions"], str):
        err_msg("This version is not compatible with sessions v1 files. Please use v3.1 or update session files.")
        return
    if "sessions" not in g_sessiondata:
        err_msg("Please start the target before using this command.")
        return

    session_name = "default"
    if len(cmd) > 0:
        # XXX: strip/replace spaces
        session_name = cmd[0]

    # check if the session exists
    # the json is only loaded/created on first hook stop
    if session_name not in g_sessiondata["sessions"]:
        g_sessiondata["sessions"][session_name] = {
            "time": "",
            "description": "",
            "breakpoints": []
        }

    # this doesn't work as expected - missing addresses
    # file_spec = lldb.SBFileSpec()
    # bpt_db_dir = g_home + '/.lldb/'
    # bpt_db_file = g_target_hash + '.bpt'
    # file_spec.SetDirectory(bpt_db_dir)
    # file_spec.SetFilename(bpt_db_file)
    # target.BreakpointsWriteToFile(file_spec)

    # the breakpoints file_addr has different meanings
    # for dyld we obtain an address without the base
    # for an object we obtain the full base address without aslr
    # we should just store offset to the image and then restore using current information
    target = get_target()
    # list all current breakpoints and store them
    for bpt in target.breakpoint_iter():
        # XXX: we need to iterate all locations of each breakpoint... geezzzzzz
        loc = bpt.location
        # for item in bpt.locations:
        item = loc[0]
        # if the address belongs nowhere this will be an invalid object so nothing to do here
        if item is None:
            continue
        # don't store one time breakpoints
        if bpt.one_shot:
            continue
        # get the SBAddress for this item -> so we can extract the module it belongs to and other info
        address = item.GetAddress()
        # the file path
        bp_path = address.module.file.fullpath
        # XXX: can we have valid addresses that don't belong to a module? payloads into allocated memory for example?
        if bp_path is None:
            continue
        # the current breakpoint memory address
        bp_addr = item.GetLoadAddress()
        # print(hex(item.GetLoadAddress()), "file_addr:", hex(address.file_addr), hex(address.offset), address.section.name, "file_offset", hex(address.section.file_offset), "section file_addr", hex(address.section.file_addr), address.module.file.fullpath)
        # we can store the offset and section information
        segment_nr = 0
        offset = 0
        # we extract offset = item.GetLoadAddress() - s.GetLoadAddress(target) [section that the item belongs to]
        # gives us the address offset since the base of that segment
        for mod in target.module_iter():
            # this brings a problem with the main module path
            # for example starting with lldb ./ls generates an image of ./ls
            # but we if attach to a process that started with ./ls we have image of /Users/username/./ls (if it was in ~)
            # or we can have full path names
            # also a problem if the target name is different but the hash still matches
            # since we can't hash on every lookup here
            # we already passed that test otherwise we wouldn't have loaded the session file for that hash
            # so we can just assume that index 0 is always the main image and compare the full path for libraries and frameworks
            # in theory the UUID should be unique and it's available from SBModule
            # if the target was patched but UUID is still the same that isnt a problem because the hash
            # this is valid for the main program - not valid for patched libs/frameworks since we don't hash those
            # that would be kinda of irrelevant anyway since the main target is still the same
            # if m.file.fullpath == address.module.file.fullpath:
            if mod.GetUUIDString().lower() == address.module.GetUUIDString().lower():
                # print("[+] Found breakpoint module: {:s}".format(bp_path))
                # these are the segments
                # print("[+] Iterating segments...")
                for sect in mod.sections:
                    # print(s.name, s.GetNumSubSections(), hex(s.file_addr), hex(address.section.file_addr), hex(address.section.addr), hex(s.GetLoadAddress(target)))
                    # if address.section.file_addr > s.file_addr and address.section.file_addr < s.file_addr + s.file_size:
                    if bp_addr > sect.GetLoadAddress(target) and bp_addr < sect.GetLoadAddress(target) + sect.size:
                        # this gives us the offset since the beginning of the segment
                        # because the internal lldb info has different meanings for the main binary and the libraries
                        # so it's easier to compute this value that can be used with loaded and attached targets, ASLRed or not
                        offset = item.GetLoadAddress() - sect.GetLoadAddress(target)
                        break
                    segment_nr += 1
        # store the breakpoint information
        names = lldb.SBStringList()
        bpt.GetNames(names)
        name = ""
        if names.IsValid():
            # we assume there is only one breakpoint name
            name = names.GetStringAtIndex(0)

        commands = lldb.SBStringList()
        cmds = []
        # returns true if there are command line commands
        if bpt.GetCommandLineCommands(commands):
            for i in range(commands.GetSize()):
                cmds.append(commands.GetStringAtIndex(i))
        # not available on every lldb version
        try:
            hardware = bpt.IsHardware()
        except:
            hardware = False

        condition = bpt.GetCondition()
        if condition is None:
            condition = ""

        module_path = os.path.abspath(address.module.file.fullpath)

        entry = {
            "offset": hex(offset),
            "address": hex(address.file_addr), # use the VM file address to help user have a reference since the offset is kinda opaque
            "segment": segment_nr,
            "enabled": bpt.enabled,
            "name": name,
            "hardware": hardware,
            "module": module_path,
            "uuid": address.module.GetUUIDString().lower(),
            "commands": cmds,
            "condition": condition,
        }
        found = 0
        # verify if the breakpoint already exists and update with the new info
        # XXX: this is ugly, to refactor
        for i, item in enumerate(g_sessiondata["sessions"][session_name]["breakpoints"]):
            # this should be enough to match
            if item["module"] == module_path and item["offset"] == hex(offset):
                g_sessiondata["sessions"][session_name]["breakpoints"][i] = entry
                found = 1
                break
        # not found so it's a new entry
        if found == 0:
            g_sessiondata["sessions"][session_name]["breakpoints"].append(entry)

    if DEBUG:
        print(g_sessiondata)
    # write to storage
    g_sessiondata["sessions"][session_name]["time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # g_sessiondata['version'] = SESSION_VERSION
    save_json_session(g_sessionfile)

# restore the breakpoint session
def cmd_restore_session(debugger, command, result, dict):
    """Restore breakpoint session. Use \'rs help\' for more information."""
    help = {
        "cmd": "rs",
        "short": "restore session",
        "desc": "Restore debugging session.",
        "args": "[<session name>]",
        "options": [{"name": "session name", "desc": "The session name. Spaces are not allowed. If no session name is specified then `default` will be used."}],
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if isinstance(g_sessiondata["sessions"], str):
        err_msg("This version is not compatible with sessions v1 files. Please use v3.1 or update session files.")
        return
    # the json is only loaded/created on first hook stop
    if "sessions" not in g_sessiondata:
        err_msg("Please start the target before using this command.")
        return

    session_name = "default"
    if len(cmd) > 0:
        session_name = cmd[0]
    # don't restore what we don't know about
    if session_name not in g_sessiondata["sessions"]:
        err_msg("The requested session name was not found.")
        return

    if len(g_sessiondata["sessions"][session_name]["breakpoints"]) == 0:
        print("No breakpoints found in requested session.")
        return

    res = lldb.SBCommandReturnObject()
    target = get_target()
    # build dictionary of all loaded modules
    modules = {}
    for m in target.module_iter():
        modules[m.GetUUIDString().lower()] = m
    # build dictionary of existing breakpoints
    # this doesn't avoid duplicate breakpoints inside the session file but we expect that to not exist
    breakpoints = {}
    for bpt in target.breakpoint_iter():
        # we assume always the first location
        item = bpt.location[0]
        if item is None:
            continue
        bp_addr = item.GetLoadAddress()
        breakpoints[bp_addr] = 1

    for i in g_sessiondata["sessions"][session_name]["breakpoints"]:
        # we need to have the module already loaded to restore
        # otherwise we don't know the base address for the stored offset
        # this is fine for the main binary and dyld breakpoints
        # but a problem but libraries/frameworks that aren't loaded yet on initial breakpoint inside dyld
        # the solution is to restore on the main binary entrypoint where the frameworks are already linked into the memory space
        if i["uuid"] in modules:
            m = modules[i["uuid"]]
            if DEBUG:
                print("Found module:", m.file.fullpath, m.num_sections)
            # these are segments and the subsections are the real sections in mach-o language
            # for s in m.sections:
            #    print(s)
            seg = m.GetSectionAtIndex(i["segment"])
            # XXX: validate value?
            la = seg.GetLoadAddress(target)
            # print("Module load address: 0x{:x}".format(la))
            target_bpt = la + int(i["offset"], 16)
            # XXX: verify if the resulting address fits the segment?
            # check if breakpoint already exists
            # no warning to the user given in this case - maybe we should say something?
            if target_bpt in breakpoints:
                continue
            if DEBUG:
                print(i)
            # software breakpoints
            if i["hardware"] is False:
                print("[+] Restoring breakpoint at 0x{:x} in {}.".format(target_bpt, i["module"]))
                b = target.BreakpointCreateByAddress(target_bpt)
                if i["name"] != "":
                    b.AddName(str(i["name"]))
                if i["enabled"] is False:
                    b.SetEnabled(False)
                if i["condition"] != "":
                    b.SetCondition(str(i["condition"]))
                if len(i["commands"]) > 0:
                    # we need to rebuild everything back into a SBStringList
                    cmds = lldb.SBStringList()
                    for x in i["commands"]:
                        # the strings will be incoming as unicode so we need to convert them to plain string
                        cmds.AppendString(str(x))
                    b.SetCommandLineCommands(cmds)
            # hardware breakpoints
            else:
                print("[+] Restoring hardware breakpoint at 0x{:x} in {}.".format(target_bpt, i["module"]))
                # the python API doesn't seem to support hardware breakpoints
                # so we set it via command line interpreter
                # XXX: missing the commands (the -C can be used but one per line)
                cmd_line = "-H -a {}".format(target_bpt)
                if i["enabled"] is False:
                    cmd_line = "{} -d".format(cmd_line)
                if i["name"] != "":
                    cmd_line = "{} -N {}".format(cmd_line, i["name"])
                if i["condition"] != "":
                    cmd_line = "{} -N {} -c {}".format(cmd_line, i["name"], i["condition"])
                lldb.debugger.GetCommandInterpreter().HandleCommand("breakpoint set {}".format(cmd_line), res)
        else:
            print("[!] Warning: couldn't find image {} with UUID {} to restore breakpoint. Still too early for this?".format(i["module"], i["uuid"]))
            print("[!] if it's a system library/framework or dyld this could be due to a system update and UUID change.")

# list all the available breakpoint sessions
# XXX: we can't display the target addresses because we don't store that information
# this is a bit annoying since it's hard to keep track of what is what until they are restored
def cmd_list_sessions(debugger, command, result, dict):
    """List breakpoint sessions. Use \'ss help\' for more information."""
    help = {
        "cmd": "ls",
        "short": "list sessions",
        "desc": "List debugging sessions.",
        "args": ""
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return

    if isinstance(g_sessiondata["sessions"], str):
        err_msg("This version is not compatible with sessions v1 files. Please use v3.1 or update session files.")
        return
    # the json is only loaded/created on first hook stop
    if "sessions" not in g_sessiondata:
        err_msg("Please start the target before using this command.")
        return

    if len(g_sessiondata["sessions"]) == 0:
        print("No breakpoint sessions found.")
        return

    if g_sessiondata["version"] == 2:
        print("{:<18} {: <14} {:^25}".format("Session Name", "# Breakpoints", "Last modified"))
        print("------------------------------------------------------------")
        for session in g_sessiondata["sessions"]:
            print("{:<18} {:^14d} {:^25}".format(session, len(g_sessiondata["sessions"][session]["breakpoints"]), g_sessiondata["sessions"][session]["time"]))
        print("------------------------------------------------------------")
        # XXX: print with verbose option?
        # print("Hash: {}".format(g_sessiondata['target']['hash']))

# we hook this so we have a chance to initialize/reset some stuff when targets are (re)run
# also modify to stop at entry point since we can't set breakpoints before
def cmd_run(debugger, command, result, dict):
    """Run the target and stop at entry. Everything else after the command is considered target arguments."""
    help = {
        "cmd": "r",
        "short": "run target",
        "desc": """Run the target, stopping at entry (dyld).""",
        "args": "",
        "notes": [
                "The 'r' is an abbreviation for 'process launch -s -X true --'.",
                "Replaces the original r/run alias."
        ],
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help)
        return
    # reset internal state variables
    res = lldb.SBCommandReturnObject()
    # must be set to true otherwise we don't get any output on the first stop hook related to this
    debugger.SetAsync(True)
    # imitate the original 'r' alias plus the stop at entry and pass everything else as target argv[]
    debugger.GetCommandInterpreter().HandleCommand("process launch -s -X true -- {}".format(command), res)

# --------------------------------------------------------------
#  The heart of lldbinit - when lldb stop this is where we land
# --------------------------------------------------------------

def HandleProcessLaunchHook(debugger, command, result, dict):
    print("Hello World!!!")
    return 0

# this only happens if there is a lldb stop
# also any commands that depend on a target existing can't run
# this creates a problem for hashing the target and loading the database
# since this hook hits many times on a debugging session (stepping code for example)
# one idea could be to define a hook on dyld_start that gets hit when we use
# process launch -s
# this would allow us to initialize everything only once but potentially conflict with user workflow
def HandleHookStopOnTarget(debugger, command, result, dict):
    """Display current code context."""
    global g_current_target
    global g_sessiondata
    global g_home
    global g_target_hash
    global g_sessionfile
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global POINTER_SIZE

    # if DEBUG:
    #   start_time = time.time()

    # Don't do anything if we're inside Xcode otherwise it will block everything there
    if os.getenv("PATH").startswith("/Applications/Xcode"):
        return

    target = get_target()
    exe = target.executable
    # XXX: there is a bug with older version where this hook is triggered on attach
    #      but the memory regions are still empty here
    #      in newer versions this doesn't occur because the hook doesn't trigger on attach (and executing "context" command works ok)
    #      this also means that we don't automatically get the display on attach and need to issue context if we wish so
    #
    #      the error message is: [-] ERROR: Invalid memory region.
    #      and a traceback to exception: Exception: [!] warning: get_frame() failed. Is the target binary started?
    #
    # workaround for older versions
    # at least Xcode 10.1 has this problem
    # issuing the get memory regions on every stop has huge performance penalty on newer xcode versions (at least with Xcode 15.4)
    # XXX: needs more versions tested to find out where is the true cut off version
    if LLDB_VARIANT == "apple" and LLDB_MAJOR <= 1000:
        if get_process().GetMemoryRegions().GetSize() == 0:
            print("[!] Attaching to process and memory regions info still not available. Use 'context' command to display current state.\n")
            return

    # load or initialize on first usage or different target
    # XXX: there is a bug in LLDB where it doesn't update the basename and fullpath internally if the files are identical
    #      but are started from different paths
    #      it does launch the new executable if we use "target create" after running the initial target
    #      but "target list" shows info of the previous one
    #      this happens if we launch with "lldb target" or empty and create the target inside
    #      if target files are different it works as expected
    if g_current_target == "" or g_current_target != exe.fullpath:
        g_current_target = exe.fullpath
        # we use the hash to lookup database file
        # one side effect (positive?) is that we don't have hash conflicts
        # since if there is hash mismatch the db file doesn't exist
        # x64dbg uses name instead and deals with the mismatches
        g_target_hash = hash_target()
        g_sessionfile = g_home + "/.lldb/" + g_target_hash + ".json"
        # load for a known target
        if os.path.exists(g_sessionfile):
            with open(g_sessionfile, "r") as f:
                g_sessiondata = json.load(f)
            if DEBUG:
                print(g_sessiondata)
            # check if hashes match
            # this is unreachable when hashes are used
            # if g_sessiondata["target"]["hash"] != g_target_hash:
            #    print("[!] Mismatch between target hash and database hash!")
                # XXX: initialize a new database? what to do here?
        # initialize for a new target
        else:
            # create skeleton
            # better use a version in case we need future expansion
            g_sessiondata["version"] = SESSION_VERSION
            g_sessiondata["comments"] = []
            # breakpoints and other info will go here
            g_sessiondata["sessions"] = {}
            g_sessiondata["target"] = {}
            g_sessiondata["target"].update({
                "name": exe.basename,
                "path": os.path.abspath(exe.fullpath),
                "hash": g_target_hash # a bit redudant since the hash is the JSON name but lets keep it
                })
            save_json_session(g_sessionfile)
            if DEBUG:
                print(g_sessiondata)

    # the separator strings based on configuration and target arch
    if is_i386():
        top_sep = SEPARATOR * I386_TOP_SIZE
        header_sep = SEPARATOR * I386_HEADER_SIZE
        stack_sep = SEPARATOR * I386_STACK_SIZE
        bottom_sep = SEPARATOR * I386_BOTTOM_SIZE
    elif is_x64():
        top_sep = SEPARATOR * X64_TOP_SIZE
        header_sep = SEPARATOR * X64_HEADER_SIZE
        stack_sep = SEPARATOR * X64_STACK_SIZE
        bottom_sep = SEPARATOR * X64_BOTTOM_SIZE
    elif is_arm():
        header_sep = SEPARATOR * ARM_HEADER_SIZE
        top_sep = SEPARATOR * ARM_TOP_SIZE
        stack_sep = SEPARATOR * ARM_STACK_SIZE
        bottom_sep = SEPARATOR * ARM_BOTTOM_SIZE
    else:
        arch = get_arch()
        err_msg("Unknown and unsupported architecture : " + arch)
        return

    debugger.SetAsync(True)

    # when we start the thread is still not valid and get_frame() will always generate a warning
    # this way we avoid displaying it in this particular case
    if get_process().GetNumThreads() == 1:
        thread = get_process().GetThreadAtIndex(0)
        if not thread.IsValid():
            return

    frame = get_frame()
    if not frame:
        return

    # XXX: this has a small bug - if we reload the script and try commands that depend on POINTER_SIZE
    # they will use the default value instead of the target until the context command is issued
    # or this hook is called
    POINTER_SIZE = get_pointer_size()

    # if we stopped because of a breakpoint try to extract which was it so we can display the name if it exists
    bp_name = ""
    thread = frame.GetThread()
    stop_reason = thread.GetStopReason()
    if stop_reason == lldb.eStopReasonBreakpoint:
        total = thread.GetStopReasonDataCount()
        if total > 0:
            n = 0
            # the available data will be in pairs when stop reason is a breakpoint
            # internal lldb breakpoints appear in the UI as negative but the function returns uint64_t
            # so we have big numbers here for those
            while n < total:
            # this gives us the breakpoint id
                bp_id = thread.GetStopReasonDataAtIndex(n)
                n += 2
                # skip the internal breakpoints
                # to avoid any other internal breakpoints just skip anything over half the big number
                # which is itself a huge number given we are not going to set that many breakpoints :-)
                if bp_id > 0xFFFFFFFFFFFFFFFF/2:
                    continue
            # now we can try to locate it
            bpx = target.FindBreakpointByID(bp_id)
            # and build the names list
            names = lldb.SBStringList()
            bpx.GetNames(names)
            if names.IsValid():
                # we assume there is only one breakpoint name
                bp_name = names.GetStringAtIndex(0)

    output(COLOR_SEPARATOR + "[ TiD:{:^3d} ]".format(thread.GetIndexID()))
    output(COLOR_SEPARATOR + header_sep)

    output(BOLD + "[regs]\n" + RESET)
    print_registers()

    if CONFIG_DISPLAY_STACK_WINDOW == 1:
        output(COLOR_SEPARATOR + stack_sep)
        output(BOLD + "[stack]\n" + RESET)
        display_stack()
        output("\n")

    if CONFIG_DISPLAY_DATA_WINDOW == 1:
        output(COLOR_SEPARATOR + top_sep)
        output(BOLD + "[data]\n" + RESET)
        display_data()
        output("\n")

    if CONFIG_DISPLAY_FLOW_WINDOW == 1:
        output(COLOR_SEPARATOR + top_sep)
        output(BOLD + "[flow]\n" + RESET)
        display_indirect_flow()

    output(COLOR_SEPARATOR + top_sep)
    output(BOLD + "[code]\n" + RESET)

    # disassemble and add its contents to output inside
    disassemble(get_current_pc(), CONFIG_DISASSEMBLY_LINE_COUNT)
    output(COLOR_SEPARATOR + bottom_sep + RESET)
    # XXX: find a better place for this - or maybe not
    if bp_name != "":
        output(COLOR_CURRENT_PC + "\nBreakpoint name: " + RESET + bp_name)
    # final newline to get correct prompt
    output("\n")
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    # if DEBUG:
    #   print("{} seconds".format(time.time() - start_time))
    return 0
