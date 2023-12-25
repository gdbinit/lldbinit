# LLDBINIT Manual

## The target data files

Version 3.1 introduces the target database file that can be found in `~/.lld` folder. It's a per target JSON file copying similar feature from [x64dbg](https://x64dbg.com). SHA256 is used to hash the target and the hash is used as the database file name. This obfuscates the name for easier lookup but I think it's better since targets can be patched and use the same name resulting in collisions. It's easy to use `grep, `ripgrep` or even `jq` to find out to which target the file belongs to.

For now there are three main sections:

* target: the information about the target binary such as hash, name and path.

* breakpoints: (multiple named) breakpoint sessions.

* comments: the disassembly comments.

The files can be manually edited, just be careful to keep the format consistent with the original.

## The disassembly comment commands

Version 3.1 introduces the possibility to add comments to the disassembly listing as [x64dbg](https://x64dbg.com). While I use IDA for this purpose most of the time, I started adding some comments within x64dbg while playing Flare-On 2023 and found it useful for certain places where you get too deep into the code and don't want to keep track with IDA at the same time.

The new commands are:

* acm: add comment.

* dcm: delete comment.

* lcm: list all comments.

## The breakpoint sessions

This is a feature that I've been wanting to introduce for a long time. Many times I need to copy the breakpoints list to restore later and so on. [x64dbg](https://x64dbg.com) has this feature and it's super useful. I have introduced multiple sessions support since managing a single session can be quite messy especially with older breakpoints that you need to activate and deactivate and can lose control of what is what.

The new commands are:

* ss: save session. Save the current breakpoints to a session.

* rs: restore breakpoint session. Restore the breakpoints from a session to the current target.

* ls: list available breakpoint sessions.

Because `lldb` isn't exactly a reverse engineer friendly debugger there are some annoyances using this feature. The breakpoints can only be restore after the target has been launched. The best way to achieve this is to start the target with the `r` or `run` command and use `rs` when the target stops on that first hit. The `r` and `run` commands have been modified since version 3.1 to stop on entrypoint (this means dyld). The alternative is to use the internal `process launch -s` command that does the same. This is only required the first time the target is run because after the breakpoints have been set `lldb` can manage them without a problem on subsequent runs (until you quit `lldb` that is).

The session save will save whatever configured breakpoints are set at the moment you use the command. Enabled and disabled breakpoints will be saved, one time breakpoints will not (doesn't make a lot of sense to save these). If the session already exists, the existing breakpoints will be updated and new ones added, and old ones stay.

If no session is specified, everything will be saved to the `default` session. Otherwise you can specify a session name.

Due to the way that `lldb` treats offsets and addresses for main binary and libraries/frameworks, the saved offset in the JSON file isn't to be used by the user. The original non-ASLRed address is also stored for easier user reference in case it's needed to import into IDA or some other tool.

The session breakpoints work fine with ASLR and non-ASLR targets, launched or attached from `lldb`. Or at least they should, otherwise please submit an issue :-).

Note: in theory `lldb` already has commands to save and restore the breakpoints but they don't seem to work. A file is saved but it contains invalid information that doesn't restore correctly. Feature seems broken since forever (or I'm missing something!).
