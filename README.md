# Windows Defender Emulator Tools
This repository contains code that I wrote to help with my reverse engineering of Windows Defender Antivirus' binary emulator, complimentary to my presentations on the emulator at Black Hat USA 2018 (<https://www.blackhat.com/us-18/briefings/schedule/index.html#windows-offender-reverse-engineering-windows-defenders-antivirus-emulator-9981>) and DEF CON 26 (<https://www.defcon.org/html/defcon-26/dc-26-speakers.html#Bulazel>). 

## `mpclient` Modifications

My code is built on top of Tavis Ormandy's `loadlibrary` (<https://github.com/taviso/loadlibrary>) project. In order to work with my code, you'll need to pull down a copy of `loadlibrary`, and then apply my patches to the project. 

```
$ git clone https://github.com/taviso/loadlibrary
$ cd loadlibrary
$ git apply OutputDebugStringAHook.patch
$ make

[Follow Tavis's instructions about setting up mpengine.dll - make sure you have the 6/25/2018 build
Dumping symbols from IDA is nice for debugging, but is not necessary for this code to work]

$ ./mpclient OutputDebugStringADemo.exe 
[+] mpengine.dll base at 0xf5e66008
[+] Setting hooks and resolving offsets
[+] Parameters<1>::Parameters<1>	RVA: 0x46e5d5	Address: 0xf62d45dd
[+] pe_read_string_ex:			RVA: 0x3e59f3	Address: 0xf624b9fb
[+] OutputDebugStringA FP:		RVA: 0x01af88	Address: 0xf637c7a8
[+] OutputDebugStringA FP replaced: 	0x804ea80
[+] Done setting hooks and resolving offsets!
main(): Scanning /mnt/hgfs/sharemp/windows_only/OutputDebugStringADemo.exe...
EngineScanCallback(): Scanning input
[+] OutputDebugStringA(pe_vars_t * v = 0x0xf5c3c008)
[+] Params[1]:	0x402010
[+] OutputDebugStringA: "This is coming from inside the emulator!"
```

IMPORTANT: The offsets contained in this project are specific to the 6/25/2018 32-bit `mpengine.dll` build, `MD5=e95d3f9e90ba3ccd1a4b8d63cbd88d1b`. If you are using a different version of `mpengine.dll`, you'll need to locate these offsets yourself. It's easiest to wait for Microsoft to publish `mpengine.dll` PDBs with symbols, but it can be done easily without them. 

Note that the included patches only contain my `OutputDebugStringA` hooking code. This will let you experiment with the engine and reproduce some of the demos I have shown. Implementing more advanced functionality demonstrated in my presentation is left as an exercise to the reader, eg: building a fuzzer, supporting format string-based output, dumping out arbitrary non-string buffers, hooking `ExitProcess` to understand when emulation is ending, or collecting coverage with a customized Lighthouse Pintool (<https://github.com/gaasedelen/lighthouse>).

---
## Binary For Emulator Exploration

In addition to the `mpclient` extensions, you'll also find a Microsoft Visual Studio 2017 project that I have found to be consistently emulated when scanned with the 6/25/2018 `mpengine.dll` running under `loadlibrary`. Make sure you build an `x86 Release` version of this project when working with it. As noted in my presentation, Defender may choose not to emulate code for a variety of reasons, so I recommend frequently verifying that your code is still getting emulated as you make modifications.

As I have removed linking against a number of system libraries, many common Windows APIs are not supported, as are many C runtime functions. You can add linking against these Windows libraries if needed, but I recommend being careful with C runtime functions, as I found linking against `msvcrt` could prevent emulation. Note that C runtime functions may be implicitly invoked by C code constructs, such as `int foo[5] = {0};` - so if you start getting linker problems complaining about `_memcpy` and other functions your code doesn't actually invoke, that may be the problem.

---

## IDA Scripts

Finally, I've included a couple of IDA scripts that I found useful in doing this reverse engineering. These plugins were all written for and tested with IDA Pro 7, earlier versions of IDA may not support them. `mp_apicall_7.py` uses APIs specific to IDA 7, and will not work with earlier versions of IDA.

#### `extract_syscall_table.py`

Parse the `mpengine.dlls` `g_syscalls` table of natively emulated APIs and dump hashes and names to a Python map, as used in `find_apicall_functions.py` and `mp_apicall_7.py`


#### `mp_apicall_7.py`

An IDA Processor Extension module to add support for disassembling the `apicall` instruction during auto-analysis. This Processor Extension module explicitly only works on IDA Pro 7. This plugin only kicks in for files with the extension `.mp.dll` (eg: `kernel32.mp.dll`)

#### `find_apicall_functions.py`

After loading a binary with `apicall` instructions disassembled by `mp_apicall_7.py`, this script can be run to label `apicall` stub functions.

---

## Support

No support is offered for this project. Feel free to report issues, but I am not planning on updating this code after publication or troubleshooting user issues. 

That said, I keep open DMs on Twitter if you have any questions about the code - `@0xAlexei` <https://twitter.com/0xAlexei>
