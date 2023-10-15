# syscalldumper

Parse ntdll.dll and newer win32u.dll files, or whereever else DLLs that have exports that have a syscall in an expected manner.

Following architecture support. Each line is their own architecture, with their different names so that you may recognize. Each of these is tested.
1. AMD64, x86-64, x64
2. x86, IA32, i686
3. Alpha AXP,
4. PowerPC, PPC
5. MIPS
6. ARMv7
7. Aarch64, ARM64

PRs are welcome to accept exports using this tool.
