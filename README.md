# SystemCopy

Copy files as 'nt authority\system' from low privileged account.

 This tool exploits this vulnerability https://www.kb.cert.org/vuls/id/906424 and is adapted from this PoC https://github.com/SandboxEscaper/randomrepo/blob/master/PoC-LPE.rar

This tool allows any user to write content of any file that **your user can read** and **the 'nt authority\system' user can write**.
This tool was successfully tested on :
- Windows 10 x64/x32
- Windows 8.1 x64/x32
- Windows 7 x64/x32

It may work on other versions including Windows Server

## usage
```SystemCopy.exe srcFile dstFile # srcFile content will be copied into dstFile.```

**WARNING : The tool leaves the dstFile world writable!**
