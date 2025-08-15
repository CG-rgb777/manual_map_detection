# Manual Map Detection
Library for detecting manual map injections **ONLY**. For **64-bit** programs. Minimum C++ version 17
## What does it detect?
●**DOS_SIGNATURE** aka MZ

●**NT_SIGNATURE** aka PE

●**DisableThreadLibraryCalls** function calls

●**Detecting DllEntryPoint** pattern (sometimes the dll entry point may be different and it will not be found)

### Author Comments
For testing this library I used Extreme Injector v3.7.3, Xenos injector and Simple Manual Map Injector from TheCruZ. All were detected. 

Were there ever any false positives? No. This was tested with large games and there were no false positives. 

Can they be? Only if something goes wrong during legitimate (I mean loading, when the dll is visible in the dll list, for example, the Loadlibrary function) loading or unloading of the dll, but this project does not affect this. 

Is it possible to bypass this protection? Yes, if an hacker finds it, it will not be difficult to bypass, I leave almost all the obfuscation to the one who will use it. But still, I added some protection methods, hid strings and hid direct use of WinApi functions ([thanks to this repository](https://github.com/AMRICHASFUCK/WinApiHide)).

If you need more understanding of what is happening, then uncomment this line in "MMP.cpp": "//#define MMP_DEBUG_MOD".

Why do you need this? I would like software developers, especially games, to have something better than the usual protection that checks only legitimately loaded modules and compares them with modules in the blacklist or protection that looks at the integrity of functions. But there are games where there is no protection at all or almost no protection and this repository is for developers who do not want to bother. 

All you need is to sometimes call the function "MMP_DETECT()" and see what it returns:

**-1**: There is something wrong with the protection

**0**: Nothing found

**1**: Something has been detected

What to do if there is a false positive? I don't know, seriously.
