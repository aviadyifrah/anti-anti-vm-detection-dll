# anti-anti-vm-detection-dll
anti anti vm dll, used to hide VMWare characteristics as files, processes, services, registry values

The method used this project is by hooking the relevat functions in OS, I'm making use in "MinHook" native c library which make my life easier a lot.

The current version aim to win7 32` bit.

One of the main goals is that the dll will be easy to configure, in order to let one to hide specific program.

The way to use the dll is to write its path to AppInit_DLLs registry value, and then every process that load user32.dll will load my dll as well.

refrences:

AppInit_DLLs: https://msdn.microsoft.com/en-us/library/windows/desktop/dd744762(v=vs.85).aspx

anti vm\sandbox techniques: https://sentinelone.com/blogs/sfg-furtims-parent/

MinHook library: http://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra
