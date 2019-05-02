using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security;

namespace ERC
{
    #region ERC_Core
    public class ERC_Core
    {
        #region Class Variables
        public const string ERC_Version = "v0.1"; //place holder, change this later
        public string Installation_Directory = null; //To be used later
        public string Working_Directory { get; set; }
        public string Author { get; set; }
        public bool Logging { get; set; }
        #endregion

        #region DLL Imports
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern bool ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        public static extern int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        public static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        public static extern bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        public static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("NTDLL.DLL", SetLastError = true, EntryPoint = "NtQueryInformationProcess")]
        public static extern int NtQueryInformationProcess32(IntPtr hProcess, PROCESSINFOCLASS pic,
            ref PROCESS_BASIC_INFORMATION32 pbi, int cb, out int pSize);

        [DllImport("NTDLL.DLL", SetLastError = true, EntryPoint = "NtQueryInformationProcess")]
        public static extern int NtQueryInformationProcess64(IntPtr hProcess, PROCESSINFOCLASS pic,
            ref PROCESS_BASIC_INFORMATION32 pbi, int cb, out int pSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule,
            int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
            [In] [MarshalAs(UnmanagedType.U4)] int nSize);
        #endregion

        #region Constructor
        public ERC_Core(string user_supplied_working_directory = null, string user_supplied_author = null)
        {
            if (Directory.Exists(user_supplied_working_directory))
            {
                Working_Directory = user_supplied_working_directory;
            }
            else
            {
                Console.WriteLine("User supplied working directory does not exist");
                Working_Directory = Directory.GetCurrentDirectory();
            }

            if(user_supplied_author != null)
            {
                Author = user_supplied_author;
            }
            else
            {
                Author = null;
            }
            
            if(user_supplied_working_directory != null)
            {
                Logging = true;
            }
            else
            {
                Logging = false;
            }
            
        }

        protected ERC_Core(ERC_Core parent)
        {
            Working_Directory = parent.Working_Directory;
            Author = parent.Author;
            Logging = parent.Logging;
        }
        #endregion
    }
    #endregion

    #region ERC_Result
    public class ERC_Result<T> : ERC_Core
    {
        public T Return_Value { get; set; }
        public Exception Error { get; set; }
        public string Error_Log_File { get; set; }
        public string Output_File { get; set; }

        public ERC_Result(ERC_Core core) : base(core)
        {
            Error_Log_File = Path.Combine(Working_Directory + "ERC_Error_log_" + DateTime.Now.TimeOfDay.ToString().Replace(':', '-') + ".txt");
        }

        public void Set_Error_File(string path)
        {
            Error_Log_File = path;
        }

        public void Log_Event()
        {
            Console.WriteLine(Error_Log_File);
            Console.WriteLine(Error);
            using (StreamWriter sw = File.AppendText(Error_Log_File))
            {
                sw.WriteLine(Error);
            }
        }
    }
    #endregion

    #region Type Definitions
    public enum MachineType
    {
        Native = 0,
        I386 = 0x014c,
        Itanium = 0x0200,
        x64 = 0x8664,
        error = -1
    }

    public struct RegisterOffset
    {
        public string Register;
        public IntPtr Register_Value;
        public int Register_Offset;
        public int String_Offset;
        public int Buffer_Size;
        public int Thread_ID;
    }

    #region DLL Headers
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_DOS_HEADER
    {
        [FieldOffset(60)] public int nt_head_ptr;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_FILE_HEADER
    {
        [FieldOffset(0)] public ushort Machine;
        [FieldOffset(2)] public ushort NumberOfSections;
        [FieldOffset(4)] public uint TimeDateStamp;
        [FieldOffset(8)] public uint PointerToSymbolTable;
        [FieldOffset(12)] public uint NumberOfSymbols;
        [FieldOffset(16)] public ushort SizeOfOptionalHeader;
        [FieldOffset(18)] public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_NT_HEADERS32
    {
        [FieldOffset(0)] public uint Signature;
        [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_NT_HEADERS64
    {
        [FieldOffset(0)] public uint Signature;
        [FieldOffset(4)] public IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(24)] public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_DATA_DIRECTORY
    {
        [FieldOffset(0)] public uint VirtualAddress;
        [FieldOffset(4)] public uint Size;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        [FieldOffset(0)] public ushort Magic;
        [FieldOffset(2)] public byte MajorLinkerVersion;
        [FieldOffset(3)] public byte MinorLinkerVersion;
        [FieldOffset(4)] public uint SizeOfCode;
        [FieldOffset(8)] public uint SizeOfInitializedData;
        [FieldOffset(12)] public uint SizeOfUninitializedData;
        [FieldOffset(16)] public uint AddressOfEntryPoint;
        [FieldOffset(20)] public uint BaseOfCode;
        [FieldOffset(24)] public uint BaseOfData;
        [FieldOffset(28)] public uint ImageBase;
        [FieldOffset(32)] public uint SectionAlignment;
        [FieldOffset(36)] public uint FileAlignment;
        [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
        [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
        [FieldOffset(44)] public ushort MajorImageVersion;
        [FieldOffset(46)] public ushort MinorImageVersion;
        [FieldOffset(48)] public ushort MajorSubsystemVersion;
        [FieldOffset(50)] public ushort MinorSubsystemVersion;
        [FieldOffset(52)] public uint Win32VersionValue;
        [FieldOffset(56)] public uint SizeOfImage;
        [FieldOffset(60)] public uint SizeOfHeaders;
        [FieldOffset(64)] public uint CheckSum;
        [FieldOffset(68)] public ushort Subsystem;
        [FieldOffset(70)] public ushort DllCharacteristics;
        [FieldOffset(72)] public uint SizeOfStackReserve;
        [FieldOffset(76)] public uint SizeOfStackCommit;
        [FieldOffset(80)] public uint SizeOfHeapReserve;
        [FieldOffset(84)] public uint SizeOfHeapCommit;
        [FieldOffset(88)] public uint LoaderFlags;
        [FieldOffset(92)] public uint NumberOfRvaAndSizes;
        //[FieldOffset(96)] public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(0)] public ushort Magic;
        [FieldOffset(2)] public byte MajorLinkerVersion;
        [FieldOffset(3)] public byte MinorLinkerVersion;
        [FieldOffset(4)] public uint SizeOfCode;
        [FieldOffset(8)] public uint SizeOfInitializedData;
        [FieldOffset(12)] public uint SizeOfUninitializedData;
        [FieldOffset(16)] public uint AddressOfEntryPoint;
        [FieldOffset(20)] public uint BaseOfCode;
        [FieldOffset(24)] public ulong ImageBase;
        [FieldOffset(32)] public uint SectionAlignment;
        [FieldOffset(36)] public uint FileAlignment;
        [FieldOffset(40)] public ushort MajorOperatingSystemVersion;
        [FieldOffset(42)] public ushort MinorOperatingSystemVersion;
        [FieldOffset(44)] public ushort MajorImageVersion;
        [FieldOffset(46)] public ushort MinorImageVersion;
        [FieldOffset(48)] public ushort MajorSubsystemVersion;
        [FieldOffset(50)] public ushort MinorSubsystemVersion;
        [FieldOffset(52)] public uint Win32VersionValue;
        [FieldOffset(56)] public uint SizeOfImage;
        [FieldOffset(60)] public uint SizeOfHeaders;
        [FieldOffset(64)] public uint CheckSum;
        [FieldOffset(68)] public ushort Subsystem;
        [FieldOffset(70)] public ushort DllCharacteristics;
        [FieldOffset(72)] public ulong SizeOfStackReserve;
        [FieldOffset(80)] public ulong SizeOfStackCommit;
        [FieldOffset(88)] public ulong SizeOfHeapReserve;
        [FieldOffset(96)] public ulong SizeOfHeapCommit;
        [FieldOffset(102)] public uint LoaderFlags;
        [FieldOffset(106)] public uint NumberOfRvaAndSizes;
        //[FieldOffset(110)] public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }
    #endregion

    #region Process Memory Information
    public enum AllocationProtect : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    public enum StateEnum : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }

    public enum TypeEnum : uint
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION32
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public StateEnum State;
        public uint Protect;
        public TypeEnum Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public ulong RegionSize;
        public StateEnum State;
        public int Protect;
        public TypeEnum Type;
        public int __alignment2;
    }
    #endregion

    #region Thread Context
    /// <summary>
    /// Enum to specify access level required when accessing a thread. 
    /// </summary>
    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        All_ACCESS = (0xFFFF)
    }

    public enum CONTEXT_FLAGS : uint
    {
        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, 
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, 
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, 
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, 
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, 
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }

    /// <summary>
    /// x86 Save area data.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    /// <summary>
    /// Structure for holding x86 register values.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT32
    {
        public CONTEXT_FLAGS ContextFlags; 
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7; 
        public FLOATING_SAVE_AREA FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    // Next x64
    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;

        public override string ToString()
        {
            return string.Format("High:{0}, Low:{1}", this.High, this.Low);
        }
    }

    /// <summary>
    /// x64 Save area data.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct XSAVE_FORMAT64
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsr_Mask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }

    /// <summary>
    /// Structure for holding x64 register values.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        public XSAVE_FORMAT64 DUMMYUNIONNAME;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }
    #endregion

    #region TEB

    #endregion

    #region PEB
    public enum PROCESSINFOCLASS : int
    {
        ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: HANDLE
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // 10
        ProcessLdtSize,
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only)
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information,
        ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
        ProcessAffinityMask, // s: KAFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // 30, q: HANDLE
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: ULONG
        ProcessExecuteFlags, // qs: ULONG
        ProcessResourceManagement,
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
        ProcessPagePriority, // q: ULONG
        ProcessInstrumentationCallback, // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // q: ULONG_PTR
        ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        MaxProcessInfoClass
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PROCESS_BASIC_INFORMATION32
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;

        public int Size
        {
            get { return Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION32)); }
        }
    }
    #endregion

    #endregion
}
