using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Xml;
using System.ComponentModel;
using ERC.Structures;

namespace ERC
{
    #region ErcCore
    /// <summary>
    /// A single instance of this object should be instantiated at a minimum. It is used for storing global variables such as the working directory etc.
    /// </summary>
    public class ErcCore
    {
        #region Class Variables
        public string ErcVersion { get; }
        public string WorkingDirectory { get; internal set; }
        public string Author { get; set; }
        private string ConfigPath { get; set; }
        public string SystemErrorLogPath { get; set; }
        public string PatternStandardPath { get; }
        public string PatternExtendedPath { get; }
        public Exception SystemError { get; set; }
        XmlDocument ErcConfig = new XmlDocument();
        #endregion

        #region DLL Imports
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern int ReadProcessMemory(IntPtr Handle, IntPtr Address, [Out] byte[] Arr, int Size, out int BytesRead);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        internal static extern int VirtualQueryEx32(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
        internal static extern int VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        internal static extern bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(IntPtr hthread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        internal static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError= true)]
        internal static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "FindResourceA")]
        public static extern IntPtr FindResouce(IntPtr hModule, ref string resName, ref string resType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("user32.dll", EntryPoint = "GetModuleHandleW", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern uint ZwQueryInformationThread(IntPtr hwnd, int i, ref ThreadBasicInformation threadinfo, 
            int length, IntPtr bytesread);

        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool EnumProcessModulesEx(IntPtr hProcess,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule,
            int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
            [In] [MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern IntPtr ImageLoad(string DllName, string DllPath);

        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation32(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);

        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation64(IntPtr dllptr, out IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);

        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation32(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY32 ImageConfigDir32);

        [DllImport("Imagehlp.dll", SetLastError = true, EntryPoint = "GetImageConfigInformation")]
        internal static extern bool GetImageConfigInformation64(ref LOADED_IMAGE loadedImage, ref IMAGE_LOAD_CONFIG_DIRECTORY64 ImageConfigDir64);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        internal static extern int MapAndLoad(string ImageName, string DllPath, out LOADED_IMAGE loadedImage, bool Dll, bool readOnly);
        #endregion

        #region Constructor
        public ErcCore()
        {
            WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
            WorkingDirectory = WorkingDirectory.Remove(0, 6);
            WorkingDirectory += "\\";
            ConfigPath = Path.Combine(WorkingDirectory, "ERC_Config.XML");
            PatternStandardPath = "";
            PatternExtendedPath = "";
            SystemErrorLogPath = Path.Combine(WorkingDirectory, "System_Error.LOG");

            bool configRead = false;
            while (configRead == false)
            {
                if (File.Exists(ConfigPath))
                {
                    try
                    {
                        ErcConfig.Load(ConfigPath);
                        var singleNode = ErcConfig.DocumentElement.SelectNodes("//Working_Directory");
                        WorkingDirectory = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Author");
                        Author = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Standard_Pattern");
                        PatternStandardPath = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Extended_Pattern");
                        PatternExtendedPath = singleNode[0].InnerText;
                        singleNode = ErcConfig.DocumentElement.SelectNodes("//Error_Log_File");
                        SystemErrorLogPath = singleNode[0].InnerText;
                        configRead = true;
                    }
                    catch (Exception e)
                    {
                        SystemError = e;
                        BuildDefaultConfig();
                    }
                }
                else
                {
                    BuildDefaultConfig();
                }
            }

            if (PatternStandardPath == "")
            {
                PatternStandardPath = Path.Combine(WorkingDirectory, "Pattern_Standard");
                if (!File.Exists(PatternStandardPath))
                {
                    Console.WriteLine("Building standard pattern file...");
                    var patternExt = Utilities.PatternTools.PatternCreate(20277, this, false);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternStandardPath, patternExt.ReturnValue);
                }
            }
            else
            {
                if (!File.Exists(PatternStandardPath))
                {
                    Console.WriteLine("Building standard pattern file...");
                    var patternExt = Utilities.PatternTools.PatternCreate(20277, this, false);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternStandardPath, patternExt.ReturnValue);
                }
            }
            
            if(PatternExtendedPath == "")
            {
                PatternExtendedPath = Path.Combine(WorkingDirectory, "Pattern_Extended");
                if (!File.Exists(PatternExtendedPath))
                {
                    Console.WriteLine("Building extended pattern file...");
                    var patternExt = Utilities.PatternTools.PatternCreate(66923, this, true);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternExtendedPath, patternExt.ReturnValue);
                }
            }
            else
            {
                if (!File.Exists(PatternExtendedPath))
                {
                    Console.WriteLine("Building extended pattern file...");
                    var patternExt = Utilities.PatternTools.PatternCreate(66923, this, true);
                    if (patternExt.Error != null)
                    {
                        patternExt.LogEvent();
                        Environment.Exit(1);
                    }
                    File.WriteAllText(PatternExtendedPath, patternExt.ReturnValue);
                }
            }
        }

        protected ErcCore(ErcCore parent)
        {
            WorkingDirectory = parent.WorkingDirectory;
            Author = parent.Author;
        }

        private void BuildDefaultConfig()
        {
            Console.WriteLine("Building ERC_Config.XML file");
            string patternStandardPath = Path.Combine(WorkingDirectory, "Pattern_Standard");
            string patternExtendedPath = Path.Combine(WorkingDirectory, "Pattern_Extended");
            string systemErrorLogPath = Path.Combine(WorkingDirectory, "System_Error.LOG");

            XmlDocument defaultConfig = new XmlDocument();
            XmlDeclaration xmlDeclaration = defaultConfig.CreateXmlDeclaration("1.0", "UTF-8", null);
            XmlElement root = defaultConfig.DocumentElement;
            defaultConfig.InsertBefore(xmlDeclaration, root);

            XmlElement erc_xml = defaultConfig.CreateElement(string.Empty, "ERC.Net", Assembly.GetExecutingAssembly().GetName().Version.ToString());
            defaultConfig.AppendChild(erc_xml);

            XmlElement parameters = defaultConfig.CreateElement(string.Empty, "Parameters", string.Empty);
            erc_xml.AppendChild(parameters);

            XmlElement workingDir = defaultConfig.CreateElement(string.Empty, "Working_Directory", string.Empty);
            XmlText text1 = defaultConfig.CreateTextNode(WorkingDirectory);
            workingDir.AppendChild(text1);
            parameters.AppendChild(workingDir);

            XmlElement author = defaultConfig.CreateElement(string.Empty, "Author", string.Empty);
            text1 = defaultConfig.CreateTextNode("No_Author_Set");
            author.AppendChild(text1);
            parameters.AppendChild(author);

            XmlElement patternS = defaultConfig.CreateElement(string.Empty, "Standard_Pattern", string.Empty);
            text1 = defaultConfig.CreateTextNode(patternStandardPath);
            patternS.AppendChild(text1);
            parameters.AppendChild(patternS);

            XmlElement patternE = defaultConfig.CreateElement(string.Empty, "Extended_Pattern", string.Empty);
            text1 = defaultConfig.CreateTextNode(patternExtendedPath);
            patternE.AppendChild(text1);
            parameters.AppendChild(patternE);

            XmlElement errorlog = defaultConfig.CreateElement(string.Empty, "Error_Log_File", string.Empty);
            text1 = defaultConfig.CreateTextNode(systemErrorLogPath);
            errorlog.AppendChild(text1);
            parameters.AppendChild(errorlog);

            try
            {
                defaultConfig.Save(ConfigPath);
            }
            catch(Exception e)
            {
                SystemError = e;
                LogEvent(e);
            }
        }
        #endregion

        #region Variable Setters

        #region SetWorkingDirectory
        /// <summary>
        /// Changes the working directory in both the XML file and associated ErcCore object
        /// </summary>
        /// <param name="path"></param>
        public void SetWorkingDirectory(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Working_Directory");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for working directory is not a valid directory");
            }
        }
        #endregion

        #region SetPatternStandardPath
        /// <summary>
        /// Sets the standard pattern file path. Any pattern can replace the standard pattern when searching however the new pattern must be written to a file and the file path set here.
        /// </summary>
        /// <param name="path">The filepath of the new standard pattern file</param>
        public void SetPatternStandardPath(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Standard_Pattern");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for the standard pattern path is not a valid directory");
            }
        }
        #endregion

        #region SetPatternExtendedPath
        /// <summary>
        /// Sets the extended pattern file path. Any pattern can replace the extended pattern when searching however the new pattern must be written to a file and the file path set here.
        /// </summary>
        /// <param name="path">The filepath of the new extended pattern file</param>
        public void SetPatternExtendedPath(string path)
        {
            if (Directory.Exists(path))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Extended_Pattern");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            }
            else
            {
                throw new Exception("User Input Error: Value supplied for the extended pattern path is not a valid directory");
            }
        }
        #endregion

        #region SetAuthor
        /// <summary>
        /// Sets the name of the author for use when outputing results to disk.
        /// </summary>
        /// <param name="author">String containing the name of the author</param>
        public void SetAuthor(string author)
        {
            XmlDocument xmldoc = new XmlDocument();
            xmldoc.Load(ConfigPath);
            var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Author");
            singleNode.InnerText = author;
            xmldoc.Save(ConfigPath);
        }
        #endregion

        #region SetSystemErrorLogFile
        /// <summary>
        /// Sets the error log file to a user specified filepath. 
        /// </summary>
        /// <param name="path">The new error log filepath.</param>
        public void SetErrorFile(string path)
        {
            if (File.Exists(path))
            {
                SystemErrorLogPath = path;
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            } 
            else if (Directory.Exists(Path.GetDirectoryName(path)))
            {
                if (!path.EndsWith("\\"))
                {
                    path += "\\";
                }
                path += "System_Error.LOG";
                File.Create(path);
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
            }
            else
            {
                File.Create(WorkingDirectory + "System_Error.LOG");
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(ConfigPath);
                var singleNode = xmldoc.DocumentElement.SelectSingleNode("//Error_Log_File");
                singleNode.InnerText = path;
                xmldoc.Save(ConfigPath);
                SystemErrorLogPath = path;
            }
        }
        #endregion

        #region LogEvent
        /// <summary>
        /// Logs events to the error log path in the XML file. This file is only appended to and never replaced.
        /// </summary>
        /// <param name="e">The exception to log</param>
        public void LogEvent(Exception e)
        {
            using (StreamWriter sw = File.AppendText(SystemErrorLogPath))
            {
                sw.WriteLine(e);
            }
        }
        #endregion

        #endregion

        #region X64toX32PointerModifier
        /// <summary>
        /// Converts a x64 pointer into a x86 pointer.
        /// </summary>
        /// <param name="ptr64">64bit pointer to be converted</param>
        /// <returns>Retruns a byte array 4 bytes long containing the modified pointer</returns>
        internal static byte[] X64toX32PointerModifier(byte[] ptr64)
        {
            byte[] ptr32 = new byte[4];
            Array.Copy(ptr64, 0, ptr32, 0, 4);
            return ptr32;
        }
        #endregion
    }
    #endregion

    #region ErcResult
    /// <summary>
    /// A basic object which contains a generic type and exception. 
    /// </summary>
    /// <typeparam name="T">A generic type</typeparam>
    public class ErcResult<T> : ErcCore
    {
        public T ReturnValue { get; set; }
        public Exception Error { get; set; }

        public ErcResult(ErcCore core) : base(core)
        {
            SystemErrorLogPath = core.SystemErrorLogPath;
        }

        public ErcResult(ErcCore core, string errorFile) : base(core)
        {
            SystemErrorLogPath = errorFile;
        }

        /// <summary>
        /// Logs an event to the ErrorLogFile value.
        /// </summary>
        public void LogEvent()
        {
            using (StreamWriter sw = File.AppendText(base.SystemErrorLogPath))
            {
                sw.WriteLine(Error);
            }
        }

        public override string ToString()
        {
            string ret = "";
            ret += "ErcResult Type = " + ReturnValue.GetType() + Environment.NewLine;
            if (Error != null)
            {
                ret += "ErcResult.Error = " + Error.ToString() + Environment.NewLine;
            }
            else
            {
                ret += "ErcResult.Error = NULL" + Environment.NewLine;
            }
            ret += "ErcResult.ErrorLogFile = " + SystemErrorLogPath + Environment.NewLine;
            return base.ToString();
        }
    }
    #endregion

    #region Type Definitions

    public enum MachineType
    {
        [Description("Native")]
        Native = 0,
        [Description("I386")]
        I386 = 0x014c,
        [Description("Itanium")]
        Itanium = 0x0200,
        [Description("x64")]
        x64 = 0x8664,
        [Description("Error")]
        error = -1
    }

    namespace Structures
    {
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
            [FieldOffset(0)] public MagicType Magic;
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
            [FieldOffset(68)] public SubSystemType Subsystem;
            [FieldOffset(70)] public ushort DllCharacteristics;
            [FieldOffset(72)] public uint SizeOfStackReserve;
            [FieldOffset(76)] public uint SizeOfStackCommit;
            [FieldOffset(80)] public uint SizeOfHeapReserve;
            [FieldOffset(84)] public uint SizeOfHeapCommit;
            [FieldOffset(88)] public uint LoaderFlags;
            [FieldOffset(92)] public uint NumberOfRvaAndSizes;
            [FieldOffset(96)] public IMAGE_DATA_DIRECTORY ExportTable;
            [FieldOffset(104)] public IMAGE_DATA_DIRECTORY ImportTable;
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ResourceTable;
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY CertificateTable;
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY Debug;
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY Architecture;
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY TLSTable;
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY BoundImport;
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY IAT;
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)] public MagicType Magic;
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
            [FieldOffset(68)] public SubSystemType Subsystem;
            [FieldOffset(70)] public ushort DllCharacteristics;
            [FieldOffset(72)] public ulong SizeOfStackReserve;
            [FieldOffset(80)] public ulong SizeOfStackCommit;
            [FieldOffset(88)] public ulong SizeOfHeapReserve;
            [FieldOffset(96)] public ulong SizeOfHeapCommit;
            [FieldOffset(104)] public uint LoaderFlags;
            [FieldOffset(108)] public uint NumberOfRvaAndSizes;
            [FieldOffset(112)] public IMAGE_DATA_DIRECTORY ExportTable;
            [FieldOffset(120)] public IMAGE_DATA_DIRECTORY ImportTable;
            [FieldOffset(128)] public IMAGE_DATA_DIRECTORY ResourceTable;
            [FieldOffset(136)] public IMAGE_DATA_DIRECTORY ExceptionTable;
            [FieldOffset(144)] public IMAGE_DATA_DIRECTORY CertificateTable;
            [FieldOffset(152)] public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            [FieldOffset(160)] public IMAGE_DATA_DIRECTORY Debug;
            [FieldOffset(168)] public IMAGE_DATA_DIRECTORY Architecture;
            [FieldOffset(176)] public IMAGE_DATA_DIRECTORY GlobalPtr;
            [FieldOffset(184)] public IMAGE_DATA_DIRECTORY TLSTable;
            [FieldOffset(192)] public IMAGE_DATA_DIRECTORY LoadConfigTable;
            [FieldOffset(200)] public IMAGE_DATA_DIRECTORY BoundImport;
            [FieldOffset(208)] public IMAGE_DATA_DIRECTORY IAT;
            [FieldOffset(216)] public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            [FieldOffset(224)] public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            [FieldOffset(232)] public IMAGE_DATA_DIRECTORY Reserved;
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY32
        {
            public uint Size;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint GlobalFlagsClear;
            public uint GlobalFlagsSet;
            public uint CriticalSectionDefaultTimeout;
            public uint DeCommitFreeBlockThreshold;
            public uint DeCommitTotalFreeThreshold;
            public uint LockPrefixTable;
            public uint MaximumAllocationSize;
            public uint VirtualMemoryThreshold;
            public uint ProcessHeapFlags;
            public uint ProcessAffinityMask;
            public ushort CSDVersion;
            public ushort DependentLoadFlags;
            public uint EditList;
            public uint SecurityCookie;
            public uint SEHandlerTable;
            public uint SEHandlerCount;
            public uint GuardCFCheckFunctionPointer;
            public uint GuardCFDispatchFunctionPointer;
            public uint GuardCFFunctionTable;
            public uint GuardCFFunctionCount;
            public uint GuardFlags;
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            public uint GuardAddressTakenIatEntryTable;
            public uint GuardAddressTakenIatEntryCount;
            public uint GuardLongJumpTargetTable;
            public uint GuardLongJumpTargetCount;
            public uint DynamicValueRelocTable;
            public uint CHPEMetadataPointer;
            public uint GuardRFFailureRoutine;
            public uint GuardRFFailureRoutineFunctionPointer;
            public uint DynamicValueRelocTableOffset;
            public ushort DynamicValueRelocTableSection;
            public ushort Reserved2;
            public uint GuardRFVerifyStackPointerFunctionPointer;
            public uint HotPatchTableOffset;
            public uint Reserved3;
            public uint EnclaveConfigurationPointer;
            public uint VolatileMetadataPointer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_DIRECTORY64
        {
            public uint Size;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint GlobalFlagsClear;
            public uint GlobalFlagsSet;
            public uint CriticalSectionDefaultTimeout;
            public ulong DeCommitFreeBlockThreshold;
            public ulong DeCommitTotalFreeThreshold;
            public ulong LockPrefixTable;
            public ulong MaximumAllocationSize;
            public ulong VirtualMemoryThreshold;
            public ulong ProcessAffinityMask;
            public uint ProcessHeapFlags;
            public ushort CSDVersion;
            public ushort DependentLoadFlags;
            public ulong EditList;
            public ulong SecurityCookie;
            public ulong SEHandlerTable;
            public ulong SEHandlerCount;
            public ulong GuardCFCheckFunctionPointer;
            public ulong GuardCFDispatchFunctionPointer;
            public ulong GuardCFFunctionTable;
            public ulong GuardCFFunctionCount;
            public uint GuardFlags;
            public IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
            public ulong GuardAddressTakenIatEntryTable;
            public ulong GuardAddressTakenIatEntryCount;
            public ulong GuardLongJumpTargetTable;
            public ulong GuardLongJumpTargetCount;
            public ulong DynamicValueRelocTable;
            public ulong CHPEMetadataPointer;
            public ulong GuardRFFailureRoutine;
            public ulong GuardRFFailureRoutineFunctionPointer;
            public uint DynamicValueRelocTableOffset;
            public ushort DynamicValueRelocTableSection;
            public ushort Reserved2;
            public ulong GuardRFVerifyStackPointerFunctionPointer;
            public uint HotPatchTableOffset;
            public uint Reserved3;
            public ulong EnclaveConfigurationPointer;
            public ulong VolatileMetadataPointer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
        {
            public ushort Flags;
            public ushort Catalog;
            public uint CatalogOffset;
            public uint Reserved;
        };

        public struct LOADED_IMAGE
        {
            public IntPtr ModuleName;
            public IntPtr hFile;
            public IntPtr MappedAddress;
            public IntPtr FileHeader;
            public IntPtr LastRvaSection;
            public uint NumberOfSections;
            public IntPtr Sections;
            public uint Characteristics;
            public bool fSystemImage;
            public bool fDOSImage;
            public bool fReadOnly;
            public byte Version;
            public LIST_ENTRY Links;
            public uint SizeOfImage;
        }

        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
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

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
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

            /// <summary>
            /// Overridden ToString method, returns register values for the current thread.
            /// </summary>
            /// <returns>String</returns>
            public override string ToString()
            {
                string ret = "";
                ret += "EDI = " + Edi.ToString("X8") + Environment.NewLine;
                ret += "ESI = " + Esi.ToString("X8") + Environment.NewLine;
                ret += "EBX = " + Ebx.ToString("X8") + Environment.NewLine;
                ret += "EDX = " + Edx.ToString("X8") + Environment.NewLine;
                ret += "ECX = " + Ecx.ToString("X8") + Environment.NewLine;
                ret += "EAX = " + Eax.ToString("X8") + Environment.NewLine;
                ret += "EBP = " + Ebp.ToString("X8") + Environment.NewLine;
                ret += "ESP = " + Esp.ToString("X8") + Environment.NewLine;
                ret += "EIP = " + Eip.ToString("X8") + Environment.NewLine;
                return ret;
            }
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

            /// <summary>
            /// Overridden ToString method, returns register values for the current thread.
            /// </summary>
            /// <returns>String</returns>
            public override string ToString()
            {
                string ret = "";
                ret += "RAX = " + Rax.ToString("X16") + Environment.NewLine;
                ret += "RCX = " + Rcx.ToString("X16") + Environment.NewLine;
                ret += "RDX = " + Rdx.ToString("X16") + Environment.NewLine;
                ret += "RBX = " + Rbx.ToString("X16") + Environment.NewLine;
                ret += "RSP = " + Rsp.ToString("X16") + Environment.NewLine;
                ret += "RBP = " + Rbp.ToString("X16") + Environment.NewLine;
                ret += "RSI = " + Rsi.ToString("X16") + Environment.NewLine;
                ret += "RDI = " + Rdi.ToString("X16") + Environment.NewLine;
                ret += "R08 = " + R8.ToString("X16") + Environment.NewLine;
                ret += "R09 = " + R9.ToString("X16") + Environment.NewLine;
                ret += "R10 = " + R10.ToString("X16") + Environment.NewLine;
                ret += "R11 = " + R11.ToString("X16") + Environment.NewLine;
                ret += "R12 = " + R12.ToString("X16") + Environment.NewLine;
                ret += "R13 = " + R13.ToString("X16") + Environment.NewLine;
                ret += "R14 = " + R14.ToString("X16") + Environment.NewLine;
                ret += "R15 = " + R15.ToString("X16") + Environment.NewLine;
                ret += "RIP = " + Rip.ToString("X16") + Environment.NewLine;
                return ret;
            }
        }

        public class RegisterInfo
        {
            public string Register { get; set; }
            public IntPtr RegisterValue { get; set; }
            public int RegisterOffset { get; set; }
            public int StringOffset { get; set; }
            public int BufferSize { get; set; }
            public int ThreadID { get; set; }
        }
        #endregion

        #region TEB
        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadBasicInformation
        {
            public uint ExitStatus;
            public IntPtr TebBaseAdress;
            public ClientID Identifiers;
            public uint AffinityMask;
            public uint Priority;
            public uint BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ClientID
        {
            public IntPtr ProcessId;
            public IntPtr ThreadId;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct TEB
        {
            public IntPtr CurrentSehFrame;
            public IntPtr TopOfStack;
            public IntPtr BottomOfStack;
            public IntPtr SubSystemTeb;
            public IntPtr FiberData;
            public IntPtr ArbitraryDataSlot;
            public IntPtr Teb;
            public IntPtr EnvironmentPointer;
            public ClientID Identifiers;
            public IntPtr RpcHandle;
            public IntPtr Tls;
            public IntPtr Peb;
            public int LastErrorNumber;
            public int CriticalSectionsCount;
            public IntPtr CsrClientThread;
            public IntPtr Win32ThreadInfo;
            public byte[] Win32ClientInfo;
            public IntPtr WoW64Reserved;
            public IntPtr CurrentLocale;
            public IntPtr FpSoftwareStatusRegister;
            public byte[] SystemReserved1;
            public IntPtr ExceptionCode;
            public byte[] ActivationContextStack;
            public byte[] SpareBytes;
            public byte[] SystemReserved2;
            public byte[] GdiTebBatch;
            public IntPtr GdiRegion;
            public IntPtr GdiPen;
            public IntPtr GdiBrush;
            public int RealProcessId;
            public int RealThreadId;
            public IntPtr GdiCachedProcessHandle;
            public IntPtr GdiClientProcessId;
            public IntPtr GdiClientThreadId;
            public IntPtr GdiThreadLocalInfo;
            public byte[] UserReserved1;
            public byte[] GlReserved1;
            public int LastStatusValue;
            public byte[] StaticUnicodeString;
            public IntPtr DeallocationStack;
            public byte[] TlsSlots;
            public long TlsLinks;
            public IntPtr Vdm;
            public IntPtr RpcReserved;
            public IntPtr ThreadErrorMode;
        }
        #endregion

        #region PEB
        
        #endregion
    }
    #endregion
}
