using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ERC
{
    public class Process_Info : ERC_Core
    {
        #region Class_Variables
        public string Process_Name { get; set; }
        public string Process_Description { get; set; }
        public string Process_Filename { get; set; }
        public int Process_ID { get; set; }

        public IntPtr Process_Handle { get; set; }
        public Process Process_Current { get; set; }
        public MachineType Process_Machine_Type { get; set; }
        public Dictionary<string, IntPtr> Process_Module_Handles = new Dictionary<string, IntPtr>();
        public List<Module_Info> Modules_Info = new List<Module_Info>();
        public List<Thread_Info> Threads_Info = new List<Thread_Info>();

        public ERC_Core Process_Core;
        public List<MEMORY_BASIC_INFORMATION32> Process_Memory_Basic_Info32;
        public List<MEMORY_BASIC_INFORMATION64> Process_Memory_Basic_Info64;

        public const uint LIST_MODULES_ALL = 0x03;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor for the Process_Info object, requires an ERC_Core object and a Process.
        /// </summary>
        public Process_Info(ERC_Core core, Process process) : base(core)
        {
            Process_Core = core;
            if (Is64Bit(process))
            {
                Process_Machine_Type = MachineType.x64;
            }
            else
            {
                Process_Machine_Type = MachineType.I386;
            }
            Process_Name = process.ProcessName;
            Process_Description = FileVersionInfo.GetVersionInfo(process.MainModule.FileName).FileDescription;
            Process_Filename = FileVersionInfo.GetVersionInfo(process.MainModule.FileName).FileName;
            Process_ID = process.Id;
            Process_Current = process;
            Process_Handle = process.Handle;
            Process_Module_Handles = GetProcessModules(Process_Handle).Return_Value; 
            
            if(Process_Module_Handles.Count == 0)
            {
                for(int i = 0; i < process.Modules.Count; i++) 
                {
                    Process_Module_Handles.Add(process.Modules[i].FileName, process.Modules[i].BaseAddress);
                }
            }
            foreach (KeyValuePair<string, IntPtr> s in Process_Module_Handles)
            {
                Module_Info this_module_info = new Module_Info(s.Key, s.Value, process, core);
                if(this_module_info.Module_Failed == false)
                {
                    Modules_Info.Add(this_module_info);
                }
            }
            for(int i = 0; i < process.Threads.Count; i++)
            {
                Thread_Info this_thread_info = new Thread_Info(process.Threads[i], Process_Core);
                if(this_thread_info.Thread_Failed == false)
                {
                    Threads_Info.Add(this_thread_info);
                }
            }
            Locate_Memory_Regions(process);
        }

        protected Process_Info(Process_Info parent)
        {
            Process_Name = parent.Process_Name;
            Process_Description = parent.Process_Description;
            Process_Filename = parent.Process_Filename;
            Process_ID = parent.Process_ID;

            Process_Handle = parent.Process_Handle;
            Process_Current = parent.Process_Current;
            Process_Machine_Type = parent.Process_Machine_Type;
            Process_Module_Handles = parent.Process_Module_Handles;
            Modules_Info = parent.Modules_Info;

            Process_Core = parent.Process_Core;
            Process_Memory_Basic_Info32 = parent.Process_Memory_Basic_Info32;
            Process_Memory_Basic_Info64 = parent.Process_Memory_Basic_Info64;

            Working_Directory = parent.Working_Directory;
            Author = parent.Author;
            Logging = parent.Logging;
        }
        #endregion

        #region List_Local_Processes
        /// <summary>
        /// Gets a list of running processes on the host and removes unusable processes (such as system processes etc)
        /// </summary>
        public static ERC_Result<Process[]> List_Local_Processes(ERC_Core core)
        {
            ERC_Result<Process[]> result = new ERC_Result<Process[]>(core);
            Process[] processes = Process.GetProcesses();
            List<int> processes_to_remove = new List<int>();

            for(int i = 0; i < processes.Length; i++)
            {
                string filename = null;
                try
                {
                    filename = processes[i].MainModule.FileName;
                }
                catch(Exception e)
                {
                    processes_to_remove.Add(i);
                }
            }

            Process[] usable_processes = new Process[processes.Length - processes_to_remove.Count];
            int process_counter = 0;
            for (int i = 0; i < processes.Length; i++)
            {
                if (!processes_to_remove.Contains(i))
                {
                    usable_processes[process_counter] = processes[i];
                    process_counter++;
                }
            }
            
            result.Return_Value = usable_processes;
            return result;
        }
        #endregion

        #region Get_Process_Modules
        /// <summary>
        /// Returns a list of files loaded by the current process as List<String>
        /// </summary>
        private ERC_Result<Dictionary<string, IntPtr>> GetProcessModules(IntPtr hProcess)
        {
            ERC_Result<Dictionary<string, IntPtr>> result = new ERC_Result<Dictionary<string, IntPtr>>(Process_Core);
            result.Return_Value = new Dictionary<string, IntPtr>();
            Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();
            if (hProcess != IntPtr.Zero)
            {
                try
                {
                    IntPtr[] modhWnds = new IntPtr[0];
                    int lpcbNeeded = 0;

                    try
                    {
                        // -- call EnumProcessModules the first time to get the size of the array needed
                        EnumProcessModulesEx(hProcess, modhWnds, 0, out lpcbNeeded, LIST_MODULES_ALL);

                        modhWnds = new IntPtr[lpcbNeeded / IntPtr.Size];
                        EnumProcessModulesEx(hProcess, modhWnds, modhWnds.Length * IntPtr.Size, out lpcbNeeded, LIST_MODULES_ALL);
                    }
                    catch
                    {
                        result.Return_Value = modules;
                        return result;
                    }

                    for (int i = 0; i < modhWnds.Length; i++)
                    {
                        StringBuilder modName = new StringBuilder(256);
                        if (GetModuleFileNameEx(hProcess, modhWnds[i], modName, modName.Capacity) != 0)
                        {
                            if (!modules.ContainsKey(modName.ToString()))
                            {
                                modules.Add(modName.ToString(), modhWnds[i]);
                            }
                        }

                    }
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.Log_Event();
                    return result;
                }
            }
            result.Return_Value = modules;
            return result;
        }
        #endregion

        #region Identify_Process_Architecture
        /// <summary>
        /// Identifies if a process is 64bit or 32 bit, returns true for 64bit and false for 32bit.
        /// </summary>
        public static bool Is64Bit(Process process)
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            bool isWow64;
            if (!IsWow64Process(process.Handle, out isWow64))
            {
                throw new Exception("An error has occured in the IsWow64Process call from Process.Is64Bit()");
            }
            return !isWow64;
        }
        #endregion

        #region Locate_Process_Memory_Regions
        /// <summary>
        /// Identifies memory regions occupied by the current process and populates the associated list with the Process_Info object.
        /// </summary>
        private void Locate_Memory_Regions(Process process)
        {
            if (Process_Machine_Type == MachineType.I386)
            {
                Process_Memory_Basic_Info32 = new List<MEMORY_BASIC_INFORMATION32>();
                long MaxAddress = 0x7fffffff;
                long address = 0;

                do
                {
                    MEMORY_BASIC_INFORMATION32 m;
                    int result = VirtualQueryEx32(process.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32)));
                    if (address == (long)m.BaseAddress + (long)m.RegionSize)
                        break;
                    address = (long)m.BaseAddress + (long)m.RegionSize;
                    if (m.State == StateEnum.MEM_COMMIT)
                    {
                        Process_Memory_Basic_Info32.Add(m);
                    }
                } while (address <= MaxAddress);
            }
            else if (Process_Machine_Type == MachineType.x64)
            {
                Process_Memory_Basic_Info64 = new List<MEMORY_BASIC_INFORMATION64>();
                long MaxAddress = 0x000007FFFFFEFFFF;
                long address = 0;

                do
                {
                    MEMORY_BASIC_INFORMATION64 m;
                    int result = VirtualQueryEx64(process.Handle, (IntPtr)address, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                    if (address == (long)m.BaseAddress + (long)m.RegionSize)
                        break;
                    address = (long)m.BaseAddress + (long)m.RegionSize;
                    if(m.State == StateEnum.MEM_COMMIT && (m.Type == TypeEnum.MEM_MAPPED || m.Type == TypeEnum.MEM_PRIVATE))
                    {
                        Process_Memory_Basic_Info64.Add(m);
                    }
                    
                } while (address <= MaxAddress);
            }
            else
            {
                throw new Exception("Machine type is invalid");
            }
        }
        #endregion

        #region Search_Functions

        /// <summary>
        /// Searches memory regions populated by the process for specific strings. Takes a string or byte array as input to be searched for. 
        /// Returns a list of IntPtr for each instance found. Takes an integer to determine search type.
        /// </summary>
        public ERC_Result<List<IntPtr>> Search_Process_Memory(int searchType, byte[] byteString = null, string searchString = null)
        {
            const int PROCESS_VM_READ = 0x0010;
            ERC_Result<List<IntPtr>> result_addresses = new ERC_Result<List<IntPtr>>(Process_Core);
            byte[] searchBytes;

            switch (searchType)
            {
                case 0:
                    searchBytes = byteString;
                    break;
                case 1:
                    searchBytes = Encoding.Unicode.GetBytes(searchString);
                    break;
                case 2:
                    searchBytes = Encoding.ASCII.GetBytes(searchString);
                    break;
                case 3:
                    searchBytes = Encoding.UTF8.GetBytes(searchString);
                    break;
                case 4:
                    searchBytes = Encoding.UTF7.GetBytes(searchString);
                    break;
                default:
                    result_addresses.Error = new Exception("Incorrect searchType value provided, value must be 0-4");
                    return result_addresses;
            }

            result_addresses.Return_Value = new List<IntPtr>();
            Process process = Process_Current;

            if (Process_Machine_Type == MachineType.I386)
            {
                for (int i = 0; i < Process_Memory_Basic_Info32.Count; i++)
                {
                    if((ulong)Process_Memory_Basic_Info32[i].RegionSize > int.MaxValue)
                    {
                        long start_address = (long)Process_Memory_Basic_Info32[i].BaseAddress;
                        long end_address = (long)Process_Memory_Basic_Info32[i].BaseAddress + (long)(Process_Memory_Basic_Info32[i].RegionSize - 1);
                        long region = (long)Process_Memory_Basic_Info32[i].RegionSize;
                        for (long j = start_address; j < end_address; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100]; 
                            int bytesRead = 0;
                            ReadProcessMemory(Process_Handle, (IntPtr)j, buffer, buffer.Length, out bytesRead);

                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    result_addresses.Return_Value.Add((IntPtr)(index + (long)Process_Memory_Basic_Info32[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long buffer_size = (long)Process_Memory_Basic_Info32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr base_address = Process_Memory_Basic_Info32[i].BaseAddress;
                        byte[] buffer = new byte[buffer_size]; 

                        ReadProcessMemory(Process_Handle, base_address, buffer, buffer.Length, out bytesRead);

                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer.Length - pos];
                            Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                result_addresses.Return_Value.Add((IntPtr)(index + (long)Process_Memory_Basic_Info32[i].BaseAddress + pos));
                            }
                            pos += index;
                            if (index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            else if(Process_Machine_Type == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < Process_Memory_Basic_Info64.Count; i++)
                {
                    if (Process_Memory_Basic_Info64[i].RegionSize > int.MaxValue)
                    {
                        ulong start_address = Process_Memory_Basic_Info64[i].BaseAddress;
                        ulong end_address = Process_Memory_Basic_Info64[i].BaseAddress + (Process_Memory_Basic_Info64[i].RegionSize - 1);
                        ulong region = Process_Memory_Basic_Info64[i].RegionSize;

                        for (ulong j = start_address; j < end_address; j += int.MaxValue / 10)
                        {
                            ReadProcessMemory(Process_Handle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            long pos = 0;
                            long index = 0;
                            do
                            {
                                byte[] buffer1Partial = new byte[buffer.Length - pos];
                                Array.Copy(buffer, pos, buffer1Partial, 0, buffer.Length - pos);
                                index = ByteIndexOf(buffer1Partial, searchBytes);

                                if (index != -1)
                                {
                                    result_addresses.Return_Value.Add((IntPtr)(index + (long)Process_Memory_Basic_Info64[i].BaseAddress + pos));
                                }
                                pos += index;
                                if (index == 0)
                                {
                                    pos += searchBytes.Length;
                                    index = 1;
                                }
                            } while (index != -1 && index != 0);
                        }
                    }
                    else
                    {
                        long buffer_size = (long)Process_Memory_Basic_Info64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr base_address = (IntPtr)Process_Memory_Basic_Info64[i].BaseAddress;
                        byte[] buffer1 = new byte[buffer_size]; 

                        ReadProcessMemory(Process_Handle, base_address, buffer1, buffer1.Length, out bytesRead);
                        long pos = 0;
                        long index = 0;
                        do
                        {
                            byte[] buffer1Partial = new byte[buffer1.Length - pos];
                            Array.Copy(buffer1, pos, buffer1Partial, 0, buffer1.Length - pos);
                            index = ByteIndexOf(buffer1Partial, searchBytes);

                            if (index != -1)
                            {
                                result_addresses.Return_Value.Add((IntPtr)(index + (long)Process_Memory_Basic_Info64[i].BaseAddress + pos));
                            }
                            pos += index;
                            if(index == 0)
                            {
                                pos += searchBytes.Length;
                                index = 1;
                            }
                        } while (index != -1 && index != 0);
                    }
                }
            }
            result_addresses.Return_Value = new HashSet<IntPtr>(result_addresses.Return_Value).ToList();
            return result_addresses;  
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. Returns an ERC_Result<List<IntPtr>>
        /// </summary>
        /// <returns></returns>
        public ERC_Result<List<IntPtr>> Search_All_Memory_PPR(List<string> excludes = null)
        {
            ERC_Result<List<IntPtr>> ptrs = new ERC_Result<List<IntPtr>>(Process_Core);
            ptrs.Return_Value = new List<IntPtr>();
            if (Process_Machine_Type == MachineType.I386)
            {
                for (int i = 0; i < Process_Memory_Basic_Info32.Count; i++)
                {
                    if ((ulong)Process_Memory_Basic_Info32[i].RegionSize > int.MaxValue)
                    {
                        long start_address = (long)Process_Memory_Basic_Info32[i].BaseAddress;
                        long end_address = (long)Process_Memory_Basic_Info32[i].BaseAddress + (long)(Process_Memory_Basic_Info32[i].RegionSize - 1);
                        long region = (long)Process_Memory_Basic_Info32[i].RegionSize;
                        for (long j = start_address; j < end_address; j += (region / 100))
                        {
                            byte[] buffer = new byte[region / 100];
                            int bytesRead = 0;
                            ReadProcessMemory(Process_Handle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = Payloads.Pop_Pop_Ret(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress));
                                }
                            }
                        }
                    }
                    else
                    {
                        long buffer_size = (long)Process_Memory_Basic_Info32[i].RegionSize;
                        int bytesRead = 0;
                        IntPtr base_address = Process_Memory_Basic_Info32[i].BaseAddress;
                        byte[] buffer = new byte[buffer_size];

                        ReadProcessMemory(Process_Handle, base_address, buffer, buffer.Length, out bytesRead);
                        List<int> pprs = Payloads.Pop_Pop_Ret(buffer);
                        if (pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress));
                            }
                        }
                    }
                }
            }
            else if (Process_Machine_Type == MachineType.x64)
            {
                byte[] buffer = new byte[int.MaxValue / 10];
                int bytesRead = 0;
                for (int i = 0; i < Process_Memory_Basic_Info64.Count; i++)
                {
                    if (Process_Memory_Basic_Info64[i].RegionSize > int.MaxValue)
                    {
                        ulong start_address = Process_Memory_Basic_Info64[i].BaseAddress;
                        ulong end_address = Process_Memory_Basic_Info64[i].BaseAddress + (Process_Memory_Basic_Info64[i].RegionSize - 1);
                        ulong region = Process_Memory_Basic_Info64[i].RegionSize;

                        for (ulong j = start_address; j < end_address; j += int.MaxValue / 10)
                        {
                            ReadProcessMemory(Process_Handle, (IntPtr)j, buffer, buffer.Length, out bytesRead);
                            List<int> pprs = Payloads.Pop_Pop_Ret(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress));
                                }
                            }
                        }
                    }
                    else
                    {
                        long buffer_size = (long)Process_Memory_Basic_Info64[i].RegionSize;
                        bytesRead = 0;
                        IntPtr base_address = (IntPtr)Process_Memory_Basic_Info64[i].BaseAddress;
                        byte[] buffer1 = new byte[buffer_size];

                        ReadProcessMemory(Process_Handle, base_address, buffer1, buffer1.Length, out bytesRead);
                        List<int> pprs = Payloads.Pop_Pop_Ret(buffer1);
                        if(pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress));
                            }
                        }
                    }
                }
            }
            List<Module_Info> modules = new List<Module_Info>();
            for(int i = 0; i < Modules_Info.Count; i++)
            {
                if (excludes != null)
                {
                    if (!excludes.Contains(Modules_Info[i].Module_Name) && !excludes.Contains(Modules_Info[i].Module_Path))
                    {
                        modules.Add(Modules_Info[i]);
                    }
                }
                else
                {
                    modules.Add(Modules_Info[i]);
                }
            }
            Console.WriteLine("modules.Count {0}", modules.Count);
            for(int i = 0; i < modules.Count; i++)
            {

                IntPtr base_address = modules[i].Module_Base;
                byte[] buffer = new byte[modules[i].Module_Size];
                int bytesread = 0;

                ReadProcessMemory(Process_Handle, modules[i].Module_Base, buffer, buffer.Length, out bytesread);
                List<int> pprs = Payloads.Pop_Pop_Ret(buffer);
                if (pprs.Count > 0)
                {
                    for (int k = 0; k < pprs.Count; k++)
                    {
                        ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)modules[i].Module_Base));
                    }
                }
            }
            return ptrs;
        }

        #endregion

        #region BoyerMoore_Search_ByteArrays
        /// <summary>
        /// Private function, BoyerMoore string search algorithm modified to search for sets of bytes in a byte array. 
        /// Takes two byte arrays, array to be searched and array to search for.
        /// </summary>
        private static int ByteIndexOf(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0)
            {
                return 0;
            }

            int[] charTable = MakeCharTable(needle);
            int[] offsetTable = MakeOffsetTable(needle);
            for (int i = needle.Length - 1; i < haystack.Length;)
            {
                int j;
                for (j = needle.Length - 1; needle[j] == haystack[i]; --i, --j)
                {
                    if (j == 0)
                    {
                        return i;
                    }
                }

                i += Math.Max(offsetTable[needle.Length - 1 - j], charTable[haystack[i]]);
            }
            return -1;
        }

        private static int[] MakeCharTable(byte[] needle)
        {
            const int ALPHABET_SIZE = 256;
            int[] table = new int[ALPHABET_SIZE];
            for (int i = 0; i < table.Length; ++i)
            {
                table[i] = needle.Length;
            }

            for (int i = 0; i < needle.Length - 1; ++i)
            {
                table[needle[i]] = needle.Length - 1 - i;
            }

            return table;
        }

        private static int[] MakeOffsetTable(byte[] needle)
        {
            int[] table = new int[needle.Length];
            int lastPrefixPosition = needle.Length;
            for (int i = needle.Length - 1; i >= 0; --i)
            {
                if (IsPrefix(needle, i + 1))
                {
                    lastPrefixPosition = i + 1;
                }

                table[needle.Length - 1 - i] = lastPrefixPosition - i + needle.Length - 1;
            }

            for (int i = 0; i < needle.Length - 1; ++i)
            {
                int slen = SuffixLength(needle, i);
                table[slen] = needle.Length - 1 - i + slen;
            }

            return table;
        }

        private static bool IsPrefix(byte[] needle, int p)
        {
            for (int i = p, j = 0; i < needle.Length; ++i, ++j)
            {
                if (needle[i] != needle[j])
                {
                    return false;
                }
            }

            return true;
        }

        private static int SuffixLength(byte[] needle, int p)
        {
            int len = 0;
            for (int i = p, j = needle.Length - 1; i >= 0 && needle[i] == needle[j]; --i, --j)
            {
                len += 1;
            }

            return len;
        }

        #endregion

        #region Output Functions
        public string Module_Info_Output()
        {
            string modOutput = Display_Output.Display_Module_Info(this);
            string modFilename = Display_Output.Get_Module_File_Name(Working_Directory, "modules_", ".txt");
            File.WriteAllText(modFilename, modOutput);
            return modOutput;
        }
        #endregion
    }
}
