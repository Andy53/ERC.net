using ERC_Lib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

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
            Process_Module_Handles = GetProcessModules().Return_Value; 
            
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
                Thread_Info this_thread_info = new Thread_Info(process.Threads[i], Process_Core, this);
                if(this_thread_info.Thread_Failed == false)
                {
                    Threads_Info.Add(this_thread_info);
                }
            }
            Locate_Memory_Regions();
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
        /// <returns>Returns an ERC_Result containing a Dictionary of module names and the associated handles</returns>
        private ERC_Result<Dictionary<string, IntPtr>> GetProcessModules()
        {
            IntPtr hProcess = Process_Handle;
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
            bool isWow64;

            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            if (!IsWow64Process(process.Handle, out isWow64))
            {
                throw new ERCException("An error has occured in the IsWow64Process call from Process.Is64Bit()");
            }

            return !isWow64;
        }
        #endregion

        #region Locate_Process_Memory_Regions
        /// <summary>
        /// Identifies memory regions occupied by the current process and populates the associated list with the Process_Info object.
        /// </summary>
        /// <param name="process"></param>
        private void Locate_Memory_Regions()
        {
            Process process = Process_Current;
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
                    if (m.State == StateEnum.MEM_COMMIT && (m.Type == TypeEnum.MEM_MAPPED || m.Type == TypeEnum.MEM_PRIVATE))
                    {
                        Process_Memory_Basic_Info64.Add(m);
                    }

                } while (address <= MaxAddress);
            }
            else
            {
                throw new ERCException("Machine type is invalid");
            }
        }
        #endregion

        #region Search_Functions

        #region Search_Process_Memory
        /// <summary>
        /// Private function called from Search_Memory. Searches memory regions populated by the process for specific strings. Takes a byte array as input to be searched for. 
        /// </summary>
        /// <param name="searchBytes"></param>
        /// <returns>Returns a list of IntPtr for each instance found.</returns>
        private ERC_Result<List<IntPtr>> Search_Process_Memory(byte[] searchBytes)
        {
            ERC_Result<List<IntPtr>> result_addresses = new ERC_Result<List<IntPtr>>(Process_Core);

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
        #endregion

        #region Search_All_Memory_PPR
        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// </summary>
        /// <returns>Returns an ERC_Result containing a dictionary of pointers and the main module in which they were found</returns>
        public ERC_Result<Dictionary<IntPtr, string>> Search_All_Memory_PPR(List<string> excludes = null)
        {
            ERC_Result<Dictionary<IntPtr, string>> ptrs = new ERC_Result<Dictionary<IntPtr, string>>(Process_Core);
            ptrs.Return_Value = new Dictionary<IntPtr, string>();
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
                            List<int> pprs = ERC.Utilities.Payloads.Pop_Pop_Ret(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.Return_Value.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress)))
                                    {
                                        ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress), Process_Filename);
                                    }
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
                        List<int> pprs = ERC.Utilities.Payloads.Pop_Pop_Ret(buffer);
                        if (pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.Return_Value.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress)))
                                {
                                    ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)Process_Memory_Basic_Info32[i].BaseAddress), Process_Filename);
                                }
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
                            List<int> pprs = ERC.Utilities.Payloads.Pop_Pop_Ret(buffer);
                            if (pprs.Count > 0)
                            {
                                for (int k = 0; k < pprs.Count; k++)
                                {
                                    if (!ptrs.Return_Value.ContainsKey((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress)))
                                    {
                                        ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress), Process_Filename);
                                    }
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
                        List<int> pprs = ERC.Utilities.Payloads.Pop_Pop_Ret(buffer1);
                        if(pprs.Count > 0)
                        {
                            for (int k = 0; k < pprs.Count; k++)
                            {
                                if (!ptrs.Return_Value.ContainsKey((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress)))
                                {
                                    ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + Process_Memory_Basic_Info64[i].BaseAddress), Process_Filename);
                                }
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
            for(int i = 0; i < modules.Count; i++)
            {

                IntPtr base_address = modules[i].Module_Base;
                byte[] buffer = new byte[modules[i].Module_Size];
                int bytesread = 0;

                ReadProcessMemory(Process_Handle, modules[i].Module_Base, buffer, buffer.Length, out bytesread);
                List<int> pprs = ERC.Utilities.Payloads.Pop_Pop_Ret(buffer);
                if (pprs.Count > 0)
                {
                    for (int k = 0; k < pprs.Count; k++)
                    {
                        if (!ptrs.Return_Value.ContainsKey((IntPtr)((ulong)pprs[k] + (ulong)modules[i].Module_Base)))
                        {
                            ptrs.Return_Value.Add((IntPtr)((ulong)pprs[k] + (ulong)modules[i].Module_Base), modules[i].Module_Path);
                        }
                    }
                }
            }
            return ptrs;
        }
        #endregion

        #region Search_Memory
        /// <summary>
        /// Searches all memory (the process and associated DLLs) for a specific string or byte array. Strings can be passed as ASCII, Unicode, UTF7 or UTF8.
        /// Specific modules can be exclude through passing a Listof strings containing module names or paths.
        /// </summary>
        /// <param name="searchType">0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="searchBytes">Byte array to be searched for (optional)</param>
        /// <param name="searchString">String to be searched for (optional)</param>
        /// <param name="excludes">Modules to be excluded from the search (optional)</param>
        /// <returns>Returns an ERC_Result containing pointers to all instances of the search query.</returns>
        public ERC_Result<Dictionary<IntPtr, string>> Search_Memory(int searchType, byte[] searchBytes = null, string searchString = null, List<string> excludes = null)
        {
            ERC_Result<Dictionary<IntPtr, string>> result_addresses = new ERC_Result<Dictionary<IntPtr, string>>(Process_Core);
            if (searchBytes == null && searchString == null)
            {
                result_addresses.Error = new ERCException("No search term provided. " +
                    "Either a byte array or string must be provided as the search term or there is nothing to search for.");
                result_addresses.Log_Event();
                return result_addresses;
            }
            result_addresses.Return_Value = new Dictionary<IntPtr, string>();
            switch (searchType)
            {
                case 0:
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
                case 5:
                    searchBytes = Encoding.UTF32.GetBytes(searchString);
                    break;
                default:
                    result_addresses.Error = new ERCException("Incorrect searchType value provided, value must be 0-4");
                    result_addresses.Log_Event();
                    return result_addresses;
            }
            var process_ptrs = Search_Process_Memory(searchBytes);
            if(process_ptrs.Error != null)
            {
                result_addresses.Error = new ERCException("Error passed from Search_Process_Memory: " + process_ptrs.Error.ToString());
                result_addresses.Log_Event();
                return result_addresses;
            }

            for(int i = 0; i < process_ptrs.Return_Value.Count; i++)
            {
                if (!result_addresses.Return_Value.ContainsKey(process_ptrs.Return_Value[i]))
                {
                    result_addresses.Return_Value.Add(process_ptrs.Return_Value[i], Process_Filename);
                }
            }

            List<Module_Info> modules = new List<Module_Info>();
            for (int i = 0; i < Modules_Info.Count; i++)
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
            for(int i = 0; i < modules.Count; i++)
            {
                var module_ptrs = modules[i].Search_Module(searchBytes);
                if(module_ptrs.Return_Value.Count > 0)
                {
                    for(int j = 0; j < module_ptrs.Return_Value.Count; j++)
                    {
                        if (!result_addresses.Return_Value.ContainsKey(module_ptrs.Return_Value[j]))
                        {
                            result_addresses.Return_Value.Add(module_ptrs.Return_Value[j], modules[i].Module_Path);
                        }
                    }
                }
            }
            return result_addresses;
        }
        #endregion

        #region FindNRP
        /// <summary>
        /// Searches process registers and identifies pointers to buffers in memory containing a non repeating pattern. Functionality to identify SEH overwrites not yet implements.
        /// </summary>
        /// <param name="searchType">(Optional) 0 = search term is system default\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="extended">(Optional) Include additional characters in the pattern (!#$%^& etc) in the to be searched</param>
        /// <returns>Returns a ERC_Result containing a List of RegisterOffset</returns>
        public ERC_Result<List<RegisterOffset>> FindNRP(int searchType = 0, bool extended = false)
        {
            ERC_Result<List<RegisterOffset>> offsets = new ERC_Result<List<RegisterOffset>>(Process_Core);
            List<string> nrps = new List<string>();
            string pattern = "";
            if(extended == false)
            {
                pattern = File.ReadAllText(Process_Core.Pattern_Standard_Path);
            }
            else
            {
                pattern = File.ReadAllText(Process_Core.Pattern_Extended_Path);
            }

            string nrp_holder = "";
            int counter = 0;
            for(int i = 0; i < pattern.Length; i++)
            {
                if(counter != 2)
                {
                    nrp_holder += pattern[i];
                    counter++;
                }
                else
                {
                    nrp_holder += pattern[i];
                    nrps.Add(nrp_holder);
                    nrp_holder = "";
                    counter = 0;
                }
            }

            for (int i = 0; i < Threads_Info.Count; i++)
            {
                var context = Threads_Info[i].Get_Context();
                if(context.Error != null)
                {
                    context.Log_Event();
                    offsets.Error = context.Error;
                }
            }

            List<RegisterOffset> registers = new List<RegisterOffset>();
            if(Process_Machine_Type == MachineType.I386)
            {
                for (int i = 0; i < Threads_Info.Count; i++)
                {
                    RegisterOffset regEdi = new RegisterOffset();
                    regEdi.Register = "EDI";
                    regEdi.Register_Value = (IntPtr)Threads_Info[i].Context32.Edi;
                    regEdi.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEdi);
                    RegisterOffset regEsi = new RegisterOffset();
                    regEsi.Register = "ESI";
                    regEsi.Register_Value = (IntPtr)Threads_Info[i].Context32.Esi;
                    regEsi.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEsi);
                    RegisterOffset regEbx = new RegisterOffset();
                    regEbx.Register = "EBX";
                    regEbx.Register_Value = (IntPtr)Threads_Info[i].Context32.Ebx;
                    regEbx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEbx);
                    RegisterOffset regEdx = new RegisterOffset();
                    regEdx.Register = "EDX";
                    regEdx.Register_Value = (IntPtr)Threads_Info[i].Context32.Edx;
                    regEdx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEdx);
                    RegisterOffset regEcx = new RegisterOffset();
                    regEcx.Register = "ECX";
                    regEcx.Register_Value = (IntPtr)Threads_Info[i].Context32.Ecx;
                    regEcx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEcx);
                    RegisterOffset regEax = new RegisterOffset();
                    regEax.Register = "EAX";
                    regEax.Register_Value = (IntPtr)Threads_Info[i].Context32.Eax;
                    regEax.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEax);
                    RegisterOffset regEsp = new RegisterOffset();
                    regEsp.Register = "ESP";
                    regEsp.Register_Value = (IntPtr)Threads_Info[i].Context32.Esp;
                    regEsp.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEsp);
                    RegisterOffset regEbp = new RegisterOffset();
                    regEbp.Register = "EBP";
                    regEbp.Register_Value = (IntPtr)Threads_Info[i].Context32.Ebp;
                    regEbp.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regEbp);
                    RegisterOffset regEIP = new RegisterOffset();
                    regEIP.Register = "EIP";
                    regEIP.Register_Value = (IntPtr)Threads_Info[i].Context32.Eip;
                    registers.Add(regEIP);
                }

                for (int i = 0; i < registers.Count; i++)
                {
                    for (int j = 0; j < Process_Memory_Basic_Info32.Count; j++)
                    {
                        ulong regionStart = (ulong)Process_Memory_Basic_Info32[j].BaseAddress;
                        ulong regionEnd = (ulong)Process_Memory_Basic_Info32[j].BaseAddress + (ulong)Process_Memory_Basic_Info32[j].RegionSize;

                        if (registers[i].Register != "EIP" && registers[i].Register != "EBP" &&
                            (ulong)registers[i].Register_Value > regionStart && 
                            (ulong)registers[i].Register_Value < regionEnd)
                        {
                            ulong bufferSize = ((ulong)Process_Memory_Basic_Info32[j].BaseAddress + (ulong)Process_Memory_Basic_Info32[j].RegionSize) - (ulong)registers[i].Register_Value;
                            byte[] buffer = new byte[bufferSize];
                            int bytesRead = 0;
                            ReadProcessMemory(Process_Handle, registers[i].Register_Value, buffer, (int)bufferSize, out bytesRead);

                            string memoryString = "";
                            switch (searchType)
                            {
                                case 0:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                                case 1:
                                    memoryString = Encoding.Unicode.GetString(buffer);
                                    break;
                                case 2:
                                    memoryString = Encoding.ASCII.GetString(buffer);
                                    break;
                                case 3:
                                    memoryString = Encoding.UTF8.GetString(buffer);
                                    break;
                                case 4:
                                    memoryString = Encoding.UTF7.GetString(buffer);
                                    break;
                                case 5:
                                    memoryString = Encoding.UTF32.GetString(buffer);
                                    break;
                                default:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                            }
                            int length = 0;
                            for(int k = 0; k < nrps.Count; k++)
                            {
                                if (memoryString.Contains(nrps[k]))
                                {
                                    if(length == 0)
                                    {
                                        registers[i].String_Offset = pattern.IndexOf(nrps[k]);

                                        //Check to see if previous characters match
                                        int index = memoryString.IndexOf(nrps[k]);
                                        registers[i].Register_Offset = index;
                                        if (index >= 2)
                                        {
                                            char pos3 = memoryString[index - 1];
                                            char pos2 = memoryString[index - 2];
                                            char pos1 = memoryString[index - 3];
                                            if (k > 0 && nrps[k - 1][2] == pos3)
                                            {
                                                registers[i].String_Offset--;
                                                registers[i].Register_Offset--;
                                                if (nrps[k - 1][1] == pos2)
                                                {
                                                    registers[i].String_Offset--;
                                                    registers[i].Register_Offset--;
                                                    if (nrps[k - 1][0] == pos1)
                                                    {
                                                        registers[i].String_Offset--;
                                                        registers[i].Register_Offset--;
                                                    }
                                                }
                                            }
                                        }
                                        else if (index == 1)
                                        {
                                            char pos3 = memoryString[index - 1];
                                            if (nrps[k - 1][2] == pos3 && k > 0)
                                            {
                                                registers[i].Register_Offset--;
                                            }
                                        }
                                    }
                                    length += 3;
                                }
                                else
                                {
                                    k = nrps.Count;
                                    registers[i].Buffer_Size = length;
                                }
                            }
                        }
                        else if (registers[i].Register != "EIP")
                        {
                            string EIPValue = "";
                            switch (searchType)
                            {
                                case 0:
                                    EIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 1:
                                    EIPValue = Encoding.Unicode.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 2:
                                    EIPValue = Encoding.ASCII.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 3:
                                    EIPValue = Encoding.UTF8.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 4:
                                    EIPValue = Encoding.UTF7.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 5:
                                    EIPValue = Encoding.UTF32.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                default:
                                    EIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                            }
                            if (pattern.Contains(EIPValue))
                            {
                                registers[i].String_Offset = pattern.IndexOf(EIPValue);
                            }
                        }
                    }
                }
            }
            else if(Process_Machine_Type == MachineType.x64)
            {
                for (int i = 0; i < Threads_Info.Count; i++)
                {
                    RegisterOffset regRax = new RegisterOffset();
                    regRax.Register = "Rax";
                    regRax.Register_Value = (IntPtr)Threads_Info[i].Context64.Rax;
                    regRax.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRax);
                    RegisterOffset regRbx = new RegisterOffset();
                    regRbx.Register = "RBX";
                    regRbx.Register_Value = (IntPtr)Threads_Info[i].Context64.Rbx;
                    regRbx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRbx);
                    RegisterOffset regRcx = new RegisterOffset();
                    regRcx.Register = "RCX";
                    regRcx.Register_Value = (IntPtr)Threads_Info[i].Context64.Rcx;
                    regRcx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRcx);
                    RegisterOffset regRdx = new RegisterOffset();
                    regRdx.Register = "RDX";
                    regRdx.Register_Value = (IntPtr)Threads_Info[i].Context64.Rdx;
                    regRdx.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRdx);
                    RegisterOffset regRsp = new RegisterOffset();
                    regRsp.Register = "RSP";
                    regRsp.Register_Value = (IntPtr)Threads_Info[i].Context64.Rsp;
                    regRsp.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRsp);
                    RegisterOffset regRbp = new RegisterOffset();
                    regRbp.Register = "RBP";
                    regRbp.Register_Value = (IntPtr)Threads_Info[i].Context64.Rbp;
                    regRbp.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRbp);
                    RegisterOffset regRsi = new RegisterOffset();
                    regRsi.Register = "RSI";
                    regRsi.Register_Value = (IntPtr)Threads_Info[i].Context64.Rsi;
                    regRsi.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRsi);
                    RegisterOffset regRdi = new RegisterOffset();
                    regRdi.Register = "RDI";
                    regRdi.Register_Value = (IntPtr)Threads_Info[i].Context64.Rdi;
                    regRdi.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRdi);
                    RegisterOffset regR8 = new RegisterOffset();
                    regR8.Register = "R8";
                    regR8.Register_Value = (IntPtr)Threads_Info[i].Context64.R8;
                    regR8.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR8);
                    RegisterOffset regR9 = new RegisterOffset();
                    regR9.Register = "R9";
                    regR9.Register_Value = (IntPtr)Threads_Info[i].Context64.R9;
                    regR9.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR9);
                    RegisterOffset regR10 = new RegisterOffset();
                    regR10.Register = "R10";
                    regR10.Register_Value = (IntPtr)Threads_Info[i].Context64.R10;
                    regR10.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR10);
                    RegisterOffset regR11 = new RegisterOffset();
                    regR11.Register = "R11";
                    regR11.Register_Value = (IntPtr)Threads_Info[i].Context64.R11;
                    regR11.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR11);
                    RegisterOffset regR12 = new RegisterOffset();
                    regR12.Register = "R12";
                    regR12.Register_Value = (IntPtr)Threads_Info[i].Context64.R12;
                    regR12.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR12);
                    RegisterOffset regR13 = new RegisterOffset();
                    regR13.Register = "R13";
                    regR13.Register_Value = (IntPtr)Threads_Info[i].Context64.R13;
                    regR13.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR13);
                    RegisterOffset regR14 = new RegisterOffset();
                    regR14.Register = "R14";
                    regR14.Register_Value = (IntPtr)Threads_Info[i].Context64.R14;
                    regR14.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR14);
                    RegisterOffset regR15 = new RegisterOffset();
                    regR15.Register = "R15";
                    regR15.Register_Value = (IntPtr)Threads_Info[i].Context64.R15;
                    regR15.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regR15);
                    RegisterOffset regRIP = new RegisterOffset();
                    regRIP.Register = "RIP";
                    regRIP.Register_Value = (IntPtr)Threads_Info[i].Context64.Rip;
                    regRIP.Thread_ID = Threads_Info[i].Thread_ID;
                    registers.Add(regRIP);
                }

                for (int i = 0; i < registers.Count; i++)
                {
                    for (int j = 0; j < Process_Memory_Basic_Info64.Count; j++)
                    {
                        ulong regionStart = Process_Memory_Basic_Info64[j].BaseAddress;
                        ulong regionEnd = Process_Memory_Basic_Info64[j].BaseAddress + Process_Memory_Basic_Info64[j].RegionSize;

                        if (registers[i].Register != "RIP" && registers[i].Register != "RBP" &&
                            (ulong)registers[i].Register_Value > regionStart &&
                            (ulong)registers[i].Register_Value < regionEnd)
                        {
                            ulong bufferSize = (Process_Memory_Basic_Info64[j].BaseAddress + Process_Memory_Basic_Info64[j].RegionSize) - (ulong)registers[i].Register_Value;
                            byte[] buffer = new byte[bufferSize];
                            int bytesRead = 0;
                            ReadProcessMemory(Process_Handle, registers[i].Register_Value, buffer, (int)bufferSize, out bytesRead);

                            string memoryString = "";
                            switch (searchType)
                            {
                                case 0:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                                case 1:
                                    memoryString = Encoding.Unicode.GetString(buffer);
                                    break;
                                case 2:
                                    memoryString = Encoding.ASCII.GetString(buffer);
                                    break;
                                case 3:
                                    memoryString = Encoding.UTF8.GetString(buffer);
                                    break;
                                case 4:
                                    memoryString = Encoding.UTF7.GetString(buffer);
                                    break;
                                case 5:
                                    memoryString = Encoding.UTF32.GetString(buffer);
                                    break;
                                default:
                                    memoryString = Encoding.Default.GetString(buffer);
                                    break;
                            }
                            int length = 0;
                            for (int k = 0; k < nrps.Count; k++)
                            {
                                if (memoryString.Contains(nrps[k]))
                                {
                                    if (length == 0)
                                    {
                                        registers[i].String_Offset = pattern.IndexOf(nrps[k]);

                                        //Check to see if previous characters match
                                        int index = memoryString.IndexOf(nrps[k]);
                                        registers[i].Register_Offset = index;
                                        if (index >= 2)
                                        {
                                            char pos3 = memoryString[index - 1];
                                            char pos2 = memoryString[index - 2];
                                            char pos1 = memoryString[index - 3];
                                            if (k > 0 && nrps[k - 1][2] == pos3)
                                            {
                                                registers[i].String_Offset--;
                                                registers[i].Register_Offset--;
                                                if (nrps[k - 1][1] == pos2)
                                                {
                                                    registers[i].String_Offset--;
                                                    registers[i].Register_Offset--;
                                                    if (nrps[k - 1][0] == pos1)
                                                    {
                                                        registers[i].String_Offset--;
                                                        registers[i].Register_Offset--;
                                                    }
                                                }
                                            }
                                        }
                                        else if (index == 1)
                                        {
                                            char pos3 = memoryString[index - 1];
                                            if (nrps[k - 1][2] == pos3 && k > 0)
                                            {
                                                registers[i].Register_Offset--;
                                            }
                                        }
                                    }
                                    length += 3;
                                }
                                else
                                {
                                    k = nrps.Count;
                                    registers[i].Buffer_Size = length;
                                }
                            }
                        }
                        else if(registers[i].Register != "RIP")
                        {
                            string RIPValue = "";
                            switch (searchType)
                            {
                                case 0:
                                    RIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 1:
                                    RIPValue = Encoding.Unicode.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 2:
                                    RIPValue = Encoding.ASCII.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 3:
                                    RIPValue = Encoding.UTF8.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 4:
                                    RIPValue = Encoding.UTF7.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                case 5:
                                    RIPValue = Encoding.UTF32.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                                default:
                                    RIPValue = Encoding.Default.GetString(BitConverter.GetBytes((ulong)registers[i].Register_Value));
                                    break;
                            }
                            if (pattern.Contains(RIPValue))
                            {
                                registers[i].String_Offset = pattern.IndexOf(RIPValue);
                            }
                        }
                    }
                }
            }
            else
            {
                offsets.Error = new ERCException("Critical Error: Process returned incompatible machine type.");
                offsets.Log_Event();
            }
            offsets.Return_Value = registers;
            return offsets;
        }
        #endregion

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
    }
}
