using ERC.Structures;
using ERC_Lib;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;


namespace ERC
{
    public class ModuleInfo
    {
        #region Class Variables
        public string ModuleName { get; private set; }
        public string ModulePath { get; private set; }
        public string ModuleVersion { get; private set; }
        public string ModuleProduct { get; private set; }

        public IntPtr ModuleBase { get; private set; }
        public IntPtr ModuleEntry { get; private set; }
        public IntPtr ModuleImageBase { get; private set; }
        public int ModuleSize { get; private set; }

        public bool ModuleASLR { get; private set; }
        public bool ModuleSafeSEH { get; private set; }
        public bool ModuleRebase { get; private set; }
        public bool ModuleNXCompat { get; private set; }
        public bool ModuleOsDll { get; private set; }
        public Process ModuleProcess { get; private set; }
        public ErcCore ModuleCore { get; private set; }

        public MachineType ModuleMachineType { get; private set; }
        internal IMAGE_DOS_HEADER ImageDosHeader = new IMAGE_DOS_HEADER();
        internal IMAGE_FILE_HEADER ImageFileHeader = new IMAGE_FILE_HEADER();
        internal IMAGE_NT_HEADERS32 ImageNTHeaders32;
        internal IMAGE_NT_HEADERS64 ImageNTHeaders64;
        internal IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader32;
        internal IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64;

        public bool ModuleFailed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor for the ModuleInfo object. Takes (string)modules filepath (IntPtr)module handle (Process)Process from which the module is loaded
        /// </summary>
        /// <param name="module">Filepath of the module</param>
        /// <param name="ptr">Handle to the module</param>
        /// <param name="process">Process where the module is loaded</param>
        internal unsafe ModuleInfo(string module, IntPtr ptr, Process process, ErcCore core)
        {
            try
            {
                ModuleCore = core;
                ModuleProcess = process;
                ModuleName = FileVersionInfo.GetVersionInfo(module).InternalName;
                ModulePath = FileVersionInfo.GetVersionInfo(module).FileName;

                FileInfo fileInfo = new FileInfo(ModulePath);
                FileStream file = fileInfo.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
                Populate_Structs(file);

                if (!string.IsNullOrEmpty(FileVersionInfo.GetVersionInfo(module).FileVersion))
                {
                    ModuleVersion = FileVersionInfo.GetVersionInfo(module).FileVersion.Split(' ')[0];
                }
                else
                {
                    ModuleVersion = "";
                }

                ModuleProduct = FileVersionInfo.GetVersionInfo(module).ProductName;
                ModuleBase = ptr;

                if (ModuleMachineType == MachineType.I386)
                {
                    ModuleEntry = (IntPtr)ImageOptionalHeader32.AddressOfEntryPoint;
                    ModuleSize = (int)ImageOptionalHeader32.SizeOfImage;
                    ModuleImageBase = (IntPtr)ImageOptionalHeader32.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(ImageOptionalHeader32.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            ModuleASLR = true;
                        }
                        else
                        {
                            ModuleASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            ModuleNXCompat = true;
                        }
                        else
                        {
                            ModuleNXCompat = false;
                        }

                        if (bits[i] == true && i == 9)
                        {
                            ModuleSafeSEH = false;
                        }
                        else
                        {
                            ModuleSafeSEH = true;
                        }
                    }
                }
                else if (ModuleMachineType == MachineType.x64)
                {
                    ModuleEntry = (IntPtr)ImageOptionalHeader64.AddressOfEntryPoint;
                    ModuleSize = (int)ImageOptionalHeader64.SizeOfImage;
                    ModuleImageBase = (IntPtr)ImageOptionalHeader64.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(ImageOptionalHeader64.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            ModuleASLR = true;
                        }
                        else if (bits[i] == false && i == 6)
                        {
                            ModuleASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            ModuleNXCompat = true;
                        }
                        else if (bits[i] == false && i == 8)
                        {
                            ModuleNXCompat = false;
                        }

                        if (bits[i] == true && i == 10)
                        {
                            ModuleSafeSEH = false;
                        }
                        else if (bits[i] == false && i == 10)
                        {
                            ModuleSafeSEH = true;
                        }
                    }
                }
                else
                {
                    ModuleFailed = true;
                    throw new ERCException("Unsupported machine type: " + ModuleMachineType.ToString());
                }             

                if (ModuleProduct == "Microsoft® Windows® Operating System")
                {
                    ModuleOsDll = true;
                }
                else
                {
                    ModuleOsDll = false;
                }

                if (ModuleImageBase != ptr)
                {
                    ModuleRebase = true;
                }
                else
                {
                    ModuleRebase = false;
                }
            }
            catch (Exception e)
            {
                ErcResult<Exception> ExceptionLogger = new ErcResult<Exception>(ModuleCore);
                ExceptionLogger.Error = e;
                ExceptionLogger.LogEvent();
                ModuleFailed = true;
            }
        }

        private unsafe void Populate_Structs(FileStream fin)
        {
            byte[] Data = new byte[4096];
            int iRead = fin.Read(Data, 0, 4096);

            fin.Flush();
            fin.Close();

            fixed (byte* p_Data = Data)
            {
                IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)p_Data;
                IMAGE_NT_HEADERS32* inhs = (IMAGE_NT_HEADERS32*)(idh->nt_head_ptr + p_Data);
                ModuleMachineType = (MachineType)inhs->FileHeader.Machine;

                if (ModuleMachineType == MachineType.I386)
                {
                    IMAGE_NT_HEADERS32* inhs32 = (IMAGE_NT_HEADERS32*)(idh->nt_head_ptr + p_Data);
                    ImageFileHeader = inhs32->FileHeader;
                    ModuleMachineType = (MachineType)inhs32->FileHeader.Machine;
                    ImageOptionalHeader32 = inhs32->OptionalHeader;
                    ModuleImageBase = (IntPtr)inhs32->OptionalHeader.ImageBase;
                }
                else if (ModuleMachineType == MachineType.x64)
                {
                    IMAGE_NT_HEADERS64* inhs64 = (IMAGE_NT_HEADERS64*)(idh->nt_head_ptr + p_Data);
                    ImageFileHeader = inhs64->FileHeader;
                    ImageOptionalHeader64 = inhs64->OptionalHeader;
                    ModuleImageBase = (IntPtr)inhs64->OptionalHeader.ImageBase;
                }
            }
        }
        #endregion

        #region SearchModule
        /// <summary>
        /// Searches for a string of bytes within a specific module. Takes a byte array to be searched for. 
        /// </summary>
        /// <param name="searchBytes">A byte array to be searched for</param>
        /// <returns>Returns ERC_Result of pointers to the search term</returns>
        public ErcResult<List<IntPtr>> SearchModule(byte[] searchBytes)
        {
            ErcResult<List<IntPtr>> results = new ErcResult<List<IntPtr>>(ModuleCore);
            List<IntPtr> ptrs = new List<IntPtr>();

            IntPtr baseAddress = ModuleBase;
            byte[] buffer = new byte[ModuleSize];
            int bytesread = 0;

            ErcCore.ReadProcessMemory(ModuleProcess.Handle, ModuleBase, buffer, buffer.Length, out bytesread);
            List<int> positions = SearchBytePattern(searchBytes, buffer);

            for(int i = 0; i < positions.Count; i++)
            {
                ptrs.Add((IntPtr)(positions[i] + (long)ModuleBase));
            }
            
            results.ReturnValue = ptrs;
            return results;
        }

        private List<int> SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        positions.Add(i);
                        i += patternLength - 1;
                    }
                }
            }
            return positions;
        }
        #endregion 
    }
}
