using ERC_Lib;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;


namespace ERC
{
    public class Module_Info
    {
        #region Class_Variables
        public string Module_Name { get; set; }
        public string Module_Path { get; set; }
        public string Module_Version { get; set; }
        public string Module_Product { get; set; }

        public IntPtr Module_Base { get; set; }
        public IntPtr Module_Entry { get; set; }
        public IntPtr Module_Image_Base { get; set; }
        public int Module_Size { get; set; }

        public bool Module_ASLR { get; set; }
        public bool Module_Safe_SEH { get; set; }
        public bool Module_Rebase { get; set; }
        public bool Module_NXCompat { get; set; }
        public bool Module_OS_DLL { get; set; }
        public Process Module_Process { get; set; }
        public ERC_Core Module_Core { get; set; }

        public MachineType Module_Machine_Type { get; set; }
        public IMAGE_DOS_HEADER Image_Dos_Header = new IMAGE_DOS_HEADER();
        public IMAGE_FILE_HEADER Image_File_Header = new IMAGE_FILE_HEADER();
        public IMAGE_NT_HEADERS32 Image_NT_Headers32;
        public IMAGE_NT_HEADERS64 Image_NT_Headers64;
        public IMAGE_OPTIONAL_HEADER32 Image_Optional_Header32;
        public IMAGE_OPTIONAL_HEADER64 Image_Optional_Header64;

        public bool Module_Failed = false;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructor for the Module_Info object. Takes (string)modules filepath (IntPtr)module handle (Process)Process from which the module is loaded
        /// </summary>
        /// <param name="module"></param>
        /// <param name="ptr"></param>
        /// <param name="process"></param>
        public unsafe Module_Info(string module, IntPtr ptr, Process process, ERC_Core core)
        {
            try
            {
                Module_Core = core;
                Module_Process = process;
                Module_Name = FileVersionInfo.GetVersionInfo(module).InternalName;
                Module_Path = FileVersionInfo.GetVersionInfo(module).FileName;

                FileInfo fileInfo = new FileInfo(Module_Path);
                FileStream file = fileInfo.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
                Populate_Structs(file);

                if (!string.IsNullOrEmpty(FileVersionInfo.GetVersionInfo(module).FileVersion))
                {
                    Module_Version = FileVersionInfo.GetVersionInfo(module).FileVersion.Split(' ')[0];
                }
                else
                {
                    Module_Version = "";
                }

                Module_Product = FileVersionInfo.GetVersionInfo(module).ProductName;
                Module_Base = ptr;

                if (Module_Machine_Type == MachineType.I386)
                {
                    Module_Entry = (IntPtr)Image_Optional_Header32.AddressOfEntryPoint;
                    Module_Size = (int)Image_Optional_Header32.SizeOfImage;
                    Module_Image_Base = (IntPtr)Image_Optional_Header32.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(Image_Optional_Header32.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            Module_ASLR = true;
                        }
                        else
                        {
                            Module_ASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            Module_NXCompat = true;
                        }
                        else
                        {
                            Module_NXCompat = false;
                        }

                        if (bits[i] == true && i == 9)
                        {
                            Module_Safe_SEH = false;
                        }
                        else
                        {
                            Module_Safe_SEH = true;
                        }
                    }
                }
                else if (Module_Machine_Type == MachineType.x64)
                {
                    Module_Entry = (IntPtr)Image_Optional_Header64.AddressOfEntryPoint;
                    Module_Size = (int)Image_Optional_Header64.SizeOfImage;
                    Module_Image_Base = (IntPtr)Image_Optional_Header64.ImageBase;
                    byte[] dllByte = BitConverter.GetBytes(Image_Optional_Header64.DllCharacteristics);
                    BitArray bits = new BitArray(dllByte);
                    for (int i = 0; i < bits.Count; i++)
                    {
                        if (bits[i] == true && i == 6)
                        {
                            Module_ASLR = true;
                        }
                        else if (bits[i] == false && i == 6)
                        {
                            Module_ASLR = false;
                        }

                        if (bits[i] == true && i == 8)
                        {
                            Module_NXCompat = true;
                        }
                        else if (bits[i] == false && i == 8)
                        {
                            Module_NXCompat = false;
                        }

                        if (bits[i] == true && i == 10)
                        {
                            Module_Safe_SEH = false;
                        }
                        else if (bits[i] == false && i == 10)
                        {
                            Module_Safe_SEH = true;
                        }
                    }
                }
                else
                {
                    Module_Failed = true;
                    throw new ERCException("Unsupported machine type: " + Module_Machine_Type.ToString());
                }             

                if (Module_Product == "Microsoft® Windows® Operating System")
                {
                    Module_OS_DLL = true;
                }
                else
                {
                    Module_OS_DLL = false;
                }

                if (Module_Image_Base != ptr)
                {
                    Module_Rebase = true;
                }
                else
                {
                    Module_Rebase = false;
                }
            }
            catch (Exception e)
            {
                ERC_Result<Exception> ExceptionLogger = new ERC_Result<Exception>(Module_Core);
                ExceptionLogger.Error = e;
                ExceptionLogger.Log_Event();
                Module_Failed = true;
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
                Module_Machine_Type = (MachineType)inhs->FileHeader.Machine;

                if (Module_Machine_Type == MachineType.I386)
                {
                    IMAGE_NT_HEADERS32* inhs32 = (IMAGE_NT_HEADERS32*)(idh->nt_head_ptr + p_Data);
                    Image_File_Header = inhs32->FileHeader;
                    Module_Machine_Type = (MachineType)inhs32->FileHeader.Machine;
                    Image_Optional_Header32 = inhs32->OptionalHeader;
                    Module_Image_Base = (IntPtr)inhs32->OptionalHeader.ImageBase;
                }
                else if (Module_Machine_Type == MachineType.x64)
                {
                    IMAGE_NT_HEADERS64* inhs64 = (IMAGE_NT_HEADERS64*)(idh->nt_head_ptr + p_Data);
                    Image_File_Header = inhs64->FileHeader;
                    Image_Optional_Header64 = inhs64->OptionalHeader;
                    Module_Image_Base = (IntPtr)inhs64->OptionalHeader.ImageBase;
                }
            }
        }
        #endregion

        #region Module_Search
        /// <summary>
        /// Searches for a string of bytes within a specific module. Takes a byte array to be searched for. 
        /// </summary>
        /// <param name="searchBytes">A byte array to be searched for</param>
        /// <returns>Returns ERC_Result of pointers to the search term</returns>
        public ERC_Result<List<IntPtr>> Search_Module(byte[] searchBytes)
        {
            ERC_Result<List<IntPtr>> results = new ERC_Result<List<IntPtr>>(Module_Core);
            List<IntPtr> ptrs = new List<IntPtr>();

            IntPtr base_address = Module_Base;
            byte[] buffer = new byte[Module_Size];
            int bytesread = 0;

            ERC_Core.ReadProcessMemory(Module_Process.Handle, Module_Base, buffer, buffer.Length, out bytesread);
            List<int> positions = SearchBytePattern(searchBytes, buffer);

            for(int i = 0; i < positions.Count; i++)
            {
                ptrs.Add((IntPtr)(positions[i] + (long)Module_Base));
            }
            
            results.Return_Value = ptrs;
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
