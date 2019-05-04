using ERC.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ERC
{
    public static class Display_Output
    {
        #region Display_Output_Functions

        #region GetFilePath
        /// <summary>
        /// Identifies output files previously created by a the Display_Modules function
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        public static string GetFilePath(string directory, string prefix, string extension)
        {
            string result = "";
            int file_number = 0;
            char[] delimiter_chars = { '_', '.' };

            DirectoryInfo d = new DirectoryInfo(directory);
            FileInfo[] files = d.GetFiles(prefix + "*");

            foreach (FileInfo f in files)
            {
                string file_number_string = Regex.Match(f.Name, @"\d+").Value;
                if (file_number < int.Parse(file_number_string))
                {
                    file_number = int.Parse(file_number_string);
                }
            }

            file_number++;
            result = directory + prefix + file_number.ToString() + extension;
            return result;
        }
        #endregion

        #region DisplayModuleInfo
        /// <summary>
        /// Displays a list of all modules and associated information from a specific process. Can output to stdout, a file or both.
        /// </summary>
        public static string DisplayModuleInfo(Process_Info info)
        {
            int ptrSegmentWidth = 16;
            int flagSegmentWidth = 10;
            string output = "";
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            if (info.Author != "No_Author_Set")
            {
                output += "Process Name: " + info.Process_Name + " Pattern created by: " + info.Author + " " +
                "Modules total: " + info.Modules_Info.Count + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + info.Process_Name + " Modules total: " + info.Modules_Info.Count + Environment.NewLine;
            }

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += " Base          | Entry point   | Size      | Rebase   | SafeSEH  | ASLR     | NXCompat | OS DLL  | Version, Name and Path" + Environment.NewLine;
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            foreach (Module_Info module in info.Modules_Info)
            {
                string base_element = " ";
                base_element += "0x" + module.Module_Base.ToString("x");
                for (int i = base_element.Length; i < ptrSegmentWidth; i++)
                {
                    base_element += " ";
                }

                string entry_element = " ";
                entry_element += "0x" + module.Module_Entry.ToString("x");
                for (int i = entry_element.Length; i < ptrSegmentWidth; i++)
                {
                    entry_element += " ";
                }

                string size_element = " ";
                size_element += "0x" + module.Module_Size.ToString("x");
                for (int i = size_element.Length; i < flagSegmentWidth; i++)
                {
                    size_element += " ";
                }

                string rebase_element = "   ";
                if (module.Module_Rebase == true)
                {
                    rebase_element += "True    ";
                }
                else
                {
                    rebase_element += "False   ";
                }

                string seh_element = "   ";
                if (module.Module_Safe_SEH == true)
                {
                    seh_element += "True     ";
                }
                else
                {
                    seh_element += "False    ";
                }

                string aslr_element = "  ";
                if (module.Module_ASLR == true)
                {
                    aslr_element += "True     ";
                }
                else
                {
                    aslr_element += "False    ";
                }

                string nx_element = "  ";
                if (module.Module_NXCompat == true)
                {
                    nx_element += "True     ";
                }
                else
                {
                    nx_element += "False    ";
                }

                string os_element = "  ";
                if (module.Module_OS_DLL == true)
                {
                    os_element += "True     ";
                }
                else
                {
                    os_element += "False    ";
                }

                string file_element = "  ";
                if (!string.IsNullOrEmpty(module.Module_Version))
                {
                    file_element += module.Module_Version + ";";
                }
                if (!string.IsNullOrEmpty(module.Module_Name))
                {
                    file_element += module.Module_Name + ";";
                }
                if (!string.IsNullOrEmpty(module.Module_Path))
                {
                    file_element += module.Module_Path;
                }
                output += base_element + entry_element + size_element + rebase_element +
                    seh_element + aslr_element + nx_element + os_element + file_element + Environment.NewLine;
            }
            return output;
        }
        #endregion

        #region Generate_Module_Info_Table
        /// <summary>
        /// Aquires filename and outputs all module data to the current working directory. Requires a Process_Info object to be passed as a parameter.
        /// </summary>
        /// <param name="info"></param>
        /// <returns>Returns a formatted string of all results</returns>
        public static string Generate_Module_Info_Table(Process_Info info)
        {
            string modOutput = DisplayModuleInfo(info);
            string modFilename = GetFilePath(info.Working_Directory, "modules_", ".txt");
            File.WriteAllText(modFilename, modOutput);
            return modOutput;
        }
        #endregion

        #region Get_SEH_Jumps
        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <returns>Returns an ERC_Result containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets. </returns>
        public static ERC_Result<List<string>> Get_SEH_Jumps(Process_Info info, List<string> excludes = null)
        {
            ERC_Result<List<string>> ret = new ERC_Result<List<string>>(info.Process_Core);
            ret.Return_Value = new List<string>();
            ERC_Result<Dictionary<IntPtr, string>> ptrs = info.Search_All_Memory_PPR(excludes);

            string sehFilename = GetFilePath(info.Working_Directory, "SEH_jumps_", ".txt");
            ret.Return_Value.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                ret.Return_Value.Add("Process Name: " + info.Process_Name + " Created by: " + info.Author + " " +
                "Total Jumps: " + ptrs.Return_Value.Count);
            }
            else
            {
                ret.Return_Value.Add("Process Name: " + info.Process_Name + " Total Jumps: " + ptrs.Return_Value.Count);
            }
            ret.Return_Value.Add("---------------------------------------------------------------------------------------");

            if (ptrs.Error != null)
            {
                ret.Error = new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
                return ret;
            }
            
            byte[] ppr = new byte[5];
            int bytesread = 0;
            foreach (KeyValuePair<IntPtr, string> s in ptrs.Return_Value)
            {
                List<byte> opcodes = new List<byte>();
                try
                {
                    ERC_Core.ReadProcessMemory(info.Process_Handle, s.Key, ppr, ppr.Length, out bytesread);
                    for (int i = 0; i < 5; i++)
                    {
                        if (ppr[i].Equals(0xC3))
                        {
                            for (int j = 0; j <= i; j++)
                            {
                                opcodes.Add(ppr[j]);
                            }
                            ERC.Utilities.Opcode_Disassembler disas = new ERC.Utilities.Opcode_Disassembler(info);
                            var result = disas.Disassemble(opcodes.ToArray());
                            ret.Return_Value.Add("0x" + s.Key.ToString("x") + " " +
                                result.Return_Value.Replace(Environment.NewLine, ", ") + " Source file: " + s.Value);
                            opcodes.Clear();
                        }
                    }
                }
                catch (Exception e)
                {
                    ret.Error = e;
                    ret.Log_Event();
                    return ret;
                }

            }
            File.WriteAllLines(sehFilename, ret.Return_Value);
            return ret;
        }
        #endregion

        #region Generate_Byte_Array
        public static byte[] Generate_Byte_Array(byte[] unwantedBytes, ERC_Core core)
        {
            string byteFilename = Display_Output.GetFilePath(core.Working_Directory, "ByteArray_", ".dll");
            byte[] Byte_Array = ERC.Utilities.Payloads.Byte_Array_Constructor(unwantedBytes);
            FileStream fs1 = new FileStream(byteFilename, FileMode.Create, FileAccess.Write);
            fs1.Write(Byte_Array, 0, Byte_Array.Length);
            fs1.Close();

            string outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += "Byte Array generated at:" + DateTime.Now + "  Omitted values: " + BitConverter.ToString(unwantedBytes).Replace("-", ", ") + Environment.NewLine;
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            outputString += "Raw:" + Environment.NewLine;

            string raw = "\\x" + BitConverter.ToString(Byte_Array).Replace("-", "\\x");
            var rawlist = Enumerable
                .Range(0, raw.Length / 48)
                .Select(i => raw.Substring(i * 48, 48))
                .ToList();
            raw = string.Join(Environment.NewLine, rawlist);
            outputString += raw;

            outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
            string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
            string CSharpTemp = "0x" + BitConverter.ToString(Byte_Array).Replace("-", ", 0x");
            var list = Enumerable
                .Range(0, CSharpTemp.Length / 48)
                .Select(i => CSharpTemp.Substring(i * 48, 48))
                .ToList();
            for (int i = 0; i < list.Count; i++)
            {
                list[i] = "    " + list[i];
            }
            CSharp += string.Join(Environment.NewLine, list) + Environment.NewLine + "}";
            outputString += CSharp;
            File.WriteAllText(byteFilename.Substring(0, (byteFilename.Length - 4)) + ".txt", outputString);

            return Byte_Array;
        }
        #endregion

        #region Generate_Egg_Hunters
        public static string Generate_Egg_Hunters(ERC_Core core, string tag = null)
        {
            var eggHunters = Payloads.Egg_Hunter_Constructor(tag);
            string eggFilename = GetFilePath(core.Working_Directory, "Egg_Hunters_", ".txt");
            string outputString = "";
            outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += "EggHunters generated at:" + DateTime.Now + Environment.NewLine;
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            foreach(KeyValuePair<string, byte[]> k in eggHunters)
            {
                outputString += k.Key + ":" + Environment.NewLine + Environment.NewLine;
                outputString += "Raw:" + Environment.NewLine; 
                string raw = "\\x" + BitConverter.ToString(k.Value).Replace("-", "\\x");
                var rawlist = Enumerable
                    .Range(0, raw.Length / 48)
                    .Select(i => raw.Substring(i * 48, 48))
                    .ToList();
                raw = string.Join(Environment.NewLine, rawlist);
                outputString += raw;

                outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
                string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
                string CSharpTemp = "0x" + BitConverter.ToString(k.Value).Replace("-", ", 0x");
                var list = Enumerable
                    .Range(0, CSharpTemp.Length / 48)
                    .Select(i => CSharpTemp.Substring(i * 48, 48))
                    .ToList();
                for (int i = 0; i < list.Count; i++)
                {
                    list[i] = "    " + list[i];
                }
                CSharp += string.Join(Environment.NewLine, list) + Environment.NewLine + "}" + Environment.NewLine + Environment.NewLine;
                outputString += CSharp;
            }
            File.WriteAllText(eggFilename, outputString);
            return outputString;
        }
        #endregion

        #region Generate_FindNRP_Table
        public static List<string> Generate_FindNRP_Table(Process_Info info, int searchType = 0, bool extended = false)
        {
            List<string> output = new List<string>();
            string fnrpFilename = GetFilePath(info.Working_Directory, "Find_NRP_", ".txt");
            output.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                output.Add("Process Name: " + info.Process_Name + " Created by: " + info.Author + " FindNRP table generated at: " + DateTime.Now);
            }
            else
            {
                output.Add("Process Name: " + info.Process_Name + " FindNRP table generated at: " + DateTime.Now);
            }
            output.Add("---------------------------------------------------------------------------------------");
            var fnrp = info.FindNRP(searchType, extended);
            if(fnrp.Error != null)
            {
                output.Add(fnrp.Error.ToString());
                File.WriteAllLines(fnrpFilename, output);
                return output;
            }
            for(int i = 0; i < fnrp.Return_Value.Count; i++)
            {
                string register_info = "";
                if(fnrp.Return_Value[i].String_Offset > 0 && !fnrp.Return_Value[i].Register.Contains("IP") && !fnrp.Return_Value[i].Register.Contains("SP"))
                {
                    register_info += "Register " + fnrp.Return_Value[i].Register + " points into pattern at position " + fnrp.Return_Value[i].String_Offset;
                }
                else if(fnrp.Return_Value[i].String_Offset > 0 && fnrp.Return_Value[i].Register.Contains("SP"))
                {
                    register_info += "Register " + fnrp.Return_Value[i].Register + " points into pattern at position " + fnrp.Return_Value[i].String_Offset;
                    if(fnrp.Return_Value[i].Register_Offset > 0)
                    {
                        register_info += " at " + fnrp.Return_Value[i].Register + " +" + fnrp.Return_Value[i].Register_Offset + " length of pattern found is " +
                            fnrp.Return_Value[i].Buffer_Size + " characters";
                    }
                    else
                    {
                        register_info += " length of pattern found is " + fnrp.Return_Value[i].Buffer_Size + " characters";
                    }
                }
                else if(fnrp.Return_Value[i].String_Offset > 0 && fnrp.Return_Value[i].Register.Contains("IP"))
                {
                    register_info += "Register " + fnrp.Return_Value[i].Register + "is overwritten with pattern at position " + fnrp.Return_Value[i].String_Offset;
                }
                output.Add(register_info);
            }
            File.WriteAllLines(fnrpFilename, output);
            return output;
        }
        #endregion

        #endregion
    }
}
