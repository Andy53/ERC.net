using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ERC
{
    public static class Display_Output
    {
        #region Display_Output_Functions
        /// <summary>
        /// Identifies output files previously created by a the Display_Modules function
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        public static string Get_Module_File_Name(string directory, string prefix, string extension)
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

        /// <summary>
        /// Displays a list of all modules and associated information from a specific process. Can output to stdout, a file or both.
        /// </summary>
        public static string Display_Module_Info(Process_Info process)
        {
            int ptr_segment_width = 16;
            int flag_segment_width = 10;
            string output = "";
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            if (!String.IsNullOrEmpty(process.Author))
            {
                output += "Process Name: " + process.Process_Name + " Pattern created by: " + process.Author + " " +
                "Modules total: " + process.Modules_Info.Count + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + process.Process_Name + " Modules total: " + process.Modules_Info.Count + Environment.NewLine;
            }

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += " Base          | Entry point   | Size      | Rebase   | SafeSEH  | ASLR     | NXCompat | OS DLL  | Version, Name and Path" + Environment.NewLine;
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            foreach (Module_Info module in process.Modules_Info)
            {
                string base_element = " ";
                base_element += "0x" + module.Module_Base.ToString("x");
                for (int i = base_element.Length; i < ptr_segment_width; i++)
                {
                    base_element += " ";
                }

                string entry_element = " ";
                entry_element += "0x" + module.Module_Entry.ToString("x");
                for (int i = entry_element.Length; i < ptr_segment_width; i++)
                {
                    entry_element += " ";
                }

                string size_element = " ";
                size_element += "0x" + module.Module_Size.ToString("x");
                for (int i = size_element.Length; i < flag_segment_width; i++)
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

        /// <summary>
        /// Aquires filename and outputs all module data to the current working directory. Requires a Process_Info object to be passed as a parameter.
        /// </summary>
        /// <param name="info"></param>
        /// <returns>Returns a formatted string of all results</returns>
        public static string Module_Info_Output(Process_Info info)
        {
            string modOutput = Display_Module_Info(info);
            string modFilename = Get_Module_File_Name(info.Working_Directory, "modules_", ".txt");
            File.WriteAllText(modFilename, modOutput);
            return modOutput;
        }

        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <returns>Returns an ERC_Result containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets. </returns>
        public static ERC_Result<List<string>> Get_SEH_Jumps(Process_Info info, List<string> excludes = null)
        {
            ERC_Result<List<string>> ret = new ERC_Result<List<string>>(info.Process_Core);
            ERC_Result<Dictionary<IntPtr, string>> ptrs = info.Search_All_Memory_PPR(excludes);
            if (ptrs.Error != null)
            {
                ret.Error = new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
                return ret;
            }
            ret.Return_Value = new List<string>();
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
                            Opcode_Disassembler disas = new Opcode_Disassembler(info);
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
            return ret;
        }
        #endregion
    }
}
