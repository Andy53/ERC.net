using System;
using System.IO;
using System.Text.RegularExpressions;

namespace ERC
{
    public class Display_Output
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
        #endregion
    }
}
