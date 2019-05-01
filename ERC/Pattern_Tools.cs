using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ERC
{
    namespace Utilities
    {
        public class Pattern_Tools
        {
            #region string Constants
            private const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            private const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            
            #endregion

            #region Pattern Create
            /// <summary>
            /// Creates a string of non repeating characters. Takes an integer as input for string length to return. Returns ERC_Result object
            /// </summary>
            public static ERC_Result<string> Pattern_Create(int length, ERC_Core core, bool extended = false)
            {
                string digits = "0123456789";
                ERC_Result<string> result = new ERC_Result<string>(core);

                if (extended == true)
                {
                    digits += ": ,.;+=-_!&()#@'({})[]%";
                    if(length > 66923)
                    {
                        result.Error = new Exception("User input error: Pattern length must be less that 66923");
                        result.Log_Event();
                        return result;
                    }
                }
                else
                {
                    if(length > 20277)
                    {
                        result.Error = new Exception("User input error: Pattern length must be less that 20277. Add the extended flag to create larger strings.");
                        result.Log_Event();
                        return result;
                    }
                }
                
                result.Return_Value = "";

                if (core.Working_Directory != null && core.Logging == true)
                {
                    result.Output_File = Get_Pattern_File_Name(core.Working_Directory, "create");
                }

                if (length < 1)
                {
                    result.Error = new Exception("Pattern length must be greate than 0.");
                    return result;
                }

                for (int i = 0; i < uppercase.Length; i++)
                {
                    for (int j = 0; j < lowercase.Length; j++)
                    {
                        for (int k = 0; k < digits.Length; k++)
                        {
                            char pos1 = uppercase[i];
                            char pos2 = lowercase[j];
                            char pos3 = digits[k];

                            if (result.Return_Value.Length > length)
                            {
                                result.Error = new Exception("Pattern string has exceeded the length supplied");
                                result.Return_Value = "";
                                return result;
                            }

                            if (result.Return_Value.Length == length)
                            {
                                if (!string.IsNullOrEmpty(result.Output_File))
                                {
                                    File.WriteAllText(result.Output_File, Pattern_Output_Builder(result.Return_Value, core));
                                }
                                return result;
                            }

                            if (result.Return_Value.Length < length - 2)
                            {
                                result.Return_Value += pos1;
                                result.Return_Value += pos2;
                                result.Return_Value += pos3;
                                if (result.Return_Value.Length == length)
                                {
                                    if (!string.IsNullOrEmpty(result.Output_File))
                                    {
                                        File.WriteAllText(result.Output_File, Pattern_Output_Builder(result.Return_Value, core));
                                    }
                                    return result;
                                }
                            }
                            else if (result.Return_Value.Length < length - 1)
                            {
                                result.Return_Value += pos1;
                                result.Return_Value += pos2;
                                if (result.Return_Value.Length == length)
                                {
                                    if (!string.IsNullOrEmpty(result.Output_File))
                                    {
                                        File.WriteAllText(result.Output_File, Pattern_Output_Builder(result.Return_Value, core));
                                    }
                                    return result;
                                }
                            }
                            else if (result.Return_Value.Length < length)
                            {
                                result.Return_Value += pos1;
                                if (result.Return_Value.Length == length)
                                {
                                    if (!string.IsNullOrEmpty(result.Output_File))
                                    {
                                        File.WriteAllText(result.Output_File, Pattern_Output_Builder(result.Return_Value, core));
                                    }
                                    return result;
                                }
                            }
                        }
                    }
                }
                result.Error = new Exception("An unknown error has occured. Function exited incorrectly");
                return result;
            }
            #endregion

            #region Pattern_Offset
            /// <summary>
            /// Takes a string of characters and returns the location of the first character in a pattern created by Pattern_Create. Returns ERC_Result object.
            /// </summary>
            public static ERC_Result<int> Pattern_Offset(string pattern, ERC_Core core, bool extended = false)
            {
                string digits = "0123456789";
                string pattern_full;
                if (extended == true)
                {
                    digits += ": ,.;+=-_!&()#@'({})[]%";
                    var result_pattern = Pattern_Create(66923, core, true);
                    pattern_full = result_pattern.Return_Value;
                }
                else
                {
                    var result_pattern = Pattern_Create(20277, core);
                    pattern_full = result_pattern.Return_Value;
                }
                ERC_Result<int> result = new ERC_Result<int>(core);

                if (pattern.Length < 3)
                {
                    result.Error = new Exception("Pattern length must be 3 characters or longer.");
                    return result;
                }

                if (pattern_full.Contains(pattern))
                {
                    result.Return_Value = pattern_full.IndexOf(pattern);
                    return result;
                }
                
                result.Error = new Exception("Error: Pattern not found.");
                return result;
            }
            #endregion

            #region Pattern Output
            /// <summary>
            /// Private function, should not be called directly. Identifies output files previously created by a the pattern_create and pattern_offset functions
            /// and identifies the last number used. Returns the next number to be used as a filename.
            /// </summary>
            private static string Get_Pattern_File_Name(string directory, string calling_function)
            {
                string result = "";
                int file_number = 0;
                char[] delimiter_chars = { '_', '.' };

                DirectoryInfo d = new DirectoryInfo(directory);
                FileInfo[] files = d.GetFiles("pattern_" + calling_function + "_*");

                foreach (FileInfo f in files)
                {
                    string file_number_string = Regex.Match(f.Name, @"\d+").Value;
                    if (file_number < Int32.Parse(file_number_string))
                    {
                        file_number = Int32.Parse(file_number_string);
                    }
                }

                file_number++;
                result = directory + "pattern_" + calling_function + "_" + file_number.ToString() + ".txt";
                return result;
            }

            /// <summary>
            /// Private function, should not be called directly. Takes input from pattern_create and outputs in an easily readable format.
            /// </summary>
            private static string Pattern_Output_Builder(string pattern, ERC_Core core)
            {
                byte[] bytes = Encoding.ASCII.GetBytes(pattern);
                string hex_pattern = BitConverter.ToString(bytes);
                string ascii_pattern = " ";
                string[] hex_array = hex_pattern.Split('-');

                for (int i = 1; i < hex_array.Length; i++)
                {
                    ascii_pattern += pattern[i];

                    if (i % 88 == 0 && i > 0)
                    {
                        ascii_pattern += "\"";
                        ascii_pattern += Environment.NewLine;
                        ascii_pattern += "\"";
                    }
                }

                hex_pattern = " ";
                for (int i = 1; i < hex_array.Length; i++)
                {
                    hex_pattern += "\\x" + hex_array[i];

                    if (i % 22 == 0 && i > 0)
                    {
                        hex_pattern += Environment.NewLine;
                    }
                }

                ascii_pattern = ascii_pattern.TrimStart(' ');
                hex_pattern = hex_pattern.TrimStart(' ');

                string output = "";
                output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
                output += "Pattern created at: " + DateTime.Now + ". Pattern created by: " + core.Author + ". Pattern length: " + pattern.Length + Environment.NewLine;
                output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
                output += Environment.NewLine;
                output += "Ascii:" + Environment.NewLine;
                output += "\"" + ascii_pattern + "\"" + Environment.NewLine;
                output += Environment.NewLine;
                output += "Hexadecimal:" + Environment.NewLine;
                output += hex_pattern;

                return output;
            }
            #endregion
        }
    }
}
