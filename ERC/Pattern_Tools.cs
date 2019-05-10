using ERC_Lib;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace ERC.Utilities
{
    public class PatternTools
    {
        #region string Constants
        private const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            
        #endregion

        #region Pattern Create
        /// <summary>
        /// Creates a string of non repeating characters. Takes an integer as input for string length to return. Returns ERC_Result object
        /// </summary>
        public static ErcResult<string> PatternCreate(int length, ErcCore core, bool extended = false)
        {
            string digits = "0123456789";
            ErcResult<string> result = new ErcResult<string>(core);

            if (extended == true)
            {
                digits += ": ,.;+=-_!&()#@'({})[]%";
                if(length > 66923)
                {
                    result.Error = new ERCException("User input error: Pattern length must be less that 66923");
                    result.LogEvent();
                    return result;
                }
            }
            else
            {
                if(length > 20277)
                {
                    result.Error = new ERCException("User input error: Pattern length must be less that 20277. Add the extended flag to create larger strings.");
                    result.LogEvent();
                    return result;
                }
            }
                
            result.ReturnValue = "";
            string outputFile = "";
            if (core.WorkingDirectory != null)
            {
                outputFile = GetPatternFileName(core.WorkingDirectory, "create");
            }

            if (length < 1)
            {
                result.Error = new ERCException("User Input Error: Pattern length must be greate than 0.");
                result.LogEvent();
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

                        if (result.ReturnValue.Length > length)
                        {
                            result.Error = new ERCException("Procedural Error: Pattern string has exceeded the length supplied");
                            result.ReturnValue = "";
                            return result;
                        }

                        if (result.ReturnValue.Length == length)
                        {
                            if (!string.IsNullOrEmpty(outputFile))
                            {
                                File.WriteAllText(outputFile, PatternOutputBuilder(result.ReturnValue, core));
                            }
                            return result;
                        }

                        if (result.ReturnValue.Length < length - 2)
                        {
                            result.ReturnValue += pos1;
                            result.ReturnValue += pos2;
                            result.ReturnValue += pos3;
                            if (result.ReturnValue.Length == length)
                            {
                                if (!string.IsNullOrEmpty(outputFile))
                                {
                                    File.WriteAllText(outputFile, PatternOutputBuilder(result.ReturnValue, core));
                                }
                                return result;
                            }
                        }
                        else if (result.ReturnValue.Length < length - 1)
                        {
                            result.ReturnValue += pos1;
                            result.ReturnValue += pos2;
                            if (result.ReturnValue.Length == length)
                            {
                                if (!string.IsNullOrEmpty(outputFile))
                                {
                                    File.WriteAllText(outputFile, PatternOutputBuilder(result.ReturnValue, core));
                                }
                                return result;
                            }
                        }
                        else if (result.ReturnValue.Length < length)
                        {
                            result.ReturnValue += pos1;
                            if (result.ReturnValue.Length == length)
                            {
                                if (!string.IsNullOrEmpty(outputFile))
                                {
                                    File.WriteAllText(outputFile, PatternOutputBuilder(result.ReturnValue, core));
                                }
                                return result;
                            }
                        }
                    }
                }
            }
            result.Error = new ERCException("An unknown error has occured. Function exited incorrectly. Function: ERC.Pattern_Tools.Pattern_Create");
            result.LogEvent();
            return result;
        }
        #endregion

        #region Pattern Offset
        /// <summary>
        /// Takes a string of characters and returns the location of the first character in a pattern created by Pattern_Create. Returns ERC_Result object.
        /// </summary>
        public static ErcResult<int> PatternOffset(string pattern, ErcCore core, bool extended = false)
        {
            string digits = "0123456789";
            string patternFull;
            if (extended == true)
            {
                digits += ": ,.;+=-_!&()#@'({})[]%";
                patternFull = File.ReadAllText(core.PatternExtendedPath);
            }
            else
            {
                patternFull = File.ReadAllText(core.PatternStandardPath);
            }
            ErcResult<int> result = new ErcResult<int>(core);

            if (pattern.Length < 3)
            {
                result.Error = new ERCException("User Input Error: Pattern length must be 3 characters or longer.");
                result.LogEvent();
                return result;
            }

            if (patternFull.Contains(pattern))
            {
                result.ReturnValue = patternFull.IndexOf(pattern);
                return result;
            }
                
            result.Error = new ERCException("Error: Pattern not found.");
            result.ReturnValue = -1;
            return result;
        }
        #endregion

        #region Pattern Output
        /// <summary>
        /// Private function, should not be called directly. Identifies output files previously created by a the pattern_create and pattern_offset functions
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        private static string GetPatternFileName(string directory, string callingFunction)
        {
            string result = "";
            int fileNumber = 0;
            char[] delimiterChars = { '_', '.' };

            DirectoryInfo d = new DirectoryInfo(directory);
            FileInfo[] files = d.GetFiles("pattern_" + callingFunction + "_*");

            foreach (FileInfo f in files)
            {
                string file_number_string = Regex.Match(f.Name, @"\d+").Value;
                if (fileNumber < int.Parse(file_number_string))
                {
                    fileNumber = int.Parse(file_number_string);
                }
            }

            fileNumber++;
            result = directory + "pattern_" + callingFunction + "_" + fileNumber.ToString() + ".txt";
            return result;
        }

        /// <summary>
        /// Private function, should not be called directly. Takes input from pattern_create and outputs in an easily readable format.
        /// </summary>
        private static string PatternOutputBuilder(string pattern, ErcCore core)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(pattern);
            string hexPattern = BitConverter.ToString(bytes);
            string asciiPattern = " ";
            string[] hexArray = hexPattern.Split('-');

            for (int i = 1; i < hexArray.Length; i++)
            {
                asciiPattern += pattern[i];

                if (i % 88 == 0 && i > 0)
                {
                    asciiPattern += "\"";
                    asciiPattern += Environment.NewLine;
                    asciiPattern += "\"";
                }
            }

            hexPattern = " ";
            for (int i = 1; i < hexArray.Length; i++)
            {
                hexPattern += "\\x" + hexArray[i];

                if (i % 22 == 0 && i > 0)
                {
                    hexPattern += Environment.NewLine;
                }
            }

            asciiPattern = asciiPattern.TrimStart(' ');
            hexPattern = hexPattern.TrimStart(' ');

            string output = "";
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += "Pattern created at: " + DateTime.Now + ". Pattern created by: " + core.Author + ". Pattern length: " + pattern.Length + Environment.NewLine;
            output += "------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Ascii:" + Environment.NewLine;
            output += "\"" + asciiPattern + "\"" + Environment.NewLine;
            output += Environment.NewLine;
            output += "Hexadecimal:" + Environment.NewLine;
            output += hexPattern;

            return output;
        }
        #endregion
    }
}
