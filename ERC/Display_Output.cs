using ERC.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ERC
{
    public static class DisplayOutput
    {
        #region Display_Output_Functions

        #region GetFilePath
        /// <summary>
        /// Identifies output files previously created by a the Display_Modules function
        /// and identifies the last number used. Returns the next number to be used as a filename.
        /// </summary>
        /// <param name="directory">The directory to be used</param>
        /// <param name="prefix">A prefix for the file name e.g. "modules_" or "Pattern_" etc</param>
        /// <param name="extension">The file extension to be used e.g. ".txt" </param>
        /// <returns>Returns a string containing the full file path to be used when writing output to disk</returns>
        internal static string GetFilePath(string directory, string prefix, string extension)
        {
            string result = "";
            int fileNumber = 0;
            char[] delimiterChars = { '_', '.' };

            DirectoryInfo d = new DirectoryInfo(directory);
            FileInfo[] files = d.GetFiles(prefix + "*");

            foreach (FileInfo f in files)
            {
                string fileNumberString = Regex.Match(f.Name, @"\d+").Value;
                if (fileNumber < int.Parse(fileNumberString))
                {
                    fileNumber = int.Parse(fileNumberString);
                }
            }

            fileNumber++;
            result = directory + prefix + fileNumber.ToString() + extension;
            return result;
        }
        #endregion

        #region DisplayModuleInfo
        /// <summary>
        /// Displays a list of all modules and associated information from a specific process. Can output to stdout, a file or both.
        /// </summary>
        /// <param name="info">The ProcessInfo object of which the module information will be displayed</param>
        /// <returns>Returns a string containing all module info from a specific process</returns>
        internal static string DisplayModuleInfo(ProcessInfo info)
        {
            int ptrSegmentWidth = 16;
            int flagSegmentWidth = 10;
            string output = "";
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;

            if (info.Author != "No_Author_Set")
            {
                output += "Process Name: " + info.ProcessName + " Pattern created by: " + info.Author + " " +
                "Modules total: " + info.ModulesInfo.Count + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + info.ProcessName + " Modules total: " + info.ModulesInfo.Count + Environment.NewLine;
            }

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            output += " Base          | Entry point   | Size      | Rebase   | SafeSEH  | ASLR     | NXCompat | OS DLL  | Version, Name and Path" + Environment.NewLine;
            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            foreach (ModuleInfo module in info.ModulesInfo)
            {
                string baseElement = " ";
                baseElement += "0x" + module.ModuleBase.ToString("x");
                for (int i = baseElement.Length; i < ptrSegmentWidth; i++)
                {
                    baseElement += " ";
                }

                string entryElement = " ";
                entryElement += "0x" + module.ModuleEntry.ToString("x");
                for (int i = entryElement.Length; i < ptrSegmentWidth; i++)
                {
                    entryElement += " ";
                }

                string sizeElement = " ";
                sizeElement += "0x" + module.ModuleSize.ToString("x");
                for (int i = sizeElement.Length; i < flagSegmentWidth; i++)
                {
                    sizeElement += " ";
                }

                string rebaseElement = "   ";
                if (module.ModuleRebase == true)
                {
                    rebaseElement += "True    ";
                }
                else
                {
                    rebaseElement += "False   ";
                }

                string sehElement = "   ";
                if (module.ModuleSafeSEH == true)
                {
                    sehElement += "True     ";
                }
                else
                {
                    sehElement += "False    ";
                }

                string aslrElement = "  ";
                if (module.ModuleASLR == true)
                {
                    aslrElement += "True     ";
                }
                else
                {
                    aslrElement += "False    ";
                }

                string nxElement = "  ";
                if (module.ModuleNXCompat == true)
                {
                    nxElement += "True     ";
                }
                else
                {
                    nxElement += "False    ";
                }

                string osElement = "  ";
                if (module.ModuleOsDll == true)
                {
                    osElement += "True     ";
                }
                else
                {
                    osElement += "False    ";
                }

                string fileElement = "  ";
                if (!string.IsNullOrEmpty(module.ModuleVersion))
                {
                    fileElement += module.ModuleVersion + ";";
                }
                if (!string.IsNullOrEmpty(module.ModuleName))
                {
                    fileElement += module.ModuleName + ";";
                }
                if (!string.IsNullOrEmpty(module.ModulePath))
                {
                    fileElement += module.ModulePath;
                }
                output += baseElement + entryElement + sizeElement + rebaseElement +
                    sehElement + aslrElement + nxElement + osElement + fileElement + Environment.NewLine;
            }
            return output;
        }
        #endregion

        #region GenerateModuleInfoTable
        /// <summary>
        /// Aquires filename and writes out all module data to the current working directory. Requires a Process_Info object to be passed as a parameter.
        /// </summary>
        /// <param name="info">The ProcessInfo object of which the module information will be displayed</param>
        /// <returns>Returns a formatted string of all results</returns>
        public static string GenerateModuleInfoTable(ProcessInfo info)
        {
            string modOutput = DisplayModuleInfo(info);
            string modFilename = GetFilePath(info.WorkingDirectory, "modules_", ".txt");
            File.WriteAllText(modFilename, modOutput);
            return modOutput;
        }
        #endregion

        #region GetSEHJumps
        /// <summary>
        /// Searches all memory associated with a given process and associated modules for POP X POP X RET instructions. 
        /// Passing a list of module paths or names will exclude those modules from the search. 
        /// Similar to Search_All_Memory_PPR however provides output in an easily readable format.
        /// </summary>
        /// <param name="info">The ProcessInfo object which will be searched for POP POP RET instructions,</param>
        /// <param name="excludes">Modules to be ignored when searching for the instruction sets.</param>
        /// <returns>Returns an ErcResult containing a list of strings detailing the pointers, opcodes and base files of suitable instruction sets.</returns>
        public static ErcResult<List<string>> GetSEHJumps(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<string>> ret = new ErcResult<List<string>>(info.ProcessCore);
            ret.ReturnValue = new List<string>();
            ErcResult<Dictionary<IntPtr, string>> ptrs = info.SearchAllMemoryPPR(excludes);

            string sehFilename = GetFilePath(info.WorkingDirectory, "SEH_jumps_", ".txt");
            ret.ReturnValue.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                ret.ReturnValue.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " " +
                "Total Jumps: " + ptrs.ReturnValue.Count);
            }
            else
            {
                ret.ReturnValue.Add("Process Name: " + info.ProcessName + " Total Jumps: " + ptrs.ReturnValue.Count);
            }
            ret.ReturnValue.Add("---------------------------------------------------------------------------------------");

            if (ptrs.Error != null)
            {
                ret.Error = new Exception("Error passed from Search_All_Memory_PPR: " + ptrs.Error.ToString());
                return ret;
            }

            byte[] ppr = new byte[5];
            int bytesread = 0;
            foreach (KeyValuePair<IntPtr, string> s in ptrs.ReturnValue)
            {
                List<byte> opcodes = new List<byte>();
                try
                {
                    ErcCore.ReadProcessMemory(info.ProcessHandle, s.Key, ppr, ppr.Length, out bytesread);
                    for (int i = 0; i < 5; i++)
                    {
                        if (ppr[i].Equals(0xC3))
                        {
                            for (int j = 0; j <= i; j++)
                            {
                                opcodes.Add(ppr[j]);
                            }
                            ERC.Utilities.OpcodeDisassembler disas = new ERC.Utilities.OpcodeDisassembler(info);
                            var result = disas.Disassemble(opcodes.ToArray());
                            ret.ReturnValue.Add("0x" + s.Key.ToString("x") + " " +
                                result.ReturnValue.Replace(Environment.NewLine, ", ") + " Source file: " + s.Value);
                            opcodes.Clear();
                        }
                    }
                }
                catch (Exception e)
                {
                    ret.Error = e;
                    ret.LogEvent();
                    return ret;
                }

            }
            File.WriteAllLines(sehFilename, ret.ReturnValue);
            return ret;
        }
        #endregion

        #region GenerateByteArray
        /// <summary>
        /// Generates an array of all possible bytes for use when identifying bad characters. Writes the output to disk in the working directory.
        /// </summary>
        /// <param name="unwantedBytes">An array of bytes to be excluded from the final byte array</param>
        /// <param name="core">An ErcCore object</param>
        /// <returns>Returns a byte array of all possible bytes.</returns>
        public static byte[] GenerateByteArray(byte[] unwantedBytes, ErcCore core)
        {
            string byteFilename = GetFilePath(core.WorkingDirectory, "ByteArray_", ".dll");
            byte[] byteArray = Payloads.Byte_Array_Constructor(unwantedBytes);
            FileStream fs1 = new FileStream(byteFilename, FileMode.Create, FileAccess.Write);
            fs1.Write(byteArray, 0, byteArray.Length);
            fs1.Close();

            string outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += "Byte Array generated at:" + DateTime.Now + "  Omitted values: " + BitConverter.ToString(unwantedBytes).Replace("-", ", ") + Environment.NewLine;
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            outputString += "Raw:" + Environment.NewLine;

            string raw = "\\x" + BitConverter.ToString(byteArray).Replace("-", "\\x");
            var rawlist = Enumerable
                .Range(0, raw.Length / 48)
                .Select(i => raw.Substring(i * 48, 48))
                .ToList();
            raw = string.Join(Environment.NewLine, rawlist);
            outputString += raw;

            outputString += Environment.NewLine + Environment.NewLine + "C#:" + Environment.NewLine;
            string CSharp = "byte[] buf = new byte[]" + Environment.NewLine + "{" + Environment.NewLine;
            string CSharpTemp = "0x" + BitConverter.ToString(byteArray).Replace("-", ", 0x");
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

            return byteArray;
        }
        #endregion

        #region GenerateEggHunters
        /// <summary>
        /// Generates a collection of EggHunter payloads.
        /// </summary>
        /// <param name="core">(Optional) If an ErcCore object is provided the output will also be written out to the working directory </param>
        /// <param name="tag">(Optional) If a tag is provided the payloads will be altered to search for that tag, the default tag is ERCD</param>
        /// <returns>Returns a string containing all EggHunters </returns>
        public static string GenerateEggHunters(ErcCore core = null, string tag = null)
        {
            var eggHunters = Payloads.EggHunterConstructor(tag);
            string eggFilename = "";
            if (core != null)
            {
                eggFilename = GetFilePath(core.WorkingDirectory, "Egg_Hunters_", ".txt");
            }

            string eggTag = "";
            if (tag != null)
            {
                eggTag = tag;
            }
            else
            {
                eggTag = "ERCD";
            }

            string outputString = "";
            outputString = "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += "EggHunters generated at:" + DateTime.Now + " Tag: " + eggTag + Environment.NewLine;
            outputString += "---------------------------------------------------------------------------------------" + Environment.NewLine;
            outputString += Environment.NewLine;
            foreach (KeyValuePair<string, byte[]> k in eggHunters)
            {
                outputString += k.Key + Environment.NewLine;
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
            if (core != null)
            {
                File.WriteAllText(eggFilename, outputString);
            }
            return outputString;
        }
        #endregion

        #region GenerateFindNRPTable
        /// <summary>
        /// Searches the memory of a process for a non repeating pattern.
        /// </summary>
        /// <param name="info">The ProcessInfo object of the process to be searched</param>
        /// <param name="searchType">Integer specifiying the format of the string: 0 = search term is in bytes\n1 = search term is in unicode\n2 = search term is in ASCII\n3 = Search term is in UTF8\n4 = Search term is in UTF7\n5 = Search term is in UTF32</param>
        /// <param name="extended">Whether the extended character range is to be used when searching for the non repeating pattern</param>
        /// <returns>Returns a List of strings containing the locations the repeating pattern was identified</returns>
        public static List<string> GenerateFindNRPTable(ProcessInfo info, int searchType = 0, bool extended = false)
        {
            List<string> output = new List<string>();
            string fnrpFilename = GetFilePath(info.WorkingDirectory, "Find_NRP_", ".txt");
            output.Add("---------------------------------------------------------------------------------------");
            if (info.Author != "No_Author_Set")
            {
                output.Add("Process Name: " + info.ProcessName + " Created by: " + info.Author + " FindNRP table generated at: " + DateTime.Now);
            }
            else
            {
                output.Add("Process Name: " + info.ProcessName + " FindNRP table generated at: " + DateTime.Now);
            }
            output.Add("---------------------------------------------------------------------------------------");
            var fnrp = info.FindNRP(searchType, extended);
            if (fnrp.Error != null)
            {
                output.Add(fnrp.Error.ToString());
                File.WriteAllLines(fnrpFilename, output);
                return output;
            }
            for (int i = 0; i < fnrp.ReturnValue.Count; i++)
            {
                string registerInfoText = "";
                if (fnrp.ReturnValue[i].StringOffset > 0 && !fnrp.ReturnValue[i].Register.Contains("IP") && !fnrp.ReturnValue[i].Register.Contains("SP")
                    && !fnrp.ReturnValue[i].Register.Contains("SEH"))
                {
                    registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " points into pattern at position " + fnrp.ReturnValue[i].StringOffset;
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("SP"))
                {
                    registerInfoText += "Register " + fnrp.ReturnValue[i].Register + " points into pattern at position " + fnrp.ReturnValue[i].StringOffset;
                    if (fnrp.ReturnValue[i].RegisterOffset > 0)
                    {
                        registerInfoText += " at " + fnrp.ReturnValue[i].Register + " +" + fnrp.ReturnValue[i].RegisterOffset + " length of pattern found is " +
                            fnrp.ReturnValue[i].BufferSize + " characters";
                    }
                    else
                    {
                        registerInfoText += " length of pattern found is " + fnrp.ReturnValue[i].BufferSize + " characters";
                    }
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("IP"))
                {
                    registerInfoText += "Register " + fnrp.ReturnValue[i].Register + "is overwritten with pattern at position " + fnrp.ReturnValue[i].StringOffset;
                }
                else if (fnrp.ReturnValue[i].StringOffset > 0 && fnrp.ReturnValue[i].Register.Contains("SEH"))
                {
                    registerInfoText += "SEH register overwritten at pattern position " + fnrp.ReturnValue[i].StringOffset;
                }
                output.Add(registerInfoText);
            }
            File.WriteAllLines(fnrpFilename, output);
            return output;
        }
        #endregion

        #endregion

        public static List<string> RopChainGadgets(RopChainGenerator rcg, ProcessInfo info)
        {
            string output = "";
            List<string> totalGadgets = new List<string>();
            List<string> curatedGadgets = new List<string>();
            string filePath = GetFilePath(info.WorkingDirectory, "gadgets_", ".txt");
            string totalGadgetsPath = GetFilePath(info.WorkingDirectory, "total_gadgest_", ".txt");
            string curatedGadgetsPath = GetFilePath(info.WorkingDirectory, "curated_gadgest_", ".txt");

            output += "-------------------------------------------------------------------------------------------------------------------------" + Environment.NewLine;
            if (info.Author != "No_Author_Set")
            {
                output += "Process Name: " + info.ProcessName + " Gadget list created by: " + info.Author + " " + Environment.NewLine;
            }
            else
            {
                output += "Process Name: " + info.ProcessName + " ROP chain gadget list" + Environment.NewLine;
            }

            if (info.ProcessMachineType == MachineType.I386)
            {
                using (StreamWriter w = File.CreateText(filePath))
                {
                    w.Write(output + "pushEax total = " + rcg.x86Opcodes.pushEax.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEax: ");
                    curatedGadgets.Add("pushEax: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEax)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if(k.Value.Contains("push eax") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if(!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                        
                    }
                    w.Write("pushEbx total = " + rcg.x86Opcodes.pushEbx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEbx: ");
                    curatedGadgets.Add("pushEbx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push ebx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEcx total = " + rcg.x86Opcodes.pushEcx.Count + ":" + Environment.NewLine);
                    totalGadgets.Add("pushEcx: ");
                    curatedGadgets.Add("pushEcx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEcx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push ecx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEdx total = " + rcg.x86Opcodes.pushEdx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEdx: ");
                    curatedGadgets.Add("pushEdx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push edx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEsp total = " + rcg.x86Opcodes.pushEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEsp: ");
                    curatedGadgets.Add("pushEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push esp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEbp total = " + rcg.x86Opcodes.pushEbp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEbp: ");
                    curatedGadgets.Add("pushEbp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEbp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push ebp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEsi total = " + rcg.x86Opcodes.pushEsi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEsi: ");
                    curatedGadgets.Add("pushEsi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEsi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push esi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushEdi total = " + rcg.x86Opcodes.pushEdi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushEdi: ");
                    curatedGadgets.Add("pushEdi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushEdi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("push edi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("JmpEsp total = " + rcg.x86Opcodes.jmpEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("JmpEsp: ");
                    curatedGadgets.Add("JmpEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.jmpEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("jmp esp"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("CallEsp total = " + rcg.x86Opcodes.callEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("CallEsp: ");
                    curatedGadgets.Add("CallEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.callEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("call esp"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("xorEax total = " + rcg.x86Opcodes.xorEax.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEax: ");
                    curatedGadgets.Add("xorEax: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEax)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor eax") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("XorEbx total = " + rcg.x86Opcodes.xorEbx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEbx: ");
                    curatedGadgets.Add("xorEbx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEbx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor ebx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("XorEcx total = " + rcg.x86Opcodes.xorEcx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEcx: ");
                    curatedGadgets.Add("xorEcx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEcx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor ecx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("XorEdx total = " + rcg.x86Opcodes.xorEdx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEdx: ");
                    curatedGadgets.Add("xorEdx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor edx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("XorEsi total = " + rcg.x86Opcodes.xorEsi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEsi: ");
                    curatedGadgets.Add("xorEsi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEsi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor esi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("xorEdi total = " + rcg.x86Opcodes.xorEdi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("xorEdi: ");
                    curatedGadgets.Add("xorEdi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.xorEdi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("xor edi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEax total = " + rcg.x86Opcodes.popEax.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEax: ");
                    curatedGadgets.Add("popEax: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEax)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop eax") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEbx total = " + rcg.x86Opcodes.popEbx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEbx: ");
                    curatedGadgets.Add("popEbx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop ebx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEcx total = " + rcg.x86Opcodes.popEcx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEcx: ");
                    curatedGadgets.Add("popEcx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEcx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop ecx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEdx total = " + rcg.x86Opcodes.popEdx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEdx: ");
                    curatedGadgets.Add("popEdx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop edx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEsp total = " + rcg.x86Opcodes.popEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEsp: ");
                    curatedGadgets.Add("popEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop esp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEbp total = " + rcg.x86Opcodes.popEbp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEbp: ");
                    curatedGadgets.Add("popEbp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEbp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop ebp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEsi total = " + rcg.x86Opcodes.popEsi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEsi: ");
                    curatedGadgets.Add("popEsi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEsi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop esi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("popEdi total = " + rcg.x86Opcodes.popEdi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("popEdi: ");
                    curatedGadgets.Add("popEdi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.popEdi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pop edo") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write("pushad total = " + rcg.x86Opcodes.pushad.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("pushad: ");
                    curatedGadgets.Add("pushad: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.pushad)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("pushad") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEax total = " + rcg.x86Opcodes.incEax.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEax: ");
                    curatedGadgets.Add("incEax: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEax)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc eax") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEax total = " + rcg.x86Opcodes.decEax.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEax: ");
                    curatedGadgets.Add("decEax: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEax)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec eax") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEbx total = " + rcg.x86Opcodes.incEbx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEbx: ");
                    curatedGadgets.Add("incEbx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc ebx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEbx total = " + rcg.x86Opcodes.decEbx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEbx: ");
                    curatedGadgets.Add("decEbx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec ebx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEcx total = " + rcg.x86Opcodes.incEcx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEcx: ");
                    curatedGadgets.Add("incEcx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEcx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc ecx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEcx total = " + rcg.x86Opcodes.decEcx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEcx: ");
                    curatedGadgets.Add("decEcx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEcx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec ecx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEdx total = " + rcg.x86Opcodes.incEdx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEdx: ");
                    curatedGadgets.Add("incEdx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc edx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEdx total = " + rcg.x86Opcodes.decEdx.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEdx: ");
                    curatedGadgets.Add("decEdx: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdx)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec edx") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEbp total = " + rcg.x86Opcodes.incEbp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEbp: ");
                    curatedGadgets.Add("incEbp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEbp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc ebp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }

                    }
                    w.Write(output + "decEbp total = " + rcg.x86Opcodes.decEbp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEbp: ");
                    curatedGadgets.Add("decEbp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEbp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec ebp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEsp total = " + rcg.x86Opcodes.incEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEsp: ");
                    curatedGadgets.Add("incEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc esp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEsp total = " + rcg.x86Opcodes.decEsp.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEsp: ");
                    curatedGadgets.Add("decEsp: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsp)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec esp") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEsi total = " + rcg.x86Opcodes.incEsi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEsi: ");
                    curatedGadgets.Add("incEsi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEsi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc esi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEsi total = " + rcg.x86Opcodes.decEsi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEsi: ");
                    curatedGadgets.Add("decEsi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEsi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec esi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "incEdi total = " + rcg.x86Opcodes.incEdi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("incEdi: ");
                    curatedGadgets.Add("incEdi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.incEdi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("inc edi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "decEdi total = " + rcg.x86Opcodes.decEdi.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("decEdi: ");
                    curatedGadgets.Add("decEdi: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.decEdi)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("dec edi") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "Add total = " + rcg.x86Opcodes.add.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("Add: ");
                    curatedGadgets.Add("Add: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.add)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("add") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "Sub total = " + rcg.x86Opcodes.sub.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("Sub: ");
                    curatedGadgets.Add("Sub: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.sub)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("sub") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                    w.Write(output + "Mov total = " + rcg.x86Opcodes.mov.Count + ": " + Environment.NewLine);
                    totalGadgets.Add("Mov: ");
                    curatedGadgets.Add("Mov: ");
                    foreach (KeyValuePair<IntPtr, string> k in rcg.x86Opcodes.mov)
                    {
                        w.Write("0x" + k.Key.ToString("X8") + " | " + k.Value + Environment.NewLine);
                        if (k.Value.Contains("mov") && k.Value.Contains("ret"))
                        {
                            totalGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            if (!k.Value.Any(char.IsDigit))
                            {
                                curatedGadgets.Add("0x" + k.Key.ToString("X8") + " | " + k.Value);
                            }
                        }
                    }
                }
                File.WriteAllLines(totalGadgetsPath, totalGadgets);
                File.WriteAllLines(curatedGadgetsPath, curatedGadgets);
            }
            return totalGadgets;
        }

    }
}
