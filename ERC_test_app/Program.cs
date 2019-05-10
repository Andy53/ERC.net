using System;
using ERC;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ERC_test_app
{
    class Program
    {
        public static ErcCore core = new ErcCore();

        static void Main(string[] args)
        {
            core.SetWorkingDirectory(@"C:\Users\Andy\Desktop\");
            Console.WriteLine("create a pattern 1000 characters long: ");
            create_a_pattern();
            Console.WriteLine("Find offset in pattern (Ag9):");
            find_pattern_offset();
            Console.WriteLine("List all local processes: ");
            List_All_Local_Processes();
            Console.WriteLine("Search Process Memory (notepad): ");
            Search_Process_Memory();
            Console.WriteLine("Assembling opcodes:");
            assembling_opcodes();
            Console.WriteLine("Disassembling Opcodes:");
            disassemble_opcodes();
            Console.WriteLine("Outputting module info");
            output_module_info();
            Console.WriteLine("Generating byte array, skipping [ 0xA1, 0xB1, 0xC1, 0xD1 ]");
            output_byte_array();
            Console.WriteLine("Get thread Context:");
            Get_Thread_Context();
            Console.WriteLine("Find SEH Jumps:");
            Find_SEH();
            Console.WriteLine("Generating egg hunters:");
            egghunters();
            Console.WriteLine("Searching for Non repeating pattern");
            FindNRP();
            Console.ReadKey();
        }

        public static void create_a_pattern()
        {
            var result = ERC.Utilities.PatternTools.PatternCreate(4000, core);
            Console.WriteLine(result.ReturnValue);
            Console.WriteLine(Environment.NewLine);
        }

        public static void find_pattern_offset()
        {
            var result = ERC.Utilities.PatternTools.PatternOffset("Ag9", core);
            Console.WriteLine(result.ReturnValue);
            Console.WriteLine(Environment.NewLine);
        }

        public static void List_All_Local_Processes()
        {
            var test = ProcessInfo.ListLocalProcesses(core);
            foreach (Process process in test.ReturnValue)
            {
                Console.WriteLine("Name: {0} ID: {1}", process.ProcessName, process.Id);
            }
            Console.WriteLine(Environment.NewLine);
        }

        public static void Search_Process_Memory()
        {
            //ensure notepad is open before running this function. Also write "anonymous" in there a few times so there is something to find
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"KMFtp"))//"x64dbg"))//
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var listy = info.SearchMemory(1, searchString: "anonymous");
            foreach (KeyValuePair<IntPtr, string> s in listy.ReturnValue)
            {
                Console.WriteLine("0x" + s.Key.ToString("x") + " Filepath: " + s.Value);
            }
        }

        public static void assembling_opcodes()
        {
            List<string> instructions = new List<string>();
            instructions.Add("POP RAX");
            instructions.Add("POP RBX");
            instructions.Add("PUSH RSP");

            var asmResult = ERC.Utilities.OpcodeAssembler.AssembleOpcodes(instructions, MachineType.x64, core);
            Console.WriteLine(BitConverter.ToString(asmResult.ReturnValue).Replace("-", ""));
        }

        public static void disassemble_opcodes()
        {
            byte[] opcodes = new byte[] { 0xFF, 0xE4, 0x48, 0x31, 0xC0, 0x55, 0xC3 };
            var result = ERC.Utilities.OpcodeDisassembler.Disassemble(opcodes, MachineType.x64, core);
            Console.WriteLine(result.ReturnValue + Environment.NewLine);
        }

        public static void output_module_info()
        {
            //ensure notepad is open before running this function.
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"KMFtp"))//"x64dbg"))//
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            Console.WriteLine(Display_Output.GenerateModuleInfoTable(info));
        }

        public static void output_byte_array()
        {
            byte[] unwantedBytes = new byte[] { 0xA1, 0xB1, 0xC1, 0xD1 };
            var bytes = Display_Output.GenerateByteArray(unwantedBytes, core);
            Console.WriteLine(BitConverter.ToString(bytes).Replace("-", " "));
        }

        public static void Get_Thread_Context()
        {
            //ensure notepad is open before running this function.
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"KMFtp"))//"x64dbg"))//
                {
                    thisProcess = process1;
                    
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            for(int i = 0; i < info.ThreadsInfo.Count; i++){
                info.ThreadsInfo[i].Get_Context();
                Console.WriteLine("i = {0}", i);
            }
            
        }

        public static void Find_SEH()
        {
            //ensure notepad is open before running this function.
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"KMFtp"))//"x64dbg"))//
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var tester = Display_Output.GetSEHJumps(info);
            foreach(string s in tester.ReturnValue)
            {
                Console.WriteLine(s);
            }
        }

        public static void egghunters()
        {
            var eggs = ERC.Display_Output.GenerateEggHunters(core, "AAAA");
            Console.WriteLine(eggs);
        }

        public static void FindNRP()
        {
            //ensure notepad is open before running this function.
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"Kolibri"))//"x64dbg"))//
                {
                    thisProcess = process1;
                }
            }
            ProcessInfo info = new ProcessInfo(core, thisProcess);
            info.FindNRP();
        }
    }
}
