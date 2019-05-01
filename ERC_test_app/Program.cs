using System;
using ERC;
using System.Diagnostics;
using System.Collections.Generic;

namespace ERC_test_app
{
    class Program
    {
        public static ERC_Core core = new ERC_Core(@"C:", "Author");

        static void Main(string[] args)
        {
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
            Console.ReadKey();
        }

        public static void create_a_pattern()
        {
            var result = ERC.Utilities.Pattern_Tools.Pattern_Create(1000, core);
            Console.WriteLine(result.Return_Value);
            Console.WriteLine(Environment.NewLine);
        }

        public static void find_pattern_offset()
        {
            var result = ERC.Utilities.Pattern_Tools.Pattern_Offset("Ag9", core);
            Console.WriteLine(result.Return_Value);
            Console.WriteLine(Environment.NewLine);
        }

        public static void List_All_Local_Processes()
        {
            var test = Process_Info.List_Local_Processes(core);
            foreach (Process process in test.Return_Value)
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

            Process_Info info = new Process_Info(core, thisProcess);
            var listy = info.Search_Process_Memory(1, searchString: "anonymous");
            foreach (IntPtr i in listy.Return_Value)
            {
                Console.WriteLine("0x" + i.ToString("x"));
            }
        }

        public static void assembling_opcodes()
        {
            List<string> instructions = new List<string>();
            instructions.Add("POP RAX");
            instructions.Add("POP RBX");
            instructions.Add("PUSH RSP");

            var asmResult = Opcode_Assembler.Assemble_Opcodes(instructions, MachineType.x64, core);
            Console.WriteLine(BitConverter.ToString(asmResult.Return_Value).Replace("-", ""));
        }

        public static void disassemble_opcodes()
        {
            byte[] opcodes = new byte[] { 0xFF, 0xE4, 0x48, 0x31, 0xC0, 0x55, 0xC3 };
            var result = Opcode_Disassembler.Disassemble(opcodes, MachineType.x64, core);
            Console.WriteLine(result.Return_Value + Environment.NewLine);
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

            Process_Info info = new Process_Info(core, thisProcess);
            Console.WriteLine(info.Module_Info_Output());
        }

        public static void output_byte_array()
        {
            byte[] unwantedBytes = new byte[] { 0xA1, 0xB1, 0xC1, 0xD1 };
            var bytes = core.Generate_Byte_Array(unwantedBytes);
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

            Process_Info info = new Process_Info(core, thisProcess);
            for(int i = 0; i < info.Threads_Info.Count; i++){
                info.Threads_Info[i].Get_Context();
                Console.WriteLine("i = {0}", i);
            }
            
        }

        public static void Find_SEH()
        {
            //ensure notepad is open before running this function.
            /*
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))//"KMFtp"))//"x64dbg"))//
                {
                    thisProcess = process1;
                }
            }

            Process_Info info = new Process_Info(core, thisProcess);*/
            byte[] bytes = new byte[] {
                0x11, 0x22, 0x33, 0x33, 0x55, 0x5F, 0x5E, 0xC3, 0x11, 0x41, 0xC3, 0xC2, 0xC3,
                0x5C, 0x44, 0xC3, 0x11, 0x11, 0x5F, 0x41, 0x5F, 0xC3, 0x11, 0x22, 0x33, 0x41, 0x58, 0x5E, 0xC3 };
            var list = Payloads.Pop_Pop_Ret(bytes);
            foreach(int i in list)
            {
                Console.WriteLine(i);
            }
            Console.WriteLine("list length = {0}", list.Count);
            Console.WriteLine("Function Complete");
        }
    }
}
