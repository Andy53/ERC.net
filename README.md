# ERC.Net     
[![License](https://img.shields.io/github/license/Andy53/ERC.Net)](license.txt)
[![GitHub issues](https://img.shields.io/github/issues-raw/Andy53/ERC.Net?style=flat)](https://github.com/Andy53/ERC.Net/issues)
<a href="https://github.com/Andy53/ERC.Net/commits/master">
    <img src="https://img.shields.io/github/last-commit/Andy53/ERC.Net?style=flat-square&logo=github&logoColor=white">
</a> 

ERC.Net is a collection of tools designed to assist in debugging Windows application crashes. ERC.Net supports both 64 and 32 bit applications, can parse DLL/EXE headers, identify compile time flags such as ASLR, DEP and SafeSEH, generate non repeating patterns, generate platform specific egg hunters, identify process information such as loaded modules and running threads, read the TEB of a specific thread, assist with identifying numerous types of memory vulnerabilities and has numerous other use cases. 

## Installing

Install one of the nuget packages ([x86](https://www.nuget.org/packages/ERC.Net-x86/)/[x64](https://www.nuget.org/packages/ERC.Net-x64/)) or download the source code from [Github](https://github.com/Andy53/ERC.net), build the library and then link it in your project.

There are two packages because the library reads pointer width at run time and
P/Invokes into Win32: pick the one matching the process you will be inspecting.

### Prerequisites

The [.NET SDK](https://dotnet.microsoft.com/download) 8.0 or newer. Visual Studio
is optional - the library builds from the command line, and nothing here needs
full MSBuild.

The library targets `net472` and `net8.0-windows`, so it can be consumed from
either .NET Framework or a modern runtime. It is Windows-only in both cases.

### Building from source

```
git clone https://github.com/Andy53/ERC.net
cd ERC.net
.\build.ps1
```

That produces both architectures for both target frameworks.

```
.\build.ps1 -Platform x64          # one architecture
.\build.ps1 -Configuration Debug   # a debug build
.\build.ps1 -CleanPackages         # restore into an empty package folder
```

`-CleanPackages` exists because this project could not, for a long time, be built
by anyone but its author: it referenced four assemblies by path into a
`ConsoleApp1` folder that existed on one machine. Building from an empty package
folder is how that class of problem gets caught rather than discovered by a
contributor.

### Running the tests

```
.\test.ps1                     # both architectures
.\test.ps1 -Platform x64       # one
.\test.ps1 -Coverage           # with a per-class coverage summary
.\test.ps1 -SkipIntegration    # skip the live-process tests
```

The suite runs against both x86 and x64 because the library is built per
architecture and reads pointer width at run time, so some behaviour genuinely
differs between the two - pointer filtering and PE flag parsing both did.

Some tests launch a real target process and inspect it, so that memory searching,
gadget finding, module parsing and thread enumeration are exercised against
something real rather than a substitute. The target
(`tests/Fixtures/ErcTestTarget`) plants known byte sequences and strings in
unmanaged memory and prints their addresses, and the tests assert that ERC finds
the exact address the target reported.

### Documentation
This library contains the fundamental specifications, documentation, and architecture that underpin ERC.Net. If you're looking to understand the system better, or want to know how to integrate the various components, there is a lot of valuable information contained here.    

[📄 Documentation and Specifications](https://andy53.github.io/ERC.net/) 

### Getting Started

Below are a set of examples detailing how to use the basic functionality provided by ERC.Net

Creating a sting of non repeating characters:
```csharp
using System;
using ERC;
using ERC.Utilities;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var p = PatternTools.PatternCreate(1000, core);
            Console.WriteLine("Pattern:" + Environment.NewLine + p.ReturnValue);
            Console.ReadKey();
        }
    }
}
```    
     
    
Identifying the position of a sting within a non repeating string:
```csharp
using System;
using ERC;
using ERC.Utilities;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var p = PatternTools.PatternOffset("Aa9", core);
            Console.WriteLine("Pattern Offset:" + Environment.NewLine + p.ReturnValue);
            Console.ReadKey();
        }
    }
}
```     
     
Display a list of all applicable local processes:
```csharp
using System;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var test = ProcessInfo.ListLocalProcesses(core);
            foreach (Process process in test.ReturnValue)
            {
                Console.WriteLine("Name: {0} ID: {1}", process.ProcessName, process.Id);
            }
            Console.WriteLine(Environment.NewLine);
            Console.ReadKey();
        }
    }
}
```

Search Process Memory for a string (the string being searched for is "anonymous", the program being searched is notepad) and return a list of pointers to that string in process memory:
```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var listy = info.SearchMemory(1, searchString: "anonymous");
            foreach (KeyValuePair<IntPtr, string> s in listy.ReturnValue)
            {
                Console.WriteLine("0x" + s.Key.ToString("x16") + " Filepath: " + s.Value);
            }
            Console.ReadKey();
        }
    }
}
```     


An example of how to assemble mnemonics into opcodes:
```csharp
using System;
using System.Collections.Generic;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            List<string> instructions = new List<string>();
            instructions.Add("ret");

            foreach (string s in instructions)
            {
                List<string> strings = new List<string>();
                strings.Add(s);
                var asmResult = ERC.Utilities.OpcodeAssembler.AssembleOpcodes(strings, MachineType.x64);
                Console.WriteLine(s + " = " + BitConverter.ToString(asmResult.ReturnValue).Replace("-", ""));
            }
            Console.ReadKey();
        }
    }
}
```     

An example of how to disassemble opcodes into mnemonics:
```csharp
using System;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            byte[] opcodes = new byte[] { 0xC3 };
            var result = ERC.Utilities.OpcodeDisassembler.Disassemble(opcodes, MachineType.x64);
            Console.WriteLine(result.ReturnValue + Environment.NewLine);
            Console.ReadKey();
        }
    }
}
```

Display information about all modules associated with a process:
```csharp
using System;
using ERC;
using System.Diagnostics;
using System.Collections.Generic;
using ERC.Utilities;

namespace ERC_test_app
{
    class Program
    {
        static void Main(string[] args)
        {
            public static ErcCore core = new ErcCore();
            Console.WriteLine("Outputting module info");
            output_module_info();
            Console.ReadKey();
        }

        public static void output_module_info()
        {
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            Console.WriteLine("Here");
            Console.WriteLine(DisplayOutput.GenerateModuleInfoTable(info));
        }
    }
}
```   

Generate a byte array of all possible bytes excluding 0xA1, 0xB1, 0xC1 and 0xD1 then save it to a file in C:\:
```csharp
using System;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            byte[] unwantedBytes = new byte[] { 0xA1, 0xB1, 0xC1, 0xD1 };
            var bytes = DisplayOutput.GenerateByteArray(unwantedBytes, core);
            Console.WriteLine(BitConverter.ToString(bytes).Replace("-", " "));
            Console.ReadKey();
        }
    }
}
```    

Return the value of all registers (Context) for a given thread:
```csharp
using System;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            for (int i = 0; i < info.ThreadsInfo.Count; i++)
            {
                info.ThreadsInfo[i].Get_Context();
                Console.WriteLine(info.ThreadsInfo[i].Context64.ToString());
            }
            Console.ReadKey();
        }
    }
}
```    

Return a pointer and mnemonics for all SEH jumps in the given process and associated modules:
```csharp
using System;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var tester = DisplayOutput.GetSEHJumps(info);
            foreach (string s in tester.ReturnValue)
            {
                Console.WriteLine(s);
            }
            Console.ReadKey();
        }
    }
}
```     

Generate a collection of egghunters with the tag "AAAA":
```csharp
using System;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var eggs = DisplayOutput.GenerateEggHunters(core, "AAAA");
            Console.WriteLine(eggs);
            Console.ReadKey();
        }
    }
}
```     

Display the SEH chain for a thread (the process must have entered an error state for this to be populated):
```csharp
using System;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("notepad"))
                {
                    thisProcess = process1;
                }
            }
            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var test = info.ThreadsInfo[0].GetSehChain();
            foreach (IntPtr i in test)
            {
                Console.WriteLine("Ptr: {0}", i.ToString("X8"));
            }
            Console.ReadKey();
        }
    }
}
```    

Find a non repeating pattern in memory and display which registers point to (or near) it:
```csharp
using System;
using System.Diagnostics;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("Vulnerable Application Name"))
                {
                    thisProcess = process1;
                }
            }
            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var strings = DisplayOutput.GenerateFindNRPTable(info, 2, false);
            foreach (string s in strings)
            {
                Console.WriteLine(s);
            }
            Console.ReadKey();
        }
    }
}
```    

Generate a 32bit ROP chain for the current process:
```csharp
using System;
using ERC;
using System.Diagnostics;
using System.Collections.Generic;
using ERC.Utilities;

namespace ERC_test_app
{
    class Program
    {
        static void Main(string[] args)
        {
            public static ErcCore core = new ErcCore();
            Console.WriteLine("Generate RopChain 32");
            GenerateRopChain32();
            Console.ReadKey();
        }

        public static void GenerateRopChain32()
        {
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains("Word"))
                {
                    thisProcess = process1;
                }
            }
            ProcessInfo info = new ProcessInfo(core, thisProcess);
            RopChainGenerator32 RCG = new RopChainGenerator32(info);
            RCG.GenerateRopChain32();
        }
    }
}
```    

## Versioning

For the versions available, see the [tags on this repository](https://github.com/Andy53/ERC.net/tags). 

## Authors

* **Andy Bowden** - [Andy53](https://github.com/Andy53)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* Other things

