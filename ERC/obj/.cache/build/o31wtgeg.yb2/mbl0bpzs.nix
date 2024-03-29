﻿<!DOCTYPE html>
<!--[if IE]><![endif]-->
<html>
  
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>ERC.Net </title>
    <meta name="viewport" content="width=device-width">
    <meta name="title" content="ERC.Net ">
    <meta name="generator" content="docfx 2.59.0.0">
    
    <link rel="shortcut icon" href="../favicon.ico">
    <link rel="stylesheet" href="../styles/docfx.vendor.css">
    <link rel="stylesheet" href="../styles/docfx.css">
    <link rel="stylesheet" href="../styles/main.css">
    <meta property="docfx:navrel" content="../toc.html">
    <meta property="docfx:tocrel" content="toc.html">
    
    
    
  </head>
  <body data-spy="scroll" data-target="#affix" data-offset="120">
    <div id="wrapper">
      <header>
        
        <nav id="autocollapse" class="navbar navbar-inverse ng-scope" role="navigation">
          <div class="container">
            <div class="navbar-header">
              <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
              
              <a class="navbar-brand" href="../index.html">
                <img id="logo" class="svg" src="../logo.svg" alt="">
              </a>
            </div>
            <div class="collapse navbar-collapse" id="navbar">
              <form class="navbar-form navbar-right" role="search" id="search">
                <div class="form-group">
                  <input type="text" class="form-control" id="search-query" placeholder="Search" autocomplete="off">
                </div>
              </form>
            </div>
          </div>
        </nav>
        
        <div class="subnav navbar navbar-default">
          <div class="container hide-when-search" id="breadcrumb">
            <ul class="breadcrumb">
              <li></li>
            </ul>
          </div>
        </div>
      </header>
      <div role="main" class="container body-content hide-when-search">
        
        <div class="sidenav hide-when-search">
          <a class="btn toc-toggle collapse" data-toggle="collapse" href="#sidetoggle" aria-expanded="false" aria-controls="sidetoggle">Show / Hide Table of Contents</a>
          <div class="sidetoggle collapse" id="sidetoggle">
            <div id="sidetoc"></div>
          </div>
        </div>
        <div class="article row grid-right">
          <div class="col-md-10">
            <article class="content wrap" id="_content" data-uid="">
<h1 id="ercnet">ERC.Net</h1>

<p><a href="license.txt"><img src="https://img.shields.io/github/license/Andy53/ERC.Net" alt="License"></a>
<a href="https://github.com/Andy53/ERC.Net/issues"><img src="https://img.shields.io/github/issues-raw/Andy53/ERC.Net?style=flat" alt="GitHub issues"></a>
<a href="https://github.com/Andy53/ERC.Net/commits/master">
<img src="https://img.shields.io/github/last-commit/Andy53/ERC.Net?style=flat-square&logo=github&logoColor=white">
</a></p>
<p>ERC.Net is a collection of tools designed to assist in debugging Windows application crashes. ERC.Net supports both 64 and 32 bit applications, can parse DLL/EXE headers, identify compile time flags such as ASLR, DEP and SafeSEH, generate non repeating patterns, generate platform specific egg hunters, identify process information such as loaded modules and running threads, read the TEB of a specific thread, assist with identifying numerous types of memory vulnerabilities and has numerous other use cases.</p>
<h2 id="installing">Installing</h2>
<p>Install one of the nuget packages (<a href="https://www.nuget.org/packages/ERC.Net-x86/">x86</a>/<a href="https://www.nuget.org/packages/ERC.Net-x64/">x64</a>) or download the source code from <a href="https://github.com/Andy53/ERC.net">Github</a>, build the library and then link it in your project.</p>
<h3 id="prerequisites">Prerequisites</h3>
<p>Visual studio<br>
.Net 4.7.2<br>
C#</p>
<h3 id="documentation">Documentation</h3>
<p>This library contains the fundamental specifications, documentation, and architecture that underpin ERC.Net. If you're looking to understand the system better, or want to know how to integrate the various components, there is a lot of valuable information contained here.</p>
<p><a href="https://andy53.github.io/ERC.net/">📄 Documentation and Specifications</a></p>
<h3 id="getting-started">Getting Started</h3>
<p>Below are a set of examples detailing how to use the basic functionality provided by ERC.Net</p>
<p>Creating a sting of non repeating characters:</p>
<pre><code class="lang-csharp">using System;
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
            Console.WriteLine(&quot;Pattern:&quot; + Environment.NewLine + p.ReturnValue);
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Identifying the position of a sting within a non repeating string:</p>
<pre><code class="lang-csharp">using System;
using ERC;
using ERC.Utilities;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var p = PatternTools.PatternOffset(&quot;Aa9&quot;, core);
            Console.WriteLine(&quot;Pattern Offset:&quot; + Environment.NewLine + p.ReturnValue);
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Display a list of all applicable local processes:</p>
<pre><code class="lang-csharp">using System;
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
                Console.WriteLine(&quot;Name: {0} ID: {1}&quot;, process.ProcessName, process.Id);
            }
            Console.WriteLine(Environment.NewLine);
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Search Process Memory for a string (the string being searched for is &quot;anonymous&quot;, the program being searched is notepad) and return a list of pointers to that string in process memory:</p>
<pre><code class="lang-csharp">using System;
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
                if (process1.ProcessName.Contains(&quot;notepad&quot;))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var listy = info.SearchMemory(1, searchString: &quot;anonymous&quot;);
            foreach (KeyValuePair&lt;IntPtr, string&gt; s in listy.ReturnValue)
            {
                Console.WriteLine(&quot;0x&quot; + s.Key.ToString(&quot;x16&quot;) + &quot; Filepath: &quot; + s.Value);
            }
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>An example of how to assemble mnemonics into opcodes:</p>
<pre><code class="lang-csharp">using System;
using System.Collections.Generic;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            List&lt;string&gt; instructions = new List&lt;string&gt;();
            instructions.Add(&quot;ret&quot;);

            foreach (string s in instructions)
            {
                List&lt;string&gt; strings = new List&lt;string&gt;();
                strings.Add(s);
                var asmResult = ERC.Utilities.OpcodeAssembler.AssembleOpcodes(strings, MachineType.x64);
                Console.WriteLine(s + &quot; = &quot; + BitConverter.ToString(asmResult.ReturnValue).Replace(&quot;-&quot;, &quot;&quot;));
            }
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>An example of how to disassemble opcodes into mnemonics:</p>
<pre><code class="lang-csharp">using System;
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
</code></pre>
<p>Display information about all modules associated with a process:</p>
<pre><code class="lang-csharp">using System;
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
            Console.WriteLine(&quot;Outputting module info&quot;);
            output_module_info();
            Console.ReadKey();
        }

        public static void output_module_info()
        {
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains(&quot;notepad&quot;))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            Console.WriteLine(&quot;Here&quot;);
            Console.WriteLine(DisplayOutput.GenerateModuleInfoTable(info));
        }
    }
}
</code></pre>
<p>Generate a byte array of all possible bytes excluding 0xA1, 0xB1, 0xC1 and 0xD1 then save it to a file in C::</p>
<pre><code class="lang-csharp">using System;
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
            Console.WriteLine(BitConverter.ToString(bytes).Replace(&quot;-&quot;, &quot; &quot;));
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Return the value of all registers (Context) for a given thread:</p>
<pre><code class="lang-csharp">using System;
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
                if (process1.ProcessName.Contains(&quot;notepad&quot;))
                {
                    thisProcess = process1;
                }
            }

            ProcessInfo info = new ProcessInfo(core, thisProcess);
            for (int i = 0; i &lt; info.ThreadsInfo.Count; i++)
            {
                info.ThreadsInfo[i].Get_Context();
                Console.WriteLine(info.ThreadsInfo[i].Context64.ToString());
            }
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Return a pointer and mnemonics for all SEH jumps in the given process and associated modules:</p>
<pre><code class="lang-csharp">using System;
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
                if (process1.ProcessName.Contains(&quot;notepad&quot;))
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
</code></pre>
<p>Generate a collection of egghunters with the tag &quot;AAAA&quot;:</p>
<pre><code class="lang-csharp">using System;
using ERC;

namespace ERC_Test_App
{
    class Program
    {
        static void Main()
        {
            ErcCore core = new ErcCore();
            var eggs = DisplayOutput.GenerateEggHunters(core, &quot;AAAA&quot;);
            Console.WriteLine(eggs);
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Display the SEH chain for a thread (the process must have entered an error state for this to be populated):</p>
<pre><code class="lang-csharp">using System;
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
                if (process1.ProcessName.Contains(&quot;notepad&quot;))
                {
                    thisProcess = process1;
                }
            }
            ProcessInfo info = new ProcessInfo(core, thisProcess);
            var test = info.ThreadsInfo[0].GetSehChain();
            foreach (IntPtr i in test)
            {
                Console.WriteLine(&quot;Ptr: {0}&quot;, i.ToString(&quot;X8&quot;));
            }
            Console.ReadKey();
        }
    }
}
</code></pre>
<p>Find a non repeating pattern in memory and display which registers point to (or near) it:</p>
<pre><code class="lang-csharp">using System;
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
                if (process1.ProcessName.Contains(&quot;Vulnerable Application Name&quot;))
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
</code></pre>
<p>Generate a 32bit ROP chain for the current process:</p>
<pre><code class="lang-csharp">using System;
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
            Console.WriteLine(&quot;Generate RopChain 32&quot;);
            GenerateRopChain32();
            Console.ReadKey();
        }

        public static void GenerateRopChain32()
        {
            Process[] processes = Process.GetProcesses();
            Process thisProcess = null;
            foreach (Process process1 in processes)
            {
                if (process1.ProcessName.Contains(&quot;Word&quot;))
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
</code></pre>
<h2 id="versioning">Versioning</h2>
<p>For the versions available, see the <a href="https://github.com/Andy53/ERC.net/tags">tags on this repository</a>.</p>
<h2 id="authors">Authors</h2>
<ul>
<li><strong>Andy Bowden</strong> - <a href="https://github.com/Andy53">Andy53</a></li>
</ul>
<h2 id="license">License</h2>
<p>This project is licensed under the GNU General Public License v3.0 - see the <a href="LICENSE.md">LICENSE.md</a> file for details</p>
<h2 id="acknowledgments">Acknowledgments</h2>
<ul>
<li>Hat tip to anyone whose code was used</li>
<li>Inspiration</li>
<li>Other things</li>
</ul>
</article>
          </div>
          
          <div class="hidden-sm col-md-2" role="complementary">
            <div class="sideaffix">
              <div class="contribution">
                <ul class="nav">
                  <li>
                    <a href="https://github.com/Andy53/ERC.net/blob/master/ERC/articles/Usage.md/#L1" class="contribution-link">Improve this Doc</a>
                  </li>
                </ul>
              </div>
              <nav class="bs-docs-sidebar hidden-print hidden-xs hidden-sm affix" id="affix">
                <h5>In This Article</h5>
                <div></div>
              </nav>
            </div>
          </div>
        </div>
      </div>
      
      <footer>
        <div class="grad-bottom"></div>
        <div class="footer">
          <div class="container">
            <span class="pull-right">
              <a href="#top">Back to top</a>
            </span>
            
            <span>Generated by <strong>DocFX</strong></span>
          </div>
        </div>
      </footer>
    </div>
    
    <script type="text/javascript" src="../styles/docfx.vendor.js"></script>
    <script type="text/javascript" src="../styles/docfx.js"></script>
    <script type="text/javascript" src="../styles/main.js"></script>
  </body>
</html>
