# ERC.Net

ERC.Net is a collection of tools designed to assist in debugging Windows application crashes. ERC.Net supports both 64 and 32 bit applications, can parse DLL/EXE headers, identify compile time flags such as ASLR, DEP and SafeSEH, generate non repeating patterns, generate platform specific egg hunters, identify process information such as loaded modules and running threads, read the TEB of a specific thread, assist with identifying numerous types of memory vulnerabilities and has numerous other use cases. 

## Installing

Install the nuget package or download the source code from [Github](https://github.com/Andy53/ERC.net), build the library and then link it in your project.

### Prerequisites

Visual studio  
.Net 4.7.2   
C#   

### Getting Started

Below are a set of examples detailing how to use the basic functionality provided by ERC.Net

Creating a sting of non repeating characters:
```
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
            Console.WriteLine("create a pattern 1000 characters long: ");
            create_a_pattern();
            Console.ReadKey();
        }

        public static void create_a_pattern()
        {
            var result = ERC.Utilities.PatternTools.PatternCreate(1000, core);
            Console.WriteLine(result.ReturnValue);
            Console.WriteLine(Environment.NewLine);
        }
    }
}
```
     
    
Identifying the position of a sting within a non repeating string:
```
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
            Console.WriteLine("Find offset in pattern (Ag9):");
            find_pattern_offset();
            Console.ReadKey();
        }

        public static void find_pattern_offset()
        {
            var result = ERC.Utilities.PatternTools.PatternOffset("Ag9", core);
            Console.WriteLine(result.ReturnValue);
        }
    }
}
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/Andy53/ERC.net/tags). 

## Authors

* **Andy** - [PurpleBooth](https://github.com/PurpleBooth)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
* Inspiration
* Other things

