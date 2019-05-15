using ERC;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ERC_Lib
{
    public static class RopChainGenerator
    {
        public static string GenerateRopChain32(ProcessInfo info, List<string> excludes = null)
        {
            GetInstructionPair(info, 0xC3);
            return "";
        }

        public static string GenerateRopChain64(ProcessInfo info, List<string> excludes = null)
        {
            return "";
        }

        private static ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> ropNops = new ErcResult<List<IntPtr>>(new ErcCore());
            ropNops.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchMemory(0, ropNop, excludes: excludes);
            foreach(KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNops.ReturnValue.Add(k.Key);
            }
            return ropNops;
        }

        private static ErcResult<Dictionary<IntPtr, string>> GetInstructionPair(ProcessInfo info, byte instruction, List<string> excludes = null)
        {
            byte[] C3 = new byte[] { 0xC3 };
            byte[] instruct = new byte[] { instruction };
            var firstInstruction = info.SearchMemory(0, instruct, excludes: excludes);
            List<IntPtr> viablePtrs = new List<IntPtr>();

            for (int i = 0; i < viablePtrs.Count; i++)
            {
                byte[] bytes = new byte[20];
                ErcCore.ReadProcessMemory(info.ProcessHandle, viablePtrs[i], bytes, 20, out int bytesRead);
                if(bytesRead != 20)
                {
                    Console.WriteLine("i = {0}", i);
                    Console.WriteLine(new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message));
                }
            }

            Console.WriteLine(firstInstruction.ReturnValue.Count);
            return null;
        }
    }
}
