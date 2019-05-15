using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ERC.Utilities
{
    public class RopChainGenerator
    {
        private const int MEM_COMMIT = 0x1000;

        Dictionary<IntPtr, string> ApiAddresses = new Dictionary<IntPtr, string>();
        List<IntPtr> RopNops = new List<IntPtr>();
        List<byte[]> opcodes32 = new List<byte[]>();
        List<byte[]> opcodes64 = new List<byte[]>();

        #region Constructor
        public RopChainGenerator()
        {   
            //Populate 32 bit list
            byte[] pushEax = new byte[] { 0x50 };
            byte[] pushEbx = new byte[] { 0x53 };
            byte[] pushEcx = new byte[] { 0x51 };
            byte[] pushEdx = new byte[] { 0x52 };
            byte[] pushEsp = new byte[] { 0x54 };
            byte[] pushEbp = new byte[] { 0x55 };
            byte[] pushEsi = new byte[] { 0x56 };
            byte[] pushEdi = new byte[] { 0x57 };
            byte[] jmpEsp = new byte[] { 0xFF, 0xE4 };
            byte[] callEsp = new byte[] { 0xFF, 0xD4 };
            byte[] xorEax = new byte[] { 0x31, 0xC0 };
            byte[] xorEbx = new byte[] { 0x31, 0xD8 };
            byte[] xorEcx = new byte[] { 0x31, 0xC9 };
            byte[] xorEdx = new byte[] { 0x31, 0xD2 };
            byte[] xorEsi = new byte[] { 0x31, 0xF6 };
            byte[] xorEdi = new byte[] { 0x31, 0xFF };
            byte[] popEax = new byte[] { 0x58 };
            byte[] popEbx = new byte[] { 0x5B };
            byte[] popEcx = new byte[] { 0x59 };
            byte[] popEdx = new byte[] { 0x5A };
            byte[] popEsp = new byte[] { 0x5C };
            byte[] popEbp = new byte[] { 0x5D };
            byte[] popEsi = new byte[] { 0x5E };
            byte[] popEdi = new byte[] { 0x5F };

            opcodes32.Add(pushEax);
            opcodes32.Add(pushEbx);
            opcodes32.Add(pushEcx);
            opcodes32.Add(pushEdx);
            opcodes32.Add(pushEsp);
            opcodes32.Add(pushEbp);
            opcodes32.Add(pushEsi);
            opcodes32.Add(pushEdi);
            opcodes32.Add(jmpEsp);
            opcodes32.Add(callEsp);
            opcodes32.Add(xorEax);
            opcodes32.Add(xorEbx);
            opcodes32.Add(xorEcx);
            opcodes32.Add(xorEdx);
            opcodes32.Add(xorEsi);
            opcodes32.Add(xorEdi);
            opcodes32.Add(popEax);
            opcodes32.Add(popEbx);
            opcodes32.Add(popEcx);
            opcodes32.Add(popEdx);
            opcodes32.Add(popEsp);
            opcodes32.Add(popEbp);
            opcodes32.Add(popEsi);
            opcodes32.Add(popEdi);

            //Populate 64 bit list
        }
        #endregion

        public ErcResult<string> GenerateRopChain32(ProcessInfo info, List<string> excludes = null)
        {
            var ret1 = GetApiAddresses(info);
            if(ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(new ErcCore());
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
                return failed;
            }
            ErcResult<string> RopChain = new ErcResult<string>(new ErcCore());
            IntPtr hModule = IntPtr.Zero;
            for (int i = 0; i < info.ModulesInfo.Count; i++)
            {
                if (info.ModulesInfo[i].ModuleName == "kernel32")
                {
                    hModule = info.ModulesInfo[i].ModuleBase;
                }
            
            }
            var virtAllocAddress = ErcCore.GetProcAddress(hModule, "VirtualAlloc");
            Console.WriteLine("Virtual Alloc Address = 0x{0}", virtAllocAddress.ToString("X"));
            if(virtAllocAddress == IntPtr.Zero)
            {
                RopChain.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            Console.WriteLine("Function Complete");
            //GetInstructionPair(info, 0xC3);
            return RopChain;
        }

        public string GenerateRopChain64(ProcessInfo info, List<string> excludes = null)
        {
            return "";
        }

        #region GetApiAddresses
        private ErcResult<int> GetApiAddresses(ProcessInfo info)
        {
            ErcResult<int> returnVar = new ErcResult<int>(new ErcCore());
            returnVar.ReturnValue = 0;

            IntPtr hModule = IntPtr.Zero;
            for (int i = 0; i < info.ModulesInfo.Count; i++)
            {
                if (info.ModulesInfo[i].ModuleName == "kernel32")
                {
                    hModule = info.ModulesInfo[i].ModuleBase;
                }

            }

            var virtAllocAddress = ErcCore.GetProcAddress(hModule, "VirtualAlloc");
            if (virtAllocAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
                Console.WriteLine(returnVar.Error);
            }
            else
            {
                ApiAddresses.Add(virtAllocAddress, "VirtualAlloc");
            }

            var HeapCreateAddress = ErcCore.GetProcAddress(hModule, "HeapCreate");
            if (HeapCreateAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
                Console.WriteLine(returnVar.Error);
            }
            else
            {
                ApiAddresses.Add(HeapCreateAddress, "HeapCreate");
            }

            var VirtualProtectAddress = ErcCore.GetProcAddress(hModule, "VirtualProtect");
            if (VirtualProtectAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
                Console.WriteLine(returnVar.Error);
            }
            else
            {
                ApiAddresses.Add(VirtualProtectAddress, "VirtualProtect");
            }

            var WriteProcessMemoryAddress = ErcCore.GetProcAddress(hModule, "WriteProcessMemory");
            if (WriteProcessMemoryAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
                Console.WriteLine(returnVar.Error);
            }
            else
            {
                ApiAddresses.Add(WriteProcessMemoryAddress, "WriteProcessMemory");
            }

            return returnVar;
        }
        #endregion

        #region GetRopNops
        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(new ErcCore());
            ropNopsResult.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchMemory(0, ropNop, excludes: excludes);
            if(ropPtrs.Error != null)
            {
                ropNopsResult.Error = ropPtrs.Error;
            }
            foreach(KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNopsResult.ReturnValue.Add(k.Key);
                RopNops.Add(k.Key);
            }
            return ropNopsResult;
        }

        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(new ErcCore());
            ropNopsResult.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchMemory(0, ropNop);
            if (ropPtrs.Error != null)
            {
                ropNopsResult.Error = ropPtrs.Error;
            }
            foreach (KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNopsResult.ReturnValue.Add(k.Key);
                RopNops.Add(k.Key);
            }
            return ropNopsResult;
        }
        #endregion

        #region PopulateOpcodes
        private ErcResult<int> PopulateOpcodes(ProcessInfo info)
        {
            ErcResult<int> ret = new ErcResult<int>(new ErcCore());

            if(info.ProcessMachineType == MachineType.I386)
            {
                
            }
            else if(info.ProcessMachineType == MachineType.x64)
            {
                //To be completed!
            }
            else
            {
                ret.Error = new ERCException("Error: ProcessInfo has invlaid machine type. Cannot continue. Error thrown during RopChainGenerator.PopulateOpcodes with ProcessInfo.ProcessName " + info.ProcessName);
                return ret;
            }
            
            return ret;
        }
        #endregion

        private ErcResult<Dictionary<byte[], string>> GenerateVirtualProtectChain(ProcessInfo info, int size, List<string> excludes = null)
        {
            ErcResult<Dictionary<byte[], string>> VirtualProtectChain = new ErcResult<Dictionary<byte[], string>>(new ErcCore());
            return VirtualProtectChain;
        }

        private ErcResult<Dictionary<byte[], string>> GenerateVirtualProtectChain(ProcessInfo info, int size)
        {
            ErcResult<Dictionary<byte[], string>> VirtualProtectChain = new ErcResult<Dictionary<byte[], string>>(new ErcCore());
            return VirtualProtectChain;
        }
    }
}
