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
            byte[] pushad = new byte[] { 0x60 };

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
            opcodes32.Add(pushad);

            //Populate 64 bit list
            byte[] pushRax = new byte[] { 0x50 };
            byte[] pushRcx = new byte[] { 0x51 };
            byte[] pushRdx = new byte[] { 0x51 };
            byte[] pushRbx = new byte[] { 0x53 };
            byte[] pushRsp = new byte[] { 0x54 };
            byte[] pushRbp = new byte[] { 0x55 };
            byte[] pushRsi = new byte[] { 0x56 };
            byte[] pushRdi = new byte[] { 0x57 };
            byte[] pushR8 = new byte[] { 0x41, 0x50 };
            byte[] pushR9 = new byte[] { 0x41, 0x51 };
            byte[] pushR10 = new byte[] { 0x41, 0x52 };
            byte[] pushR11 = new byte[] { 0x41, 0x53 };
            byte[] pushR12 = new byte[] { 0x41, 0x54 };
            byte[] pushR13 = new byte[] { 0x41, 0x55 };
            byte[] pushR14 = new byte[] { 0x41, 0x56 };
            byte[] pushR15 = new byte[] { 0x41, 0x57 };
            byte[] popRax = new byte[] { 0x58 };
            byte[] popRbx = new byte[] { 0x5B };
            byte[] popRcx = new byte[] { 0x59 };
            byte[] popRdx = new byte[] { 0x5A };
            byte[] popRsp = new byte[] { 0x5C };
            byte[] popRbp = new byte[] { 0x5D };
            byte[] popRsi = new byte[] { 0x5E };
            byte[] popRdi = new byte[] { 0x5F };
            byte[] popR8 = new byte[] { 0x41, 0x58 };
            byte[] popR9 = new byte[] { 0x41, 0x59 };
            byte[] popR10 = new byte[] { 0x41, 0x5A };
            byte[] popR11 = new byte[] { 0x41, 0x5B };
            byte[] popR12 = new byte[] { 0x41, 0x5C };
            byte[] popR13 = new byte[] { 0x41, 0x5D };
            byte[] popR14 = new byte[] { 0x41, 0x5E };
            byte[] popR15 = new byte[] { 0x41, 0x5F };
            byte[] xorRax = new byte[] { 0x48, 0x31, 0xC0 };
            byte[] xorRbx = new byte[] { 0x48, 0x31, 0xD8 };
            byte[] xorRcx = new byte[] { 0x48, 0x31, 0xC9 };
            byte[] xorRdx = new byte[] { 0x48, 0x31, 0xD2 };
            byte[] xorRsi = new byte[] { 0x48, 0x31, 0xF6 };
            byte[] xorRdi = new byte[] { 0x48, 0x31, 0xFF };
            byte[] xorRsp = new byte[] { 0x48, 0x31, 0xE4 };
            byte[] xorRbp = new byte[] { 0x48, 0x31, 0xED };
            byte[] xorR8 = new byte[] { 0x48, 0x31, 0xC8 };
            byte[] xorR9 = new byte[] { 0x48, 0x31, 0xC9 };
            byte[] xorR10 = new byte[] { 0x48, 0x31, 0xD2 };
            byte[] xorR11 = new byte[] { 0x48, 0x31, 0xDB };
            byte[] xorR12 = new byte[] { 0x48, 0x31, 0xE4 };
            byte[] xorR13 = new byte[] { 0x48, 0x31, 0xED };
            byte[] xorR14 = new byte[] { 0x48, 0x31, 0xF6 };
            byte[] xorR15 = new byte[] { 0x48, 0x31, 0xFF };
            byte[] jmpRsp = new byte[] { 0xFF, 0xE4 };
            byte[] callRsp = new byte[] { 0xFF, 0xD4 };

            opcodes64.Add(pushRax);
            opcodes64.Add(pushRcx);
            opcodes64.Add(pushRdx);
            opcodes64.Add(pushRbx);
            opcodes64.Add(pushRsp);
            opcodes64.Add(pushRbp);
            opcodes64.Add(pushRsi);
            opcodes64.Add(pushRdi);
            opcodes64.Add(pushR8);
            opcodes64.Add(pushR9);
            opcodes64.Add(pushR10);
            opcodes64.Add(pushR11);
            opcodes64.Add(pushR12);
            opcodes64.Add(pushR13);
            opcodes64.Add(pushR14);
            opcodes64.Add(pushR15);
            opcodes64.Add(popRax);
            opcodes64.Add(popRbx);
            opcodes64.Add(popRcx);
            opcodes64.Add(popRdx);
            opcodes64.Add(popRsp);
            opcodes64.Add(popRbp);
            opcodes64.Add(popRsi);
            opcodes64.Add(popRdi);
            opcodes64.Add(popR8);
            opcodes64.Add(popR9);
            opcodes64.Add(popR10);
            opcodes64.Add(popR11);
            opcodes64.Add(popR12);
            opcodes64.Add(popR13);
            opcodes64.Add(popR14);
            opcodes64.Add(popR15);
            opcodes64.Add(xorRax);
            opcodes64.Add(xorRbx);
            opcodes64.Add(xorRcx);
            opcodes64.Add(xorRdx);
            opcodes64.Add(xorRsi);
            opcodes64.Add(xorRdi);
            opcodes64.Add(xorRsp);
            opcodes64.Add(xorRbp);
            opcodes64.Add(xorR8);
            opcodes64.Add(xorR9);
            opcodes64.Add(xorR10);
            opcodes64.Add(xorR11);
            opcodes64.Add(xorR12);
            opcodes64.Add(xorR13);
            opcodes64.Add(xorR14);
            opcodes64.Add(xorR15);
            opcodes64.Add(jmpRsp);
            opcodes64.Add(callRsp);
        }
        #endregion

        public ErcResult<string> GenerateRopChain32(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<string> RopChain = new ErcResult<string>(new ErcCore());

            Console.WriteLine("Starting GetApiAddresses...");
            var watch = System.Diagnostics.Stopwatch.StartNew();

            var ret1 = GetApiAddresses(info);
            if(ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(new ErcCore());
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
                return failed;
            }
            watch.Stop();
            Console.WriteLine("Finishing GetApiAddresses at {0}", watch.Elapsed);

            Console.WriteLine("Starting GetRopNops...");
            watch = System.Diagnostics.Stopwatch.StartNew();
            var ret2 = GetRopNops(info, excludes);
            if (ret1.Error != null && RopNops.Count <= 0)
            {
                Console.WriteLine("An Error has occured: ", ret2.Error);
                ErcResult<string> failed = new ErcResult<string>(new ErcCore());
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
                return failed;
            }
            watch.Stop();
            Console.WriteLine("Finishing GetRopNops at {0}", watch.Elapsed);

            Console.WriteLine("Starting PopulateOpcodes...");
            watch = System.Diagnostics.Stopwatch.StartNew();
            var ret3 = PopulateOpcodes(info);
            watch.Stop();
            Console.WriteLine("Finishing PopulateOpcodes at {0}", watch.Elapsed);
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
                Console.WriteLine("GetProcAddress Error: " + returnVar.Error);
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
                Console.WriteLine("GetProcAddress Error: " + returnVar.Error);
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
                Console.WriteLine("GetProcAddress Error: " + returnVar.Error);
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
                Console.WriteLine("GetProcAddress Error: " + returnVar.Error);
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

            for(int i = 0; i < RopNops.Count; i++)
            {
                byte[] bytes = new byte[20];
                IntPtr baseAddress = RopNops[i] - 20;
                ErcCore.ReadProcessMemory(info.ProcessHandle, baseAddress, bytes, 20, out int bytesRead);
                if (bytesRead != 20)
                {
                    ret.Error = new ERCException("ReadProcessMemory Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    ret.LogEvent();
                }
                var ret1 = ParseByteArrayForRopCodes(bytes, info.ProcessMachineType);
                if(ret1.Error != null)
                {
                    ret.Error = ret1.Error;
                    return ret;
                }
            }
            return ret;
        }
        #endregion

        private ErcResult<int> ParseByteArrayForRopCodes(byte[] bytes, MachineType machineType)
        {
            Console.WriteLine("Inside ParseByteArrayForRopCodes...");
            ErcResult<int> ret = new ErcResult<int>(new ErcCore());
            if(machineType == MachineType.I386)
            {
                for (int i = bytes.Length - 1; i >= 0; i--)
                {
                    for (int j = 0; j < opcodes32.Count; j++)
                    {
                        if (bytes[i] == opcodes32[j][0]){
                            Console.WriteLine("The Comparison works!!!!!");
                        }
                    }
                }
            }
            else if(machineType == MachineType.x64)
            {
                Console.WriteLine("Inside ParseByteArrayForRopCodes.x64");
                for (int i = bytes.Length - 1; i >= 0; i--)
                {
                    for (int j = 0; j < opcodes64.Count; j++)
                    {
                        if (bytes[i] == opcodes64[j][0])
                        {
                            Console.WriteLine("The Comparison works!!!!!");
                        }
                    }
                }
            }
            else
            {
                ret.Error = new ERCException("Error: Invlaid machine type provided. Cannot continue. Error thrown during RopChainGenerator.ParseByteArrayForRopCodes with MachineType: " + machineType.ToString());
                ret.LogEvent();
                return ret;
            }
            return ret;
        }

        private ErcResult<Dictionary<byte[], string>> GenerateVirtualProtectChain(ProcessInfo info)
        {
            ErcResult<Dictionary<byte[], string>> VirtualProtectChain = new ErcResult<Dictionary<byte[], string>>(new ErcCore());
            return VirtualProtectChain;
        }
    }
}
