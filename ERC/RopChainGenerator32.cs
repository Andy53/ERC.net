using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;

namespace ERC.Utilities
{
    public class RopChainGenerator
    {
        #region Class Variables
        private const int MEM_COMMIT = 0x1000;

        public List<Tuple<byte[], string>> VirtualAllocChain = new List <Tuple<byte[], string>>();

        Dictionary<string, IntPtr> ApiAddresses = new Dictionary<string, IntPtr>();
        List<IntPtr> RopNops = new List<IntPtr>();
        List<byte[]> opcodes32 = new List<byte[]>();
        internal X86Lists x86Opcodes;
        internal X86Lists usableX86Opcodes;
        private ProcessInfo info;
        Registers32 regState32;
        RegisterModifiers32 regModified32;
        #endregion

        #region Constructor
        public RopChainGenerator(ProcessInfo _info)
        {

            if (_info.ProcessMachineType == MachineType.I386)
            {
                x86Opcodes = new X86Lists();
            }
            else
            {
                throw new ArgumentException("Fatal Error: Unsupported processor version.");
            }

            info = _info;
            //Populate 32 bit list
            byte[] pushEax = new byte[] { 0x50 };
            byte[] pushEbx = new byte[] { 0x53 };
            byte[] pushEcx = new byte[] { 0x51 };
            byte[] pushEdx = new byte[] { 0x52 };
            byte[] pushEsp = new byte[] { 0x54 };
            byte[] pushEbp = new byte[] { 0x55 };
            byte[] pushEsi = new byte[] { 0x56 };
            byte[] pushEdi = new byte[] { 0x57 };
            byte[] popEax = new byte[] { 0x58 };
            byte[] popEbx = new byte[] { 0x5B };
            byte[] popEcx = new byte[] { 0x59 };
            byte[] popEdx = new byte[] { 0x5A };
            byte[] popEsp = new byte[] { 0x5C };
            byte[] popEbp = new byte[] { 0x5D };
            byte[] popEsi = new byte[] { 0x5E };
            byte[] popEdi = new byte[] { 0x5F };
            byte[] pushad = new byte[] { 0x60 };
            byte[] incEax = new byte[] { 0X40 };
            byte[] incEbx = new byte[] { 0X43 };
            byte[] incEcx = new byte[] { 0X41 };
            byte[] incEdx = new byte[] { 0X42 };
            byte[] incEbp = new byte[] { 0X45 };
            byte[] incEsp = new byte[] { 0X44 };
            byte[] incEsi = new byte[] { 0X46 };
            byte[] incEdi = new byte[] { 0X47 };
            byte[] decEax = new byte[] { 0X48 };
            byte[] decEbx = new byte[] { 0X4B };
            byte[] decEcx = new byte[] { 0X49 };
            byte[] decEdx = new byte[] { 0X4A };
            byte[] decEbp = new byte[] { 0X4D };
            byte[] decEsp = new byte[] { 0X4C };
            byte[] decEsi = new byte[] { 0X4E };
            byte[] decEdi = new byte[] { 0X4F };
            byte[] jmpEsp = new byte[] { 0xFF, 0xE4 };
            byte[] callEsp = new byte[] { 0xFF, 0xD4 };
            byte[] xorEax = new byte[] { 0x31, 0xC0 };
            byte[] xorEbx = new byte[] { 0x31, 0xD8 };
            byte[] xorEcx = new byte[] { 0x31, 0xC9 };
            byte[] xorEdx = new byte[] { 0x31, 0xD2 };
            byte[] xorEsi = new byte[] { 0x31, 0xF6 };
            byte[] xorEdi = new byte[] { 0x31, 0xFF };
            byte[] add = new byte[] { 0x03 };
            byte[] sub = new byte[] { 0x2B };
            byte[] mov = new byte[] { 0x8B };

            opcodes32.Add(pushEax);
            opcodes32.Add(pushEbx);
            opcodes32.Add(pushEcx);
            opcodes32.Add(pushEdx);
            opcodes32.Add(pushEsp);
            opcodes32.Add(pushEbp);
            opcodes32.Add(pushEsi);
            opcodes32.Add(pushEdi);
            opcodes32.Add(popEax);
            opcodes32.Add(popEbx);
            opcodes32.Add(popEcx);
            opcodes32.Add(popEdx);
            opcodes32.Add(popEsp);
            opcodes32.Add(popEbp);
            opcodes32.Add(popEsi);
            opcodes32.Add(popEdi);
            opcodes32.Add(pushad);
            opcodes32.Add(incEax);
            opcodes32.Add(incEbx);
            opcodes32.Add(incEcx);
            opcodes32.Add(incEdx);
            opcodes32.Add(incEbp);
            opcodes32.Add(incEsp);
            opcodes32.Add(incEsi);
            opcodes32.Add(incEdi);
            opcodes32.Add(decEax);
            opcodes32.Add(decEbx);
            opcodes32.Add(decEcx);
            opcodes32.Add(decEdx);
            opcodes32.Add(decEbp);
            opcodes32.Add(decEsp);
            opcodes32.Add(decEsi);
            opcodes32.Add(decEdi);
            opcodes32.Add(jmpEsp);
            opcodes32.Add(callEsp);
            opcodes32.Add(xorEax);
            opcodes32.Add(xorEbx);
            opcodes32.Add(xorEcx);
            opcodes32.Add(xorEdx);
            opcodes32.Add(xorEsi);
            opcodes32.Add(xorEdi);
            opcodes32.Add(add);
            opcodes32.Add(sub);
            opcodes32.Add(mov);
        }
        #endregion

        public ErcResult<string> GenerateRopChain32(IntPtr startAddress, int size, List<string> excludes = null)
        {
            ErcResult<string> RopChain = new ErcResult<string>(info.ProcessCore);
            x86Opcodes = new X86Lists();

            Console.WriteLine("Starting GetApiAddresses...");////////////////////////delete
            var watch = System.Diagnostics.Stopwatch.StartNew();////////////////////////delete

            var ret1 = GetApiAddresses(info);
            if (ret1.Error != null && ApiAddresses.Count <= 0)
            {
                ErcResult<string> failed = new ErcResult<string>(info.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
                return failed;
            }
            watch.Stop();////////////////////////delete
            foreach (KeyValuePair<string, IntPtr> k in ApiAddresses)////////////////////////delete
            {////////////////////////delete
                Console.WriteLine("Fucntion: 0x{0} Address: {1}", k.Key, k.Value.ToString("X"));////////////////////////delete
            }////////////////////////delete
            Console.WriteLine("Finishing GetApiAddresses at {0}", watch.Elapsed);////////////////////////delete

            Console.WriteLine("Starting GetRopNops...");////////////////////////delete

            watch = Stopwatch.StartNew();////////////////////////delete
            var ret2 = GetRopNops(info, excludes);
            if (ret1.Error != null && RopNops.Count <= 0)
            {
                Console.WriteLine("An Error has occured: ", ret2.Error);////////////////////////delete
                ErcResult<string> failed = new ErcResult<string>(info.ProcessCore);
                failed.ReturnValue = "An error has occured, check log file for more details.";
                failed.Error = ret1.Error;
                return failed;
            }
            watch.Stop();////////////////////////delete
            Console.WriteLine("Finishing GetRopNops at {0}", watch.Elapsed);////////////////////////delete

            Console.WriteLine("Starting PopulateOpcodes...");////////////////////////delete
            watch = Stopwatch.StartNew();////////////////////////delete
            var ret3 = PopulateOpcodes(info);
            watch.Stop();////////////////////////delete
            Console.WriteLine("Finishing PopulateOpcodes at {0}", watch.Elapsed);////////////////////////delete
            optimiseLists(info);
            
            Console.WriteLine("Starting to build VirtualAlloc32 RopChain...");////////////////////////delete
            watch = Stopwatch.StartNew();////////////////////////delete
            var chain = GenerateVirtualAllocChain32(info, startAddress, size);
            if(chain.Error == null)
            {
                VirtualAllocChain = chain.ReturnValue;
            }
            watch.Stop();////////////////////////delete
            Console.WriteLine("Finished building VirtualAlloc32 RopChain at {0}", watch.Elapsed);////////////////////////delete
            Console.WriteLine("VirtualAllocROP.Count = {0}", VirtualAllocChain.Count);
            DisplayOutput.RopChainGadgets(this, info);
            return RopChain;
        }

        #region GetApiAddresses
        private ErcResult<int> GetApiAddresses(ProcessInfo info)
        {
            ErcResult<int> returnVar = new ErcResult<int>(info.ProcessCore);
            returnVar.ReturnValue = 0;

            IntPtr hModule = IntPtr.Zero;
            for (int i = 0; i < info.ModulesInfo.Count; i++)
            {
                if (info.ModulesInfo[i].ModuleName == "kernel32")
                {
                    hModule = info.ModulesInfo[i].ModuleBase;
                }
            }

            if (info.ProcessMachineType == MachineType.I386 && Environment.Is64BitOperatingSystem)
            {
                ApiAddresses.Add("VirtualAlloc", hModule + 0x166B0);
                ApiAddresses.Add("HeapCreate", hModule + 0x154F0);
                ApiAddresses.Add("VirtualProtect", hModule + 0x16770);
                ApiAddresses.Add("WriteProcessMemory", hModule + 0x168B0);
                return returnVar;
            }

            var virtAllocAddress = ErcCore.GetProcAddress(hModule, "VirtualAlloc");
            if (virtAllocAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("VirtualAlloc", virtAllocAddress);
            }

            var HeapCreateAddress = ErcCore.GetProcAddress(hModule, "HeapCreate");
            if (HeapCreateAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("HeapCreate", HeapCreateAddress);
            }

            var VirtualProtectAddress = ErcCore.GetProcAddress(hModule, "VirtualProtect");
            if (VirtualProtectAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("VirtualProtect", VirtualProtectAddress);
            }

            var WriteProcessMemoryAddress = ErcCore.GetProcAddress(hModule, "WriteProcessMemory");
            if (WriteProcessMemoryAddress == IntPtr.Zero)
            {
                returnVar.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                returnVar.LogEvent();
            }
            else
            {
                ApiAddresses.Add("WriteProcessMemory", WriteProcessMemoryAddress);
            }

            return returnVar;
        }
        #endregion

        #region GetRopNops
        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(info.ProcessCore);
            ropNopsResult.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchMemory(0, ropNop, excludes: excludes);
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

        private ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info)
        {
            ErcResult<List<IntPtr>> ropNopsResult = new ErcResult<List<IntPtr>>(info.ProcessCore);
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
            ErcResult<int> ret = new ErcResult<int>(info.ProcessCore);

            for (int i = 0; i < RopNops.Count; i++)
            {
                byte[] bytes = new byte[20];
                IntPtr baseAddress = RopNops[i] - 19;
                ErcCore.ReadProcessMemory(info.ProcessHandle, baseAddress, bytes, 20, out int bytesRead);
                if (bytesRead != 20)
                {
                    ret.Error = new ERCException("ReadProcessMemory Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    ret.LogEvent();
                }
                var ret1 = ParseByteArrayForRopCodes(bytes, info, baseAddress);
                if (ret1.Error != null)
                {
                    ret.Error = ret1.Error;
                    return ret;
                }
            }
            return ret;
        }
        #endregion

        #region ParseByteArrayForRopCodes
        private ErcResult<int> ParseByteArrayForRopCodes(byte[] bytes, ProcessInfo info, IntPtr baseAddress)
        {
            ErcResult<int> ret = new ErcResult<int>(info.ProcessCore);
            bool pushEaxDone = false;
            bool pushEbxDone = false;
            bool pushEcxDone = false;
            bool pushEdxDone = false;
            bool pushEspDone = false;
            bool pushEbpDone = false;
            bool pushEsiDone = false;
            bool pushEdiDone = false;
            bool jmpEspDone = false;
            bool callEspDone = false;
            bool xorEaxDone = false;
            bool xorEbxDone = false;
            bool xorEcxDone = false;
            bool xorEdxDone = false;
            bool xorEsiDone = false;
            bool xorEdiDone = false;
            bool popEaxDone = false;
            bool popEbxDone = false;
            bool popEcxDone = false;
            bool popEdxDone = false;
            bool popEspDone = false;
            bool popEbpDone = false;
            bool popEsiDone = false;
            bool popEdiDone = false;
            bool pushadDone = false;
            bool incEaxDone = false;
            bool incEbxDone = false;
            bool incEcxDone = false;
            bool incEdxDone = false;
            bool incEbpDone = false;
            bool incEspDone = false;
            bool incEsiDone = false;
            bool incEdiDone = false;
            bool decEaxDone = false;
            bool decEbxDone = false;
            bool decEcxDone = false;
            bool decEdxDone = false;
            bool decEbpDone = false;
            bool decEspDone = false;
            bool decEsiDone = false;
            bool decEdiDone = false;
            bool addDone = false;
            bool subDone = false;
            bool movDone = false;
            
            for (int i = bytes.Length - 1; i > 0; i--)
            {
                for (int j = 0; j < opcodes32.Count; j++)
                {
                    if (bytes[i] == opcodes32[j][0] && opcodes32[j].Length == 1)
                    {
                        byte[] opcodes = new byte[bytes.Length - i];
                        switch (j)
                        {
                            case 0:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEax.ContainsKey(baseAddress + i) && pushEaxDone == false)
                                {
                                    pushadDone = true;
                                    x86Opcodes.pushEax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 1:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEbx.ContainsKey(baseAddress + i) && pushEbxDone == false)
                                {
                                    pushEbxDone = true;
                                    x86Opcodes.pushEbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 2:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEcx.ContainsKey(baseAddress + i) && pushEcxDone == false)
                                {
                                    pushEcxDone = true;
                                    x86Opcodes.pushEcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 3:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEdx.ContainsKey(baseAddress + i) && pushEdxDone == false)
                                {
                                    pushEdxDone = true;
                                    x86Opcodes.pushEdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 4:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEsp.ContainsKey(baseAddress + i) && pushEspDone == false)
                                {
                                    pushEspDone = true;
                                    x86Opcodes.pushEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 5:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEbp.ContainsKey(baseAddress + i) && pushEbpDone == false)
                                {
                                    pushEbpDone = true;
                                    x86Opcodes.pushEbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 6:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEsi.ContainsKey(baseAddress + i) && pushEsiDone == false)
                                {
                                    pushEsiDone = true;
                                    x86Opcodes.pushEsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 7:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushEdi.ContainsKey(baseAddress + i) && pushEdiDone == false)
                                {
                                    pushEdiDone = true;
                                    x86Opcodes.pushEdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 8:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEax.ContainsKey(baseAddress + i) && popEaxDone == false)
                                {
                                    popEaxDone = true;
                                    x86Opcodes.popEax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 9:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEbx.ContainsKey(baseAddress + i) && popEbxDone == false)
                                {
                                    popEbxDone = true;
                                    x86Opcodes.popEbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 10:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEcx.ContainsKey(baseAddress + i) && popEcxDone == false)
                                {
                                    popEcxDone = true;
                                    x86Opcodes.popEcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 11:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEdx.ContainsKey(baseAddress + i) && popEdxDone == false)
                                {
                                    popEdxDone = true;
                                    x86Opcodes.popEdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 12:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEsp.ContainsKey(baseAddress + i) && popEspDone == false)
                                {
                                    popEspDone = true;
                                    x86Opcodes.popEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 13:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEbp.ContainsKey(baseAddress + i) && popEbpDone == false)
                                {
                                    popEbpDone = true;
                                    x86Opcodes.popEbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 14:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEsi.ContainsKey(baseAddress + i) && popEsiDone == false)
                                {
                                    popEsiDone = true;
                                    x86Opcodes.popEsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 15:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.popEdi.ContainsKey(baseAddress + i) && popEdiDone == false)
                                {
                                    popEdiDone = true;
                                    x86Opcodes.popEdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 16:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.pushad.ContainsKey(baseAddress + i) && pushadDone == false)
                                {
                                    pushadDone = true;
                                    x86Opcodes.pushad.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 17:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEax.ContainsKey(baseAddress + i) && incEaxDone == false)
                                {
                                    incEaxDone = true;
                                    x86Opcodes.incEax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 18:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEbx.ContainsKey(baseAddress + i) && incEbxDone == false)
                                {
                                    incEbxDone = true;
                                    x86Opcodes.incEbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 19:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEcx.ContainsKey(baseAddress + i) && incEcxDone == false)
                                {
                                    incEcxDone = true;
                                    x86Opcodes.incEcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 20:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEdx.ContainsKey(baseAddress + i) && incEdxDone == false)
                                {
                                    incEdxDone = true;
                                    x86Opcodes.incEdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 21:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEbp.ContainsKey(baseAddress + i) && incEbpDone == false)
                                {
                                    incEbpDone = true;
                                    x86Opcodes.incEbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 22:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEsp.ContainsKey(baseAddress + i) && incEspDone == false)
                                {
                                    incEspDone = true;
                                    x86Opcodes.incEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 23:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEsi.ContainsKey(baseAddress + i) && incEsiDone == false)
                                {
                                    incEsiDone = true;
                                    x86Opcodes.incEsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 24:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.incEdi.ContainsKey(baseAddress + i) && incEdiDone == false)
                                {
                                    incEdiDone = true;
                                    x86Opcodes.incEdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 25:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEax.ContainsKey(baseAddress + i) && decEaxDone == false)
                                {
                                    decEaxDone = true;
                                    x86Opcodes.decEax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 26:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEbx.ContainsKey(baseAddress + i) && decEbxDone == false)
                                {
                                    decEbxDone = true;
                                    x86Opcodes.decEbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 27:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEcx.ContainsKey(baseAddress + i) && decEcxDone == false)
                                {
                                    decEcxDone = true;
                                    x86Opcodes.decEcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 28:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEdx.ContainsKey(baseAddress + i) && decEdxDone == false)
                                {
                                    decEdxDone = true;
                                    x86Opcodes.decEdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 29:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEbp.ContainsKey(baseAddress + i) && decEbpDone == false)
                                {
                                    decEbpDone = true;
                                    x86Opcodes.decEbp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 30:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEsp.ContainsKey(baseAddress + i) && decEspDone == false)
                                {
                                    decEspDone = true;
                                    x86Opcodes.decEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 31:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEsi.ContainsKey(baseAddress + i) && decEsiDone == false)
                                {
                                    decEsiDone = true;
                                    x86Opcodes.decEsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 32:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.decEdi.ContainsKey(baseAddress + i) && decEdiDone == false)
                                {
                                    decEdiDone = true;
                                    x86Opcodes.decEdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 41:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.add.ContainsKey(baseAddress + i) && addDone == false)
                                {
                                    addDone = true;
                                    x86Opcodes.add.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 42:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.sub.ContainsKey(baseAddress + i) && subDone == false)
                                {
                                    subDone = true;
                                    x86Opcodes.sub.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            case 43:
                                Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                if (!x86Opcodes.mov.ContainsKey(baseAddress + i) && movDone == false)
                                {
                                    movDone = true;
                                    x86Opcodes.mov.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                }
                                break;
                            default:
                                throw new ERCException("An error has occured in RopChainGenerator.ParseByteArrayForRopCodes whilst parsing single length x86 instructions");

                        }
                    }
                    else if (opcodes32[j].Length > 1)
                    {
                        if (bytes[i] == opcodes32[j][0] && i < bytes.Length - 1 && j < opcodes32.Count + 1 && bytes[i + 1] == opcodes32[j][1])
                        {
                            byte[] opcodes = new byte[bytes.Length - i];
                            switch (j)
                            {
                                case 33:
                                    opcodes = new byte[2];
                                    Array.Copy(bytes, i, opcodes, 0, 2);
                                    if (!x86Opcodes.jmpEsp.ContainsKey(baseAddress + i) && jmpEspDone == false)
                                    {
                                        jmpEspDone = true;
                                        x86Opcodes.jmpEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 34:
                                    opcodes = new byte[2];
                                    Array.Copy(bytes, i, opcodes, 0, 2);
                                    if (!x86Opcodes.callEsp.ContainsKey(baseAddress + i) && callEspDone == false)
                                    {
                                        callEspDone = true;
                                        x86Opcodes.callEsp.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 35:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEax.ContainsKey(baseAddress + i) && xorEaxDone == false)
                                    {
                                        xorEaxDone = true;
                                        x86Opcodes.xorEax.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 36:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEbx.ContainsKey(baseAddress + i) && xorEbxDone == false)
                                    {
                                        xorEbxDone = true;
                                        x86Opcodes.xorEbx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 37:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEcx.ContainsKey(baseAddress + i) && xorEcxDone == false)
                                    {
                                        xorEcxDone = true;
                                        x86Opcodes.xorEcx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 38:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEdx.ContainsKey(baseAddress + i) && xorEdxDone == false)
                                    {
                                        xorEdxDone = true;
                                        x86Opcodes.xorEdx.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 39:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEsi.ContainsKey(baseAddress + i) && xorEsiDone == false)
                                    {
                                        xorEsiDone = true;
                                        x86Opcodes.xorEsi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                case 40:
                                    Array.Copy(bytes, i, opcodes, 0, bytes.Length - i);
                                    if (!x86Opcodes.xorEdi.ContainsKey(baseAddress + i) && xorEdiDone == false)
                                    {
                                        xorEdiDone = true;
                                        x86Opcodes.xorEdi.Add(baseAddress + i, OpcodeDisassembler.Disassemble(opcodes, MachineType.I386).ReturnValue.Replace(Environment.NewLine, ", "));
                                    }
                                    break;
                                default:
                                    throw new ERCException("An error has occured in RopChainGenerator.ParseByteArrayForRopCodes whilst parsing double length x86 instructions");

                            }
                        }
                    }
                }
            }
            return ret;
        }
        #endregion

        #region Optimse Lists
        private void optimiseLists(ProcessInfo info)
        {
            usableX86Opcodes = new X86Lists();
            var thisList = x86Opcodes.pushEax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push eax") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push ebx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push ecx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push edx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push esp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push ebp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push esi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushEdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("push edi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushEdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.jmpEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("jmp esp"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.jmpEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.callEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("call esp"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.callEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor eax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor ebx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor ecx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor edx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor esi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.xorEdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("xor edi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.xorEdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop eax") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop ebx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop ecx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop edx") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop esp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop ebp") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop esi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.popEdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pop edi") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.popEdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.pushad.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("pushad") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.pushad.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc eax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc ebx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc ecx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc edx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc ebp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc esp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc esi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.incEdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("inc edi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.incEdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEax.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec eax") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEax.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEbx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec ebx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEbx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEcx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec ecx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEcx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEdx.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec edx") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEdx.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEbp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec ebp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEbp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEsp.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec esp") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEsp.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEsi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec esi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEsi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.decEdi.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("dec edi") || !thisList[i].Value.Contains("ret"))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.decEdi.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.add.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("add") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.add.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.sub.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("sub") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.sub.Add(thisList[i].Key, thisList[i].Value);
                }
            }
            thisList = x86Opcodes.mov.ToList();
            thisList.Sort((x, y) => x.Value.Length.CompareTo(y.Value.Length));
            for (int i = 0; i < thisList.Count; i++)
            {
                if (!thisList[i].Value.Contains("mov") || !thisList[i].Value.Contains("ret") || thisList[i].Value.Any(char.IsDigit))
                {
                    thisList.RemoveAt(i);
                }
                else
                {
                    usableX86Opcodes.mov.Add(thisList[i].Key, thisList[i].Value);
                }
            }
        }
        #endregion

        #region GenerateVirtualAllocChain32
        private ErcResult<List<Tuple<byte[], string>>> GenerateVirtualAllocChain32(ProcessInfo info, IntPtr startAddress, int size)
        {
            /////////////////////////////////////////////////////////////////
            /// VirtualAlloc Template:                                     //
            /// EAX: 90909090 -> Nop sled                                  //
            /// ECX: 00000040 -> flProtect                                 //
            /// EDX: 00001000 -> flAllocationType                          //
            /// EBX: ???????? -> Int size (area to be set as executable)   //
            /// ESP: ???????? -> No Change                                 //
            /// EBP: ???????? -> Jmp Esp / Call Esp                        //
            /// ESI: ???????? -> ApiAddresses["VirtualAlloc"]              //
            /// EDI: ???????? -> RopNop                                    //
            /////////////////////////////////////////////////////////////////

            ErcResult<List<Tuple<byte[], string>>> VirtualAlloc = new ErcResult<List<Tuple<byte[], string>>>(info.ProcessCore);
            VirtualAlloc.ReturnValue = new List<Tuple<byte[], string>>();
            regState32 = new Registers32();
            regModified32 = new RegisterModifiers32();

            foreach (Registers32 i in Enum.GetValues(typeof(Registers32)))
            {
                SetRegisterModifier(Registers32.ESP, i);
                SetRegisterModifier(i, Registers32.ESP);
            }

            RegisterLists32 regLists32 = new RegisterLists32();

            while (!CompleteRegisters32(regState32))
            {
                #region Populate EDI
                if (!regState32.HasFlag(Registers32.EDI))
                {
                    regLists32.ediList = null;
                    regLists32.ediList = new List<Tuple<byte[], string>>();
                    for (int i = 0; i < usableX86Opcodes.popEdi.Count; i++)
                    {
                        if (!regState32.HasFlag(Registers32.EDI))
                        {
                            if (usableX86Opcodes.popEdi.ElementAt(i).Value.Length <= 14 && !usableX86Opcodes.popEdi.ElementAt(i).Value.Contains("invalid"))
                            {
                                regLists32.ediList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.popEdi.ElementAt(i).Key)),
                                    usableX86Opcodes.popEdi.ElementAt(i).Value));
                                regLists32.ediList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)RopNops[0])), "ROP NOP"));
                                regState32 |= Registers32.EDI;
                            }
                        }
                        else
                        {
                            i = usableX86Opcodes.popEdi.Count;
                        }
                    }
                    foreach (Registers32 i in Enum.GetValues(typeof(Registers32)))
                    {
                        if (!regState32.HasFlag(Registers32.EDI))
                        {
                            var popInstruction = GetPopInstruction(Registers32.EDI, i);
                            if (popInstruction != null)
                            {
                                var movInstruction = GetMovInstruction(Registers32.EDI, i);
                                if (movInstruction != null)
                                {
                                    regLists32.ediList.Add(Tuple.Create(X64toX32PointerModifier(popInstruction.Item1), popInstruction.Item2));
                                    regLists32.ediList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)RopNops[0])), "ROP NOP"));
                                    regLists32.ediList.Add(Tuple.Create(X64toX32PointerModifier(movInstruction.Item1), movInstruction.Item2));
                                    SetRegisterModifier(Registers32.EDI, i);
                                    regState32 &= ~i;
                                    regState32 |= Registers32.EDI;
                                }
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    if (!regState32.HasFlag(Registers32.EDI))
                    {
                        byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                        VirtualAlloc.ReturnValue.Add(Tuple.Create(nullBytes,
                            "Unable to find appropriate instruction. EDI must be allocated manually"));
                        regState32 |= Registers32.EDI;
                    }
                }
                #endregion

                #region Populate ESI
                if (!regState32.HasFlag(Registers32.ESI))
                {
                    regLists32.esiList = null;
                    regLists32.esiList = new List<Tuple<byte[], string>>();
                    for (int i = 0; i < usableX86Opcodes.popEsi.Count; i++)
                    {
                        if (!regState32.HasFlag(Registers32.ESI))
                        {
                            if (usableX86Opcodes.popEsi.ElementAt(i).Value.Length <= 14 && !usableX86Opcodes.popEsi.ElementAt(i).Value.Contains("invalid"))
                            {
                                regLists32.esiList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.popEsi.ElementAt(i).Key)),
                                    usableX86Opcodes.popEsi.ElementAt(i).Value));
                                regLists32.esiList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)ApiAddresses["VirtualAlloc"])), "Pointer to VirtualAlloc."));
                                regState32 |= Registers32.ESI;
                            }
                        }
                        else
                        {
                            i = usableX86Opcodes.popEsi.Count;
                        }
                    }
                    if (!regState32.HasFlag(Registers32.ESI))
                    {
                        foreach (Registers32 i in Enum.GetValues(typeof(Registers32)))
                        {
                            if (!regState32.HasFlag(Registers32.ESI))
                            {
                                var popInstruction = GetPopInstruction(Registers32.ESI, i);
                                if (popInstruction != null)
                                {
                                    var movInstruction = GetMovInstruction(Registers32.ESI, i);
                                    if (movInstruction != null)
                                    {
                                        regLists32.esiList.Add(Tuple.Create(X64toX32PointerModifier(popInstruction.Item1), popInstruction.Item2));
                                        regLists32.esiList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)ApiAddresses["VirtualAlloc"])), "Pointer to VirtualAlloc."));
                                        regLists32.esiList.Add(Tuple.Create(X64toX32PointerModifier(movInstruction.Item1), movInstruction.Item2));
                                        SetRegisterModifier(Registers32.ESI, i);
                                        regState32 &= ~i;
                                        regState32 |= Registers32.ESI;
                                    }
                                }
                            }
                        }
                        if (!regState32.HasFlag(Registers32.ESI))
                        {
                            byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                            VirtualAlloc.ReturnValue.Add(Tuple.Create(nullBytes,
                                "Unable to find appropriate instruction. ESI must be allocated manually"));
                            regState32 |= Registers32.ESI;
                        }
                    }
                }
                #endregion

                #region Populate EBP
                if (!regState32.HasFlag(Registers32.EBP))
                {
                    regLists32.ebpList = null;
                    regLists32.ebpList = new List<Tuple<byte[], string>>();
                    for (int i = 0; i < usableX86Opcodes.popEbp.Count; i++)
                    {
                        if (!regState32.HasFlag(Registers32.EBP))
                        {
                            if (usableX86Opcodes.popEbp.ElementAt(i).Value.Length <= 14 && !usableX86Opcodes.popEbp.ElementAt(i).Value.Contains("invalid"))
                            {
                                regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.popEbp.ElementAt(i).Key)),
                                    usableX86Opcodes.popEbp.ElementAt(i).Value));
                                if (usableX86Opcodes.jmpEsp.Count > 0)
                                {
                                    regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.jmpEsp.ElementAt(0).Key)),
                                        usableX86Opcodes.jmpEsp.ElementAt(0).Value));
                                }
                                else
                                {
                                    regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.callEsp.ElementAt(0).Key)),
                                        usableX86Opcodes.callEsp.ElementAt(0).Value));
                                }
                                regState32 |= Registers32.EBP;
                            }
                        }
                        else
                        {
                            i = usableX86Opcodes.popEbp.Count;
                        }
                    }
                    if (!regState32.HasFlag(Registers32.EBP))
                    {
                        foreach (Registers32 i in Enum.GetValues(typeof(Registers32)))
                        {
                            if (!regState32.HasFlag(Registers32.EBP))
                            {
                                var popInstruction = GetPopInstruction(Registers32.EBP, i);
                                if (popInstruction != null)
                                {
                                    var movInstruction = GetMovInstruction(Registers32.EBP, i);
                                    if (movInstruction != null)
                                    {
                                        regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(popInstruction.Item1), popInstruction.Item2));
                                        if (usableX86Opcodes.jmpEsp.Count > 0)
                                        {
                                            regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.jmpEsp.ElementAt(0).Key)),
                                                usableX86Opcodes.jmpEsp.ElementAt(0).Value));
                                        }
                                        else
                                        {
                                            regLists32.ebpList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.callEsp.ElementAt(0).Key)),
                                                usableX86Opcodes.callEsp.ElementAt(0).Value));
                                        }
                                        regLists32.ebpList.Add(Tuple.Create(movInstruction.Item1, movInstruction.Item2));
                                        SetRegisterModifier(Registers32.EBP, i);
                                        regState32 &= ~i;
                                        regState32 |= Registers32.EBP;
                                    }
                                }
                            }
                        }
                        if (!regState32.HasFlag(Registers32.EBP))
                        {
                            byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                            VirtualAlloc.ReturnValue.Add(Tuple.Create(nullBytes,
                                "Unable to find appropriate instruction. EBP must be allocated manually"));
                            regState32 |= Registers32.EBP;
                        }
                    }
                }
                #endregion

                #region Populate EBX
                // Populate EBX
                if (!regState32.HasFlag(Registers32.EBX))
                {
                    regLists32.ebxList = null;
                    regLists32.ebxList = new List<Tuple<byte[], string>>();
                    //var zeroEbx = ZeroRegister(Registers32.EBX);
                    var xorEbx = GetXorInstruction(Registers32.EBX);
                    if (xorEbx != null)
                    {
                        regLists32.ebxList.Add(Tuple.Create(xorEbx.Item1, xorEbx.Item2));
                        if (usableX86Opcodes.incEbx.Count > 0)
                        {
                            if (usableX86Opcodes.incEbx.ElementAt(0).Value.Length <= 14)
                            {
                                regLists32.ebxList.Add(Tuple.Create(X64toX32PointerModifier(BitConverter.GetBytes((long)usableX86Opcodes.incEbx.ElementAt(0).Key)),
                                    usableX86Opcodes.incEbx.ElementAt(0).Value));
                                regState32 |= Registers32.EBX;
                            }
                        }
                        
                    }
                    if (!regState32.HasFlag(Registers32.EBX))
                    {
                        var zeroEbx = ZeroRegister(Registers32.EBX);
                        if (zeroEbx != null && usableX86Opcodes.incEbx.Count > 0 && usableX86Opcodes.incEbx.ElementAt(0).Value.Length <= 14)
                        {
                            for (int i = 0; i < zeroEbx.Count; i++)
                            {
                                regLists32.ebxList.Add(Tuple.Create(X64toX32PointerModifier(zeroEbx[i].Item1), zeroEbx[i].Item2));
                            }
                            regLists32.ebxList.Add(Tuple.Create(X64toX32PointerModifier(
                                BitConverter.GetBytes((long)usableX86Opcodes.incEbx.ElementAt(0).Key)),
                                usableX86Opcodes.incEbx.ElementAt(0).Value));
                            SetRegisterModifier(Registers32.EBX, zeroEbx[0].Item3);
                            regState32 &= ~zeroEbx[0].Item3;
                            regState32 |= Registers32.EBX;
                        }
                    }
                    if (!regState32.HasFlag(Registers32.EBX))
                    {
                        foreach (Registers32 i in Enum.GetValues(typeof(Registers32)))
                        {
                            var popInstruction = GetPopInstruction(Registers32.EBP, i);
                            if (popInstruction != null)
                            {
                                for (int j = 0; j < x86Opcodes.add.Count; j++)
                                {
                                    if (!regState32.HasFlag(Registers32.EBX))
                                    {
                                        var strings = x86Opcodes.add.ElementAt(j).Value.Split(',');
                                        if (strings[0].Contains(" ebx") && strings[1].Contains(i.ToString().ToLower()))
                                        {
                                            regLists32.ebxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                            byte[] bytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };//......................................replace this with a more long term solution. Dynamically allocate size based on the size category in 
                                            regLists32.ebxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                            regLists32.ebxList.Add(Tuple.Create(BitConverter.GetBytes((long)x86Opcodes.add.ElementAt(j).Key),
                                                x86Opcodes.add.ElementAt(j).Value));
                                            regLists32.ebxList.Add(Tuple.Create(popInstruction.Item1, popInstruction.Item2));
                                            bytes = new byte[] { 0x01, 0x01, 0x10, 0x01 };//......................................replace this with a more long term solution. Dynamically allocate size based on the size category in 
                                            regLists32.ebxList.Add(Tuple.Create(bytes, "To be popped into " + i.ToString()));
                                            regLists32.ebxList.Add(Tuple.Create(BitConverter.GetBytes((long)x86Opcodes.add.ElementAt(j).Key),
                                            x86Opcodes.add.ElementAt(j).Value));
                                            SetRegisterModifier(Registers32.EBX, i);
                                            regState32 &= ~i;
                                            regState32 |= Registers32.EBX;
                                        }
                                    }
                                }
                            }
                        }
                    }    
                    
                }
                if (!regState32.HasFlag(Registers32.EBX))
                {
                    regLists32.ebxList = null;
                    regLists32.ebxList = new List<Tuple<byte[], string>>();
                    byte[] nullBytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
                    VirtualAlloc.ReturnValue.Add(Tuple.Create(nullBytes,
                        "Unable to find appropriate instruction. EBX must be allocated manually"));
                    regState32 |= Registers32.EBX;
                }
                regState32 |= Registers32.ESP;
                regState32 |= Registers32.EAX;
                regState32 |= Registers32.ECX;
                regState32 |= Registers32.EDX;
                Console.WriteLine("Before EBX");
                if (regState32.HasFlag(Registers32.EDI))
                    Console.WriteLine("regState.EDI == true");
                else
                    Console.WriteLine("regState.EDI == false");
                #endregion
            }

            VirtualAlloc.ReturnValue = BuildRopChain(regLists32, regModified32);
            Console.WriteLine("VirtualAllocChain.ReturnValue.Count = {0}", VirtualAlloc.ReturnValue.Count);
            return VirtualAlloc;
        }
        #endregion

        private ErcResult<Dictionary<byte[], string>> GenerateVirtualProtectChain32(ProcessInfo info)
        {
            ErcResult<Dictionary<byte[], string>> VirtualProtectChain = new ErcResult<Dictionary<byte[], string>>(info.ProcessCore);
            IntPtr VirtualProctect = ApiAddresses["VirtualProtect"];
            return VirtualProtectChain;
        }

        #region BuildRopChain
        private List<Tuple<byte[], string>> BuildRopChain(RegisterLists32 regLists32, RegisterModifiers32 regModified32)
        {
            Console.WriteLine("In EDI = {0}", regLists32.ediList.Count);
            Console.WriteLine("In EBP = {0}", regLists32.ebpList.Count);
            Console.WriteLine("In EBX = {0}", regLists32.ebxList.Count);
            Console.WriteLine("In ESI = {0}", regLists32.esiList.Count);
            List<Tuple<byte[], string>> ret = new List<Tuple<byte[], string>>();
            for (int i = 0; i < regLists32.ediList.Count; i++)
            {
                ret.Add(regLists32.ediList[i]);
            }
            for (int i = 0; i < regLists32.esiList.Count; i++)
            {
                ret.Add(regLists32.esiList[i]);
            }
            for (int i = 0; i < regLists32.ebpList.Count; i++)
            {
                ret.Add(regLists32.ebpList[i]);
            }
            for (int i = 0; i < regLists32.ebxList.Count; i++)
            {
                ret.Add(regLists32.ebxList[i]);
            }
            return ret;
        }
        #endregion

        #region CalculateAddInstructions32
        private List<byte[]> CalculateAddInstructions32(byte[] size)
        {
            return null;
        }
        #endregion

        #region X64toX32PointerModifier
        private byte[] X64toX32PointerModifier(byte[] ptr64)
        {
            byte[] ptr32 = new byte[4];
            Array.Copy(ptr64, 0, ptr32, 0, 4);
            return ptr32;
        }
        #endregion

        #region ZeroRegister
        /// <summary>
        /// Checks for a combination of instructions that can be used to zero out a register, this can be a xor instruction on itself or a xor instruction elsewhere
        /// followed by a move to the selected register. This function should be extended with further methods for zeroing a register at a later date.
        /// </summary>
        /// <param name="modifyingReg">The Register32 value for the register to be zeroed.</param>
        /// <returns>A dictionary(byte[], string) containing pointers to the instructions and the associated mnemonics</returns>
        private List<Tuple<byte[], string, Registers32>> ZeroRegister(Registers32 modifyingReg)
        {
            List<Tuple<byte[], string, Registers32>> instructions = new List<Tuple<byte[], string, Registers32>>();
            var xor = GetXorInstruction(modifyingReg);
            if (xor != null)
            {
                instructions.Add(xor);
                return instructions;
            }

            for (int i = 0; i < usableX86Opcodes.mov.Count; i++)
            {

                string[] gadgetElements = usableX86Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(modifyingReg.ToString().ToLower()))
                {
                    var reg = registerIdentifier32(gadgetElements[1]);
                    if (reg != Registers32.NONE && !GetRegisterModified(modifyingReg, reg))
                    {
                        var xorReg = GetXorInstruction(reg);
                        if (xorReg != null && !GetRegisterModified(modifyingReg, reg))
                        {
                            instructions.Add(xorReg);
                            instructions.Add(Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.mov.ElementAt(i).Key), 
                                usableX86Opcodes.mov.ElementAt(i).Value, reg));
                            return instructions;
                        }
                    }
                }
            }
            return null;
        }
        #endregion

        #region SetRegisterModifier 32 bit
        /// <summary>
        /// Sets the flag of a Register32 enum in a RegisterModifiers32 class. This flag is used to identify whether setting the value of one 
        /// register involved editing another register. For example if setting EAX involved modifying EBX then RegisterModifiers32.EAX will have the EBX flag set. Any
        /// register should not be able to modify the value of any other register twice.
        /// 
        /// The purpose of this is to stop an infitinte loop where each register modifies the other in order to achieve the correct value.
        /// </summary>
        /// <param name="modifiedReg">The Registers32 which is being modified</param>
        /// <param name="modifyingReg">The Registers32 which is doing the modification</param>
        private void SetRegisterModifier(Registers32 modifiedReg, Registers32 modifyingReg)
        {
            switch (modifiedReg)
            {
                case Registers32.EAX:
                    regModified32.EAX |= modifiedReg;
                    return;
                case Registers32.EBX:
                    regModified32.EBX |= modifiedReg;
                    return;
                case Registers32.ECX:
                    regModified32.ECX |= modifiedReg;
                    return;
                case Registers32.EDX:
                    regModified32.EDX |= modifiedReg;
                    return;
                case Registers32.EBP:
                    regModified32.EBP |= modifiedReg;
                    return;
                case Registers32.ESP:
                    regModified32.ESP |= modifiedReg;
                    return;
                case Registers32.ESI:
                    regModified32.ESI |= modifiedReg;
                    return;
                case Registers32.EDI:
                    regModified32.EDI |= modifiedReg;
                    return;
            }
        }
        #endregion

        #region GetRegisterModifier 32 bit
        /// <summary>
        /// Returns a boolean indicating whether one register has modified the value of another register attempting to set the correct value.
        /// </summary>
        /// <param name="modifiedReg">The Registers32 which is being modified</param>
        /// <param name="modifyingReg">The Registers32 which is doing the modification</param>
        /// <returns>A bool, true = register was modified by this register false = register was not modified by this register</returns>
        private bool GetRegisterModified(Registers32 modifyingReg, Registers32 modifiedReg)
        {
            Registers32 thisReg;
            bool modified = false;
            switch (modifyingReg)
            {
                case Registers32.EAX:
                    thisReg = regModified32.EAX;
                    break;
                case Registers32.EBX:
                    thisReg = regModified32.EBX;
                    break;
                case Registers32.ECX:
                    thisReg = regModified32.ECX;
                    break;
                case Registers32.EDX:
                    thisReg = regModified32.EDX;
                    break;
                case Registers32.EBP:
                    thisReg = regModified32.EBP;
                    break;
                case Registers32.ESP:
                    thisReg = regModified32.ESP;
                    break;
                case Registers32.ESI:
                    thisReg = regModified32.ESI;
                    break;
                case Registers32.EDI:
                    thisReg = regModified32.EDI;
                    break;
                default:
                    return true;
            }

            if (thisReg.HasFlag(modifiedReg))
            {
                modified = true;
            }
            return modified;
        }
        #endregion

        #region GetPopInstruction 32 bit
        private Tuple<byte[], string, Registers32> GetPopInstruction(Registers32 destReg, Registers32 srcReg)
        {
           switch(srcReg){
                case Registers32.EAX:
                    for (int i = 0; i < usableX86Opcodes.popEax.Count; i++)
                    {
                        if (usableX86Opcodes.popEax.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.EAX))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEax.ElementAt(i).Key), usableX86Opcodes.popEax.ElementAt(i).Value, Registers32.EAX);
                        }
                    }
                    break;
                case Registers32.EBX:
                    for (int i = 0; i < usableX86Opcodes.popEbx.Count; i++)
                    {
                        if (usableX86Opcodes.popEbx.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.EBX))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEbx.ElementAt(i).Key), usableX86Opcodes.popEbx.ElementAt(i).Value, Registers32.EBX);
                        }
                    }
                    break;
                case Registers32.ECX:
                    for (int i = 0; i < usableX86Opcodes.popEcx.Count; i++)
                    {
                        if (usableX86Opcodes.popEcx.ElementAt(i).Value.Length == 14 && !!GetRegisterModified(destReg, Registers32.ECX))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEcx.ElementAt(i).Key), usableX86Opcodes.popEcx.ElementAt(i).Value, Registers32.ECX);
                        }
                    }
                    break;
                case Registers32.EDX:
                    for (int i = 0; i < usableX86Opcodes.popEdx.Count; i++)
                    {
                        if (usableX86Opcodes.popEdx.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.EDX))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEdx.ElementAt(i).Key), usableX86Opcodes.popEdx.ElementAt(i).Value, Registers32.EDX);
                        }
                    }
                    break;
                case Registers32.EBP:
                    for (int i = 0; i < usableX86Opcodes.popEbp.Count; i++)
                    {
                        if (usableX86Opcodes.popEbp.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.EBP))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEbp.ElementAt(i).Key), usableX86Opcodes.popEbp.ElementAt(i).Value, Registers32.EBP);
                        }
                    }
                    break;
                case Registers32.ESP:
                    for (int i = 0; i < usableX86Opcodes.popEsp.Count; i++)
                    {
                        if (usableX86Opcodes.popEsp.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.ESP))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEsp.ElementAt(i).Key), usableX86Opcodes.popEsp.ElementAt(i).Value, Registers32.ESP);
                        }
                    }
                    break;
                case Registers32.ESI:
                    for (int i = 0; i < usableX86Opcodes.popEsi.Count; i++)
                    {
                        if (usableX86Opcodes.popEsi.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.ESI))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEsi.ElementAt(i).Key), usableX86Opcodes.popEsi.ElementAt(i).Value, Registers32.ESI);
                        }
                    }
                    break;
                case Registers32.EDI:
                    for (int i = 0; i < usableX86Opcodes.popEdi.Count; i++)
                    {
                        if (usableX86Opcodes.popEdi.ElementAt(i).Value.Length == 14 && !GetRegisterModified(destReg, Registers32.EDI))
                        {
                            return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.popEdi.ElementAt(i).Key), usableX86Opcodes.popEdi.ElementAt(i).Value, Registers32.EDI);
                        }
                    }
                    break;
                default:
                    return null;
            }
            return null;
        }
        #endregion

        #region getXorInstruction 32 bit
        private Tuple<byte[], string, Registers32> GetXorInstruction(Registers32 reg)
        {
            switch (reg)
            {
                case Registers32.EAX:
                    if (usableX86Opcodes.xorEax.Count > 0 && usableX86Opcodes.xorEax.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEax.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEax.ElementAt(0).Value, Registers32.EAX);
                    }
                    break;
                case Registers32.EBX:
                    if (usableX86Opcodes.xorEbx.Count > 0 && usableX86Opcodes.xorEbx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEbx.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEbx.ElementAt(0).Value, Registers32.EBX);
                    }
                    break;
                case Registers32.ECX:
                    if (usableX86Opcodes.xorEcx.Count > 0 && usableX86Opcodes.xorEcx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEcx.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEcx.ElementAt(0).Value, Registers32.ECX);
                    }
                    break;
                case Registers32.EDX:
                    if (usableX86Opcodes.xorEdx.Count > 0 && usableX86Opcodes.xorEdx.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEdx.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEdx.ElementAt(0).Value, Registers32.EDX);
                    }
                    break;
                case Registers32.ESI:
                    if (usableX86Opcodes.xorEsi.Count > 0 && usableX86Opcodes.xorEsi.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEsi.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEsi.ElementAt(0).Value, Registers32.ESI);
                    }
                    break;
                case Registers32.EDI:
                    if (usableX86Opcodes.xorEdi.Count > 0 && usableX86Opcodes.xorEdi.ElementAt(0).Value.Length <= 19)
                    {
                        byte[] gadget1 = BitConverter.GetBytes((long)usableX86Opcodes.xorEdi.ElementAt(0).Key);
                        return Tuple.Create(gadget1, usableX86Opcodes.xorEdi.ElementAt(0).Value, Registers32.EDI);
                    }
                    break;
                default:
                    break;
            }
            return null;
        }
        #endregion

        #region GetMovInstruction 32 bit
        /// <summary>
        /// Finds a mov instruction going from the src register to the destination register
        /// </summary>
        /// <param name="destReg">The destination register</param>
        /// <param name="srcReg">The source register</param>
        /// <returns>Returns a dictionary of byte[] string containing a pointer to the instruction and the associated mnemonics</returns>
        private Tuple<byte[], string, Registers32> GetMovInstruction(Registers32 destReg, Registers32 srcReg)
        {
            for (int i = 0; i < usableX86Opcodes.mov.Count; i++)
            {
                string[] gadgetElements = usableX86Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(destReg.ToString()))
                {
                    var reg = registerIdentifier32(gadgetElements[1]);
                    if (reg == srcReg)
                    {
                        return Tuple.Create(BitConverter.GetBytes((long)usableX86Opcodes.mov.ElementAt(i).Key), 
                            usableX86Opcodes.mov.ElementAt(i).Value, reg);
                    }
                }
            }
            return null;
        }
        #endregion

        #region registerIdentifier32
        private Registers32 registerIdentifier32(string reg)
        {
            switch (reg)
            {
                case " eax":
                    return Registers32.EAX;
                case " ebx":
                    return Registers32.EBX;
                case " ecx":
                    return Registers32.ECX;
                case " edx":
                    return Registers32.EDX;
                case " ebp":
                    return Registers32.EBP;
                case " esp":
                    return Registers32.ESP;
                case " esi":
                    return Registers32.ESI;
                case " edi":
                    return Registers32.EDI;
                default:
                    return Registers32.NONE;
            }
        }
        #endregion

        #region CompleteRegisters32
        /// <summary>
        /// Checks all values of a Registers32 enum and returns false if any of them are not set. 
        /// </summary>
        /// <param name="regState">The Registers32 object to be tested</param>
        /// <returns>A boolean value is returned</returns>
        private bool CompleteRegisters32(Registers32 regState)
        {
            bool complete = true;

            if (!regState32.HasFlag(Registers32.EAX))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.EBX))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.ECX))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.EDX))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.EBP))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.ESP))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.ESI))
            {
                return false;
            }
            if (!regState32.HasFlag(Registers32.EDI))
            {
                return false;
            }

            return complete;
        }
        #endregion

        #region Registers32
        private enum Registers32
        {
            NONE = 0,
            [Description(" eax")]
            EAX  = 1,
            [Description(" ebx")]
            EBX  = 2,
            [Description(" ecx")]
            ECX  = 4,
            [Description(" edx")]
            EDX  = 8,
            [Description(" ebp")]
            EBP  = 16,
            [Description(" esp")]
            ESP  = 32,
            [Description(" esi")]
            ESI  = 64,
            [Description(" edi")]
            EDI  = 128
        }
        #endregion

        #region Opcode List Holders
        public class X86Lists
        {
            public Dictionary<IntPtr, string> pushEax = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEbx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEcx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEdx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEbp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEsi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushEdi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> jmpEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> callEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEax = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEbx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEcx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEdx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEsi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> xorEdi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEax = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEbx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEcx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEdx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEbp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEsi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> popEdi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> pushad = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEax = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEbx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEcx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEdx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEbp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEsi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> incEdi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEax = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEbx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEcx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEdx = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEbp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEsp = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEsi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> decEdi = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> add = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> sub = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> mov = new Dictionary<IntPtr, string>();
        }
        #endregion

        private class RegisterModifiers32
        {
            public Registers32 EAX;
            public Registers32 EBX;
            public Registers32 ECX;
            public Registers32 EDX;
            public Registers32 EBP;
            public Registers32 ESP;
            public Registers32 ESI;
            public Registers32 EDI;
        }

        private class RegisterLists32
        {
            public List<Tuple<byte[], string>> eaxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> ebxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> ecxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> edxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> ebpList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> esiList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> ediList = new List<Tuple<byte[], string>>();
        }
    }
}
