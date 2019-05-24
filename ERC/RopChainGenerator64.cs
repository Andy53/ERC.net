using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ERC.Utilities
{
    class RopChainGenerator64
    {
        private const int MEM_COMMIT = 0x1000;

        public List<Tuple<byte[], string>> VirtualAllocChain = new List<Tuple<byte[], string>>();

        Dictionary<string, IntPtr> ApiAddresses = new Dictionary<string, IntPtr>();
        List<IntPtr> RopNops = new List<IntPtr>();
        List<byte[]> opcodes64 = new List<byte[]>();
        internal X64Lists x64Opcodes;
        internal X64Lists usableX64Opcodes;
        private ProcessInfo info;
        Registers64 regState64;
        RegisterModifiers64 regModified64;

        #region Constructor
        public RopChainGenerator64(ProcessInfo _info)
        {
            if (_info.ProcessMachineType == MachineType.x64)
            {
                x64Opcodes = new X64Lists();
            }
            else
            {
                throw new ArgumentException("Fatal Error: This is not a 64bit process.");
            }

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

        public string GenerateRopChain64(ProcessInfo info, List<string> excludes = null)
        {
            return "";
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

        private ErcResult<int> ParseByteArrayForRopCodes(byte[] bytes, ProcessInfo info, IntPtr baseAddress)
        {
            return null;
        }

        private void optimiseLists(ProcessInfo info)
        {

        }

        private ErcResult<List<Tuple<byte[], string>>> GenerateVirtualAllocChain32(ProcessInfo info, IntPtr startAddress, int size)
        {
            return null;
        }

        private List<Tuple<byte[], string>> BuildRopChain(RegisterLists64 regLists64, RegisterModifiers64 regModified32)
        {
            return null;
        }

        #region CalculateAddInstructions64
        private List<byte[]> CalculateAddInstructions64(byte[] size)
        {
            return null;
        }
        #endregion region

        #region ZeroRegister
        /// <summary>
        /// Checks for a combination of instructions that can be used to zero out a register, this can be a xor instruction on itself or a xor instruction elsewhere
        /// followed by a move to the selected register. This function should be extended with further methods for zeroing a register at a later date.
        /// </summary>
        /// <param name="modifyingReg">The Register32 value for the register to be zeroed.</param>
        /// <returns>A dictionary(byte[], string) containing pointers to the instructions and the associated mnemonics</returns>
        private List<Tuple<byte[], string, Registers64>> ZeroRegister(Registers64 modifyingReg)
        {
            List<Tuple<byte[], string, Registers64>> instructions = new List<Tuple<byte[], string, Registers64>>();
            var xor = GetXorInstruction(modifyingReg);
            if (xor != null)
            {
                instructions.Add(xor);
                return instructions;
            }

            for (int i = 0; i < usableX64Opcodes.mov.Count; i++)
            {

                string[] gadgetElements = usableX64Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(modifyingReg.ToString().ToLower()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg != Registers64.NONE && !GetRegisterModified(modifyingReg, reg))
                    {
                        var xorReg = GetXorInstruction(reg);
                        if (xorReg != null && !GetRegisterModified(modifyingReg, reg))
                        {
                            instructions.Add(xorReg);
                            instructions.Add(Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.mov.ElementAt(i).Key),
                                usableX64Opcodes.mov.ElementAt(i).Value, reg));
                            return instructions;
                        }
                    }
                }
            }
            return null;
        }
        #endregion

        #region SetRegisterModifier 64 bit
        private void SetRegisterModifier(Registers64 modifiedReg, Registers64 modifyingReg)
        {

        }
        #endregion

        #region GetRegisterModifier 64 bit
        private bool GetRegisterModified(Registers64 modifiedReg, Registers64 modifyingReg)
        {
            bool modified = false;
            return modified;
        }
        #endregion

        #region GetPopInstruction 64 bit
        private Tuple<byte[], string, Registers64> GetPopInstruction(Registers64 srcReg)
        {
            return null;
        }
        #endregion

        #region getXorInstruction 64 bit
        private Tuple<byte[], string, Registers64> GetXorInstruction(Registers64 reg)
        {
            return null;
        }
        #endregion

        #region GetMovInstruction 64 bit
        /// <summary>
        /// Finds a mov instruction going from the src register to the destination register
        /// </summary>
        /// <param name="destReg">The destination register</param>
        /// <param name="srcReg">The source register</param>
        /// <returns>Returns a dictionary of byte[] string containing a pointer to the instruction and the associated mnemonics</returns>
        private Tuple<byte[], string, Registers64> GetMovInstruction(Registers64 destReg, Registers64 srcReg)
        {
            for (int i = 0; i < usableX64Opcodes.mov.Count; i++)
            {
                string[] gadgetElements = usableX64Opcodes.mov.ElementAt(i).Value.Split(',');
                if (gadgetElements[0].Contains(destReg.ToString()))
                {
                    var reg = registerIdentifier64(gadgetElements[1]);
                    if (reg == srcReg)
                    {
                        return Tuple.Create(BitConverter.GetBytes((long)usableX64Opcodes.mov.ElementAt(i).Key), usableX64Opcodes.mov.ElementAt(i).Value, reg);
                    }
                }
            }
            return null;
        }
        #endregion

        #region registerIdentifier64
        private Registers64 registerIdentifier64(string reg)
        {
            switch (reg)
            {
                case " rax":
                    return Registers64.RAX;
                case " rbx":
                    return Registers64.RBX;
                case " rcx":
                    return Registers64.RCX;
                case " rdx":
                    return Registers64.RDX;
                case " rbp":
                    return Registers64.RBP;
                case " rsp":
                    return Registers64.RSP;
                case " rsi":
                    return Registers64.RSI;
                case " rdi":
                    return Registers64.RDI;
                case " r8":
                    return Registers64.R8;
                case " r9":
                    return Registers64.R9;
                case " r10":
                    return Registers64.R10;
                case " r11":
                    return Registers64.R11;
                case " r12":
                    return Registers64.R12;
                case " r13":
                    return Registers64.R13;
                case " r14":
                    return Registers64.R14;
                case " r15":
                    return Registers64.R15;
                default:
                    return Registers64.NONE;
            }
        }
        #endregion

        #region CompleteRegisters64
        private bool CompleteRegisters64(Registers64 regState)
        {
            bool complete = true;

            if (!regState64.HasFlag(Registers64.RAX))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RBX))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RCX))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RDX))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RBP))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RSP))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RSI))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.RDI))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R8))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R9))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R10))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R11))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R12))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R13))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R14))
            {
                return false;
            }
            if (!regState64.HasFlag(Registers64.R15))
            {
                return false;
            }

            return complete;
        }
        #endregion

        #region Registers64
        private enum Registers64
        {
            NONE = 0,
            [Description(" rax")]
            RAX = 1,
            [Description(" rbx")]
            RBX = 2,
            [Description(" rcx")]
            RCX = 4,
            [Description(" rdx")]
            RDX = 8,
            [Description(" rbp")]
            RBP = 16,
            [Description(" rsp")]
            RSP = 32,
            [Description(" rsi")]
            RSI = 64,
            [Description(" rdi")]
            RDI = 128,
            [Description(" r8")]
            R8 = 256,
            [Description(" r9")]
            R9 = 512,
            [Description(" r10")]
            R10 = 1024,
            [Description(" r11")]
            R11 = 2048,
            [Description(" r12")]
            R12 = 4096,
            [Description(" r13")]
            R13 = 8192,
            [Description(" r14")]
            R14 = 16384,
            [Description(" r15")]
            R15 = 32768
        }
        #endregion

        private class RegisterModifiers64
        {
            public Registers64 RAX;
            public Registers64 RBX;
            public Registers64 RCX;
            public Registers64 RDX;
            public Registers64 RBP;
            public Registers64 RSP;
            public Registers64 RSI;
            public Registers64 RDI;
            public Registers64 R8;
            public Registers64 R9;
            public Registers64 R10;
            public Registers64 R11;
            public Registers64 R12;
            public Registers64 R13;
            public Registers64 R14;
            public Registers64 R15;
        }

        public class X64Lists
        {
            public Dictionary<IntPtr, string> add = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> sub = new Dictionary<IntPtr, string>();
            public Dictionary<IntPtr, string> mov = new Dictionary<IntPtr, string>();
        }

        private class RegisterLists64
        {
            public List<Tuple<byte[], string>> RaxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RbxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RcxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RdxList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RbpList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RsiList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> RdiList = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R8List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R9List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R10List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R11List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R12List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R13List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R14List = new List<Tuple<byte[], string>>();
            public List<Tuple<byte[], string>> R15List = new List<Tuple<byte[], string>>();
        }
    }
}
