using System;
using System.Linq;

namespace ERC.Utilities
{
    public class Opcode_Disassembler : Process_Info
    {
        public Opcode_Disassembler(Process_Info parent) : base(parent)
        {

        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions. Takes a byte array containing opcodes and returns an ERC_Result containing
        /// associated instructions.
        /// </summary>
        /// <param name="opcodes"></param>
        /// <returns></returns>
        public ERC_Result<string> Disassemble(byte[] opcodes)
        {
            ERC_Result<string> result = new ERC_Result<string>(Process_Core);
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            SharpDisasm.Disassembler disasm;
            SharpDisasm.ArchitectureMode mode;

            try
            {
                if (Process_Machine_Type == MachineType.I386)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_32;
                }
                else if (Process_Machine_Type == MachineType.x64)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_64;
                }
                else
                {
                    throw new Exception("User input error: Machine Type is invalid, must be ERC.MachineType.x86_64 or ERC.MachineType.x86_32");
                }
            }
            catch (Exception e)
            {
                result.Error = e;
                result.Log_Event();
                return result;
            }

            try
            {
                disasm = new SharpDisasm.Disassembler(
                HexStringToByteArray(BitConverter.ToString(opcodes).Replace("-", "")),
                mode, 0, true);
            }
            catch (Exception e)
            {
                result.Error = e;
                result.Log_Event();
                return result;
            }

            foreach (var insn in disasm.Disassemble())
            {
                var mne = insn.ToString().Split(new string[] { "  " }, StringSplitOptions.None);
                result.Return_Value += mne[mne.Length - 1].Trim() + Environment.NewLine;
            }

            return result;
        }

        /// <summary>
        /// Disassembles opcodes into the associated instructions. Takes a byte array containing opcodes, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns an ERC_Result containing associated instructions.
        /// </summary>
        /// <param name="opcodes"></param>
        /// <returns></returns>
        public static ERC_Result<string> Disassemble(byte[] opcodes, MachineType machineType, ERC_Core core)
        {
            ERC_Result<string> result = new ERC_Result<string>(core);
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            SharpDisasm.Disassembler disasm;
            SharpDisasm.ArchitectureMode mode;

            try
            {
                if (machineType == MachineType.I386)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_32;
                }
                else if (machineType == MachineType.x64)
                {
                    mode = SharpDisasm.ArchitectureMode.x86_64;
                }
                else
                {
                    throw new Exception("User input error: Machine Type is invalid, must be ERC.MachineType.x86_64 or ERC.MachineType.x86_32");
                }
            }
            catch(Exception e)
            {
                result.Error = e;
                result.Log_Event();
                return result;
            }

            try
            {
                disasm = new SharpDisasm.Disassembler(
                HexStringToByteArray(BitConverter.ToString(opcodes).Replace("-", "")),
                mode, 0, true);
            }
            catch(Exception e)
            {
                result.Error = e;
                result.Log_Event();
                return result;
            }

            foreach (var insn in disasm.Disassemble())
            {
                var mne = insn.ToString().Split(new string[] { "  " }, StringSplitOptions.None);
                result.Return_Value += mne[mne.Length - 1].Trim() + Environment.NewLine;
            }

            return result;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
