using System;
using System.Collections.Generic;
using Reloaded.Assembler;

namespace ERC
{
    public class Opcode_Assembler : Process_Info
    {
        public Opcode_Assembler(Process_Info parent) : base(parent)
        {

        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions and returns the associated opcodes. Returns an ERC_Result. 
        /// </summary>
        /// <param name="instructions"></param>
        /// <returns></returns>
        public ERC_Result<byte[]> Assemble_Opcodes(List<string> instructions)
        {
            ERC_Result<byte[]> result = new ERC_Result<byte[]>(Process_Core);
            List<string> mnemonics = new List<string>();
            if (Process_Machine_Type == MachineType.I386)
            {
                mnemonics.Add("use32");
            }
            else if (Process_Machine_Type == MachineType.x64)
            {
                mnemonics.Add("use64");
            }

            for (int i = 0; i < instructions.Count; i++)
            {
                mnemonics.Add(instructions[i]);
            }

            var asm = new Assembler();

            try
            {
                result.Return_Value = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch (Exception e)
            {
                result.Error = e;
                result.Log_Event();
                asm.Dispose();
                return result;
            }
            return result;
        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns the associated opcodes. Returns an ERC_Result. 
        /// </summary>
        /// <param name="instructions"></param>
        /// <returns></returns>
        public static ERC_Result<byte[]> Assemble_Opcodes(List<string> instructions, MachineType machineType, ERC_Core core)
        {
            ERC_Result<byte[]> result = new ERC_Result<byte[]>(core);
            List<string> mnemonics = new List<string>();
            if (machineType == MachineType.I386)
            {
                mnemonics.Add("use32");
            }
            else if (machineType == MachineType.x64)
            {
                mnemonics.Add("use64");
            }

            for(int i = 0; i < instructions.Count; i++)
            {
                mnemonics.Add(instructions[i]);
            }

            var asm = new Assembler();

            try
            {
                result.Return_Value = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch(Exception e)
            {
                result.Error = e;
                result.Log_Event();
                asm.Dispose();
                return result;
            }
            return result;
        }
    }
}
