using System;
using System.Collections.Generic;
using Reloaded.Assembler;

namespace ERC.Utilities
{
    public class OpcodeAssembler : ProcessInfo
    {
        public OpcodeAssembler(ProcessInfo parent) : base(parent)
        {

        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions and returns the associated opcodes.  
        /// </summary>
        /// <param name="instructions"></param>
        /// <returns>Returns an ErcResult byte array</returns>
        public ErcResult<byte[]> AssembleOpcodes(List<string> instructions)
        {
            ErcResult<byte[]> result = new ErcResult<byte[]>(ProcessCore);
            List<string> mnemonics = new List<string>();
            if (ProcessMachineType == MachineType.I386)
            {
                mnemonics.Add("use32");
            }
            else if (ProcessMachineType == MachineType.x64)
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
                result.ReturnValue = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch (Exception e)
            {
                result.Error = e;
                result.LogEvent();
                asm.Dispose();
                return result;
            }
            return result;
        }

        /// <summary>
        /// Takes either an array or list of strings containing assembly instructions, a MachineType of I386 or x64, 
        /// an instance of the ERC_Core object and returns the associated opcodes.  
        /// </summary>
        /// <param name="instructions"></param>
        /// <returns>Returns an ERC_Result. byte array</returns>
        public static ErcResult<byte[]> AssembleOpcodes(List<string> instructions, MachineType machineType, ErcCore core)
        {
            ErcResult<byte[]> result = new ErcResult<byte[]>(core);
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
                result.ReturnValue = asm.Assemble(mnemonics);
                asm.Dispose();
            }
            catch(Exception e)
            {
                result.Error = e;
                result.LogEvent();
                asm.Dispose();
                return result;
            }
            return result;
        }
    }
}
