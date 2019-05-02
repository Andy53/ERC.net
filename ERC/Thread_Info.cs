using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace ERC
{
    public class Thread_Info
    {
        public IntPtr Thread_HANDLE { get; set; }
        public int Thread_ID { get; set; }
        public bool Thread_Failed { get; set; }
        public bool x64 { get; set; }
        public ProcessThread Thread_Current { get; set; }
        public ERC_Core Thread_Core { get; set; }
        public CONTEXT32 Context32;
        public CONTEXT64 Context64;

        public Thread_Info(ProcessThread thread, ERC_Core core, Process_Info Thread_Process)
        {
            Thread_ID = thread.Id;
            Thread_Current = thread;
            Thread_Core = core;

            if (Thread_Process.Process_Machine_Type == MachineType.x64)
            {
                x64 = true;
            }

            try
            {
                Thread_HANDLE = ERC_Core.OpenThread(ThreadAccess.GET_CONTEXT, false, (uint)thread.Id);
                if(Thread_HANDLE == null)
                {
                    Thread_Failed = true;
                    
                    throw new Exception(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
            }
            catch(Exception e)
            {
                ERC_Result<Exception> exceptionThrower = new ERC_Result<Exception>(Thread_Core)
                {
                    Error = e
                };
                exceptionThrower.Log_Event();
            }
        }

        public ERC_Result<string> Get_Context()
        {
            ERC_Result<string> result = new ERC_Result<string>(Thread_Core);
            
            if(x64 == true)
            {
                Context64 = new CONTEXT64();
                Context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    ERC_Core.GetThreadContext64(Thread_HANDLE, ref Context64);
                }
                catch (Exception e)
                {
                    result.Error = new Win32Exception(Marshal.GetLastWin32Error());
                    result.Log_Event();
                    return result;
                }
            }
            else
            {
                Context32 = new CONTEXT32();
                Context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_CONTROL;
                try
                {
                    ERC_Core.GetThreadContext32(Thread_HANDLE, ref Context32);
                }
                catch (Exception e)
                {
                    result.Error = new Win32Exception(Marshal.GetLastWin32Error());
                    result.Log_Event();
                    return result;
                }
            }
            return result;
        }
    }
}
