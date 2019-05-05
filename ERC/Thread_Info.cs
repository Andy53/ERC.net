using ERC_Lib;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace ERC
{
    public class ThreadInfo
    {
        public IntPtr ThreadHandle { get; set; }
        public int ThreadID { get; set; }
        public bool ThreadFailed { get; set; }
        public bool x64 { get; set; }
        public ProcessThread ThreadCurrent { get; set; }
        public ErcCore ThreadCore { get; set; }
        public CONTEXT32 Context32;
        public CONTEXT64 Context64;

        public ThreadInfo(ProcessThread thread, ErcCore core, ProcessInfo Thread_Process)
        {
            ThreadID = thread.Id;
            ThreadCurrent = thread;
            ThreadCore = core;

            if (Thread_Process.ProcessMachineType == MachineType.x64)
            {
                x64 = true;
            }

            try
            {
                ThreadHandle = ErcCore.OpenThread(ThreadAccess.GET_CONTEXT, false, (uint)thread.Id);
                if(ThreadHandle == null)
                {
                    ThreadFailed = true;
                    
                    throw new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
            }
            catch(ERCException e)
            {
                ErcResult<Exception> exceptionThrower = new ErcResult<Exception>(ThreadCore)
                {
                    Error = e
                };
                exceptionThrower.LogEvent();
            }
        }

        public ErcResult<string> Get_Context()
        {
            ErcResult<string> result = new ErcResult<string>(ThreadCore);
            
            if(x64 == true)
            {
                Context64 = new CONTEXT64();
                Context64.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    ErcCore.GetThreadContext64(ThreadHandle, ref Context64);
                    if(new Win32Exception(Marshal.GetLastWin32Error()).Message != "The operation completed successfully")
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context" + 
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch(Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            else if(Environment.Is64BitProcess == true && x64 == false)
            {
                Context32 = new CONTEXT32();
                Context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    ErcCore.Wow64GetThreadContext(ThreadHandle, ref Context32);
                    if (new Win32Exception(Marshal.GetLastWin32Error()).Message != "The operation completed successfully")
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context" +
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            else
            {
                Context32 = new CONTEXT32();
                Context32.ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL;
                try
                {
                    ErcCore.GetThreadContext32(ThreadHandle, ref Context32);
                    if (new Win32Exception(Marshal.GetLastWin32Error()).Message != "The operation completed successfully")
                    {
                        throw new ERCException("Win32 Exception encountered when attempting to get thread context" +
                            new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                catch (ERCException e)
                {
                    result.Error = e;
                    result.LogEvent();
                    return result;
                }
                catch (Exception e)
                {
                    result.Error = e;
                    result.LogEvent(e);
                }
            }
            return result;
        }
    }
}
