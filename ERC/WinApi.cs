using ERC;
using ERC.Structures;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ERC_Lib
{
    /// <summary>
    /// Contains C# wrappers for functions within the Windows API.
    /// </summary>
    public static class WinApi
    {
        #region OpenProcess
        public static ErcResult<IntPtr> OpenProcess(Process proc, ProcessAccessFlags flags)
        {
            ErcResult<IntPtr> ProcessHandle = new ErcResult<IntPtr>(new ErcCore());
            ProcessHandle.ReturnValue = ErcCore.OpenProcess(flags, false, proc.Id);
            if(ProcessHandle.ReturnValue == IntPtr.Zero)
            {
                ProcessHandle.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            return ProcessHandle;
        }

        public static ErcResult<IntPtr> OpenProcess(int processID, ProcessAccessFlags flags)
        {
            ErcResult<IntPtr> ProcessHandle = new ErcResult<IntPtr>(new ErcCore());
            ProcessHandle.ReturnValue = ErcCore.OpenProcess(flags, false, processID);
            if (ProcessHandle.ReturnValue == IntPtr.Zero)
            {
                ProcessHandle.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            return ProcessHandle;
        }
        #endregion

        #region ReadProcessMemory
        public static ErcResult<byte[]> ReadProcessMemory(IntPtr Handle, IntPtr Address, int Size)
        {
            ErcResult<byte[]> readMemory = new ErcResult<byte[]>(new ErcCore());

            int bytesRead = 0;
            byte[] memBytes = new byte[Size];
            var retRPM = ErcCore.ReadProcessMemory(Handle, Address, memBytes, Size, out bytesRead);
            if(retRPM != 0)
            {
                readMemory.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            return readMemory;
        }
        #endregion

        #region IsWow64Process
        public static bool IsWow64Process(IntPtr hProcess)
        {
            bool ret = false;
            ErcCore.IsWow64Process(hProcess, out ret);
            return ret;
        }
        #endregion

        #region VirtualQueryEx
        public static dynamic VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress)
        {
            if (IsWow64Process(hProcess))
            {
                ErcResult<MEMORY_BASIC_INFORMATION64> memBasInf64 = new ErcResult<MEMORY_BASIC_INFORMATION64>(new ErcCore());
                MEMORY_BASIC_INFORMATION64 m = new MEMORY_BASIC_INFORMATION64();
                var ret = ErcCore.VirtualQueryEx64(hProcess, lpAddress, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                if (ret == 0)
                {
                    memBasInf64.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                memBasInf64.ReturnValue = m;
                return memBasInf64;
            }
            else
            {
                ErcResult<MEMORY_BASIC_INFORMATION32> memBasInf32 = new ErcResult<MEMORY_BASIC_INFORMATION32>(new ErcCore());
                MEMORY_BASIC_INFORMATION32 m = new MEMORY_BASIC_INFORMATION32();
                var ret = ErcCore.VirtualQueryEx32(hProcess, lpAddress, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION32)));
                if (ret == 0)
                {
                    memBasInf32.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                memBasInf32.ReturnValue = m;
                return memBasInf32;
            }
        }
        #endregion

        #region OpenThread
        public static ErcResult<IntPtr> OpenThread(int ThreadID, ThreadAccess access = ThreadAccess.All_ACCESS)
        {
            ErcResult<IntPtr> threadPtr = new ErcResult<IntPtr>(new ErcCore());
            var retPtr = ErcCore.OpenThread(ThreadAccess.All_ACCESS, false, (uint)ThreadID);
            if(retPtr == IntPtr.Zero)
            {
                threadPtr.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            return threadPtr;
        }

        public static ErcResult<IntPtr> OpenThread(ProcessThread thread, ThreadAccess access = ThreadAccess.All_ACCESS)
        {
            ErcResult<IntPtr> threadPtr = new ErcResult<IntPtr>(new ErcCore());
            var retPtr = ErcCore.OpenThread(ThreadAccess.All_ACCESS, false, (uint)thread.Id);
            if (retPtr == IntPtr.Zero)
            {
                threadPtr.Error = new ERCException(new Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
            return threadPtr;
        }
        #endregion
    }
}
