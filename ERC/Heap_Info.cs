using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ERC.Structures;

namespace ERC
{
    public class HeapInfo
    {
        #region Variables
        internal List<HEAPENTRY32> heapentries = new List<HEAPENTRY32>();
        internal List<HEAPLIST32> heaplists = new List<HEAPLIST32>();
        internal ProcessInfo HeapProcess;

        #endregion

        #region Constructor
        public HeapInfo(ProcessInfo info)
        {
            HeapProcess = info;
            HEAPLIST32 firstHeapList = new HEAPLIST32();
            firstHeapList.dwSize = (UIntPtr)Marshal.SizeOf(typeof(HEAPLIST32));
            IntPtr Handle = ErcCore.CreateToolhelp32Snapshot(SnapshotFlags.HeapList, (uint)info.ProcessID);

            if ((int)Handle == -1)
            {
                throw new ERCException("CreateToolhelp32Snapshot returned an invalid handle value (-1)");
            }

            if (ErcCore.Heap32ListFirst(Handle, ref firstHeapList))
            {
                heaplists.Add(firstHeapList);
                bool moreHeaps = false;
                do
                {
                    HEAPLIST32 currentHeap = new HEAPLIST32();
                    currentHeap.dwSize = (UIntPtr)Marshal.SizeOf(typeof(HEAPLIST32));
                    moreHeaps = ErcCore.Heap32ListNext(Handle, ref currentHeap);
                    if(heapentries.Count == 0)
                    {
                        currentHeap = firstHeapList;
                    }

                    if (moreHeaps)
                    {
                        heaplists.Add(currentHeap);
                        HEAPENTRY32 heapentry32 = new HEAPENTRY32();
                        heapentry32.dwSize = (UIntPtr)Marshal.SizeOf(typeof(HEAPENTRY32));

                        if (ErcCore.Heap32First(ref heapentry32, (uint)HeapProcess.ProcessID, currentHeap.th32HeapID))
                        {
                            bool moreheapblocks = false;
                            do
                            {
                                heapentries.Add(heapentry32);
                                moreheapblocks = ErcCore.Heap32Next(ref heapentry32);
                            }
                            while (moreheapblocks);
                        }
                    }
                }
                while (moreHeaps);
            }
            else
            {
                throw new ERCException("Heap32ListFirst returned an invalid response. Error: " + Utilities.Win32Errors.GetLastWin32Error());
            }
        }

        #endregion

        #region Accessors
        public void SearchHeap()
        {

        }

        /// <summary>
        /// Returns a collections of stats related to the heap of the current process object.
        /// </summary>
        /// <param name="extended"></param>
        /// <returns></returns>
        public List<string> HeapStatistics(bool extended = false)
        {
            List<string> heapStats = new List<string>();
            heapStats.Add("ProcessID = " + HeapProcess.ProcessID + Environment.NewLine);
            heapStats.Add("Number of heaps = " + heaplists.Count + Environment.NewLine);
            int count = 0;
            foreach(HEAPLIST32 hl in heaplists)
            {
                count++;
                int heapEnts = 0;
                heapStats.Add("    Heap " + count + " ID = " + hl.th32HeapID + Environment.NewLine);
                
                foreach(HEAPENTRY32 he in heapentries)
                {
                    if(he.th32HeapID == hl.th32HeapID)
                    {
                        if(extended == true)
                        {
                            if (HeapProcess.ProcessMachineType == MachineType.I386)
                            {
                                heapStats.Add("       Heap Start Address = 0x" + string.Format("0x{0:X}", he.dwAddress) + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + (ulong)he.dwBlockSize + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                            else
                            {
                                heapStats.Add("       Heap Start Address = 0x" + string.Format("0x{0:X}", he.dwAddress) + Environment.NewLine);
                                heapStats.Add("       Heap Entry size = " + (ulong)he.dwBlockSize + Environment.NewLine);
                                switch (he.dwFlags)
                                {
                                    case 1:
                                        heapStats.Add("       Heap flags = LF32_FIXED" + Environment.NewLine);
                                        break;
                                    case 2:
                                        heapStats.Add("       Heap flags = LF32_FREE" + Environment.NewLine);
                                        break;
                                    case 4:
                                        heapStats.Add("       Heap flags = LF32_MOVEABLE" + Environment.NewLine);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                        heapEnts++;
                    }
                }
                heapStats.Add("        Total number of entries in heap: " + heapEnts + Environment.NewLine);
            }
            return heapStats;
        }

        /// <summary>
        /// Lists all HeapIDs associated with a process.
        /// </summary>
        /// <returns>Returns an ErcResult<List<ulong>>"</returns>
        public ErcResult<List<ulong>> HeapIDs()
        {
            ErcResult<List<ulong>> result = new ErcResult<List<ulong>>(HeapProcess);
            result.ReturnValue = new List<ulong>();
            foreach(HEAPLIST32 hl in heaplists)
            {
                result.ReturnValue.Add((ulong)hl.th32HeapID);
            }

            if(result.ReturnValue.Count == 0)
            {
                result.Error = new ERCException("Error: No heap ids found associated with this process.");
            }
            return result;
        }
        #endregion
    }
}
