using ERC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ERC_Lib
{
    public static class RopChainGenerator
    {
        public static string GenerateRopChain32(ProcessInfo info, List<string> excludes = null)
        {
            return "";
        }

        public static string GenerateRopChain64(ProcessInfo info, List<string> excludes = null)
        {
            return "";
        }

        private static ErcResult<List<IntPtr>> GetRopNops(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> ropNops = new ErcResult<List<IntPtr>>(new ErcCore());
            ropNops.ReturnValue = new List<IntPtr>();
            byte[] ropNop = new byte[] { 0xC3 };
            var ropPtrs = info.SearchMemory(0, ropNop, excludes: excludes);
            foreach(KeyValuePair<IntPtr, string> k in ropPtrs.ReturnValue)
            {
                ropNops.ReturnValue.Add(k.Key);
            }
            return ropNops;
        }

        #region EAX
        private static ErcResult<List<IntPtr>> GetPushEax(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEaxs = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEaxs.ReturnValue = new List<IntPtr>();
            byte[] pushEax = new byte[] { 0x50, 0xC3 };
            var eaxPtrs = info.SearchMemory(0, pushEax, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in eaxPtrs.ReturnValue)
            {
                pushEaxs.ReturnValue.Add(k.Key);
            }
            return pushEaxs;
        }

        private static ErcResult<List<IntPtr>> GetPopEax(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> popEaxs = new ErcResult<List<IntPtr>>(new ErcCore());
            popEaxs.ReturnValue = new List<IntPtr>();
            byte[] popEax = new byte[] { 0x58, 0xC3 };
            var eaxPtrs = info.SearchMemory(0, popEax, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in eaxPtrs.ReturnValue)
            {
                popEaxs.ReturnValue.Add(k.Key);
            }
            return popEaxs;
        }
        #endregion

        #region EBX
        private static ErcResult<List<IntPtr>> GetPushEbx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEbxs = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEbxs.ReturnValue = new List<IntPtr>();
            byte[] pushEbx = new byte[] { 0x53, 0xC3 };
            var ebxPtrs = info.SearchMemory(0, pushEbx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in ebxPtrs.ReturnValue)
            {
                pushEbxs.ReturnValue.Add(k.Key);
            }
            return pushEbxs;
        }

        private static ErcResult<List<IntPtr>> GetPopEbx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> PopEbxs = new ErcResult<List<IntPtr>>(new ErcCore());
            PopEbxs.ReturnValue = new List<IntPtr>();
            byte[] PopEbx = new byte[] { 0x5B, 0xC3 };
            var ebxPtrs = info.SearchMemory(0, PopEbx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in ebxPtrs.ReturnValue)
            {
                PopEbxs.ReturnValue.Add(k.Key);
            }
            return PopEbxs;
        }
        #endregion

        #region ECX
        private static ErcResult<List<IntPtr>> GetPushEcx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEcxs = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEcxs.ReturnValue = new List<IntPtr>();
            byte[] pushEcx = new byte[] { 0x51, 0xC3 };
            var ecxPtrs = info.SearchMemory(0, pushEcx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in ecxPtrs.ReturnValue)
            {
                pushEcxs.ReturnValue.Add(k.Key);
            }
            return pushEcxs;
        }

        private static ErcResult<List<IntPtr>> GetPopEcx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> popEcxs = new ErcResult<List<IntPtr>>(new ErcCore());
            popEcxs.ReturnValue = new List<IntPtr>();
            byte[] popEcx = new byte[] { 0x59, 0xC3 };
            var ecxPtrs = info.SearchMemory(0, popEcx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in ecxPtrs.ReturnValue)
            {
                popEcxs.ReturnValue.Add(k.Key);
            }
            return popEcxs;
        }
        #endregion

        #region EDX
        private static ErcResult<List<IntPtr>> GetPushEdx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEdxs = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEdxs.ReturnValue = new List<IntPtr>();
            byte[] pushEdx = new byte[] { 0x52, 0xC3 };
            var edxPtrs = info.SearchMemory(0, pushEdx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in edxPtrs.ReturnValue)
            {
                pushEdxs.ReturnValue.Add(k.Key);
            }
            return pushEdxs;
        }

        private static ErcResult<List<IntPtr>> GetPopEdx(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEdxs = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEdxs.ReturnValue = new List<IntPtr>();
            byte[] pushEdx = new byte[] { 0x5A, 0xC3 };
            var edxPtrs = info.SearchMemory(0, pushEdx, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in edxPtrs.ReturnValue)
            {
                pushEdxs.ReturnValue.Add(k.Key);
            }
            return pushEdxs;
        }
        #endregion

        private static ErcResult<List<IntPtr>> GetPushAd(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushAds = new ErcResult<List<IntPtr>>(new ErcCore());
            pushAds.ReturnValue = new List<IntPtr>();
            byte[] pushAd = new byte[] { 0x60, 0xC3 };
            var pushadPtrs = info.SearchMemory(0, pushAd, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in pushadPtrs.ReturnValue)
            {
                pushAds.ReturnValue.Add(k.Key);
            }
            return pushAds;
        }

        private static ErcResult<List<IntPtr>> GetPushEsi(ProcessInfo info, List<string> excludes = null)
        {
            ErcResult<List<IntPtr>> pushEsis = new ErcResult<List<IntPtr>>(new ErcCore());
            pushEsis.ReturnValue = new List<IntPtr>();
            byte[] pushEsi = new byte[] { 0x60, 0xC3 };
            var esiPtrs = info.SearchMemory(0, pushEsi, excludes: excludes);
            foreach (KeyValuePair<IntPtr, string> k in esiPtrs.ReturnValue)
            {
                pushEsis.ReturnValue.Add(k.Key);
            }
            return pushEsis;
        }

        
    }
}
