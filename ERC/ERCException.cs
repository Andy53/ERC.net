using System;
using System.Runtime.Serialization;

namespace ERC_Lib
{
    /// <summary>
    /// Custom exception handler.
    /// </summary>
    [Serializable]
    public class ERCException : Exception
    {
        // Constructors
        public ERCException(string message)
            : base(message)
        { }

        // Ensure Exception is Serializable
        protected ERCException(SerializationInfo info, StreamingContext ctxt)
            : base(info, ctxt)
        { }
    }
}
