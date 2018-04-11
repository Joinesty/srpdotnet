using System;
namespace SRPDotNet.Models
{
    public class VerificationKey
    {
        public string Username { get; set; }
        public byte[] Salt { get; set; }
        public byte[] Verifier { get; set; }
    }
}
