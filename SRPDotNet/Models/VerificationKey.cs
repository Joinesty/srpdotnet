using System;
namespace SRPDotNet.Models
{
    public class VerificationKey
    {
        public string Username { get; set; }
        public string Salt { get; set; }
        public string Verifier { get; set; }
    }
}
