using System;
namespace SRPDotNet.Models
{
    public class VerificationChallenge
    {
        public byte[] ServerKey;
        public byte[] PublicEphemeralKey;
    }
}
