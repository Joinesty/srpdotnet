using System;
using System.Numerics;
using System.Security.Cryptography;
using SRPDotNet.Helpers;

namespace SRPDotNet.Parameters
{
    public abstract class SRPParameter
    {
        readonly BigInteger _primeNumber;
        readonly BigInteger _generator;
        readonly int _keyLength;
        readonly int _saltLength;

        public BigInteger PrimeNumber 
        {
            get {
                return _primeNumber;
            }
        }

        public BigInteger Generator
        {
            get
            {
                return _generator;
            }
        }

        public int KeyLength
        {
            get 
            {
                return _keyLength;
            }
        }

        public int SaltLength
        {
            get
            {
                return _saltLength;
            }
        }

        protected SRPParameter(byte[] primeNumber, byte[] generator, int keyLength)
            : this(primeNumber, generator, keyLength, 32) {}

        protected SRPParameter(byte[] primeNumber, byte[] generator, int keyLength, int saltLength)
        {
            _primeNumber = primeNumber.ToBigInteger();
            _generator = generator.ToBigInteger();
            _keyLength = keyLength;
            _saltLength = saltLength;
        }

    }
}
