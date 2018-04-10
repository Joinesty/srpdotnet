using System.Numerics;
using SRPDotNet.Parameters;
using SRPDotNet.Models;
using SRPDotNet.Helpers;
using System.Security.Cryptography;
using System;

namespace SRPDotNet
{
    public class Verifier : SecureRemoteProtocol
    {
        readonly HashAlgorithm _hashAlgorithm;
        readonly BigInteger _s;
        readonly BigInteger _v;
        readonly byte[] _K;
        bool _isAuthenticated;
        readonly BigInteger _k;
        readonly SRPParameter _parameter;
        readonly byte[] _A;
        readonly BigInteger _b;
        readonly BigInteger _B;
        readonly BigInteger _u;
        readonly BigInteger _S;
        readonly byte[] _M;
        readonly byte[] _HMAK;
        readonly VerificationKey _verificationKey;


        public bool IsAuthenticated
        {
            get {
                return _isAuthenticated;
            }
        }

        public byte[] GetSessionKey()
        {
            return _K;
        }

        public byte[] GetEphemeralSecret()
        {
            return _b.ToByteArray();
        }

        public VerificationChallenge GetChallenge()
        {
            VerificationChallenge challenge = new VerificationChallenge();

            if ((_A.ToBigInteger() % _parameter.PrimeNumber) == 0)
            {
                challenge.ServerKey = null;
                challenge.PublicEphemeralKey = null;
            }
            else
            {
                challenge.ServerKey = _s.ToByteArray();
                challenge.PublicEphemeralKey = _B.ToByteArray();
            }

            return challenge;
        }

        public HAMK VerifiySession(Session session)
        {
            if (!((_A.ToBigInteger() % _parameter.PrimeNumber) == 0) && (session.Key == _M))
            {
                _isAuthenticated = true;
                return new HAMK() { Key = _HMAK };
            }
            return null;
        }

        /// <summary>
        /// <premaster secret> = (A * v^u) ^ b % N
        /// </summary>
        /// <param name="A"></param>
        /// <param name="v"></param>
        /// <param name="u"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        BigInteger Compute_S(BigInteger A, BigInteger v, BigInteger u, BigInteger b)
        {
            if (A % _parameter.PrimeNumber == BigInteger.Zero)
            {
                throw new Exception("A mod N == 0");
            }

            return BigInteger.ModPow(A * BigInteger.ModPow(v, u, _parameter.PrimeNumber), b, _parameter.PrimeNumber);
        }


        public string GetUsername()
        {
            return _verificationKey.Username;
        }


        public Verifier(HashAlgorithm hashAlgorithm, SRPParameter parameter, VerificationKey verification, byte[] A, byte[] b)
            : base(hashAlgorithm, parameter)
        {
            _hashAlgorithm = hashAlgorithm;
            _parameter = parameter;
            _A = A;
            _b = b.ToBigInteger();
            _s = verification.Salt.ToBigInteger();
            _v = verification.PasswordVerifier.ToBigInteger();
            _k = Compute_k().ToBigInteger();
            _B = Compute_B(_v, _k, _b);
            _u = Compute_u(_A, _B.ToByteArray()).ToBigInteger();
            _S = Compute_S(_A.ToBigInteger(), _v, _k, _b);
            _K = Compute_K(_S.ToByteArray());
            _M = Compute_M(verification.Username, verification.Salt, _A, _B.ToByteArray(), _K);
            _HMAK = Compute_HAMK(_A, _M, _K);
            _verificationKey = verification;
        }


      
       
    }
}
