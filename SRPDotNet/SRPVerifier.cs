using System.Numerics;
using SRPDotNet.Parameters;
using SRPDotNet.Models;
using SRPDotNet.Helpers;
using System.Security.Cryptography;
using System;
using System.Linq;

namespace SRPDotNet
{
    public class SRPVerifier : SecureRemoteProtocol
    {
        readonly HashAlgorithm _hashAlgorithm;
        readonly BigInteger _s;
        readonly BigInteger _v;
        readonly byte[] _K;
        bool _isAuthenticated;
        readonly BigInteger _k;
        readonly SRPParameter _parameter;
        readonly BigInteger _A;
        readonly BigInteger _b;
        readonly BigInteger _B;
        readonly BigInteger _u;
        readonly BigInteger _S;
        readonly byte[] _M;
        readonly byte[] _HMAK;
        readonly VerificationKey _verificationKey;
        readonly string _username;


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
            return _b.ToBytes();
        }

        public VerificationChallenge GetChallenge()
        {
            VerificationChallenge challenge = new VerificationChallenge();

            if ((_A % _parameter.PrimeNumber) == BigInteger.Zero)
            {
                challenge.ServerKey = null;
                challenge.PublicEphemeralKey = null;
            }
            else
            {
                challenge.ServerKey = _s.ToBytes();
                challenge.PublicEphemeralKey = _B.ToBytes();
            }

            return challenge;
        }

        public HAMK VerifiySession(Session session)
        {
            HAMK hamk = null;
            if (((_A % _parameter.PrimeNumber) != BigInteger.Zero) && (session.Key.CheckEquals(_M)))
            {
                _isAuthenticated = true;
                hamk =  new HAMK() { Key = _HMAK };
            }
            return hamk;
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
            return _username;
        }


        public SRPVerifier(HashAlgorithm hashAlgorithm, SRPParameter parameter, 
                           VerificationKey verification, byte[] A, byte[] b = null)
            : base(hashAlgorithm, parameter)
        {
            _hashAlgorithm = hashAlgorithm;
            _parameter = parameter;

            _s = verification.Salt.StringToBytes().ToBigInteger();
            _v = verification.Verifier.StringToBytes().ToBigInteger();
            _username = verification.Username;

            _A = A.ToBigInteger();

            if ((_A % _parameter.PrimeNumber) == BigInteger.Zero) 
            {
                throw new Exception("Safety check failed");
            }

            _b = b != null ? b.ToBigInteger() : GetRandomNumber().ToBytes().ToBigInteger();
         
            _k = Compute_k().ToBigInteger();

            _B = (_k * _v + BigInteger.ModPow(
                _parameter.Generator, _b, _parameter.PrimeNumber)
                   ) % _parameter.PrimeNumber;
        
            _u = Compute_u(_A.ToBytes(), _B.ToBytes()).ToBigInteger();
            _S = Compute_S(_A, _v, _u, _b);
            _K = Compute_K(_S.ToBytes());
            _M = Compute_M(_username, _s.ToBytes(), _A.ToBytes(), _B.ToBytes(), _K);
            _HMAK = Compute_HAMK(_A.ToBytes(), _M, _K);
            _verificationKey = verification;

#if DEBUG
            Console.WriteLine("=================== Verifier ====================");
            Console.WriteLine("_s = {0}", _s);
            Console.WriteLine("_v = {0}", _v);
            Console.WriteLine("_username = {0}", _username);
            Console.WriteLine("_A = {0}", _A);
            Console.WriteLine("_b = {0}", _b);
            Console.WriteLine("_k = {0}", _k);
            Console.WriteLine("_B = {0}", _B);
            Console.WriteLine("_u = {0}", _u);
            Console.WriteLine("_S = {0}", _S);
            Console.WriteLine("_K = {0}", _K.ToBigInteger());
            Console.WriteLine("_M = {0}", _M.ToBigInteger());
            Console.WriteLine("=============================================");
#endif

        }

        /// <summary>
        /// u = H(PAD(A) | PAD(B))
        /// </summary>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <returns></returns>
        byte[] Compute_u(byte[] A, byte[] B)
        {
            byte[] paddedA = A;
            byte[] paddedB = B;
            return _hashAlgorithm.ComputeHash(paddedA.Concat(paddedB).ToArray());
        }
    }
}
