using System.Numerics;
using System.Security.Cryptography;
using SRPDotNet.Helpers;
using SRPDotNet.Parameters;
using SRPDotNet.Models;
using System;
using System.Diagnostics;

namespace SRPDotNet
{
    public class User : SecureRemoteProtocol
    {
        readonly HashAlgorithm _hashAlgorithm;
        BigInteger _v;
        byte[] _K;
        bool _isAuthenticated;
        readonly BigInteger _k;
        readonly SRPParameter _parameter;
        readonly byte[] _A;
        BigInteger _B;
        BigInteger _u;
        BigInteger _S;
        byte[] _M;
        byte[] _HMAK;
        readonly string _username;
        readonly string _password;
        byte[] _s;
        BigInteger _x;
        readonly BigInteger _a;
        //VerificationKey _verificationKey; // s and v


        public bool IsAuthenticated
        {
            get
            {
                return _isAuthenticated;
            }
        }

        public byte[] GetEphemeralSecret()
        {
            return _a.ToBytes();
        }

        public User(string username, string password, HashAlgorithm hashAlgorithm,
                    SRPParameter parameter, byte[] a) : base(hashAlgorithm, parameter)
        {
            _hashAlgorithm = hashAlgorithm;
            _parameter = parameter;
            _k = Compute_k().ToBigInteger();
            _username = username;
            _password = password;
            if (a == null)
            {
                a = GetRandomNumber().ToBytes();
            }
            _a = a.ToBigInteger();
            _A = Compute_A(_a);

#if DEBUG
            Console.WriteLine("=================== User ====================");
            Console.WriteLine("_k = {0}", _k);
            Console.WriteLine("_a = {0}", _a);
            Console.WriteLine("_A = {0}", _A.ToBigInteger());
            Console.WriteLine("=============================================");
#endif

        }


        BigInteger Compute_S(BigInteger B, BigInteger k, BigInteger u, BigInteger a, BigInteger x)
        {
            if((B % _parameter.PrimeNumber) == BigInteger.Zero)
            {
                throw new Exception("B mod N == 0");
            }

            var v = BigInteger.ModPow(_parameter.Generator, x, _parameter.PrimeNumber);

            //return BigInteger.ModPow(B + (_parameter.PrimeNumber - (k * v) % _parameter.PrimeNumber),
            //a + u * x, _parameter.PrimeNumber);

            return BigInteger.ModPow((B - k * v), (a + u * x), _parameter.PrimeNumber);
        }


        public Session ProcessChallenge(VerificationChallenge challenge)
        {
            
            _s = challenge.ServerKey;
            _B = challenge.PublicEphemeralKey.ToBigInteger();

            if (_B % _parameter.PrimeNumber == 0) 
            {
                throw new Exception("Mod B % PrimeNumber could not be 0");
            }

            _u = Compute_u(_A, _B.ToBytes()).ToBigInteger();

            if(_u == 0)
            {
                throw new Exception("u could not be 0");
            }

            _x = Compute_x(_s, _username, _password).ToBigInteger();
            _v = Compute_v(_x);
            _S = Compute_S(_B, _k, _u, _a, _x);
            _K = Compute_K(_S.ToBytes());
            _M = Compute_M(_username, _s, _A, _B.ToBytes(), _K);
            _HMAK = Compute_HAMK(_A, _M, _K);

            var session = new Session()
            {
                Key = _M
            };


            #if DEBUG
            Console.WriteLine("=================== User Challenge====================");
            Console.WriteLine("_s = {0}", _s.ToBigInteger());
            Console.WriteLine("_B = {0}", _B);
            Console.WriteLine("_u = {0}", _u);
            Console.WriteLine("_x = {0}", _x);
            Console.WriteLine("_v = {0}", _v);
            Console.WriteLine("_S = {0}", _S);
            Console.WriteLine("_K = {0}", _K.ToBigInteger());
            Console.WriteLine("_M = {0}", _M.ToBigInteger());
            Console.WriteLine("=============================================");
#endif

            return session;
        }

        public Authentication StartAuthentication()
        {
            var authentication = new Authentication()
            {
                Username = _username,
                PublicKey = _A
            };

            return authentication;
        }


        public void VerifySession(HAMK hamk)
        {
            _isAuthenticated |= _HMAK == hamk.Key;
        }
    }
}
