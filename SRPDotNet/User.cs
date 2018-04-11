using System.Numerics;
using System.Security.Cryptography;
using SRPDotNet.Helpers;
using SRPDotNet.Parameters;
using SRPDotNet.Models;
using System;

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
        VerificationKey _verificationKey; // s and v


        public bool IsAuthenticated
        {
            get
            {
                return _isAuthenticated;
            }
        }

        public VerificationKey VerificationKey
        {
            get
            {
                return _verificationKey;
            }

        }

        public User(string username, string password, HashAlgorithm hashAlgorithm,
                    SRPParameter parameter, byte[] a) : base(hashAlgorithm, parameter)
        {
            _hashAlgorithm = hashAlgorithm;
            _parameter = parameter;
            _k = Compute_k().ToBigInteger();
            _username = username;
            _password = password;
            _a = a.ToBigInteger();
            _A = Compute_A(_a);
        }


        BigInteger Compute_S(BigInteger B, BigInteger v, BigInteger u, BigInteger a)
        {
            return BigInteger.ModPow((B - (_k * v )), (a + (u * _x)), _parameter.PrimeNumber);
        }


        public Session ProcessChallenge(VerificationChallenge challenge)
        {
            
            _s = challenge.ServerKey;
            _B = challenge.PublicEphemeralKey.ToBigInteger();

            if (_B % _parameter.PrimeNumber == 0) 
            {
                throw new Exception("Mod B % PrimeNumber could not be 0");
            }

            _u = Compute_u(_A, _B.ToByteArray()).ToBigInteger();

            if(_u == 0)
            {
                throw new Exception("u could not be 0");
            }

            _x = Compute_x(_s, _username, _password).ToBigInteger();
            _v = Compute_v(_x);
            _S = Compute_S(_B, _v, _u, _a);
            _K = Compute_K(_S.ToByteArray());
            _M = Compute_M(_username, _s, _A, _B.ToByteArray(), _K);
            _HMAK = Compute_HAMK(_A, _M, _K);

            var session = new Session()
            {
                Key = _M
            };

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

        public VerificationKey CreateVerificationKey()
        {
            var v = new VerificationKey
            {
                Salt = _a.ToByteArray(),
                Username = _username
            };

            var x = Compute_x(v.Salt, _username, _password);
            v.PasswordVerifier = Compute_v(x.ToBigInteger()).ToByteArray();
            _verificationKey = v;
            return _verificationKey;
        }

        public void VerifySession(HAMK hamk)
        {
            _isAuthenticated |= _HMAK == hamk.Key;
        }
    }
}
