using System.Numerics;
using System.Security.Cryptography;
using SRPDotNet.Helpers;
using SRPDotNet.Parameters;
using SRPDotNet.Models;


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

        public User(string username, string password, HashAlgorithm hashAlgorithm, SRPParameter parameter, byte[] a) :
        base(hashAlgorithm, parameter)
        {
            _k = Compute_k().ToBigInteger();
            _username = username;
            _hashAlgorithm = hashAlgorithm;
            _A = Compute_A(a.ToBigInteger());
            _a = a.ToBigInteger();
            _password = password;
            _parameter = parameter;
        }



       /// <summary>
        /// Computes the S = (A * v^u) ^ b % N 
       /// </summary>
       /// <returns>The s.</returns>
       /// <param name="B">B.</param>
       /// <param name="v">V.</param>
       /// <param name="u">U.</param>
       /// <param name="a">The alpha component.</param>
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
                return null;
            }

            _u = Compute_u(_A, _B.ToByteArray()).ToBigInteger();

            if(_u == 0)
            {
                return null;
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
