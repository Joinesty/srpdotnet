using System.Security.Cryptography;
using System.Text;
using System.Linq;
using SRPDotNet.Parameters;
using System.Numerics;
using SRPDotNet.Helpers;
using SRPDotNet.Models;

namespace SRPDotNet
{
    public class SecureRemoteProtocol
    {
        readonly SRPParameter _parameter;
        readonly HashAlgorithm _hashAlgorithm;
        byte[] _s;
        VerificationKey _verificationKey;


        public HashAlgorithm HashAlgorithm
        {
            get
            {
                return _hashAlgorithm;
            }
        }

        public HashAlgorithmName HashAlgorithmName
        {
            get
            {
                return _hashAlgorithm.GetHashAlgorithmNameFromHashAlgorithm();
            }
        }


        public SRPParameter Parameter
        {
            get
            {
                return _parameter;
            }
        }

        public VerificationKey CreateVerificationKey(string username, string password)
        {
            _s = GetRandomNumber().ToBytes();

            var v = new VerificationKey
            {
                Salt = _s.ByteArrayToString(),
                Username = username
            };

            var x = Compute_x(_s, username, password);
            v.Verifier = Compute_v(x.ToBigInteger()).ToBytes().ByteArrayToString();
            _verificationKey = v;
            return _verificationKey;
        }



        public SecureRemoteProtocol(HashAlgorithm hashAlgorithm, SRPParameter parameter)
        {
            _hashAlgorithm = hashAlgorithm;
            _parameter = parameter;
        }

        /// <summary>
        /// x = H(s | H(I | ":" | P))
        /// </summary>
        /// <returns>The multiplier.</returns>
        /// <param name="salt">Salt, this is the s value.</param>
        /// <param name="username">Username, this is the I value</param>
        /// <param name="password">Password, this is the P value</param>
        protected byte[] Compute_x(byte[] salt, string username, string password)
        {
            return _hashAlgorithm.ComputeHash(salt.Concat(
                _hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(username + ":" + password))
            ).ToArray());
        }

        /// <summary>
        /// v = g^x % N
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        protected BigInteger Compute_v(BigInteger x)
        {
            return BigInteger.ModPow(_parameter.Generator, x, _parameter.PrimeNumber);
        }


        /// <summary>
        /// Computes the M H(H(N) XOR H(g) | H(I) | s | A | B | K)
        /// </summary>
        /// <returns>The m.</returns>
        /// <param name="username">Username.</param>
        /// <param name="salt">Salt.</param>
        /// <param name="A">A.</param>
        /// <param name="B">B.</param>
        /// <param name="K">K.</param>
        protected byte[] Compute_M(string username, byte[] salt, byte[] A,
                                   byte[] B, byte[] K)
        {
            byte[] hashPrimeNumber = _hashAlgorithm.ComputeHash(
                _parameter.PrimeNumber.ToBytes());
            byte[] hashGenerator= _hashAlgorithm.ComputeHash(
                _parameter.Generator.ToBytes());

            for (int i = 0; i < hashPrimeNumber.Length; i++)
            {
                hashPrimeNumber[i] ^= hashGenerator[i];
            }

            byte[] hashUsername = _hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(username));

            return _hashAlgorithm.ComputeHash(hashPrimeNumber.Concat(hashUsername)
                                              .Concat(salt)
                                              .Concat(A)
                                              .Concat(B)
                                              .Concat(K).ToArray());
        }

        protected byte[] Compute_HAMK(byte[] A, byte[] M, byte[] K)
        {
            return _hashAlgorithm.ComputeHash(A.Concat(M).Concat(K).ToArray());
        }

        /// <summary>
        /// K = H_Interleave(S)
        /// </summary>
        /// <param name="S"></param>
        /// <returns></returns>
        protected byte[] Compute_K(byte[] S)
        {
            return _hashAlgorithm.ComputeHash(S);
        }


        byte[] Pad(byte[] value)
        {
            var result = new byte[_parameter.KeyLength / 8];
            value.CopyTo(result, result.Length - value.Length);
            return result;
        }


        /// <summary>
        /// k = H(N | PAD(g))
        /// </summary>
        /// <returns></returns>
        protected byte[] Compute_k()
        {
            byte[] padded_g = Pad(_parameter.Generator.ToBytes());
            return _hashAlgorithm.ComputeHash(_parameter.PrimeNumber.ToBytes()
                                              .Concat(padded_g).ToArray());
        }

        /// <summary>
        /// u = H(PAD(A) | PAD(B))
        /// </summary>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <returns></returns>
        protected byte[] Compute_u(byte[] A, byte[] B)
        {
            byte[] paddedA = Pad(A);
            byte[] paddedB = Pad(B);
            return _hashAlgorithm.ComputeHash(paddedA.Concat(paddedB).ToArray());
        }


        /// <summary>
        /// B = k*v + g^b % N
        /// </summary>
        /// <param name="v"></param>
        /// <param name="k"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        protected BigInteger Compute_B(BigInteger v, BigInteger k, BigInteger b)
        {
            return (k * v + BigInteger.ModPow(
                _parameter.Generator, b, _parameter.PrimeNumber)
                   ) % _parameter.PrimeNumber;
        }

        /// <summary>
        /// A = g^a % N
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        protected byte[] Compute_A(BigInteger a)
        {
            return BigInteger.ModPow(_parameter.Generator, 
                                     a, _parameter.PrimeNumber).ToBytes();
        }


        public static BigInteger GetRandomNumber()
        {
            var randomData = new byte[32];

            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(randomData);
            }

            return randomData.ToBigInteger();
        }

    }
}
