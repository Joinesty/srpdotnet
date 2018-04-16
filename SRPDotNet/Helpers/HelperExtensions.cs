using System;
using System.Numerics;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Xml;


namespace SRPDotNet.Helpers
{
    public static class HelperExtensions
    {
        public static bool CheckEquals(this byte[] source, byte[] target)
        {
            return source.SequenceEqual(target);
        }


        public static byte[] ToByteArray(this string hexString)
        {
            return StringToByteArray(hexString);
        }


        public static BigInteger ToBigInteger(this byte[] data)
        {
            return new BigInteger(data.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        public static string ByteArrayToString(this byte[] byteArray)
        {
            return BitConverter.ToString(byteArray).Replace("-","");
        }

        public static byte[] StringToByteArray(this string hex)
        {
            hex = hex.Replace(" ", "");
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
                
            return bytes;
        }

        public static byte[] ToBytes(this BigInteger value)
        {
            var valueArray = value.ToByteArray();

            if (valueArray[valueArray.Length - 1] != 0)
            {
                Array.Reverse(valueArray);
                return valueArray;
            }

            var result = new byte[valueArray.Length - 1];
            Array.Copy(valueArray, result, valueArray.Length - 1);
            Array.Reverse(result);
            return result;
        }

        public static HashAlgorithmName GetHashAlgorithmNameFromHashAlgorithm(this HashAlgorithm hash)
        {
            switch (hash.ToString())
            {
                case "System.Security.Cryptography.HMACMD5":
                    return HashAlgorithmName.MD5;

                case "System.Security.Cryptography.HMACSHA1":
                    return HashAlgorithmName.SHA1;

                case "System.Security.Cryptography.HMACSHA256":
                    return HashAlgorithmName.SHA256;

                case "System.Security.Cryptography.HMACSHA384":
                    return HashAlgorithmName.SHA384;

                case "System.Security.Cryptography.HMACSHA512":
                    return HashAlgorithmName.SHA512;

                default:
                    return HashAlgorithmName.SHA512;

            }
        }

    }
}
