using System.Security.Cryptography;
using Java.Security;
using Java.Security.Spec;
using Java.Lang;
using Java.Math;
using Java.Util;
using Android.Util;

namespace DotNetDroidUtils
{
    /// <summary>
    /// Cryptography utilities optimized for Android environment
    /// </summary>
    public static class Cryptography
    {
        /// <summary>
        /// Generates an RSA keypair of the provided length using Java libraries
        /// and configures an RSACryptoServiceProvider with them for ease of use with .NET systems.
        /// This is much more performant than generating keys directly from an RSACryptoServiceProvider
        /// when running on an Android system.
        /// </summary>
        /// <returns></returns>
        public static RSACryptoServiceProvider GenerateRsaKeyPair(int keySize = 2048)
        {
            //Generate an RSA key-pair of the provided size. This approach is as fast as anything I have found for Android devices.
            //On a Nexus 6P, this code consistently creates a 2048-bit key-pair in less than 10 seconds while standard .NET libraries 
            //and BouncyCastle all took anywhere from 10 - 30 seconds.
            var keyPairGenerator = KeyPairGenerator.GetInstance("RSA");
            keyPairGenerator.Initialize(keySize);
            var keys = keyPairGenerator.GenerateKeyPair();
            KeyFactory kf = KeyFactory.GetInstance("RSA");
            var spec = (RSAPrivateCrtKeySpec)kf.GetKeySpec(keys.Private, Class.FromType(typeof(RSAPrivateCrtKeySpec)));

            //Create an Xml node for the provided element name using the provided number in Base64-string format as its value
            string FormatElement(string name, BigInteger value)
            {
                var bytes = value.ToByteArray();
                int length = bytes.Length;
                if (length % 2 != 0 && bytes[0] == 0) //BigInteger is signed, so remove the extra byte
                    bytes = Arrays.CopyOfRange(bytes, 1, length);
                var content = Base64.EncodeToString(bytes, Base64Flags.Default);

                return $"<{name}>{content}</{name}>";
            }

            //Create an XML version of the private key
            var stb = new System.Text.StringBuilder();
            stb.Append("<RSAKeyValue>");
            stb.Append(FormatElement("Modulus", spec.Modulus));
            stb.Append(FormatElement("Exponent", spec.PublicExponent));
            stb.Append(FormatElement("P", spec.PrimeP));
            stb.Append(FormatElement("Q", spec.PrimeQ));
            stb.Append(FormatElement("DP", spec.PrimeExponentP));
            stb.Append(FormatElement("DQ", spec.PrimeExponentQ));
            stb.Append(FormatElement("InverseQ", spec.CrtCoefficient));
            stb.Append(FormatElement("D", spec.PrivateExponent));
            stb.Append("</RSAKeyValue>");
            var privateKeyXml = stb.ToString();

            //Configure an RSACryptoServiceProvider using the generated key XML
            var rsaCryptoServiceProvider = new RSACryptoServiceProvider(keySize);
            rsaCryptoServiceProvider.FromXmlString(privateKeyXml);

            return rsaCryptoServiceProvider;
        }
    }
}
