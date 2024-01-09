using DataJuggler.Cryptography;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Hanssens.Net.Helpers
{
    /// <summary>
    /// Helpers for encrypting and decrypting.
    /// </summary>
    /// <remarks>
    /// Originally inspired by https://msdn.microsoft.com/en-us/library/system.security.cryptography.aesmanaged(v=vs.110).aspx
    /// (although changed substantially due to *not* using Rijndael)
    /// </remarks>
    internal class CryptographyHelpers
    {
        internal static string Decrypt(string password, string encrypted_value)
        {
            return CryptographyHelper.DecryptString(encrypted_value, password);
        }

        internal static string Encrypt(string password, string plain_text)
        {
            return CryptographyHelper.EncryptString(plain_text, password);
        }

        //private static byte[] ToByteArray(string input)
        //{
        //     // note: the Convert.FromBase64String function
        //     // does not accept certain characters, like '-',
        //     // so strip these out first
        //    var valid_base64 = input.Replace('-', '+');
        //    return Convert.FromBase64String(valid_base64);
        //}

        //private static Tuple<byte[], byte[]> GetAesKeyAndIV(string password, string salt, SymmetricAlgorithm symmetricAlgorithm)
        //{
        //    // inspired by @troyhunt: https://www.troyhunt.com/owasp-top-10-for-net-developers-part-7/
        //    const int bits = 8;
        //    var key = new byte[16];
        //    var iv = new byte[16];

        //    var derive_bytes = new Rfc2898DeriveBytes(password, ToByteArray(salt), 10000, HashAlgorithmName.SHA512);

        //    key = derive_bytes.GetBytes(symmetricAlgorithm.KeySize / bits);
        //    iv = derive_bytes.GetBytes(symmetricAlgorithm.BlockSize / bits);

        //    return new Tuple<byte[], byte[]>(key, iv);
        //}

    }
}