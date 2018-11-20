using System;
using System.IO;
using System.Security.Cryptography;

namespace Ballance.SimpleCryptoLib
{
    public class SimpleCryptoElf
    {
        private const int IvLength = 16;

        public static string EncryptString(string plainText, string key)
        {
            using (var cipherAlgo = CryptoBuilder())
            {
                cipherAlgo.Key = Convert.FromBase64String(key);
                cipherAlgo.GenerateIV();

                var encrypted = EncryptStringToBytes(plainText, cipherAlgo.Key);

                return Convert.ToBase64String(encrypted);
            }
        }

        public static string DecryptString(string encryptedString, string key)
        {
            return DecryptStringFromBytes(
                Convert.FromBase64String(encryptedString),
                Convert.FromBase64String(key)
            );
        }

        private static byte[] EncryptStringToBytes(string plainText, byte[] key)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));

            using (var algo = CryptoBuilder())
            {
                algo.Key = key;
                algo.GenerateIV();

                var encryptor = algo.CreateEncryptor(algo.Key, algo.IV);

                byte[] encrypted;
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                return AddIv(encrypted, algo.IV);
            }
        }

        private static string DecryptStringFromBytes(byte[] cipherText, byte[] key)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));

            string plaintext = null;

            using (var algo = CryptoBuilder())
            {
                algo.Key = key;
                algo.IV = GetIv(cipherText);

                var decryptor = algo.CreateDecryptor(algo.Key, algo.IV);
                var withoutIv = RemoveIv(cipherText);
                using (var memoryStream = new MemoryStream(withoutIv))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var decSr = new StreamReader(cryptoStream))
                        {
                            plaintext = decSr.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (var i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    return false;

            return true;
        }

        private static byte[] RemoveIv(byte[] withIv)
        {
            var withoutIv = new byte[withIv.Length - IvLength];
            Array.Copy(withIv, IvLength, withoutIv, 0, withIv.Length - IvLength);
            return withoutIv;
        }

        private static byte[] AddIv(byte[] withoutIv, byte[] iv)
        {
            var encryptedWithIv = new byte[withoutIv.Length + IvLength];
            Array.Copy(iv, encryptedWithIv, IvLength);
            Array.Copy(withoutIv, 0, encryptedWithIv, IvLength, withoutIv.Length);
            return encryptedWithIv;
        }

        private static byte[] GetIv(byte[] arr)
        {
            var iv = new byte[IvLength];
            Array.Copy(arr, 0, iv, 0, IvLength);
            return iv;
        }

        private static RijndaelManaged CryptoBuilder()
        {
            var algo = new RijndaelManaged
            {
                Padding = PaddingMode.PKCS7,
                BlockSize = 128,
                KeySize = 128,
                Mode = CipherMode.CBC,
            };
            return algo;
        }
    }
}
