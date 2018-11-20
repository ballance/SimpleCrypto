using System;
using System.IO;

namespace Ballance.SimpleCrypto
{
    class Program
    {
        private static string testKey = "5VZdbHeberJ2FabDNLs1Zw==";

        static void Main(string[] args)
        {
            Console.WriteLine("Starting up.");
            
            //var plainText = "The quick brown fox jumps over the lazy dog.";
            var plainText = File.ReadAllText("plainText.txt");

            Console.WriteLine("Plaintext is:");
            Console.WriteLine(plainText);
            Console.WriteLine();
            var encryptedString = SimpleCryptoElf.EncryptString(plainText, testKey);
            
            Console.WriteLine("cipherText is:");
            Console.WriteLine(encryptedString);
            Console.WriteLine();

            string decryptedString = SimpleCryptoElf.DecryptString(encryptedString, testKey);
            
            Console.WriteLine("decrypted text is:");
            Console.WriteLine(decryptedString);
            Console.WriteLine();

            Console.WriteLine("Done.");

            Console.WriteLine(plainText.Equals(decryptedString) ? "Great success!" : "Epic Fail!");
            Console.ReadKey();
        }
    }
}
