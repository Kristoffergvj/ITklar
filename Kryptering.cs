using System;
using System.Text.Json;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace ItSec_ver4
{
    class Kryptering
    {
        public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        
        public static byte[] GenerateIV()
        {
            Aes iv = Aes.Create();
            return iv.IV;
        }
        //genererar en random SecretKey med AES klassen.
        public static byte[] GenerateSecretKey()
        {
            Aes secretkey = Aes.Create();

            return secretkey.Key;

            //RandomNumberGenerator rng = RandomNumberGenerator.Create();
            //byte[] secretkey = new byte[16];

            //return secretkey;
        }

        public static byte[] GenerateVaultKey(string masterpassword, byte[] secretkey)
        {
            Aes Vault = Aes.Create();

            Rfc2898DeriveBytes vaultkey = new Rfc2898DeriveBytes(masterpassword, secretkey);
            Vault.Key = vaultkey.GetBytes(16);

            return Vault.Key;
        }
        //semi

        public static string EncryptVault(Dictionary<string, string> vaultdict, string clientfile, string serverfile, string pwd)
        {
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverfile));
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientfile));

            byte[] iv = Convert.FromBase64String(serverDict["IV"]);
            byte[] secretKey = Convert.FromBase64String(clientDict["Secret key"]);
            byte[] vaultKey = Kryptering.GenerateVaultKey(pwd, secretKey);

            string vaultString = JsonSerializer.Serialize(vaultdict);
            byte[] encryptedVaultBytes = EncryptStringToBytes_Aes(vaultString, vaultKey, iv);
            string encryptedVaultBase64 = Convert.ToBase64String(encryptedVaultBytes);

            return encryptedVaultBase64;
        }
        //semi
        public static string EncryptVault(Dictionary<string, string> vaultdict, string clientfile, string serverfile, string pwd, string secretkey)
        {
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverfile));
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientfile));

            byte[] iv = Convert.FromBase64String(serverDict["IV"]);
            byte[] secretKey = Convert.FromBase64String(secretkey);
            byte[] vaultKey = Kryptering.GenerateVaultKey(pwd, secretKey);

            string vaultString = JsonSerializer.Serialize(vaultdict);
            byte[] encryptedVaultBytes = EncryptStringToBytes_Aes(vaultString, vaultKey, iv);
            string encryptedVaultBase64 = Convert.ToBase64String(encryptedVaultBytes);

            return encryptedVaultBase64;
        }
       
        //semi
        public static string DecryptVault(string clientfile, string serverfile, string pwd)
        {


            //testar med return type string
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientfile));
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverfile));

            byte[] iv = Convert.FromBase64String(serverDict["IV"]);
            byte[] encryptedVaultBytes = Convert.FromBase64String(serverDict["Vault"]);
            byte[] secretKeyBytes = Convert.FromBase64String(clientDict["Secret key"]);
            byte[] vaultKeyBytes = Kryptering.GenerateVaultKey(pwd, secretKeyBytes);

            string decryptedVaultString = DecryptStringFromBytes_Aes(encryptedVaultBytes, vaultKeyBytes, iv);

            // Dictionary<string, string> decryptedVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVaultString);

            return decryptedVaultString;
        }
        public static string DecryptVault(string clientfile, string serverfile, string pwd, string secretkey)
        {


            //testar med return type string
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientfile));
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverfile));

            byte[] iv = Convert.FromBase64String(serverDict["IV"]);
            byte[] encryptedVaultBytes = Convert.FromBase64String(serverDict["Vault"]);
            byte[] secretKeyBytes = Convert.FromBase64String(secretkey);
            byte[] vaultKeyBytes = Kryptering.GenerateVaultKey(pwd, secretKeyBytes);

            string decryptedVaultString = DecryptStringFromBytes_Aes(encryptedVaultBytes, vaultKeyBytes, iv);

            // Dictionary<string, string> decryptedVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVaultString);

            return decryptedVaultString;
        }
        


        //klar
        public static string PasswordGenerator(int length)
        {
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new Random();
            StringBuilder password = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                password.Append(characters[random.Next(characters.Length)]);
            }
            return password.ToString();
        }



    }
}

