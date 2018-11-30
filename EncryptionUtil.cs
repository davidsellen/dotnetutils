using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Utils
{
    public interface IEncryptionUtil
    {
        string Decrypt(string text);
        string Encrypt(string clearText);
    }
    
    public class EncryptionUtil : IEncryptionUtil
    {
        private const int _saltSize = 10;
        private const int _iterations = 10000;
        private const string _prefix = "Encr:V1:";

        private readonly string _entryptionKey;

        public static IEncryptionUtil Create()
        {
            return new EncryptionUtil("This is my private key");
        }
        
        internal EncryptionHelper(string encryptionKey)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey))
            {
                throw new ArgumentNullException("encryptionKey");
            }

            _entryptionKey = encryptionKey;
        }

        public string Encrypt(string clearText)
        {

            if (string.IsNullOrWhiteSpace(clearText))
            {
                return clearText;
            }

            if (clearText.StartsWith(_prefix))
            {
                return clearText;
            }

            /* Create the salt value with a cryptographic PRNG */
            byte[] salt;

            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(salt = new byte[_saltSize]);
            }

            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_entryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }

                    byte[] hash = ms.ToArray();

                    int size = hash.Length + salt.Length;

                    byte[] allbBytes = new byte[size];

                    Array.Copy(salt, 0, allbBytes, 0, salt.Length);
                    Array.Copy(hash, 0, allbBytes, salt.Length, hash.Length);

                    var base64 = Convert.ToBase64String(allbBytes);

                    return _prefix + base64;
                }
            }
        }

        public string Decrypt(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return text;
            }

            if (!text.StartsWith(_prefix))
            {
                return text;
            }

            var cipherText = text.Substring(_prefix.Length);

            byte[] allbytes = Convert.FromBase64String(cipherText);

            byte[] salt = new byte[_saltSize];

            Array.Copy(allbytes, 0, salt, 0, _saltSize);

            byte[] cypherBytes = new byte[allbytes.Length - _saltSize];

            Array.Copy(allbytes, _saltSize, cypherBytes, 0, cypherBytes.Length);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_entryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cypherBytes, 0, cypherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return cipherText;
        }
    }
}
