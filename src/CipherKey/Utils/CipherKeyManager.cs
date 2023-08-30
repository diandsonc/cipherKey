using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CipherKey.Utils
{
    /// <summary>
    /// Provides key management and cryptographic operations for the CipherKey system.
    /// </summary>
    public static partial class CipherKeyManager
    {
        /// <summary>
        /// Generates a new API key for a specified purpose.
        /// </summary>
        /// <param name="name">The name or purpose of the API key.</param>
        /// <returns>The generated API key.</returns>
        public static string GenerateApiKey(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("Key name cannot be null or empty.");
            }

            using (var sha256 = SHA256.Create())
            {
                var nameBytes = Encoding.UTF8.GetBytes(name);
                var hashBytes = sha256.ComputeHash(nameBytes);

                var hexHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                var formattedKey = MyRegex().Replace(hexHash[..31], @"$1-$2-$3-$4-$5");

                return formattedKey;
            };
        }

        /// <summary>
        /// Generate a new secret key with the specified size, up to a maximum of 512 bytes.
        /// </summary>
        /// <param name="size">The size of the secret key to generate.</param>
        /// <returns>The generated secret key.</returns>
        public static string GenerateSecretKey(int size)
        {
            if (size <= 0 || size > 512)
            {
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be between 1 and 512.");
            }

            const string allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var secretKey = new char[size];

            using (var rng = RandomNumberGenerator.Create())
            {
                for (var i = 0; i < size; i++)
                {
                    byte[] randomBytes = new byte[4];
                    rng.GetBytes(randomBytes);
                    int randomIndex = Math.Abs(BitConverter.ToInt32(randomBytes, 0)) % allowedChars.Length;
                    secretKey[i] = allowedChars[randomIndex];
                }
            }

            return new string(secretKey);
        }

        /// <summary>
        /// Encrypts text using the provided encryption key and initialization vector (IV).
        /// </summary>
        /// <param name="text">The text to be encrypted.</param>
        /// <param name="encryptionKey">The encryption key to use.</param>
        /// <param name="encryptionIV">The initialization vector (IV) for encryption.</param>
        /// <returns>The encrypted text.</returns>
        public static string Encrypt(string text, string encryptionKey, string encryptionIV)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey) || encryptionKey.Length < 32)
            {
                throw new ArgumentException("Encryption key must be at least 32 characters long.");
            }

            if (string.IsNullOrWhiteSpace(encryptionIV) || encryptionIV.Length < 16)
            {
                throw new ArgumentException("Encryption IV must be at least 16 characters long.");
            }

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encryptionKey[..32]);
                aesAlg.IV = Encoding.UTF8.GetBytes(encryptionIV[..16]);
                aesAlg.Padding = PaddingMode.ISO10126;

                byte[] encryptedBytes;
                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(text);
                            };

                            encryptedBytes = msEncrypt.ToArray();
                        };
                    };
                };

                string base64Encrypted = Convert.ToBase64String(encryptedBytes);
                byte[] hashBytes = ComputeHashBytes(base64Encrypted, encryptionKey);

                string base64EncodedHash = Convert.ToBase64String(hashBytes);

                return base64EncodedHash + base64Encrypted;
            }
        }

        /// <summary>
        /// Decrypts encrypted text using the provided encryption key and initialization vector (IV).
        /// </summary>
        /// <param name="encryptedText">The encrypted text to be decrypted.</param>
        /// <param name="encryptionKey">The encryption key to use.</param>
        /// <param name="encryptionIV">The initialization vector (IV) for decryption.</param>
        /// <returns>The decrypted text.</returns>
        public static string Decrypt(string encryptedText, string encryptionKey, string encryptionIV)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey) || encryptionKey.Length < 32)
            {
                throw new ArgumentException("Encryption key must be at least 32 characters long.");
            }

            if (string.IsNullOrWhiteSpace(encryptionIV) || encryptionIV.Length < 16)
            {
                throw new ArgumentException("Encryption IV must be at least 16 characters long.");
            }

            string base64EncodedHash = encryptedText[..44];
            string base64Encrypted = encryptedText[44..];

            byte[] computedHashBytes = ComputeHashBytes(base64Encrypted, encryptionKey);

            if (!ByteArraysEqual(Convert.FromBase64String(base64EncodedHash), computedHashBytes))
            {
                throw new SecurityException("Data integrity compromised. Hash mismatch.");
            }

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encryptionKey[..32]);
                aesAlg.IV = Encoding.UTF8.GetBytes(encryptionIV[..16]);
                aesAlg.Padding = PaddingMode.ISO10126;

                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                {
                    var encryptedBytes = Convert.FromBase64String(base64Encrypted);
                    using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            };
                        };
                    };
                };
            };
        }

        private static byte[] ComputeHashBytes(string input, string key)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
            };
        }

        private static bool ByteArraysEqual(byte[] a1, byte[] a2)
        {
            if (a1.Length != a2.Length)
            {
                return false;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                if (a1[i] != a2[i])
                {
                    return false;
                }
            }

            return true;
        }

        [GeneratedRegex("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{11})")]
        private static partial Regex MyRegex();
    }
}
