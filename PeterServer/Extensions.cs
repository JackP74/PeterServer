using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PeterServer;

static internal class Extensions
{
    private static readonly string privateKeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privateKey.xml");
    private static readonly string publicKeyPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "publicKey.xml");

    /// <summary>
    /// Encrypts a string using an RSA public key.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="publicKeyXml">The XML string of the RSA public key.</param>
    /// <returns>The encrypted data as a Base64 string.</returns>
    public static string Encrypt(string plainText, string? publicKeyXml = null)
    {
        using RSA rsa = RSA.Create(2048);

        try
        {
            rsa.FromXmlString(File.ReadAllText(publicKeyXml ?? publicKeyPath));
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes = rsa.Encrypt(plainTextBytes, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(encryptedBytes);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());
            return null;
        }
    }

    /// <summary>
    /// Decrypts a string using an RSA private key.
    /// </summary>
    /// <param name="encryptedText">The Base64 encrypted string.</param>
    /// <param name="privateKeyXml">The XML string of the RSA private key.</param>
    /// <returns>The decrypted plaintext string.</returns>
    public static string Decrypt(string encryptedText, string? privateKeyXml = null)
    {
        using RSA rsa = RSA.Create(2048);

        try
        {
            rsa.FromXmlString(File.ReadAllText(privateKeyXml ?? privateKeyPath));
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.ToString());
            return null;
        }
    }
}