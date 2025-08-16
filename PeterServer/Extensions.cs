using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Diagnostics.CodeAnalysis;
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
    public static string? Encrypt(string plainText, string? publicKeyXml = null)
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
    public static string? Decrypt(string encryptedText, string? privateKeyXml = null)
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

    /// <summary>
    /// Determines if a given type is a nullable value type (e.g., int?, bool?).
    /// </summary>
    /// <param name="input">The System.Type to check.</param>
    /// <returns>True if the type is a nullable value type; otherwise, false.</returns>
    private static bool IsNullable(Type input)
    {
        return Nullable.GetUnderlyingType(input) != null;
    }

    /// <summary>
    /// Serializes an object to its JSON string representation using Newtonsoft.Json.
    /// </summary>
    /// <typeparam name="T">The type of the object to serialize.</typeparam>
    /// <param name="input">The object instance to serialize.</param>
    /// <returns>A JSON string representing the object, or null if serialization fails.</returns>
    /// <remarks>
    /// This method gracefully handles exceptions by catching them and returning null,
    /// preventing crashes from malformed objects.
    /// </remarks>
    public static string? Serialize<T>(T input)
    {
        try
        {
            return JsonConvert.SerializeObject(input);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Deserializes a JSON string into an object of the specified type using Newtonsoft.Json.
    /// </summary>
    /// <typeparam name="T">The type of the object to deserialize to.</typeparam>
    /// <param name="input">The JSON string to deserialize.</param>
    /// <returns>
    /// The deserialized object from the JSON string, or the default value for type T 
    /// (e.g., null for reference types) if deserialization fails.
    /// </returns>
    /// <remarks>
    /// This method gracefully handles exceptions by catching them and returning default(T),
    /// which prevents crashes from invalid or malformed JSON strings.
    /// </remarks>
    public static T? Deserialize<T>(string input)
    {
        try
        {
            return JsonConvert.DeserializeObject<T>(input);
        }
        catch
        {
            return default;
        }
    }

    public static void WriteError(string error)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(error);
        Console.ForegroundColor = ConsoleColor.White;
    }
}