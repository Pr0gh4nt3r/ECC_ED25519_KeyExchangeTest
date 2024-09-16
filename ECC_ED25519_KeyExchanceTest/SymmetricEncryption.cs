using System.Numerics;
using System.Security.Cryptography;

public class SymmetricEncryption
{
    // Erzeugung eines AES-Schlüssels aus dem gemeinsamen Geheimnis
    public static byte[] DeriveAesKeyFromSharedSecret(BigInteger[] sharedSecret)
    {
        // Kombinieren Sie die beiden Koordinaten des Shared Secrets
        byte[] secretBytes = sharedSecret[0].ToByteArray().Concat(sharedSecret[1].ToByteArray()).ToArray();

        // Verwenden Sie SHA-256, um aus dem Shared Secret einen 256-Bit AES-Schlüssel zu erzeugen
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(secretBytes);
        }
    }

    // Verschlüsseln einer Nachricht mit AES
    public static byte[] Encrypt(string plainText, byte[] key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.GenerateIV(); // Initialisierungsvektor (IV) generieren

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // Speichern Sie das IV zuerst
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }

                return msEncrypt.ToArray(); // Zurückgeben des verschlüsselten Bytes inkl. IV
            }
        }
    }

    // Entschlüsseln einer Nachricht mit AES
    public static string Decrypt(byte[] cipherText, byte[] key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                byte[] iv = new byte[16]; // AES-Blockgröße für IV
                msDecrypt.Read(iv, 0, iv.Length); // IV aus dem verschlüsselten Text extrahieren

                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd(); // Rückgabe des entschlüsselten Textes
                    }
                }
            }
        }
    }
}
