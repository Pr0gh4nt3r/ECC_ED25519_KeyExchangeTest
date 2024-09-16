using ECC_ED25519;
using System.Numerics;

public class KeyExchangeAndEncryption
{
    public static void Main()
    {
        // Partei 1 erzeugt ihren Schlüssel
        Ed25519 party1 = new();
        Console.WriteLine("Party 1 Private Key: " + party1.PrivateKey);
        Console.WriteLine("Party 1 Public Key: (" + party1.PublicKey[0] + ", " + party1.PublicKey[1] + ")");

        // Partei 2 erzeugt ihren Schlüssel
        Ed25519 party2 = new();
        Console.WriteLine("\nParty 2 Private Key: " + party2.PrivateKey);
        Console.WriteLine("Party 2 Public Key: (" + party2.PublicKey[0] + ", " + party2.PublicKey[1] + ")");

        // Beide Parteien berechnen den gemeinsamen Schlüssel
        BigInteger[] aliceSharedSecret = Ed25519.CalculateSharedSecret(party1.PrivateKey, party2.PublicKey);
        BigInteger[] bobSharedSecret = Ed25519.CalculateSharedSecret(party2.PrivateKey, party1.PublicKey);

        // Überprüfe, ob die gemeinsamen Geheimnisse gleich sind
        bool secretsMatch = aliceSharedSecret[0] == bobSharedSecret[0] && aliceSharedSecret[1] == bobSharedSecret[1];

        // Stellen sicher, dass die gemeinsamen Geheimnisse übereinstimmen
        if (secretsMatch)
        {
            Console.WriteLine("\nShared secret keys match!");

            // Ableitung des AES-Schlüssels aus dem Shared Secret
            byte[] aesKey = SymmetricEncryption.DeriveAesKeyFromSharedSecret(aliceSharedSecret);
            Console.WriteLine("AES Key: " + BitConverter.ToString(aesKey));

            // Partei 1 verschlüsselt eine Nachricht
            string originalMessage = "Hello Party 2, this is Party 1!";
            Console.WriteLine("\nOriginal Message: " + originalMessage);
            byte[] encryptedMessage = SymmetricEncryption.Encrypt(originalMessage, aesKey);
            Console.WriteLine("Encrypted Message: " + BitConverter.ToString(encryptedMessage));

            // Partei 2 entschlüsselt die Nachricht
            string decryptedMessage = SymmetricEncryption.Decrypt(encryptedMessage, aesKey);
            Console.WriteLine("Decrypted Message: " + decryptedMessage);
        }
        else
        {
            Console.WriteLine("Shared secret keys do not match!");
        }
    }
}