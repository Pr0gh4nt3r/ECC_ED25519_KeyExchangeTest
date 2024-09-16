using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ECC_ED25519
{
    public class Ed25519
    {
        // Modulus for the prime field
        private static readonly BigInteger CurveP = BigInteger.Pow(2, 255) - 19;

        // Ed25519 base point in BigEndian (x, y)
        BigInteger[] G = {
            BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
            BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033651085030581511"),
        };

        // Curve parameter d
        private static readonly BigInteger D = new BigInteger(-121665) * ModInverse(121666, CurveP) % CurveP;

        private BigInteger privateKey;
        private BigInteger[] publicKey;

        // Constructor that generates a random private key
        public Ed25519()
        {
            privateKey = GeneratePrivateKey();
            publicKey = ScalarMultiplication(privateKey, G);

            bool isPointOnCurve = IsPointOnCurve(PublicKey);

            if (isPointOnCurve)
            {
                return;
            }
            else
            {
                throw new Exception("Der errechnete Punkt liegt nicht auf der Kurve!");
            }
        }

        public BigInteger PrivateKey => privateKey;
        public BigInteger[] PublicKey => publicKey;

        private static BigInteger ByteArrayToBigInteger(byte[] byteArray)
        {
            // Konvertiere das Byte-Array in einen Hex-String
            string hexString = BitConverter.ToString(byteArray).Replace("-", "");

            // Interpretiere den Hex-String als BigInteger
            // Wir setzen das `NumberStyles.AllowHexSpecifier` Flag, um die Hex-Darstellung zu parsen
            return BigInteger.Parse(hexString, System.Globalization.NumberStyles.AllowHexSpecifier);
        }

        // Generate a random 256-bit private key (Ed25519 private key should be 32 bytes, and clamped according to the Ed25519 standard)
        private static BigInteger GeneratePrivateKey()
        {
            byte[] keyBytes = new byte[32]; // 256 bits = 32 bytes

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(keyBytes);
            }

            // Clamp the key as per Ed25519 specification
            keyBytes[0] &= 248;
            keyBytes[31] &= 127;
            keyBytes[31] |= 64;

            // Konvertiere das Byte-Array in einen BigInteger
            BigInteger privateKey = ByteArrayToBigInteger(keyBytes);

            // Stelle sicher, dass der privateKey positiv ist
            if (privateKey < 0)
            {
                privateKey += CurveP; // Mach es positiv, falls es negativ ist
            }

            // Reduziere den privaten Schlüssel modulo CurveP, um sicherzustellen, dass er im gültigen Bereich ist
            return privateKey % CurveP;
        }

        // Helper function: Modular inverse using extended Euclidean algorithm
        private static BigInteger ModInverse(BigInteger a, BigInteger mod)
        {
            BigInteger m0 = mod, q, t;
            BigInteger y = 0, x = 1;

            if (mod == 1)
                return 0;

            while (a > 1)
            {
                // q is quotient
                q = a / mod;
                t = mod;

                // mod is remainder now, process same as Euclid's algo
                mod = a % mod;
                a = t;
                t = y;

                // Update x and y
                y = x - q * y;
                x = t;
            }

            // Make x positive
            if (x < 0)
                x += m0;

            return x;
        }

        // Addition von zwei Punkten auf der elliptischen Kurve
        private static BigInteger[] PointAddition(BigInteger[] P, BigInteger[] Q)
        {
            BigInteger x1 = P[0], y1 = P[1];
            BigInteger x2 = Q[0], y2 = Q[1];

            // Berechne x3 und y3 basierend auf den elliptischen Kurvenoperationen
            BigInteger numeratorX = ((x1 * y2) + (x2 * y1)) % CurveP;
            BigInteger denominatorX = ModInverse(1 + (D * x1 * x2 * y1 * y2), CurveP);
            BigInteger x3 = (numeratorX * denominatorX) % CurveP;

            BigInteger numeratorY = ((y1 * y2) + (x1 * x2)) % CurveP;
            BigInteger denominatorY = ModInverse(1 - (D * x1 * x2 * y1 * y2), CurveP);
            BigInteger y3 = (numeratorY * denominatorY) % CurveP;

            // Ergebnis als neues Punktpaar (x3, y3)
            return new BigInteger[] { x3, y3 };
        }

        // Skalare Multiplikation mit Double-and-Add Methode
        private static BigInteger[] ScalarMultiplication(BigInteger sk, BigInteger[] pk)
        {
            // Überprüfen Sie den privaten Schlüssel
            Console.WriteLine("Privater Schlüssel: " + sk);

            BigInteger[] result = { 0, 1 }; // Identitäts-Element auf der Kurve (Punkt auf Unendlich)
            BigInteger[] addend = pk;

            // Schleife, um die skalare Multiplikation durchzuführen
            while (sk > 0)
            {
                // Wenn das niedrigstwertige Bit von k 1 ist, addiere das aktuelle Addend zum Resultat
                if ((sk & 1) == 1)
                {
                    Console.WriteLine("Addiere: " + addend[0] + ", " + addend[1]);
                    result = PointAddition(result, addend);
                    Console.WriteLine("Aktuelles Ergebnis: " + result[0] + ", " + result[1]);
                }

                // Verdopple den Punkt (Addiere ihn zu sich selbst)
                addend = PointDoubling(addend);
                Console.WriteLine("Verdopple: " + addend[0] + ", " + addend[1]);

                // Bit-Shifting: sk >> 1
                sk >>= 1;
            }

            Console.WriteLine("Endergebnis: " + result[0] + ", " + result[1]);
            return result;
        }

        // Punktverdopplung auf der Kurve
        private static BigInteger[] PointDoubling(BigInteger[] P)
        {
            return PointAddition(P, P);
        }

        private static bool IsPointOnCurve(BigInteger[] point)
        {
            BigInteger x = point[0];
            BigInteger y = point[1];

            // Berechnung von y^2 mod curveP
            BigInteger ySquared = (y * y) % CurveP;

            // Berechnung von x^3 + 486662 * x^2 + x mod P
            BigInteger xCubed = (x * x * x) % CurveP;
            BigInteger term1 = (486662 * (x * x)) % CurveP;
            BigInteger term2 = x % CurveP;
            BigInteger curveEquation = (xCubed + term1 + term2) % CurveP;

            // Überprüfung, ob y^2 gleich der Kurvengleichung ist
            return ySquared == curveEquation;
        }

        // Calculate the shared secret using the private key and the public key of the other party
        public static BigInteger[] CalculateSharedSecret(BigInteger ownPrivateKey, BigInteger[] otherPublicKey)
        {
            // Shared secret = (otherPublicKey) ^ (privateKey)
            return ScalarMultiplication(ownPrivateKey, otherPublicKey);
        }
    }
}
