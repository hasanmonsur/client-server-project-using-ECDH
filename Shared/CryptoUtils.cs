using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Shared
{
    public static class CryptoUtils
    {
        private const string CurveName = "nistP256";
        private const int AesGcmNonceSize = 12;
        private const int AesGcmTagSize = 16;

        // Export public ECParameters (curve + Q.X + Q.Y) into a simple binary format.
        public static byte[] ExportPublicParameters(ECDiffieHellman ecdh)
        {
            var p = ecdh.ExportParameters(false);
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

            bw.Write(CurveName);
            bw.Write(p.Q.X.Length);
            bw.Write(p.Q.X);
            bw.Write(p.Q.Y.Length);
            bw.Write(p.Q.Y);

            return ms.ToArray();
        }

        // Reconstruct ECParameters from the binary format (supports nistP256 in this sample).
        public static ECParameters ImportPublicParameters(byte[] blob)
        {
            using var ms = new MemoryStream(blob);
            using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);

            var curveName = br.ReadString();
            if (curveName != CurveName)
                throw new NotSupportedException($"Only curve {CurveName} is supported in this sample.");

            var xLen = br.ReadInt32();
            var x = br.ReadBytes(xLen);
            var yLen = br.ReadInt32();
            var y = br.ReadBytes(yLen);

            var ec = new ECParameters
            {
                Q = new ECPoint { X = x, Y = y },
                Curve = ECCurve.NamedCurves.nistP256
            };
            return ec;
        }

        // Derive a 32-byte AES key from the raw shared secret using SHA-256.
        public static byte[] DeriveAesKey(byte[] sharedSecret)
        {
            return SHA256.HashData(sharedSecret); // 32 bytes
        }

        // Encrypt with AES-GCM. Returns payload: nonce|tag|ciphertext (separated in output tuple as arrays).
        public static (byte[] nonce, byte[] ciphertext, byte[] tag) EncryptAesGcm(byte[] key, byte[] plaintext, byte[]? associatedData = null)
        {
            var nonce = RandomNumberGenerator.GetBytes(AesGcmNonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[AesGcmTagSize];

            using var aes = new AesGcm(key);
            if (associatedData is null)
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            else
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            return (nonce, ciphertext, tag);
        }

        // Decrypt AES-GCM from nonce, ciphertext, tag.
        public static byte[] DecryptAesGcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[]? associatedData = null)
        {
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key);
            if (associatedData is null)
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            else
                aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            return plaintext;
        }

        // Helpers to frame messages: nonce|tag|ciphertext into a single buffer for sending.
        public static byte[] BuildAesGcmPayload(byte[] nonce, byte[] tag, byte[] ciphertext)
        {
            var buffer = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, buffer, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, buffer, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, buffer, nonce.Length + tag.Length, ciphertext.Length);
            return buffer;
        }

        public static void ParseAesGcmPayload(byte[] payload, out byte[] nonce, out byte[] tag, out byte[] ciphertext)
        {
            nonce = new byte[AesGcmNonceSize];
            tag = new byte[AesGcmTagSize];
            Buffer.BlockCopy(payload, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(payload, nonce.Length, tag, 0, tag.Length);
            var ctLen = payload.Length - nonce.Length - tag.Length;
            ciphertext = new byte[ctLen];
            Buffer.BlockCopy(payload, nonce.Length + tag.Length, ciphertext, 0, ctLen);
        }
    }
}
