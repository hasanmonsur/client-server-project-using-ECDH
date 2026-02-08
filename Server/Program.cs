// See https://aka.ms/new-console-template for more information
using Shared;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Hello, World!");


const int Port = 5000;

    var listener = new TcpListener(IPAddress.Loopback, Port);
    listener.Start();
    Console.WriteLine($"Server listening on 127.0.0.1:{Port}...");

    while (true)
    {
        using var client = listener.AcceptTcpClient();
        Console.WriteLine("Client connected.");
        using var ns = client.GetStream();
        using var br = new BinaryReader(ns, Encoding.UTF8, leaveOpen: true);
        using var bw = new BinaryWriter(ns, Encoding.UTF8, leaveOpen: true);

        // Create server ECDH key pair
        using var serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var serverPubBlob = CryptoUtils.ExportPublicParameters(serverEcdh);

        // Send server public parameters
        bw.Write(serverPubBlob.Length);
        bw.Write(serverPubBlob);
        bw.Flush();

        // Receive client public parameters
        var clientPubLen = br.ReadInt32();
        var clientPubBlob = br.ReadBytes(clientPubLen);
        var clientParams = CryptoUtils.ImportPublicParameters(clientPubBlob);

        // Create an ECDH object representing the client's public key (public-only)
        using var clientPubEcdh = ECDiffieHellman.Create(clientParams);

        // Derive shared secret
        var shared = serverEcdh.DeriveKeyMaterial(clientPubEcdh.PublicKey);
        var aesKey = CryptoUtils.DeriveAesKey(shared);

        Console.WriteLine("Shared key established (server).");

        // Read encrypted message from client (length-prefixed payload)
        var payloadLen = br.ReadInt32();
        var payload = br.ReadBytes(payloadLen);
        CryptoUtils.ParseAesGcmPayload(payload, out var nonce, out var tag, out var ciphertext);

        var plaintext = CryptoUtils.DecryptAesGcm(aesKey, nonce, ciphertext, tag);
        Console.WriteLine("Received (decrypted): " + Encoding.UTF8.GetString(plaintext));

        // Reply to client
        var reply = Encoding.UTF8.GetBytes("Hello from server");
        var (rNonce, rCt, rTag) = CryptoUtils.EncryptAesGcm(aesKey, reply);
        var replyPayload = CryptoUtils.BuildAesGcmPayload(rNonce, rTag, rCt);

        bw.Write(replyPayload.Length);
        bw.Write(replyPayload);
        bw.Flush();

        Console.WriteLine("Reply sent, closing connection.\n");
    }
