// See https://aka.ms/new-console-template for more information
using Shared;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

Console.WriteLine("Hello, World!");
const string Host = "127.0.0.1";
const int Port = 5000;


    using var tcp = new TcpClient();
    tcp.Connect(Host, Port);
    using var ns = tcp.GetStream();
    using var br = new BinaryReader(ns, Encoding.UTF8, leaveOpen: true);
    using var bw = new BinaryWriter(ns, Encoding.UTF8, leaveOpen: true);

    // Create client ECDH key pair
    using var clientEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    var clientPubBlob = CryptoUtils.ExportPublicParameters(clientEcdh);

    // Receive server public parameters
    var serverPubLen = br.ReadInt32();
    var serverPubBlob = br.ReadBytes(serverPubLen);
    var serverParams = CryptoUtils.ImportPublicParameters(serverPubBlob);

    // Send client public parameters
    bw.Write(clientPubBlob.Length);
    bw.Write(clientPubBlob);
    bw.Flush();

    // Create an ECDH object representing server's public key (public-only)
    using var serverPubEcdh = ECDiffieHellman.Create(serverParams);

    // Derive shared secret
    var shared = clientEcdh.DeriveKeyMaterial(serverPubEcdh.PublicKey);
    var aesKey = CryptoUtils.DeriveAesKey(shared);

    Console.WriteLine("Shared key established (client).");

    // Send an encrypted message to server
    var message = Encoding.UTF8.GetBytes("Hello from client");
    var (nonce, ct, tag) = CryptoUtils.EncryptAesGcm(aesKey, message);
    var payload = CryptoUtils.BuildAesGcmPayload(nonce, tag, ct);

    bw.Write(payload.Length);
    bw.Write(payload);
    bw.Flush();

    // Read reply from server
    var replyLen = br.ReadInt32();
    var replyPayload = br.ReadBytes(replyLen);
    CryptoUtils.ParseAesGcmPayload(replyPayload, out var rNonce, out var rTag, out var rCt);

    var replyPlain = CryptoUtils.DecryptAesGcm(aesKey, rNonce, rCt, rTag);
    Console.WriteLine("Server replied (decrypted): " + Encoding.UTF8.GetString(replyPlain));
